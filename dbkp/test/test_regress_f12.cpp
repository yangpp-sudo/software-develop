/* ============================================================================
 *  test_regress_f12.cpp  -- F12（登录失败限速 + CORS 收敛）
 *
 *  背景（整改清单 F12）：
 *    ① hLogin 此前对失败次数不设限，本机端口可被离线字典无限爆破；
 *       现在按来源 IP 计数，连续 5 次失败上锁，之后指数退避 1s→2s→4s→…
 *       封顶 300s，成功登录清零，到期自动放开。
 *    ② serialize()/sseHead() 此前对所有响应无条件发
 *       Access-Control-Allow-Origin: *（且允许 Authorization 头），任意恶意
 *       网页可读取本机 API 响应。现在按请求 Origin 判定：无 Origin 不发、
 *       null 回 null、回环地址回原值、其余不发；--cors-origin 可显式覆盖。
 *
 *  单测口径：hLogin 的 429 分支与 serialize 的报头都长在 socket 路径上，
 *    本仓库没有 socket 型用例（见 test/ 下无 WSAStartup/socket 调用），
 *    因此这里直接回归两处暴露出来的纯函数：
 *      loginThrottleAllow / loginThrottleRecord（限速本体）
 *      resolveCorsOrigin + CHttpResponse::serialize / sseHead（CORS 本体）
 * ==========================================================================*/
#include "TestFramework.h"

#include <string>

#include <chrono>
#include <thread>

#include "Web/Api.h"
#include "Web/Http.h"

using namespace DBKP;

namespace {

bool contains(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

void sleepMs(int ms) {
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

} /* anonymous namespace */

/* ------------------------------------------------------------ 登录限速 */

/* 连续 5 次失败后，第 6 次必须被拒，并给出可回显的 Retry-After 秒数 */
TEST(RegressF12, five_failures_then_locked_with_retry_after) {
    resetLoginThrottleForTest();
    const std::string ip = "10.0.0.11";
    long long ra = -1;
    for (int i = 0; i < 5; ++i) {
        ra = -1;
        EXPECT_TRUE(loginThrottleAllow(ip, ra));      /* 前 5 次都放行 */
        loginThrottleRecord(ip, false);
    }
    ra = -1;
    EXPECT_FALSE(loginThrottleAllow(ip, ra));         /* 第 6 次拒绝 */
    EXPECT_GE(ra, 1);                                /* 带 Retry-After */
    EXPECT_LE(ra, 2);
    resetLoginThrottleForTest();
}

/* 锁定期内即使口令正确也被拒（不校验口令，限速才有意义）；
   退避到期后自动放开，不需要人工干预。base=1s，睡 1.3s 足够跨过去。 */
TEST(RegressF12, locked_during_backoff_released_after_expiry) {
    resetLoginThrottleForTest();
    const std::string ip = "10.0.0.12";
    long long ra = 0;
    for (int i = 0; i < 5; ++i) {
        loginThrottleAllow(ip, ra);
        loginThrottleRecord(ip, false);
    }
    /* 模拟"用户这次输对了"：Allow 先拦下，根本走不到口令比对 */
    EXPECT_FALSE(loginThrottleAllow(ip, ra));
    sleepMs(1300);
    ra = 99;
    EXPECT_TRUE(loginThrottleAllow(ip, ra));          /* 到期放开 */
    EXPECT_EQ(ra, 0LL);
    resetLoginThrottleForTest();
}

/* 成功登录清零：4 次失败 + 1 次成功，之后再来 4 次失败仍不该触发锁定 */
TEST(RegressF12, success_clears_failure_count) {
    resetLoginThrottleForTest();
    const std::string ip = "10.0.0.13";
    long long ra = 0;
    for (int i = 0; i < 4; ++i) loginThrottleRecord(ip, false);
    loginThrottleRecord(ip, true);                    /* 一次成功，计数归零 */
    for (int i = 0; i < 4; ++i) {
        ra = -1;
        EXPECT_TRUE(loginThrottleAllow(ip, ra));
        loginThrottleRecord(ip, false);
    }
    ra = -1;
    EXPECT_TRUE(loginThrottleAllow(ip, ra));          /* 累计 8 次但被清零打断 */
    resetLoginThrottleForTest();
}

/* 第 6 次起翻倍的退避：5 次失败锁 1s，熬过一次后再失败应锁更久 */
TEST(RegressF12, backoff_grows_exponentially) {
    resetLoginThrottleForTest();
    const std::string ip = "10.0.0.14";
    long long ra = 0;
    for (int i = 0; i < 5; ++i) loginThrottleRecord(ip, false);
    EXPECT_FALSE(loginThrottleAllow(ip, ra));
    const long long first = ra;
    EXPECT_GE(first, 1LL);
    EXPECT_LE(first, 2LL);
    sleepMs(1300);                                    /* 等第一轮锁定过去 */
    EXPECT_TRUE(loginThrottleAllow(ip, ra));
    loginThrottleRecord(ip, false);                   /* 第 6 次失败 → 翻倍 */
    long long second = 0;
    EXPECT_FALSE(loginThrottleAllow(ip, second));
    EXPECT_GE(second, first);                         /* 单调不减 */
    EXPECT_LE(second, 4LL);
    resetLoginThrottleForTest();
}

/* 不同 IP 互不影响：A 被锁不能连带把 B 也拦下 */
TEST(RegressF12, throttle_is_per_ip) {
    resetLoginThrottleForTest();
    long long ra = 0;
    for (int i = 0; i < 5; ++i) loginThrottleRecord("10.0.0.21", false);
    EXPECT_FALSE(loginThrottleAllow("10.0.0.21", ra));
    ra = -1;
    EXPECT_TRUE(loginThrottleAllow("10.0.0.22", ra));
    EXPECT_EQ(ra, 0LL);
    resetLoginThrottleForTest();
}

/* ---------------------------------------------------------------- CORS */

/* 无 Origin 头（同源、命令行、PowerShell 脚本）→ 不发任何 CORS 头 */
TEST(RegressF12, no_origin_means_no_acao) {
    EXPECT_EQ(resolveCorsOrigin("", ""), std::string());
    CHttpResponse r = CHttpResponse::jsonOk(CJsonValue());
    r.corsAllowOrigin = resolveCorsOrigin("", "");
    const std::string raw = r.serialize();
    EXPECT_FALSE(contains(raw, "Access-Control-Allow-Origin"));
    EXPECT_FALSE(contains(raw, "Vary: Origin"));
}

/* Origin: null（file:// 双击打开前端）→ 回 null 且带 Vary: Origin。
   这条必须成立，否则双击打开 index.html 的用法整体报废。 */
TEST(RegressF12, null_origin_is_allowed_and_echoed) {
    EXPECT_EQ(resolveCorsOrigin("", "null"), std::string("null"));
    EXPECT_EQ(resolveCorsOrigin("", "NULL"), std::string("null"));
    CHttpResponse r = CHttpResponse::jsonOk(CJsonValue());
    r.corsAllowOrigin = "null";
    const std::string raw = r.serialize();
    EXPECT_TRUE(contains(raw, "Access-Control-Allow-Origin: null\r\n"));
    EXPECT_TRUE(contains(raw, "Vary: Origin\r\n"));
    /* SSE 头同样处理 */
    const std::string sse = sseHead("null");
    EXPECT_TRUE(contains(sse, "Access-Control-Allow-Origin: null\r\n"));
    EXPECT_TRUE(contains(sse, "Vary: Origin\r\n"));
}

/* 回环地址放行并回原值；其余来源一律不发 */
TEST(RegressF12, loopback_allowed_other_origins_denied) {
    EXPECT_EQ(resolveCorsOrigin("", "http://localhost:8087"),
              std::string("http://localhost:8087"));
    EXPECT_EQ(resolveCorsOrigin("", "http://127.0.0.1:8087"),
              std::string("http://127.0.0.1:8087"));
    EXPECT_EQ(resolveCorsOrigin("", "http://LOCALHOST"),
              std::string("http://LOCALHOST"));
    /* 前缀陷阱：localhost.evil 不是回环 */
    EXPECT_EQ(resolveCorsOrigin("", "http://localhost.evil:8087"), std::string());
    EXPECT_EQ(resolveCorsOrigin("", "http://evil.example"), std::string());
    EXPECT_EQ(resolveCorsOrigin("", "http://10.0.0.5:8087"), std::string());
    EXPECT_EQ(resolveCorsOrigin("", "https://localhost:8087"), std::string());

    CHttpResponse r = CHttpResponse::jsonOk(CJsonValue());
    r.corsAllowOrigin = resolveCorsOrigin("", "http://evil.example");
    EXPECT_FALSE(contains(r.serialize(), "Access-Control-Allow-Origin"));
}

/* --cors-origin 显式配置优先于一切判定（含 *，供本地开发显式放行） */
TEST(RegressF12, configured_origin_overrides_everything) {
    EXPECT_EQ(resolveCorsOrigin("*", "http://evil.example"), std::string("*"));
    EXPECT_EQ(resolveCorsOrigin("*", ""), std::string("*"));
    EXPECT_EQ(resolveCorsOrigin("http://192.168.1.50:3000", "http://evil.example"),
              std::string("http://192.168.1.50:3000"));
}

/* Retry-After 由 hLogin 写进 extraHeaders，serialize 必须原样发出 */
TEST(RegressF12, retry_after_header_is_serialized) {
    CHttpResponse r = CHttpResponse::jsonError(E_BUSY, "登录失败次数过多", 429);
    r.setHeader("Retry-After", "7");
    const std::string raw = r.serialize();
    EXPECT_TRUE(contains(raw, "HTTP/1.1 429 Too Many Requests\r\n"));
    EXPECT_TRUE(contains(raw, "Retry-After: 7\r\n"));
}
