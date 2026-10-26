/* ============================================================================
 *  test_web_http.cpp  -- Web 层"不需要 socket 也能验"的部分
 *
 *  这里每一条都对应一个真实踩过的坑，改动 Http/Json/Api 时请务必全跑一遍：
 *    1) 请求解析忘了保存带查询串的原始 target  -> 所有 ?k=v 静默失效
 *       （/api/stat 的 path、/api/events 的 job、/api/jobs 的 log 全中）
 *    2) "Bearer " 前缀长度写错（6/7）          -> 登录后仍然 401
 *    3) JSON 的 \uXXXX（含代理对）解码          -> 中文路径变成另一种字节
 *    4) 路径沙箱比对（正反斜杠、大小写、.. 逃逸）-> 任务被误拒/越界读写
 * ==========================================================================*/
#include "TestFramework.h"

#include "Web/Api.h"
#include "Web/Http.h"
#include "Web/Json.h"

#include <ctime>
#include <string>
#include <vector>

using namespace DBKP;

namespace {

/* 解析一条完整报文：解析成功且不需要再读更多字节 */
bool parseReq(const std::string& raw, CHttpRequest& req, std::string& err) {
    std::size_t need = 0;
    if (!parseHttpRequest(raw, req, err, need)) return false;
    return need == 0;
}

bool endsWith(const std::string& s, const std::string& tail) {
    return s.size() >= tail.size() &&
           s.compare(s.size() - tail.size(), tail.size(), tail) == 0;
}

} /* anonymous namespace */

TEST(WebHttp, QueryStringIsKept) {
    CHttpRequest req;
    std::string err;
    const std::string raw =
        "GET /api/stat?path=D%3A%2Ftmp%2Fa.dbkp&log=1 HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n\r\n";
    ASSERT_TRUE(parseReq(raw, req, err));
    EXPECT_STREQ(req.method.c_str(), "GET");
    EXPECT_STREQ(req.path.c_str(), "/api/stat");
    /* 这两条就是那次"所有查询参数失效"的回归锁：rawTarget 忘赋值时会全落回默认值 */
    EXPECT_STREQ(req.query("path").c_str(), "D:/tmp/a.dbkp");
    EXPECT_STREQ(req.query("log").c_str(), "1");
    EXPECT_STREQ(req.query("absent", "def").c_str(), "def");
    EXPECT_STREQ(req.rawTarget().c_str(), "/api/stat?path=D%3A%2Ftmp%2Fa.dbkp&log=1");
}

TEST(WebHttp, QueryUtf8AndPlus) {
    CHttpRequest req;
    std::string err;
    const std::string raw =
        "GET /api/events?job=7&name=%E4%B8%AD%E6%96%87+a+b HTTP/1.1\r\n\r\n";
    ASSERT_TRUE(parseReq(raw, req, err));
    EXPECT_STREQ(req.query("job").c_str(), "7");          /* SSE 的 job 参数 */
    EXPECT_TRUE(endsWith(req.query("name"), "中文 a b"));
}

TEST(WebHttp, BearerTokenParsing) {
    CHttpRequest req;
    std::string err;
    /* "Bearer " 含空格是 7 个字符：写成 6 会把 "Bearer xxx" 当成 token 本身 */
    ASSERT_TRUE(parseReq("POST /api/jobs HTTP/1.1\r\nAuthorization: Bearer sig.123\r\n"
                         "Content-Length: 2\r\n\r\n{}", req, err));
    EXPECT_STREQ(req.bearerToken().c_str(), "sig.123");
    EXPECT_EQ(req.body, std::string("{}"));

    CHttpRequest lower;
    ASSERT_TRUE(parseReq("GET /api/x HTTP/1.1\r\nAuthorization: bearer ABcd\r\n\r\n", lower, err));
    EXPECT_STREQ(lower.bearerToken().c_str(), "ABcd");

    CHttpRequest basic;
    ASSERT_TRUE(parseReq("GET /api/x HTTP/1.1\r\nAuthorization: Basic Zm9v\r\n\r\n", basic, err));
    EXPECT_STREQ(basic.bearerToken().c_str(), "");        /* 不是 Bearer 就不该硬解 */

    CHttpRequest viaQuery;
    ASSERT_TRUE(parseReq("GET /api/events?token=qq HTTP/1.1\r\n\r\n", viaQuery, err));
    EXPECT_STREQ(viaQuery.bearerToken().c_str(), "qq");   /* EventSource 只能走查询串 */
}

TEST(WebHttp, HeadersAndExpectContinue) {
    CHttpRequest req;
    std::string err;
    const std::string raw =
        "POST /api/jobs HTTP/1.1\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        "Expect: 100-continue\r\n"
        "X-Custom: v\r\n"
        "Content-Length: 13\r\n"
        "\r\n"
        "{\"a\":1,\"b\":2}";
    /* 先喂半截：解析器必须报"还需要多少字节"，而不是当成坏请求 */
    const std::string half = raw.substr(0, raw.find("\r\n\r\n") + 4) + "{\"a\"";
    std::size_t need = 0;
    CHttpRequest partial;
    std::string why;
    EXPECT_TRUE(parseHttpRequest(half, partial, why, need));
    EXPECT_GT(need, static_cast<std::size_t>(0));

    ASSERT_TRUE(parseReq(raw, req, err));
    EXPECT_TRUE(req.isJsonBody());
    EXPECT_TRUE(req.hasExpectContinue());                 /* .NET 客户端靠它才肯发体 */
    EXPECT_STREQ(req.header("x-custom").c_str(), "v");    /* 头名大小写不敏感 */
    EXPECT_STREQ(req.header("absent", "dflt").c_str(), "dflt");

    CHttpRequest plain;
    ASSERT_TRUE(parseReq("GET / HTTP/1.1\r\n\r\n", plain, err));
    EXPECT_FALSE(plain.hasExpectContinue());
}

TEST(WebHttp, RejectsMalformedRequests) {
    CHttpRequest req;
    std::string err;
    std::size_t need = 0;
    EXPECT_FALSE(parseHttpRequest("GARBAGE\r\n\r\n", req, err, need));
    EXPECT_FALSE(parseHttpRequest("GET / HTTP/0.9\r\n\r\n", req, err, need));       /* 版本 */
    EXPECT_FALSE(parseHttpRequest("PATCH /api/x HTTP/1.1\r\n\r\n", req, err, need)); /* 方法 */
    EXPECT_FALSE(parseHttpRequest("GET / HTTP/1.1\r\nnot-a-header\r\n\r\n", req, err, need));
}

TEST(WebHttp, StaticPathTraversalBlocked) {
    std::string rel;
    EXPECT_TRUE(normalizeStaticPath("/", rel));
    EXPECT_STREQ(rel.c_str(), "index.html");
    EXPECT_TRUE(normalizeStaticPath("/css/app.css", rel));
    EXPECT_STREQ(rel.c_str(), "css/app.css");
    EXPECT_FALSE(normalizeStaticPath("/../../Makefile", rel));   /* 明文 .. */
    EXPECT_FALSE(normalizeStaticPath("/a/../../b", rel));
    EXPECT_FALSE(normalizeStaticPath("/a\\b", rel));             /* 反斜杠：Windows 分隔符 */
    EXPECT_FALSE(normalizeStaticPath("/C:/Windows/x", rel));     /* 盘符 */
    /* %2e%2e 在进服务器前就被 decode 成 ".."，所以同样被拦 */
    CHttpRequest req;
    std::string err;
    ASSERT_TRUE(parseReq("GET /%2e%2e/Makefile HTTP/1.1\r\n\r\n", req, err));
    EXPECT_STREQ(req.path.c_str(), "/../Makefile");
    EXPECT_FALSE(normalizeStaticPath(req.path, rel));
}

TEST(WebJson, UnicodeEscapesBecomeUtf8) {
    CJsonValue v;
    std::string err;
    ASSERT_TRUE(CJsonValue::parse("{\"s\":\"\\u5927\\u56db\"}", v, err));
    EXPECT_STREQ(v.at("s").asString().c_str(), "大四");     /* 源码里的 UTF-8 字面量 */

    /* 代理对必须拼成 4 字节 UTF-8，不能各自退化成 U+FFFD */
    ASSERT_TRUE(CJsonValue::parse("{\"s\":\"\\ud83d\\ude00\"}", v, err));
    const std::string emoji = std::string("\xF0\x9F\x98\x80");
    EXPECT_EQ(v.at("s").asString(), emoji);
    EXPECT_EQ(v.at("s").asString().size(), static_cast<std::size_t>(4));

    /* 常用转义集合：引号/反斜杠/斜杠/控制符 */
    ASSERT_TRUE(CJsonValue::parse("{\"s\":\"a\\\"b\\\\c\\/d\\ne\\tf\"}", v, err));
    EXPECT_STREQ(v.at("s").asString().c_str(), "a\"b\\c/d\ne\tf");
    /* 非法转义要报错，不能悄悄吞掉一个字符 */
    EXPECT_FALSE(CJsonValue::parse("{\"s\":\"\\q\"}", v, err));
}

TEST(WebJson, NestedRoundTrip) {
    CJsonValue root = CJsonValue::makeObject();
    root["type"] = CJsonValue::makeString("backup");
    root["cn"] = CJsonValue::makeString("软件开发综合实验");
    root["id"] = CJsonValue::makeInt(42);
    root["ratio"] = CJsonValue::makeDouble(0.5);
    root["ok"] = CJsonValue::makeBool(true);
    CJsonValue arr = CJsonValue::makeArray();
    arr.push_back(CJsonValue::makeString("*.tmp"));
    CJsonValue inner = CJsonValue::makeObject();
    inner["n"] = CJsonValue::makeInt(-7);
    arr.push_back(inner);
    root["filter"] = CJsonValue::makeObject();
    root["filter"]["excludePaths"] = arr;

    const std::string text = root.dump();
    CJsonValue back;
    std::string err;
    ASSERT_TRUE(CJsonValue::parse(text, back, err));
    EXPECT_STREQ(back.at("type").asString().c_str(), "backup");
    EXPECT_STREQ(back.at("cn").asString().c_str(), "软件开发综合实验");   /* 非 ASCII 原样输出 */
    EXPECT_EQ(back.at("id").asInt(), static_cast<int64_t>(42));
    EXPECT_TRUE(back.at("ok").asBool());
    EXPECT_EQ(back.at("filter").at("excludePaths").items().size(), static_cast<std::size_t>(2));
    EXPECT_STREQ(back.at("filter").at("excludePaths").items()[0].asString().c_str(), "*.tmp");
    EXPECT_EQ(back.at("filter").at("excludePaths").items()[1].at("n").asInt(),
              static_cast<int64_t>(-7));
    EXPECT_NEAR(back.at("ratio").asDouble(), 0.5, 1e-9);

    /* 结构被破坏必须识别出来，而不是返回一个"看起来正常"的空对象 */
    EXPECT_FALSE(CJsonValue::parse("[1,2", back, err));
    EXPECT_FALSE(CJsonValue::parse("", back, err));
    EXPECT_FALSE(CJsonValue::parse("{\"a\":1\"b\":2}", back, err));
}

TEST(WebApi, PathWithinRootSandbox) {
    std::string out;
    EXPECT_TRUE(pathWithinRoot("/srv/data", "/srv/data/src", out));
    EXPECT_STREQ(out.c_str(), "/srv/data/src");
    EXPECT_TRUE(pathWithinRoot("/srv/data/", "/srv/data", out));        /* 根本身也算在内 */
    EXPECT_FALSE(pathWithinRoot("/srv/data", "/srv/other", out));
    EXPECT_FALSE(pathWithinRoot("/srv/data", "/srv/database/x", out));  /* 前缀像但不是子目录 */
    EXPECT_FALSE(pathWithinRoot("/srv/data", "", out));
    /* ".." 不能把路径顶出根：折叠后落到 /etc，于是被拒 */
    EXPECT_FALSE(pathWithinRoot("/srv/data", "/srv/data/../../etc", out));
    EXPECT_STREQ(out.c_str(), "/etc");
    /* 未配 dataRoot = 不限制，但依然给出绝对化的解析结果 */
    EXPECT_TRUE(pathWithinRoot("", "relative/dir", out));
    EXPECT_GT(out.size(), static_cast<std::size_t>(0));
#ifdef _WIN32
    EXPECT_TRUE(pathWithinRoot("D:\\db\\root", "D:/db/root/src", out));  /* 正反斜杠混用 */
    EXPECT_TRUE(pathWithinRoot("D:/db/ROOT", "d:/db/root/src", out));    /* Windows 不分大小写 */
#endif
}

TEST(WebApi, TokenSignVerifyExpire) {
    ApiContext ctx;
    ctx.password = "test123";
    ctx.secret = "unit-test-secret";
    const long long now = static_cast<long long>(std::time(nullptr));

    std::string why;
    const std::string good = issueToken(ctx, now + 3600);
    EXPECT_TRUE(good.find('.') != std::string::npos);
    EXPECT_TRUE(verifyToken(ctx, good, why));

    EXPECT_FALSE(verifyToken(ctx, issueToken(ctx, now - 1), why));      /* 已过期 */
    EXPECT_FALSE(verifyToken(ctx, "", why));                             /* 缺令牌 */
    EXPECT_FALSE(verifyToken(ctx, "without-dot", why));                  /* 格式不对 */
    std::string tampered = good;
    tampered[0] = (tampered[0] == 'a') ? 'b' : 'a';
    EXPECT_FALSE(verifyToken(ctx, tampered, why));                       /* 签名被改 */

    ApiContext other;
    other.password = "test123";
    other.secret = "another-secret";
    EXPECT_FALSE(verifyToken(other, good, why));                         /* 换密钥即作废 */

    ApiContext open;                                                     /* 空口令 = 免鉴权 */
    EXPECT_TRUE(verifyToken(open, "", why));
}
