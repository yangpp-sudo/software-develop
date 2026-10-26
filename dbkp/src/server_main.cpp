/* ============================================================================
 *  server_main.cpp —— bkd：数据备份软件的 Web 服务端（守护进程入口）
 *
 *  与 bk（CLI）的关系：共用同一套内核，这里只是把"命令行动作"换成
 *  "HTTP 接口 + 后台任务"，本身不含任何备份逻辑（分层干净的证据）。
 *
 *  启动：
 *      bkd --host 127.0.0.1 --port 8080 --web web --data-root ./sandbox
 *  然后浏览器打开  http://127.0.0.1:8080/
 * ==========================================================================*/
#include "Crypto/Sha256.h"
#include "Platform/Args.h"
#include "Platform/FS.h"
#include "Utils/Logger.h"
#include "Utils/SimpleFile.h"
#include "Web/Api.h"
#include "Web/HttpServer.h"
#include "Web/Json.h"
#include "Web/Router.h"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

using namespace DBKP;

namespace {

std::atomic<bool> g_stop(false);
void onSignal(int) { g_stop.store(true); }

/**
 * @brief 把 --data-root 定成绝对路径。
 *
 * dataRoot 同时扮演两个角色：沙箱边界 + 接口里相对路径的基准。给成 "tmp" 这种
 * 相对形式时，用户（和报错信息）看不出它到底指哪儿，界面显示的 dataRoot 也没法
 * 直接拿去填表。目录存在就走 canonicalPath（顺便折叠 ..、统一分隔符），不存在
 * 就用当前目录拼一个——启动时目录还没建也允许，后面建了照样能用。
 */
std::string absolutizeDataRoot(const std::string& in) {
    if (in.empty()) return in;
    const bool explicitAbs =
        in[0] == '/' || in[0] == '\\' || (in.size() >= 2 && in[1] == ':');
    std::string out;
    if (explicitAbs) {
        out = in;
    } else {
        std::string abs;
        if (Platform::canonicalPath(in, abs) == E_OK && !abs.empty()) {
            out = abs;
        } else {
            std::string cur;
            if (Platform::currentDir(cur) != E_OK || cur.empty()) return in;
            out = cur + "/" + in;
        }
    }
    if (out.size() >= 2 && out[0] == '/' && out[1] == '/') return in;   /* UNC 不动它 */
    for (std::string::size_type i = 0; i != out.size(); ++i)
        if (out[i] == '\\') out[i] = '/';      /* 分隔符统一，界面/报错/回显一个样 */
    return out;
}

void printUsage() {
    std::printf(
        "usage: bkd [options]\n"
        "  --config FILE        JSON 配置文件（命令行参数优先级更高）\n"
        "  --host ADDR          监听地址，默认 127.0.0.1（0.0.0.0 = 允许局域网访问）\n"
        "  --port N             端口，默认 8080；0 表示让系统随机分配\n"
        "  --web DIR            静态页面目录，默认 ./web\n"
        "  --data-root DIR      允许备份/还原的根目录，默认不限制\n"
        "  --password PASS      登录口令；--password-sha256 HEX 只存摘要更安全\n"
        "  --token-ttl HOURS    令牌有效期，默认 12 小时\n"
        "  --max-body MB        请求体上限（MB），默认 64\n"
        "  --workers N          并发任务数，默认 2（限制 1~8）\n"
        "  --secret STR         令牌签名密钥，默认每次启动随机\n"
        "  --no-static          只提供 API，不发静态页\n"
        "  --log-level L        quiet|error|warn|info|debug\n"
        "  -h, --help           显示本帮助\n");
}

bool nextValue(int argc, char** argv, int& i, std::string& out) {
    if (i + 1 >= argc) { LOG_ERR("missing value for " + std::string(argv[i])); return false; }
    out = argv[++i];
    return true;
}

std::string cfgStr(const CJsonValue& c, const std::string& key, const std::string& def) {
    const CJsonValue& v = c.at(key);
    return v.isString() ? v.asString() : def;
}

int64_t cfgInt(const CJsonValue& c, const std::string& key, int64_t def) {
    const CJsonValue& v = c.at(key);
    if (v.isInt()) return v.asInt();
    if (v.isDouble()) return static_cast<int64_t>(v.asDouble());
    return def;
}

std::string randomSecret() {
    /* 没配 secret 时用"时间 + 缓冲区地址"混进 SHA-256 当一个进程内随机值：
       重启即换密钥，旧 token 全部失效——对本机工具是好事。 */
    char seed[128];
    std::snprintf(seed, sizeof(seed), "%llu|%p|%d",
                  static_cast<unsigned long long>(
                      std::chrono::steady_clock::now().time_since_epoch().count()),
                  static_cast<const void*>(seed), static_cast<int>(std::rand()));
    uint8_t digest[CSha256::kDigestSize];
    CSha256::hash(seed, std::strlen(seed), digest);
    return CSha256::toHex(digest);
}

} /* anonymous namespace */

int main(int argc, char** argv) {
    /* 命令行里随时可能出现中文路径：argv 是 ANSI 码页字节，必须先转成
       工程内部统一的 UTF-8，否则 --data-root 会和 HTTP 请求体里的
       UTF-8 路径比不上（任务全被沙箱拒掉，这是我们踩过的坑）。 */
    std::vector<std::string> argStore;
    Platform::useUtf8Args(argc, argv, argStore);

    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);
#ifdef _WIN32
    std::system("chcp 65001 >nul 2>&1");   /* 让中文日志在旧控制台里不花屏 */
#endif

    CHttpServer::Options opt;
    ApiContext ctx;
    ctx.startedAt = static_cast<long long>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    ctx.tokenTtlHours = 12;
    ctx.defaultAlgorithm = "huffman";
    size_t workers = 2;
    int maxBodyMb = 64;
    std::string configFile, password, passwordSha;

    /* 先读配置文件再按命令行覆盖：bkd.conf 里长期存口令，
       临时换个端口不必动文件。 */
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--config" && i + 1 < argc) configFile = argv[++i];
    }
    CJsonValue conf = CJsonValue::makeObject();
    if (!configFile.empty()) {
        std::vector<uint8_t> bytes;
        const ErrCode ec = CSimpleFile::readWhole(configFile, bytes);
        if (ec != E_OK) { LOG_ERR("配置文件读取失败: " + configFile); return 2; }
        const std::string text(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        std::string err;
        if (!CJsonValue::parse(text, conf, err)) {
            LOG_ERR("配置文件不是合法 JSON: " + configFile + " " + err);
            return 2;
        }
        opt.bindAddress = cfgStr(conf, "host", opt.bindAddress);
        opt.port = static_cast<int>(cfgInt(conf, "port", opt.port));
        opt.webRoot = cfgStr(conf, "web", opt.webRoot);
        ctx.dataRoot = cfgStr(conf, "dataRoot", "");
        ctx.defaultSource = cfgStr(conf, "defaultSource", "");
        ctx.defaultDestination = cfgStr(conf, "defaultDestination", "");
        ctx.defaultAlgorithm = cfgStr(conf, "defaultAlgorithm", "huffman");
        password = cfgStr(conf, "password", "");
        passwordSha = cfgStr(conf, "passwordSha256", "");
        ctx.secret = cfgStr(conf, "secret", "");
        ctx.tokenTtlHours = static_cast<int>(cfgInt(conf, "tokenTtlHours", 12));
        workers = static_cast<size_t>(cfgInt(conf, "workers", 2));
        maxBodyMb = static_cast<int>(cfgInt(conf, "maxBodyMb", 64));
        opt.serveStatic = cfgInt(conf, "serveStatic", 1) != 0;
        Logger::instance().setLevelFromText(cfgStr(conf, "logLevel", "info"));
    }

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        std::string v;
        if (a == "-h" || a == "--help") { printUsage(); return 0; }
        else if (a == "--config") { ++i; }              /* 上面处理过了 */
        else if (a == "--host") { if (!nextValue(argc, argv, i, v)) return 2; opt.bindAddress = v; }
        else if (a == "--port") { if (!nextValue(argc, argv, i, v)) return 2; opt.port = std::atoi(v.c_str()); }
        else if (a == "--web") { if (!nextValue(argc, argv, i, v)) return 2; opt.webRoot = v; }
        else if (a == "--data-root") { if (!nextValue(argc, argv, i, v)) return 2; ctx.dataRoot = v; }
        else if (a == "--password") { if (!nextValue(argc, argv, i, v)) return 2; password = v; passwordSha.clear(); }
        else if (a == "--password-sha256") { if (!nextValue(argc, argv, i, v)) return 2; passwordSha = v; password.clear(); }
        else if (a == "--token-ttl") { if (!nextValue(argc, argv, i, v)) return 2; ctx.tokenTtlHours = std::atoi(v.c_str()); }
        else if (a == "--max-body") { if (!nextValue(argc, argv, i, v)) return 2; maxBodyMb = std::atoi(v.c_str()); }
        else if (a == "--workers") { if (!nextValue(argc, argv, i, v)) return 2; workers = static_cast<size_t>(std::atoi(v.c_str())); }
        else if (a == "--secret") { if (!nextValue(argc, argv, i, v)) return 2; ctx.secret = v; }
        else if (a == "--default-source") { if (!nextValue(argc, argv, i, v)) return 2; ctx.defaultSource = v; }
        else if (a == "--default-destination") { if (!nextValue(argc, argv, i, v)) return 2; ctx.defaultDestination = v; }
        else if (a == "--no-static") { opt.serveStatic = false; }
        else if (a == "--log-level") { if (!nextValue(argc, argv, i, v)) return 2; Logger::instance().setLevelFromText(v); }
        else if (a == "-v" || a == "--verbose") { Logger::instance().setLevel(LL_DEBUG); }
        else if (a == "-q" || a == "--quiet") { Logger::instance().setLevel(LL_ERROR); }
        else { LOG_ERR("未知参数: " + a); printUsage(); return 2; }
    }

    /* 口令优先取摘要：配了 passwordSha256 就不该再留明文 */
    ctx.password = !passwordSha.empty() ? passwordSha : password;
    if (ctx.secret.empty()) ctx.secret = randomSecret();
    if (maxBodyMb < 1) maxBodyMb = 1;
    opt.maxBodyBytes = static_cast<std::size_t>(maxBodyMb) * 1024u * 1024u;
    if (workers < 1) workers = 1;
    ctx.dataRoot = absolutizeDataRoot(ctx.dataRoot);   /* 边界=基准，必须是绝对路径 */

    CJobManager jobs(workers);
    CRouter router;
    registerApiRoutes(router, ctx);

    CHttpServer server;
    ctx.jobs = &jobs;
    ctx.server = &server;
    server.setOptions(opt);
    server.setRouter(&router);

    std::string err;
    if (!server.start(err)) {
        LOG_ERR("启动失败: " + err);
        jobs.stop();
        return 1;
    }
    std::printf("dbkp web 服务已启动： http://%s:%d/   （Ctrl+C 退出）\n",
                opt.bindAddress == "0.0.0.0" ? "127.0.0.1" : opt.bindAddress.c_str(),
                server.boundPort());
    std::printf("  静态目录 : %s\n", opt.serveStatic ? opt.webRoot.c_str() : "(已关闭)");
    std::printf("  数据根   : %s\n", ctx.dataRoot.empty() ? "(未限制，任意路径)" : ctx.dataRoot.c_str());
    std::printf("  登录鉴权 : %s\n", ctx.password.empty() ? "关闭（仅建议本机调试）" : "开启");
    std::printf("  并发任务 : %zu    请求体上限 : %dMB\n", workers, maxBodyMb);
    std::fflush(stdout);

    /* 主循环等三件事：Ctrl+C 信号、服务自己停止、/api/shutdown 置的标志。
       最后一种必须等响应写回客户端之后再 stop()，否则网页看到的是连接被掐。 */
    while (!g_stop.load() && server.running() && !ctx.stopRequested.load())
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

    LOG_INFO("正在停止服务…");
    server.stop();          /* 先关连接：不再接受新请求 */
    jobs.stop();            /* 再取消并 join 后台任务线程 */
    std::printf("服务已退出\n");
    return 0;
}

