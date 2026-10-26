/* ============================================================================
 *  Api.h  -- REST 接口层：把内核能力映射成浏览器能调的 JSON API
 *
 *  路由一览（全部在 /api 下，静态页面由 CHttpServer 直接从 web/ 目录发）：
 *    GET    /api/info                 服务信息与平台能力（免鉴权，登录页要用）
 *    POST   /api/login                {password} -> {token}
 *    GET    /api/config               默认参数（前端表单预填）
 *    GET    /api/browse?path=         列目录（限 dataRoot）
 *    GET    /api/stat?path=           读 .dbkp 归档头 + 统计
 *    POST   /api/jobs                 创建备份/还原/校验任务
 *    GET    /api/jobs                 任务列表
 *    GET    /api/jobs/:id             任务详情（?log=1 附带最近日志）
 *    POST   /api/jobs/:id/cancel      取消任务
 *    GET    /api/events?job=ID        SSE 进度流
 *
 *  鉴权：除 info/login 外都要 Authorization: Bearer <token>（SSE 用 ?token=）。
 *  token = hex(HMAC-SHA256(secret, "expire")) . expire，无状态、不落盘：
 *  重启服务后旧 token 失效，这对本机工具有利无害。
 * ==========================================================================*/
#ifndef DBKP_WEB_API_H
#define DBKP_WEB_API_H

#include "Web/Http.h"
#include "Web/JobManager.h"
#include "Web/Router.h"

#include <atomic>
#include <string>

namespace DBKP {

class CHttpServer;      /* 只在 ApiContext 里以指针出现，避免拖进 socket 头 */

struct ApiContext {
    CJobManager* jobs = nullptr;
    CHttpServer* server = nullptr;      /* SSE 直接写连接 */

    std::string password;               /* 空 = 免鉴权（仅限本机调试） */
    std::string secret;                 /* token 签名密钥 */
    std::string dataRoot;               /* 允许访问的路径根；空 = 不限 */
    int         tokenTtlHours = 12;

    std::string defaultSource;          /* 前端表单预填 */
    std::string defaultDestination;
    std::string defaultAlgorithm = "huffman";
    std::string webRoot = "web";
    long long   startedAt = 0;

    /* /api/shutdown 只把它置 true，绝不能在 handler 里直接 server->stop()：
       stop() 会 shutdown 掉包括本请求在内的所有连接，响应还没发出去就被掐，
       客户端只能看到"连接被意外关闭"。真正的停止由 main 的等待循环做完。 */
    std::atomic<bool> stopRequested;

    ApiContext() : jobs(nullptr), server(nullptr), tokenTtlHours(12), startedAt(0),
                   stopRequested(false) {}
};

/** 把所有 /api 路由注册进 router。ctx 必须比 router 活得久（由 main 保证）。 */
void registerApiRoutes(CRouter& router, ApiContext& ctx);

/* 暴露给单测：不依赖 socket 就能验证的逻辑 */
std::string issueToken(const ApiContext& ctx, long long expireSec);
bool        verifyToken(const ApiContext& ctx, const std::string& token, std::string& why);
bool        pathWithinRoot(const std::string& root, const std::string& path, std::string& resolved);

} /* namespace DBKP */

#endif /* DBKP_WEB_API_H */
