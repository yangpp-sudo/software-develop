/* ============================================================================
 *  HttpServer.h  -- 单端口多线程 HTTP/1.1 服务器（Web 层的骨架）
 *
 *  线程模型（刻意简单）：
 *      1 个 accept 线程 + 每连接 1 个线程，处理完即关连接（Connection: close）。
 *      本工具的并发量是"一个人开几个浏览器标签"，几百连接用不到，
 *      换来的好处是 handler 里可以放心阻塞（读盘、压缩），不必写状态机。
 *
 *  安全边界：
 *      - 默认只绑 127.0.0.1（可配 0.0.0.0，但 README 明确写了风险）
 *      - 静态资源只从 webRoot 里取，路径经 normalizeStaticPath 过滤 ".."
 *      - 请求体上限 maxBodyBytes，超限直接 413，避免一次请求吃掉内存
 * ==========================================================================*/
#ifndef DBKP_WEB_HTTPSERVER_H
#define DBKP_WEB_HTTPSERVER_H

#include "Web/Router.h"

#include "Platform/Compat.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace DBKP {

/* CbkSocket / kCbkInvalidSocket 定义在 Web/Http.h（整数句柄，不污染 winsock2.h） */

class CHttpServer {
public:
    struct Options {
        std::string bindAddress = "127.0.0.1";
        int         port = 8080;
        std::string webRoot = "web";      /* 相对进程工作目录；start() 前会转绝对 */
        std::size_t maxBodyBytes = 64u * 1024u * 1024u;
        int         ioTimeoutMs = 30000;  /* 单连接的读写等待上限 */
        int         maxClients = 32;      /* 同时存活的连接线程数 */
        bool        serveStatic = true;
    };

    CHttpServer();
    ~CHttpServer();

    void setRouter(const CRouter* router) { m_router = router; }
    const Options& options() const { return m_opt; }
    void setOptions(const Options& opt) { m_opt = opt; }

    /** 绑定并启动 accept 线程。失败时 err 给出可直接显示给用户的中文/英文原因。 */
    bool start(std::string& err);
    /** 幂等：停止接受新连接，shutdown 现有连接并 join 全部线程。 */
    void stop();

    bool running() const { return m_running.load(); }
    int  boundPort() const { return m_boundPort; }

    /* 供 SSE / 长任务使用：把响应直接写进某个连接（不关闭），
       返回 false 表示客户端已断开。 */
    bool writeRaw(CbkSocket sock, const std::string& bytes);

private:
    /* 读请求的结果分类：serveConnection 依据它决定回 408/413/400 还是不发响应
       （客户端提前断开时发也没意义）。 */
    enum ReadStatus { RS_OK, RS_TIMEOUT, RS_TOO_LARGE, RS_BAD, RS_CLOSED };

    /* 每连接一线程。done 由 worker 自己置位，accept 线程顺路 join，
       这样 stop() 能等到干净退出，而运行期又不会积累僵尸线程。 */
    struct Worker {
        std::thread                   th;
        std::shared_ptr<std::atomic<bool> > done;
    };

    void acceptLoop();
    void serveConnection(CbkSocket sock, std::string peerIp, unsigned short peerPort,
                         std::shared_ptr<std::atomic<bool> > done);
    ReadStatus readRequest(CbkSocket sock, CHttpRequest& req, std::string& err);
    CHttpResponse routeRequest(CHttpRequest& req);
    CHttpResponse serveStaticFile(const std::string& urlPath);
    bool sendAll(CbkSocket sock, const char* data, std::size_t len);
    /* 关连接前把对端残余数据读干，避免 closesocket 发 RST 打掉自己的响应 */
    void drainSocket(CbkSocket sock);

    void trackSocket(CbkSocket sock);
    void untrackSocket(CbkSocket sock);

    Options            m_opt;
    const CRouter*     m_router = nullptr;
    CbkSocket          m_listen = kCbkInvalidSocket;
    int                m_boundPort = 0;
    std::string        m_absWebRoot;
    std::atomic<bool>  m_running;
    std::atomic<int>   m_clients;
    std::thread        m_acceptor;
    std::vector<Worker> m_workers;
    std::mutex         m_mutex;               /* 保护 m_workers / m_sockets */
    std::set<CbkSocket> m_sockets;            /* stop() 时逐个 shutdown */

    static bool s_wsaReady;                   /* WSAStartup 进程内只需一次 */
    static std::mutex s_wsaMutex;

    DBKP_DISALLOW_COPY_AND_ASSIGN(CHttpServer);
};

} /* namespace DBKP */

#endif /* DBKP_WEB_HTTPSERVER_H */
