/* ============================================================================
 *  HttpServer.cpp  -- 见 Http.h / HttpServer.h
 * ==========================================================================*/

/* 必须在任何 include 之前定义：mingw-w64 的 ws2tcpip.h 用 NTDDI_VERSION 决定
   是否给出 inet_ntop/inet_pton 原型（只设 _WIN32_WINNT 还不够，NTDDI_VERSION
   会退回默认的 NTDDI_WINXP），Linux 侧无此问题。 */
#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  #ifndef _WIN32_WINNT
  #define _WIN32_WINNT 0x0600
  #endif
  #ifndef WINVER
  #define WINVER 0x0600
  #endif
  #ifndef NTDDI_VERSION
  #define NTDDI_VERSION 0x06000000
  #endif
#endif

#include "Web/HttpServer.h"

#include "Platform/FS.h"
#include "Utils/Logger.h"
#include "Utils/SimpleFile.h"

#include <cerrno>
#include <cstring>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  typedef int        cbkSockLen;
  #define CBK_MSG_FLAGS 0
#else
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <sys/socket.h>
  #include <sys/time.h>
  #include <unistd.h>
  typedef socklen_t  cbkSockLen;
  #define CBK_MSG_FLAGS MSG_NOSIGNAL   /* 对端断开时别用 SIGPIPE 打死进程 */
#endif

namespace DBKP {

bool CHttpServer::s_wsaReady = false;
std::mutex CHttpServer::s_wsaMutex;

namespace {

const std::size_t kReadChunk = 8192;

int lastSockErr() {
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

bool isTimeoutErr(int e) {
#ifdef _WIN32
    return e == WSAETIMEDOUT;
#else
    return e == EAGAIN || e == EWOULDBLOCK;
#endif
}

void closeSock(CbkSocket s) {
#ifdef _WIN32
    ::closesocket(static_cast<SOCKET>(s));
#else
    ::close(static_cast<int>(s));
#endif
}

void shutdownSock(CbkSocket s) {
#ifdef _WIN32
    ::shutdown(static_cast<SOCKET>(s), SD_BOTH);
#else
    ::shutdown(static_cast<int>(s), SHUT_RDWR);
#endif
}

void setIoTimeout(CbkSocket s, int ms) {
#ifdef _WIN32
    DWORD v = static_cast<DWORD>(ms);
    ::setsockopt(static_cast<SOCKET>(s), SOL_SOCKET, SO_RCVTIMEO,
                 reinterpret_cast<const char*>(&v), sizeof(v));
    ::setsockopt(static_cast<SOCKET>(s), SOL_SOCKET, SO_SNDTIMEO,
                 reinterpret_cast<const char*>(&v), sizeof(v));
#else
    struct timeval tv;
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    ::setsockopt(static_cast<int>(s), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(static_cast<int>(s), SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

std::string peerAddress(const struct sockaddr_in& sa) {
    char buf[64] = {0};
    /* 非 const 指针：Windows 的 inet_ntop 形参是 PVOID，POSIX 是 const void*，
       这里取的是 &sa.sin_addr 的只读副本地址，const_cast 安全。 */
    ::inet_ntop(AF_INET, const_cast<void*>(static_cast<const void*>(&sa.sin_addr)),
                buf, static_cast<cbkSockLen>(sizeof(buf)));
    return std::string(buf);
}

} /* anonymous namespace */

/* ------------------------------------------------------------ 生命周期 */
CHttpServer::CHttpServer()
    : m_listen(kCbkInvalidSocket), m_running(false), m_clients(0) {}

CHttpServer::~CHttpServer() { stop(); }

bool CHttpServer::start(std::string& err) {
    if (m_running.load()) { err = "服务器已在运行"; return false; }

#ifdef _WIN32
    {
        std::lock_guard<std::mutex> lk(s_wsaMutex);
        if (!s_wsaReady) {
            WSADATA wd;
            const int rc = ::WSAStartup(MAKEWORD(2, 2), &wd);
            if (rc != 0) { err = "WSAStartup 失败，错误码 " + std::to_string(rc); return false; }
            s_wsaReady = true;
        }
    }
#endif

    /* webRoot 立刻定成绝对路径：任务线程/守护进程可能改变工作目录，
       相对路径在那之后会指向错误的地方。 */
    {
        std::string abs;
        if (Platform::canonicalPath(m_opt.webRoot, abs) == E_OK && !abs.empty())
            m_absWebRoot = abs;
        else {
            std::string cur;
            Platform::currentDir(cur);
            m_absWebRoot = cur + "/" + m_opt.webRoot;
        }
    }

    const CbkSocket fd = static_cast<CbkSocket>(::socket(AF_INET, SOCK_STREAM, 0));
    if (fd == kCbkInvalidSocket) { err = "创建套接字失败"; return false; }

    int on = 1;
    ::setsockopt(static_cast<int>(fd), SOL_SOCKET, SO_REUSEADDR,
                 reinterpret_cast<const char*>(&on), sizeof(on));

    struct sockaddr_in sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    if (m_opt.bindAddress.empty() || m_opt.bindAddress == "*" ||
        m_opt.bindAddress == "0.0.0.0") {
        sa.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        char buf[64];
        std::strncpy(buf, m_opt.bindAddress.c_str(), sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        if (::inet_pton(AF_INET, buf, &sa.sin_addr) != 1) {
            err = "监听地址无效：" + m_opt.bindAddress + "（需 IPv4，如 127.0.0.1）";
            closeSock(fd);
            return false;
        }
    }
    sa.sin_port = htons(static_cast<unsigned short>(m_opt.port < 0 ? 0 : m_opt.port));

    if (::bind(static_cast<int>(fd), reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa)) != 0) {
        err = "绑定端口 " + std::to_string(m_opt.port) + " 失败（端口被占用或权限不足），错误码 "
              + std::to_string(lastSockErr());
        closeSock(fd);
        return false;
    }
    if (::listen(static_cast<int>(fd), 32) != 0) {
        err = "监听失败，错误码 " + std::to_string(lastSockErr());
        closeSock(fd);
        return false;
    }

    struct sockaddr_in bound;
    std::memset(&bound, 0, sizeof(bound));
    cbkSockLen bl = static_cast<cbkSockLen>(sizeof(bound));
    if (::getsockname(static_cast<int>(fd), reinterpret_cast<struct sockaddr*>(&bound), &bl) == 0)
        m_boundPort = ntohs(bound.sin_port);
    else
        m_boundPort = m_opt.port;

    m_listen = fd;
    m_running.store(true);
    m_acceptor = std::thread(&CHttpServer::acceptLoop, this);
    return true;
}

void CHttpServer::stop() {
    const bool was = m_running.exchange(false);

    /* 先让 accept 立刻返回：shutdown+close 会让阻塞中的 accept 失败退出 */
    if (m_listen != kCbkInvalidSocket) {
        shutdownSock(m_listen);
        closeSock(m_listen);
        m_listen = kCbkInvalidSocket;
    }
    /* 再掐断在途连接，否则 stop() 要等到 ioTimeoutMs 才返回 */
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        for (std::set<CbkSocket>::iterator it = m_sockets.begin(); it != m_sockets.end(); ++it)
            shutdownSock(*it);
    }

    if (m_acceptor.joinable()) {
        /* stop() 允许从任意线程调用（main 等信号、Ctrl+C 之后的主循环）。
           万一真是 accept 线程自己调的，只能 detach，绝不能自杀式 join。 */
        if (m_acceptor.get_id() == std::this_thread::get_id()) m_acceptor.detach();
        else m_acceptor.join();
    }
    std::vector<Worker> pool;
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        pool.swap(m_workers);
    }
    const std::thread::id self = std::this_thread::get_id();
    for (std::size_t i = 0; i < pool.size(); ++i) {
        if (!pool[i].th.joinable()) continue;
        /* 正在处理请求的线程可能就在池子里（SSE handler 观察 running() 后
           自己退出前，主线程已经在 join）：那种情况只能 detach */
        if (pool[i].th.get_id() == self) pool[i].th.detach();
        else pool[i].th.join();
    }
    if (was) LOG_INFO("web 服务已停止");
}

void CHttpServer::trackSocket(CbkSocket sock) {
    std::lock_guard<std::mutex> lk(m_mutex);
    m_sockets.insert(sock);
}

void CHttpServer::untrackSocket(CbkSocket sock) {
    std::lock_guard<std::mutex> lk(m_mutex);
    m_sockets.erase(sock);
}

/* ------------------------------------------------------------ 接受循环 */
void CHttpServer::acceptLoop() {
    while (m_running.load()) {
        struct sockaddr_in peer;
        std::memset(&peer, 0, sizeof(peer));
        cbkSockLen len = static_cast<cbkSockLen>(sizeof(peer));
        const CbkSocket fd = static_cast<CbkSocket>(
            ::accept(static_cast<int>(m_listen), reinterpret_cast<struct sockaddr*>(&peer), &len));
        if (fd == kCbkInvalidSocket) {
            /* stop() 期间 accept 必然失败：这不是错误，不要刷屏 */
            if (m_running.load()) LOG_WARN("accept 失败，错误码 " + std::to_string(lastSockErr()));
            if (!m_running.load()) break;
            continue;
        }
        if (m_clients.load() >= m_opt.maxClients) {
            std::string body = CHttpResponse::jsonError(503, "服务繁忙，请稍后再试", 503).serialize();
            sendAll(fd, body.data(), body.size());
            closeSock(fd);
            continue;
        }

        /* 回收已结束的工作线程：worker 退出时把自己的 done 置位，
           这里顺路 join，线程数才不会只增不减。 */
        {
            std::lock_guard<std::mutex> lk(m_mutex);
            for (std::vector<Worker>::iterator it = m_workers.begin(); it != m_workers.end(); ) {
                if (it->done->load()) { if (it->th.joinable()) it->th.join(); it = m_workers.erase(it); }
                else ++it;
            }
        }

        const std::string ip = peerAddress(peer);
        const unsigned short port = ntohs(peer.sin_port);
        std::shared_ptr<std::atomic<bool> > done(new std::atomic<bool>(false));
        Worker w;
        w.done = done;
        w.th = std::thread(&CHttpServer::serveConnection, this, fd, ip, port, done);
        {
            std::lock_guard<std::mutex> lk(m_mutex);
            m_workers.push_back(std::move(w));
        }
        ++m_clients;
    }
}

/* ----------------------------------------------------------- 单连接处理 */
void CHttpServer::serveConnection(CbkSocket sock, std::string peerIp, unsigned short peerPort,
                                  std::shared_ptr<std::atomic<bool> > done) {
    try {
        setIoTimeout(sock, m_opt.ioTimeoutMs);
        trackSocket(sock);

        CHttpRequest req;
        std::string err;
        const ReadStatus st = readRequest(sock, req, err);

        CHttpResponse res;
        if (st == RS_CLOSED) {
            /* 浏览器探测/预连接会立刻断开，回它也没意义，静默收尾 */
        } else if (st == RS_TIMEOUT) {
            res = CHttpResponse::jsonError(408, "读取请求超时", 408);
        } else if (st == RS_TOO_LARGE) {
            res = CHttpResponse::jsonError(413, "请求体超过上限 "
                    + std::to_string(m_opt.maxBodyBytes / (1024 * 1024)) + "MB", 413);
        } else if (st == RS_BAD) {
            res = CHttpResponse::jsonError(400, "请求报文格式错误：" + err, 400);
        } else {
            req.setClient(peerIp, peerPort);
            req.setSocket(sock);           /* SSE handler 需要它自己往连接写事件 */
            if (req.method == "OPTIONS") {
                res = CHttpResponse::text(204, "");      /* CORS 预检：serialize 会带上允许头 */
            } else {
                res = routeRequest(req);
                if (req.method == "HEAD") res.body.clear();
            }
        }

        if (st != RS_CLOSED && !res.streaming) {
            /* streaming：handler（/api/events）已经把头和事件写完，这里再写一遍
               就会让前端看到重复报文，必须跳过 */
            const std::string out = res.serialize();
            if (!sendAll(sock, out.data(), out.size()))
                LOG_DEBUG("写响应失败（客户端可能已关闭页面）: " + req.path);
        }
    } catch (const std::exception& e) {
        LOG_ERR(std::string("连接处理异常: ") + e.what());
    } catch (...) {
        LOG_ERR("连接处理发生未知异常");
    }
    /* 关连接前先把对端可能还在发的字节读干：直接 closesocket() 会发 RST，
       而 RST 会把本端尚未被 ACK 的响应一起销毁——客户端就表现为
       "只收到响应头、响应体是空的"（PowerShell / 部分浏览器会踩到）。 */
    drainSocket(sock);
    shutdownSock(sock);
    untrackSocket(sock);
    closeSock(sock);
    --m_clients;
    done->store(true);
}

CHttpServer::ReadStatus CHttpServer::readRequest(CbkSocket sock, CHttpRequest& req,
                                                 std::string& err) {
    std::string raw;
    const std::size_t hardLimit = m_opt.maxBodyBytes + kReadChunk * 8;  /* 头 + 体 + 余量 */
    bool sent100 = false;
    for (;;) {
        if (!m_running.load()) { err = "服务正在停止"; return RS_CLOSED; }
        char buf[kReadChunk];
        const long n = ::recv(static_cast<int>(sock), buf, static_cast<int>(sizeof(buf)), 0);
        if (n > 0) {
            raw.append(buf, static_cast<std::size_t>(n));
            if (raw.size() > hardLimit) { err = "请求过大"; return RS_TOO_LARGE; }
            std::size_t need = 0;
            const bool ok = parseHttpRequest(raw, req, err, need);
            if (!ok) {
                /* 体积超限和格式错误要分开回：413 对用户是可行动的提示 */
                if (err == "request body too large" || err == "request header too large")
                    return RS_TOO_LARGE;
                return RS_BAD;
            }
            if (need == 0) return RS_OK;
            /* .NET（PowerShell 的 Invoke-WebRequest）发 POST 时会带
               "Expect: 100-continue"，它先把请求体扣住，等中间响应；
               不回它，它也要干等一段超时才肯继续。按 RFC 回 100 最省事。 */
            if (!sent100 && req.hasExpectContinue()) {
                sent100 = true;
                static const char k100[] = "HTTP/1.1 100 Continue\r\n\r\n";
                if (!sendAll(sock, k100, sizeof(k100) - 1))
                    { err = "客户端在等待 100 响应时断开"; return RS_CLOSED; }
            }
            continue;
        }
        if (n == 0) { err = raw.empty() ? "客户端关闭连接" : "请求不完整"; return RS_CLOSED; }
        const int e = lastSockErr();
        if (isTimeoutErr(e)) return RS_TIMEOUT;
        err = "读取失败，错误码 " + std::to_string(e);
        return RS_CLOSED;
    }
}

/* ------------------------------------------------------------- 路由/静态 */
CHttpResponse CHttpServer::routeRequest(CHttpRequest& req) {
    if (m_router) {
        CHttpResponse res;
        if (m_router->dispatch(req, res)) return res;
    }
    const bool isApi = (req.path.compare(0, 5, "/api/") == 0 || req.path == "/api");
    if (isApi)
        return CHttpResponse::jsonError(404, "接口不存在：" + req.path, 404);
    if (m_opt.serveStatic && (req.method == "GET" || req.method == "HEAD"))
        return serveStaticFile(req.path);
    return CHttpResponse::jsonError(404, "页面不存在：" + req.path, 404);
}

CHttpResponse CHttpServer::serveStaticFile(const std::string& urlPath) {
    std::string rel;
    if (!normalizeStaticPath(urlPath, rel))
        return CHttpResponse::text(403, "403 Forbidden: 路径不合法");

    const std::string full = m_absWebRoot + "/" + rel;
    std::vector<uint8_t> bytes;
    const ErrCode ec = CSimpleFile::readWhole(full, bytes);
    if (ec != E_OK) {
        /* 前端会请求 favicon.ico 之类，缺文件是常态，回文本 404 即可，不打日志 */
        return CHttpResponse::text(404, "404 Not Found: " + rel);
    }
    return CHttpResponse::file(mimeTypeOf(rel),
                               std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size()));
}

/* --------------------------------------------------------------- 收发 */
void CHttpServer::drainSocket(CbkSocket sock) {
    /* 只给 300ms：够把已经在路上的字节收完，收不到也不算错。
       目的是让后面的 close 走 FIN 而不是 RST，保住已发出去的响应体。 */
    setIoTimeout(sock, 300);
    char buf[512];
    for (int i = 0; i < 32; ++i) {
        const long n = ::recv(static_cast<int>(sock), buf, static_cast<int>(sizeof(buf)), 0);
        if (n <= 0) break;              /* 0=对端已 FIN，-1=超时/出错，都不必再等 */
    }
}

bool CHttpServer::sendAll(CbkSocket sock, const char* data, std::size_t len) {
    std::size_t off = 0;
    while (off < len) {
        const std::size_t want = len - off < kReadChunk ? (len - off) : kReadChunk;
        const long n = ::send(static_cast<int>(sock), data + off,
                              static_cast<int>(want), CBK_MSG_FLAGS);
        if (n <= 0) return false;
        off += static_cast<std::size_t>(n);
    }
    return true;
}

bool CHttpServer::writeRaw(CbkSocket sock, const std::string& bytes) {
    return sendAll(sock, bytes.data(), bytes.size());
}

} /* namespace DBKP */
