/* ============================================================================
 *  Http.h  -- Web 层的 HTTP 数据结构与工具（零依赖，自实现）
 *
 *  为什么不用现成库：见 README「设计约束」——内核与 Web 层都不引入第三方依赖，
 *  所以这里只实现本项目真正需要的最小子集：
 *    - 解析请求行 + 头字段 + Content-Length 体（不支持 chunked：我们自己的
 *      前端从不发 chunked，浏览器上传走 multipart/base64，长度已知）
 *    - 拼响应（状态行 + 头 + 体），统一 CORS 与 JSON 响应模板
 *  刻意不做的：压缩、流水线、keep-alive 复用（浏览器每次新建连接也能工作，
 *  代价是多几次握手；换来的是实现与线程模型都简单可靠）。
 * ==========================================================================*/
#ifndef DBKP_WEB_HTTP_H
#define DBKP_WEB_HTTP_H

#include "Web/Json.h"

#include <map>
#include <string>

namespace DBKP {

/* 套接字句柄用整数表示，避免把 winsock2.h 传染给所有 include Http.h 的文件 */
typedef uintptr_t CbkSocket;
const CbkSocket kCbkInvalidSocket = static_cast<CbkSocket>(~static_cast<uintptr_t>(0));

/* --------------------------------------------------------------- 请求 */
class CHttpRequest {
public:
    std::string method;              /* 大写："GET" / "POST" / "DELETE" */
    std::string target;              /* 原始请求目标，可能带查询串 */
    std::string path;                /* 解码后的路径（不含查询串） */
    std::string version;             /* "HTTP/1.1" */
    std::string body;

    /* path 参数：/api/jobs/3 命中 "/api/jobs/:id" 时 params["id"]="3" */
    typedef std::map<std::string, std::string> TParams;
    TParams params;

    std::string query(const std::string& key, const std::string& def = "") const;
    std::string header(const std::string& key, const std::string& def = "") const;

    /** 把 body 按 JSON 解析到 req；失败时返回 false 并把原因写入 err */
    bool json(CJsonValue& value, std::string& err) const;

    /** Authorization: Bearer <token>；没有则回退 ?token= 查询串（EventSource 用） */
    std::string bearerToken() const;

    /** Content-Type 是否含 "application/json" */
    bool isJsonBody() const;

    /** Expect 头里是否要求 "100-continue"（.NET 的 POST 默认带） */
    bool hasExpectContinue() const;

    void setHeader(const std::string& key, const std::string& value) { m_headers[ToLower(key)] = value; }
    void setRawTarget(const std::string& raw) { m_rawTarget = raw; }
    const std::string& rawTarget() const { return m_rawTarget; }
    void setClient(const std::string& ip, unsigned short port) { m_clientIp = ip; m_clientPort = port; }
    const std::string& clientIp() const { return m_clientIp; }
    unsigned short clientPort() const { return m_clientPort; }

    /* 连接句柄：SSE handler 要在返回之前持续往这个 socket 写事件，
       所以请求对象必须能拿到它（由服务器填写，handler 只读）。 */
    void setSocket(CbkSocket sock) { m_socket = sock; }
    CbkSocket socket() const { return m_socket; }

    /* body 为空时从查询串里取字段（DELETE/GET 的简单参数） */
    std::string form(const std::string& key, const std::string& def = "") const;

private:
    std::map<std::string, std::string> m_headers;  /* key 一律小写 */
    std::string m_rawTarget;
    std::string m_clientIp;
    unsigned short m_clientPort = 0;
    CbkSocket m_socket = kCbkInvalidSocket;

    static std::string ToLower(const std::string& s);

public:
    /* 报文解析器（自由函数 parseHttpRequest）要把方法名规范化成大写，
       所以这个helper 得是公开的 */
    static std::string methodUpper(const std::string& m);
};

/* --------------------------------------------------------------- 响应 */
class CHttpResponse {
public:
    int  status = 200;
    std::string statusText;          /* 为空时按 status 自动填充 */
    std::string contentType = "text/plain; charset=utf-8";
    std::string body;
    bool   wantClose = true;         /* 恒为 true：单请求单连接，写完即关 */
    bool   streaming = false;        /* true 表示 handler 已自行把响应写完（SSE），
                                        服务器不得再 serialize/发送一遍 */
    std::map<std::string, std::string> extraHeaders;

    /* ---- JSON 统一模板：{"code":int,"msg":string,"data":...} ----
     * 约定：code==0 表示成功，非 0 为内核错误码（见 Defs.h），
     * HTTP 状态另按语义给（401/403/404/400/409/500），前端两处都能用。 */
    static CHttpResponse jsonOk(const CJsonValue& data);
    static CHttpResponse jsonOk(const CJsonValue& data, const std::string& msg);
    static CHttpResponse jsonError(int code, const std::string& msg, int httpStatus = 200);
    static CHttpResponse text(int status, const std::string& bodyText);
    static CHttpResponse html(const std::string& markup);
    static CHttpResponse file(const std::string& contentType, const std::string& bytes);
    static CHttpResponse notModified();

    /** data 为 null 时省略 "data" 字段，便于只回 code/msg 的接口 */
    static CHttpResponse makeJson(int code, const std::string& msg,
                                   const CJsonValue& data, bool includeData);

    void setHeader(const std::string& key, const std::string& value) { extraHeaders[key] = value; }

    /** 序列化为完整报文（含 CORS 头）。Content-Length 自动计算。 */
    std::string serialize() const;

    static const char* statusTextOf(int status);
};

/* ---------------------------------------------------------------- 工具 */
/** percent-decode；'+' 也当空格（表单/查询串习惯）。非法转义序列按原样保留。 */
std::string urlDecode(const std::string& in);
std::string urlEncode(const std::string& in);

/** 解析 "k1=v1&k2=v2"，值已解码；重复键取第一个。 */
void parseQueryPairs(const std::string& text, std::map<std::string, std::string>& out);

/** 标准 base64（用于 data: URL 上传与下载链接）。 */
std::string base64Encode(const std::string& in);
bool base64Decode(const std::string& in, std::string& out);

/** 按扩展名给 MIME（只覆盖前端会用到的几种） */
const char* mimeTypeOf(const std::string& path);

/** 去掉 ".."，防止 URL 穿越到 web 根目录之外。返回 false 表示越界。 */
bool normalizeStaticPath(const std::string& urlPath, std::string& relPath);

/* ------------------------------------------------------------ SSE 片段 */
/** text/event-stream 的响应头（无 Content-Length：流式） */
std::string sseHead();
/** 一条 SSE 事件："event: name\ndata: <json 或文本>\n\n" */
std::string sseEvent(const std::string& name, const std::string& data);

/** 解析一份（可能不完整的）HTTP/1.1 请求。
 *  need 出参：>0 表示还需要这么多字节，请继续读；0 表示解析成功。
 *  返回 false 表示报文非法（调用方直接回 400）。
 *  单独成函数而不是塞进 socket 代码，是为了能脱离网络做单元测试。 */
bool parseHttpRequest(const std::string& raw, CHttpRequest& req,
                      std::string& err, std::size_t& need);

} /* namespace DBKP */

#endif /* DBKP_WEB_HTTP_H */
