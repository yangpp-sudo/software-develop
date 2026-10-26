/* ============================================================================
 *  Http.cpp  -- 见 Http.h
 * ==========================================================================*/
#include "Web/Http.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace DBKP {

/* ------------------------------------------------------------- 小工具 */
std::string CHttpRequest::ToLower(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        out += static_cast<char>((c >= 'A' && c <= 'Z') ? c - 'A' + 'a' : c);
    }
    return out;
}

std::string CHttpRequest::methodUpper(const std::string& m) {
    std::string out;
    out.reserve(m.size());
    for (std::size_t i = 0; i < m.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(m[i]);
        out += static_cast<char>((c >= 'a' && c <= 'z') ? c - 'a' + 'A' : c);
    }
    return out;
}

static bool hexVal(char c, int& out) {
    if (c >= '0' && c <= '9') out = c - '0';
    else if (c >= 'a' && c <= 'f') out = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F') out = c - 'A' + 10;
    else return false;
    return true;
}

std::string urlDecode(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    for (std::size_t i = 0; i < in.size(); ++i) {
        const char c = in[i];
        if (c == '+') { out += ' '; continue; }
        if (c == '%' && i + 2 < in.size()) {
            int hi = 0, lo = 0;
            if (hexVal(in[i + 1], hi) && hexVal(in[i + 2], lo)) {
                out += static_cast<char>((hi << 4) + lo);
                i += 2;
                continue;
            }
        }
        out += c;                     /* 非法转义原样保留：宁可宽容也不丢路径 */
    }
    return out;
}

std::string urlEncode(const std::string& in) {
    static const char* kHex = "0123456789ABCDEF";
    std::string out;
    out.reserve(in.size() + 8);
    for (std::size_t i = 0; i < in.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(in[i]);
        const bool safe = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                          (c >= '0' && c <= '9') || c == '-' || c == '_' ||
                          c == '.' || c == '~' || c == '/';
        if (safe) out += static_cast<char>(c);
        else { out += '%'; out += kHex[c >> 4]; out += kHex[c & 0xF]; }
    }
    return out;
}

void parseQueryPairs(const std::string& text, std::map<std::string, std::string>& out) {
    std::size_t pos = 0;
    while (pos < text.size()) {
        std::size_t eq = text.find('=', pos);
        std::size_t amp = text.find('&', pos);
        if (amp == std::string::npos) amp = text.size();
        std::string key, val;
        if (eq == std::string::npos || eq > amp) {
            key = text.substr(pos, amp - pos);       /* 无值开关，如 ?verbose */
        } else {
            key = text.substr(pos, eq - pos);
            val = text.substr(eq + 1, amp - eq - 1);
        }
        if (!key.empty()) {
            const std::string k = urlDecode(key);
            if (out.find(k) == out.end()) out[k] = urlDecode(val);  /* 重复键取首个 */
        }
        pos = amp + 1;
    }
}

/* ------------------------------------------------------------- 请求访问 */
std::string CHttpRequest::query(const std::string& key, const std::string& def) const {
    const std::size_t q = m_rawTarget.find('?');
    if (q == std::string::npos) return def;
    std::map<std::string, std::string> kv;
    parseQueryPairs(m_rawTarget.substr(q + 1), kv);
    std::map<std::string, std::string>::const_iterator it = kv.find(key);
    return it == kv.end() ? def : it->second;
}

std::string CHttpRequest::header(const std::string& key, const std::string& def) const {
    std::map<std::string, std::string>::const_iterator it = m_headers.find(ToLower(key));
    return it == m_headers.end() ? def : it->second;
}

bool CHttpRequest::isJsonBody() const {
    return header("content-type").find("application/json") != std::string::npos;
}

bool CHttpRequest::hasExpectContinue() const {
    return ToLower(header("expect")).find("100-continue") != std::string::npos;
}

bool CHttpRequest::json(CJsonValue& value, std::string& err) const {
    if (body.empty()) { err = "empty request body"; return false; }
    return CJsonValue::parse(body, value, err);
}

std::string CHttpRequest::bearerToken() const {
    const std::string auth = header("authorization");
    /* "Bearer " 是 7 个字符（含空格）：早期写成 6 会让所有带 token 的请求
       都掉去查 ?token=，表现为"登录后仍然 401" */
    if (auth.size() >= 7 && ToLower(auth.substr(0, 7)) == "bearer ")
        return auth.substr(7);
    return query("token");            /* EventSource 不能设请求头，只能用查询串 */
}

std::string CHttpRequest::form(const std::string& key, const std::string& def) const {
    if (!body.empty() && header("content-type").find("x-www-form-urlencoded") != std::string::npos) {
        std::map<std::string, std::string> kv;
        parseQueryPairs(body, kv);
        std::map<std::string, std::string>::const_iterator it = kv.find(key);
        if (it != kv.end()) return it->second;
    }
    return query(key, def);
}

/* -------------------------------------------------------------- base64 */
static const char* kB64Chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64Encode(const std::string& in) {
    std::string out;
    out.reserve((in.size() + 2) / 3 * 4);
    std::size_t i = 0;
    while (i + 2 < in.size()) {
        const unsigned v = (static_cast<unsigned char>(in[i]) << 16) |
                           (static_cast<unsigned char>(in[i + 1]) << 8) |
                            static_cast<unsigned char>(in[i + 2]);
        out += kB64Chars[(v >> 18) & 63];
        out += kB64Chars[(v >> 12) & 63];
        out += kB64Chars[(v >> 6) & 63];
        out += kB64Chars[v & 63];
        i += 3;
    }
    const std::size_t rem = in.size() - i;
    if (rem == 1) {
        const unsigned v = static_cast<unsigned char>(in[i]) << 16;
        out += kB64Chars[(v >> 18) & 63];
        out += kB64Chars[(v >> 12) & 63];
        out += "==";
    } else if (rem == 2) {
        const unsigned v = (static_cast<unsigned char>(in[i]) << 16) |
                           (static_cast<unsigned char>(in[i + 1]) << 8);
        out += kB64Chars[(v >> 18) & 63];
        out += kB64Chars[(v >> 12) & 63];
        out += kB64Chars[(v >> 6) & 63];
        out += '=';
    }
    return out;
}

bool base64Decode(const std::string& in, std::string& out) {
    int table[256];
    for (int i = 0; i < 256; ++i) table[i] = -1;
    for (int i = 0; i < 64; ++i) table[static_cast<unsigned char>(kB64Chars[i])] = i;
    table[static_cast<unsigned char>('-')] = 62;   /* 容忍 URL-safe 变体 */
    table[static_cast<unsigned char>('_')] = 63;

    out.clear();
    out.reserve(in.size() / 4 * 3 + 3);
    int bits = 0, acc = 0, n = 0;
    for (std::size_t i = 0; i < in.size(); ++i) {
        const unsigned char c = in[i];
        if (c == '=' || c == '\n' || c == '\r') { if (c == '=') break; continue; }
        const int v = table[c];
        if (v < 0) return false;                   /* 非法字符：交给上层报 400 */
        acc = (acc << 6) | v;
        bits += 6;
        ++n;
        if (bits >= 8) {
            bits -= 8;
            out += static_cast<char>((acc >> bits) & 0xFF);
        }
    }
    (void)n;
    return true;
}

/* ---------------------------------------------------------------- MIME */
const char* mimeTypeOf(const std::string& path) {
    const std::size_t dot = path.find_last_of('.');
    if (dot == std::string::npos) return "application/octet-stream";
    std::string ext = path.substr(dot + 1);
    for (std::size_t i = 0; i < ext.size(); ++i)
        ext[i] = static_cast<char>((ext[i] >= 'A' && ext[i] <= 'Z') ? ext[i] - 'A' + 'a' : ext[i]);
    if (ext == "html" || ext == "htm") return "text/html; charset=utf-8";
    if (ext == "css")  return "text/css; charset=utf-8";
    if (ext == "js")   return "application/javascript; charset=utf-8";
    if (ext == "json") return "application/json; charset=utf-8";
    if (ext == "svg")  return "image/svg+xml";
    if (ext == "png")  return "image/png";
    if (ext == "jpg" || ext == "jpeg") return "image/jpeg";
    if (ext == "ico")  return "image/x-icon";
    if (ext == "txt" || ext == "log") return "text/plain; charset=utf-8";
    if (ext == "wasm") return "application/wasm";
    return "application/octet-stream";
}

/* -------------------------------------------------- 静态路径安全化处理 */
bool normalizeStaticPath(const std::string& urlPath, std::string& relPath) {
    relPath.clear();
    if (urlPath.empty() || urlPath.find('\0') != std::string::npos) return false;

    /* 逐段处理：只接受普通名字，遇到 "." ".." 反斜杠一律拒绝。
     * 注意 path 已经 percent-decode 过，"%2e%2e" 这类编码穿越在这里
     * 已经还原成 ".."，所以能一并拦掉。 */
    std::size_t pos = 0;
    if (urlPath[0] == '/') pos = 1;
    bool any = false;
    while (pos <= urlPath.size()) {
        std::size_t slash = urlPath.find('/', pos);
        if (slash == std::string::npos) slash = urlPath.size();
        const std::string seg = urlPath.substr(pos, slash - pos);
        if (seg.empty()) {                          /* 连续斜杠：跳过 */
            if (slash >= urlPath.size()) break;
            pos = slash + 1;
            continue;
        }
        if (seg == "." || seg == ".." || seg.find('\\') != std::string::npos ||
            seg.find(':') != std::string::npos)
            return false;
        if (any) relPath += '/';
        relPath += seg;
        any = true;
        if (slash >= urlPath.size()) break;
        pos = slash + 1;
    }
    if (!any) { relPath = "index.html"; return true; }   /* "/" -> 首页 */
    if (urlPath[urlPath.size() - 1] == '/') relPath += "/index.html";
    return true;
}

/* -------------------------------------------------------------- 响应 */
const char* CHttpResponse::statusTextOf(int status) {
    switch (status) {
    case 200: return "OK";
    case 201: return "Created";
    case 204: return "No Content";
    case 304: return "Not Modified";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 409: return "Conflict";
    case 413: return "Payload Too Large";
    case 429: return "Too Many Requests";
    case 500: return "Internal Server Error";
    case 501: return "Not Implemented";
    case 503: return "Service Unavailable";
    default:  return "Unknown";
    }
}

CHttpResponse CHttpResponse::makeJson(int code, const std::string& msg,
                                      const CJsonValue& data, bool includeData) {
    CHttpResponse r;
    CJsonValue o = CJsonValue::makeObject();
    o["code"] = CJsonValue::makeInt(code);
    o["msg"] = CJsonValue::makeString(msg);
    if (includeData) o["data"] = data;
    r.contentType = "application/json; charset=utf-8";
    r.body = o.dump();
    return r;
}

CHttpResponse CHttpResponse::jsonOk(const CJsonValue& data) {
    return makeJson(0, "ok", data, !data.isNull());
}

CHttpResponse CHttpResponse::jsonOk(const CJsonValue& data, const std::string& msg) {
    CHttpResponse r = makeJson(0, msg, data, !data.isNull());
    return r;
}

CHttpResponse CHttpResponse::jsonError(int code, const std::string& msg, int httpStatus) {
    CHttpResponse r = makeJson(code, msg, CJsonValue(), false);
    r.status = httpStatus;
    return r;
}

CHttpResponse CHttpResponse::text(int status, const std::string& bodyText) {
    CHttpResponse r;
    r.status = status;
    r.contentType = "text/plain; charset=utf-8";
    r.body = bodyText;
    return r;
}

CHttpResponse CHttpResponse::html(const std::string& markup) {
    CHttpResponse r;
    r.contentType = "text/html; charset=utf-8";
    r.body = markup;
    return r;
}

CHttpResponse CHttpResponse::file(const std::string& contentType_, const std::string& bytes) {
    CHttpResponse r;
    r.contentType = contentType_;
    r.body = bytes;
    return r;
}

CHttpResponse CHttpResponse::notModified() {
    CHttpResponse r;
    r.status = 304;
    r.body.clear();
    return r;
}

std::string CHttpResponse::serialize() const {
    std::string out;
    out.reserve(body.size() + 320);
    out += "HTTP/1.1 ";
    out += std::to_string(status);
    out += ' ';
    out += statusText.empty() ? statusTextOf(status) : statusText;
    out += "\r\n";

    if (status != 304 && !body.empty())
        out += "Content-Type: " + contentType + "\r\n";
    out += "Content-Length: " + std::to_string(status == 304 ? 0u : body.size()) + "\r\n";
    out += "Connection: close\r\n";

    /* 同源部署时这些头无害；开发期直接用 file:// 或另开前端端口时才必要。
     * 不做 Origin 白名单是有意为之：本机单人实验工具，README 已提示
     * 若暴露到不可信网络应加 token 校验（我们本来也加了）。 */
    out += "Access-Control-Allow-Origin: *\r\n";
    out += "Access-Control-Allow-Headers: Content-Type, Authorization\r\n";
    out += "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n";
    out += "Access-Control-Max-Age: 86400\r\n";
    out += "Cache-Control: no-store\r\n";

    for (std::map<std::string, std::string>::const_iterator it = extraHeaders.begin();
         it != extraHeaders.end(); ++it)
        out += it->first + ": " + it->second + "\r\n";

    out += "\r\n";
    if (status != 304 && status != 204) out += body;
    return out;
}

/* ------------------------------------------------------------ 请求解析 */
static const std::size_t kMaxHeaderBytes = 64u * 1024u;
static const std::size_t kMaxBodyBytes   = 64u * 1024u * 1024u;   /* 硬上限，
                                     站点配置里的 maxBodyBytes 通常远小于它 */

static std::string trimSpaces(const std::string& s) {
    std::size_t b = 0, e = s.size();
    while (b < e && (s[b] == ' ' || s[b] == '\t')) ++b;
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' ||
                     s[e - 1] == '\r' || s[e - 1] == '\n')) --e;
    return s.substr(b, e - b);
}

bool parseHttpRequest(const std::string& raw, CHttpRequest& req,
                      std::string& err, std::size_t& need) {
    need = 0;
    const std::string sep = "\r\n\r\n";
    const std::size_t headEnd = raw.find(sep);
    if (headEnd == std::string::npos) {
        if (raw.size() > kMaxHeaderBytes) { err = "request header too large"; return false; }
        need = 1;                     /* 头还没收完，继续读 */
        return true;
    }

    const std::string head = raw.substr(0, headEnd);
    const std::size_t firstBreak = head.find("\r\n");
    const std::string line = firstBreak == std::string::npos ? head : head.substr(0, firstBreak);

    const std::size_t sp1 = line.find(' ');
    if (sp1 == std::string::npos) { err = "malformed request line"; return false; }
    const std::size_t sp2 = line.find(' ', sp1 + 1);
    if (sp2 == std::string::npos) { err = "malformed request line"; return false; }

    req.method = CHttpRequest::methodUpper(line.substr(0, sp1));
    req.target = trimSpaces(line.substr(sp1 + 1, sp2 - sp1 - 1));
    req.version = trimSpaces(line.substr(sp2 + 1));
    if (req.version != "HTTP/1.1" && req.version != "HTTP/1.0") {
        err = "unsupported protocol version " + req.version;
        return false;
    }
    if (req.method != "GET" && req.method != "POST" && req.method != "PUT" &&
        req.method != "DELETE" && req.method != "OPTIONS" && req.method != "HEAD") {
        err = "unsupported method " + req.method;
        return false;
    }

    /* 头字段 */
    std::size_t pos = firstBreak == std::string::npos ? head.size() : firstBreak + 2;
    while (pos < head.size()) {
        std::size_t brk = head.find("\r\n", pos);
        if (brk == std::string::npos) brk = head.size();
        const std::string one = head.substr(pos, brk - pos);
        pos = brk + 2;
        if (one.empty()) continue;
        if (one[0] == ' ' || one[0] == '\t') continue;   /* 折行头：本项目用不到 */
        const std::size_t colon = one.find(':');
        if (colon == std::string::npos) { err = "malformed header line"; return false; }
        req.setHeader(one.substr(0, colon), trimSpaces(one.substr(colon + 1)));
    }

    /* 路径：查询串单独留着给 query() 用 */
    const std::size_t q = req.target.find('?');
    const std::string rawPath = q == std::string::npos ? req.target : req.target.substr(0, q);
    req.path = urlDecode(rawPath);
    /* 必须把带查询串的原始 target 也存下来：query() 是从 m_rawTarget 里
       找 '?' 的，漏了这一步就会让所有 ?xxx=yyy 参数静默失效
       （/api/stat 的 path、/api/events 的 job、/api/jobs 的 log 全中招）。 */
    req.setRawTarget(req.target);
    req.body.clear();

    /* 请求体：只支持 Content-Length（不实现 chunked，理由见 Http.h） */
    const std::string clStr = trimSpaces(req.header("content-length", "0"));
    unsigned long long cl = 0;
    if (!clStr.empty()) {
        char* end = nullptr;
        cl = std::strtoull(clStr.c_str(), &end, 10);
        if (end == clStr.c_str() || (end && *end != '\0')) { err = "bad Content-Length"; return false; }
    }
    if (cl > kMaxBodyBytes) { err = "request body too large"; return false; }

    const std::size_t total = headEnd + sep.size() + static_cast<std::size_t>(cl);
    if (raw.size() < total) { need = total - raw.size(); return true; }   /* 体还没收完 */
    req.body = raw.substr(headEnd + sep.size(), static_cast<std::size_t>(cl));
    return true;
}

/* ---------------------------------------------------------------- SSE */
std::string sseHead() {
    std::string out;
    out += "HTTP/1.1 200 OK\r\n";
    out += "Content-Type: text/event-stream; charset=utf-8\r\n";
    out += "Cache-Control: no-cache\r\n";
    out += "Connection: close\r\n";
    out += "X-Accel-Buffering: no\r\n";     /* 经 nginx 反代时禁用缓冲 */
    out += "Access-Control-Allow-Origin: *\r\n";
    out += "\r\n";
    return out;
}

std::string sseEvent(const std::string& name, const std::string& data) {
    std::string out;
    out += "event: " + name + "\r\n";
    /* data 可能多行（日志），SSE 要求每行都以 "data: " 开头 */
    std::size_t start = 0;
    for (;;) {
        const std::size_t nl = data.find('\n', start);
        out += "data: ";
        if (nl == std::string::npos) { out += data.substr(start); break; }
        out += data.substr(start, nl - start);
        start = nl + 1;
        if (start >= data.size()) break;
    }
    out += "\r\n\r\n";
    return out;
}

} /* namespace DBKP */
