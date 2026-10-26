/* ============================================================================
 *  Api.cpp  -- 见 Api.h
 * ==========================================================================*/
#include "Web/Api.h"

#include "Backup/BackupEngine.h"
#include "Crypto/Sha256.h"
#include "Enumerator/FilterOptions.h"
#include "Pack/MyPack.h"
#include "Platform/FS.h"
#include "Utils/Logger.h"
#include "Web/HttpServer.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <thread>

namespace DBKP {

namespace {

long long nowSec() {
    return static_cast<long long>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

std::string hmacHex(const std::string& key, const std::string& msg) {
    uint8_t digest[CSha256::kDigestSize];
    CSha256::hmac(key.empty() ? "" : key.data(), key.size(), msg.data(), msg.size(), digest);
    return CSha256::toHex(digest);
}

/* 定长比较：避免用 == 比较摘要时被计时侧信道（本机工具用不上，
   但这是几行成本，写上比不写好） */
bool constTimeEqual(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i)
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    return diff == 0;
}

std::string toSlash(const std::string& p) {
    std::string out;
    out.reserve(p.size());
    for (std::size_t i = 0; i < p.size(); ++i)
        out += (p[i] == '\\') ? '/' : p[i];
    return out;
}

/* 纯字符串折叠 "." / ".."：不碰文件系统，因此"还不存在的目标目录"
   也能安全校验（canonicalPath 对不存在的路径是失败的）。 */
std::string collapsePath(const std::string& in) {
    std::vector<std::string> parts;
    const bool rootSlash = !in.empty() && in[0] == '/';
    std::string prefix;
    std::size_t i = 0;
    if (!rootSlash && in.size() >= 2 && in[1] == ':') {
        prefix = in.substr(0, 2);
        i = 2;
    }
    while (i < in.size()) {
        std::size_t j = in.find('/', i);
        if (j == std::string::npos) j = in.size();
        const std::string seg = in.substr(i, j - i);
        if (seg.empty() || seg == ".") {
            /* 跳过 */
        } else if (seg == "..") {
            if (!parts.empty()) parts.pop_back();     /* 越过根就截住，不逃逸 */
        } else {
            parts.push_back(seg);
        }
        i = j + 1;
    }
    std::string body;
    for (std::size_t k = 0; k < parts.size(); ++k) { if (k) body += "/"; body += parts[k]; }
    if (rootSlash) return "/" + body;
    if (!prefix.empty()) return prefix + "/" + body;
    return body.empty() ? std::string(".") : body;
}

bool makeAbsolute(const std::string& in, std::string& out) {
    const std::string s = toSlash(in);
    if (s.empty()) return false;
    const bool abs = s[0] == '/' || (s.size() >= 2 && s[1] == ':');
    if (abs) { out = collapsePath(s); return true; }
    std::string cur;
    if (Platform::currentDir(cur) != E_OK) return false;
    out = collapsePath(toSlash(cur) + "/" + s);
    return true;
}

#ifdef _WIN32
const bool kCaseInsensitivePath = true;
#else
const bool kCaseInsensitivePath = false;
#endif

std::string lowerIfWin(const std::string& s) {
    if (!kCaseInsensitivePath) return s;
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i)
        out += static_cast<char>(std::tolower(static_cast<unsigned char>(s[i])));
    return out;
}

bool authFailed(const CHttpRequest& req, const ApiContext& ctx, CHttpResponse& out) {
    std::string why;
    if (verifyToken(ctx, req.bearerToken(), why)) return false;
    out = CHttpResponse::jsonError(401, why, 401);
    return true;
}

std::string jsonStr(const CJsonValue& o, const std::string& key, const std::string& def) {
    const CJsonValue& v = o.at(key);
    return v.isString() ? v.asString() : def;
}

int64_t jsonInt(const CJsonValue& o, const std::string& key, int64_t def) {
    const CJsonValue& v = o.at(key);
    if (v.isInt()) return v.asInt();
    if (v.isDouble()) return static_cast<int64_t>(v.asDouble());
    return def;
}

bool jsonBool(const CJsonValue& o, const std::string& key, bool def) {
    const CJsonValue& v = o.at(key);
    if (v.isBool()) return v.asBool();
    return def;
}

void readStringArray(const CJsonValue& arr, std::vector<std::string>& out) {
    if (!arr.isArray()) return;
    for (std::size_t i = 0; i < arr.items().size(); ++i)
        if (arr.items()[i].isString() && !arr.items()[i].asString().empty())
            out.push_back(arr.items()[i].asString());
}

/* 过滤条件：与 CLI 的 6 个维度一一对应，前端表单直接送同名 JSON 字段。
   尺寸/时间沿用 FilterOptions 的人类可读解析（"10MB"/"7d"），
   免得 Web 端和命令行出现两套语义。 */
void applyFilterJson(const CJsonValue& f, FilterOptions& out) {
    if (!f.isObject()) return;
    readStringArray(f.at("includePaths"), out.includePaths);
    readStringArray(f.at("excludePaths"), out.excludePaths);
    readStringArray(f.at("nameGlobs"), out.nameGlobs);
    readStringArray(f.at("nameRejects"), out.nameRejects);

    const std::string allow = jsonStr(f, "typeAllow", "");
    if (!allow.empty()) out.setTypeSpec(allow);
    const std::string deny = jsonStr(f, "typeDeny", "");
    for (std::size_t i = 0; i < deny.size(); ++i)
        if (deny[i] != ',') out.typeDeny.push_back(deny[i]);

    bool ok = false;
    const std::string minSize = jsonStr(f, "minSize", "");
    if (!minSize.empty()) { const int64_t v = FilterOptions::parseSize(minSize, &ok); if (ok) out.minSize = v; }
    const std::string maxSize = jsonStr(f, "maxSize", "");
    if (!maxSize.empty()) { const int64_t v = FilterOptions::parseSize(maxSize, &ok); if (ok) out.maxSize = v; }
    const std::string after = jsonStr(f, "mtimeAfter", "");
    if (!after.empty()) { const int64_t v = FilterOptions::parseTime(after, &ok); if (ok) out.mtimeAfter = v; }
    const std::string before = jsonStr(f, "mtimeBefore", "");
    if (!before.empty()) { const int64_t v = FilterOptions::parseTime(before, &ok); if (ok) out.mtimeBefore = v; }

    out.followSymlinks = jsonBool(f, "followSymlinks", out.followSymlinks);
    out.noCrossDevice  = jsonBool(f, "noCrossDevice", out.noCrossDevice);
    out.skipSpecials   = jsonBool(f, "skipSpecials", out.skipSpecials);
    out.includeDirs    = jsonBool(f, "includeDirs", out.includeDirs);
    out.maxDepth       = static_cast<int>(jsonInt(f, "maxDepth", out.maxDepth));
}

bool parseChecksum(const std::string& name, ChecksumId& out) {
    if (name.empty() || name == "crc64")  { out = CHK_CRC64;  return true; }
    if (name == "none")   { out = CHK_NONE;   return true; }
    if (name == "sha256") { out = CHK_SHA256; return true; }
    return false;
}

/* --------------------------------------------------------------- 任务规格 */
struct Spec {
    std::string type = "backup";        /* backup | restore | verify */
    std::string label;
    std::string source;                 /* 备份：源目录；还原：归档/备份目录 */
    std::string destination;            /* 备份：.dbkp 或目标目录；还原：目标目录 */
    BackupMode mode = MODE_AUTO;
    PackOptions pack;
    FilterOptions filter;
    bool preserveMeta = true;
    bool verifyAfter = true;
    bool overwrite = false;
    std::string password;
    std::string why;                    /* 解析失败原因，直接回给前端 */

    bool parse(const CJsonValue& body, const ApiContext& ctx) {
        type = jsonStr(body, "type", "backup");
        if (type != "backup" && type != "restore" && type != "verify") {
            why = "type 只能是 backup / restore / verify";
            return false;
        }
        label = jsonStr(body, "label", "");
        source = jsonStr(body, "source", ctx.defaultSource);
        destination = jsonStr(body, "destination", ctx.defaultDestination);
        password = jsonStr(body, "password", "");
        if (source.empty()) { why = "source 不能为空"; return false; }
        if (type != "verify" && destination.empty()) { why = "destination 不能为空"; return false; }

        /* 路径沙箱：配了 dataRoot 就不许越界读写（pathWithinRoot 会顺便把
           相对路径转绝对、折叠 ".."） */
        if (!pathWithinRoot(ctx.dataRoot, source, source)) {
            why = "source 超出允许访问的根目录：" + ctx.dataRoot;
            return false;
        }
        if (!destination.empty() && !pathWithinRoot(ctx.dataRoot, destination, destination)) {
            why = "destination 超出允许访问的根目录：" + ctx.dataRoot;
            return false;
        }

        const std::string modeText = jsonStr(body, "mode", "auto");
        if (modeText == "auto") mode = MODE_AUTO;
        else if (modeText == "archive") mode = MODE_ARCHIVE;
        else if (modeText == "copy") mode = MODE_COPY;
        else { why = "mode 只能是 auto / archive / copy"; return false; }

        filter = FilterOptions();
        applyFilterJson(body.at("filter"), filter);
        pack.filter = filter;

        const std::string alg = jsonStr(body, "algorithm", ctx.defaultAlgorithm);
        pack.comp = algorithmFromName(alg);
        if (alg != "none" && pack.comp == ALG_NONE) {
            why = "未知压缩算法：" + alg + "（可选 none/huffman/lz77/lzhuff/rle）";
            return false;
        }
        const std::string cry = jsonStr(body, "crypto", "none");
        pack.crypto = cryptoFromName(cry);
        if (cry != "none" && pack.crypto == CRY_NONE) {
            why = "未知加密算法：" + cry + "（可选 none/aes256/chacha20）";
            return false;
        }
        if (pack.crypto != CRY_NONE && password.empty()) {
            why = "选择了加密算法但没有给密码";
            return false;
        }
        if (!parseChecksum(jsonStr(body, "checksum", "crc64"), pack.checksum)) {
            why = "checksum 只能是 none/crc64/sha256";
            return false;
        }
        pack.password = password;
        pack.comment = jsonStr(body, "comment", "dbkp web");
        pack.hardlinkDedupe = jsonBool(body, "hardlinkDedupe", true);
        pack.preserveMeta = jsonBool(body, "preserveMeta", true);
        preserveMeta = pack.preserveMeta;
        verifyAfter = jsonBool(body, "verifyAfter", true);
        overwrite = jsonBool(body, "overwrite", false);
        if (label.empty()) label = type + ":" + source;
        return true;
    }

    /* 备份看目标后缀、还原看来源后缀，和 CLI 判据完全一致 */
    BackupMode resolve() const {
        return CBackupEngine::resolveMode(type == "backup" ? destination : source, mode);
    }
};

/* ------------------------------------------------------------- 任务构造 */
CJobManager::Task makeTask(const Spec& spec) {
    Spec s = spec;                          /* 值捕获：handler 栈结束后仍可安全执行 */
    const BackupMode bm = s.resolve();

    if (s.type == "backup") {
        return [s, bm](IProgressSink& sink, std::string& msg) -> ErrCode {
            CBackupEngine engine;
            BackupOptions opt;
            opt.source = s.source;
            opt.destination = s.destination;
            opt.mode = bm;
            opt.pack = s.pack;
            opt.filter = s.filter;
            opt.preserveMeta = s.preserveMeta;
            opt.verifyAfter = s.verifyAfter;
            opt.password = s.password;
            opt.progress = &sink;
            const ErrCode ec = engine.run(opt);
            if (ec == E_OK)
                msg = std::string("备份完成（") + backupModeName(bm) + "），警告 "
                      + std::to_string(opt.warnings) + " 条";
            else
                msg = engine.lastError().empty() ? errCodeToString(ec) : engine.lastError();
            return ec;
        };
    }

    if (s.type == "restore") {
        const bool archive = (bm == MODE_ARCHIVE);
        return [s, archive](IProgressSink& sink, std::string& msg) -> ErrCode {
            if (archive) {
                CMyPack pack;
                UnpackOptions u;
                u.overwrite = s.overwrite;
                u.restoreMeta = s.preserveMeta;
                u.password = s.password;
                u.progress = &sink;
                const ErrCode ec = pack.unpack(s.source, s.destination, u);
                msg = (ec == E_OK)
                    ? "还原完成，警告 " + std::to_string(u.warnings) + " 条"
                    : (pack.lastErrorText().empty() ? errCodeToString(ec) : pack.lastErrorText());
                return ec;
            }
            CBackupEngine engine;
            int warnings = 0;
            const ErrCode ec = engine.copyRestore(s.source, s.destination,
                                                  s.preserveMeta, warnings, &sink);
            msg = (ec == E_OK)
                ? "还原完成，警告 " + std::to_string(warnings) + " 条"
                : (engine.lastError().empty() ? errCodeToString(ec) : engine.lastError());
            return ec;
        };
    }

    /* verify：归档模式只验 CRC/解码，复制模式与源目录逐条对比 */
    const bool archive = (bm == MODE_ARCHIVE);
    return [s, archive](IProgressSink& sink, std::string& msg) -> ErrCode {
        if (archive) {
            CMyPack pack;
            int bad = 0;
            ErrCode ec = pack.verify(s.source, s.password, bad);
            if (ec == E_OK && bad != 0) ec = E_CHECKSUM_MISMATCH;
            msg = (ec == E_OK) ? "校验通过：所有记录 CRC 与解码一致"
                               : ("校验未通过（损坏记录 " + std::to_string(bad) + " 条）："
                                  + pack.lastErrorText());
            return ec;
        }
        CBackupEngine engine;
        int diff = 0;
        ErrCode ec = engine.verifyCopy(s.source, s.destination, s.filter, diff);
        if (ec == E_OK && diff != 0) ec = E_CHECKSUM_MISMATCH;
        msg = (ec == E_OK) ? "对比一致：备份目录与源目录逐条相同"
                           : "发现 " + std::to_string(diff) + " 处差异";
        (void)sink;
        return ec;
    };
}

/* ---------------------------------------------------------------- 处理器 */
const char* const kApiVersion = "1.0";

CJsonValue capabilitiesToJson() {
    CJsonValue c = CJsonValue::makeObject();
    c["symlink"]   = CJsonValue::makeBool(Platform::supportsSymlink());
    c["hardlink"]  = CJsonValue::makeBool(Platform::supportsHardlink());
    c["fifo"]      = CJsonValue::makeBool(Platform::supportsFifo());
    c["deviceNode"]= CJsonValue::makeBool(Platform::supportsDeviceNode());
    c["owner"]     = CJsonValue::makeBool(Platform::supportsOwner());
    c["nanoTime"]  = CJsonValue::makeBool(Platform::supportsNanoTime());
    c["os"]        = CJsonValue::makeString(Platform::osName());
    return c;
}

CHttpResponse hInfo(ApiContext& ctx) {
    CJsonValue d = CJsonValue::makeObject();
    d["app"] = CJsonValue::makeString("dbkp");
    d["apiVersion"] = CJsonValue::makeString(kApiVersion);
    d["serverTime"] = CJsonValue::makeInt(nowSec());
    d["uptimeSec"] = CJsonValue::makeInt(nowSec() - ctx.startedAt);
    d["authRequired"] = CJsonValue::makeBool(!ctx.password.empty());
    d["jobCount"] = CJsonValue::makeInt(ctx.jobs ? static_cast<int64_t>(ctx.jobs->count()) : 0);
    d["revision"] = CJsonValue::makeInt(ctx.jobs ? static_cast<int64_t>(ctx.jobs->revision()) : 0);
    d["capabilities"] = capabilitiesToJson();
    return CHttpResponse::jsonOk(d);
}

CHttpResponse hLogin(ApiContext& ctx, const CHttpRequest& req) {
    CJsonValue body;
    std::string err;
    std::string given;
    if (req.json(body, err)) given = jsonStr(body, "password", "");
    else given = req.form("password", "");            /* 也接受表单提交 */

    if (ctx.password.empty()) {                       /* 免鉴权模式：直接发 token */
        CJsonValue d = CJsonValue::makeObject();
        d["token"] = CJsonValue::makeString(issueToken(ctx, nowSec() + 3600));
        d["expiresIn"] = CJsonValue::makeInt(3600);
        d["anonymous"] = CJsonValue::makeBool(true);
        return CHttpResponse::jsonOk(d, "无需登录");
    }

    bool ok = false;
    if (ctx.password.size() == 64) {
        /* 配置里给的是 sha256 十六进制摘要时，比对摘要，明文不落盘 */
        uint8_t digest[CSha256::kDigestSize];
        CSha256::hash(given.data(), given.size(), digest);
        ok = constTimeEqual(CSha256::toHex(digest), ctx.password);
    } else {
        ok = constTimeEqual(given, ctx.password);
    }
    if (!ok) {
        LOG_WARN("登录失败，来源 " + req.clientIp());
        return CHttpResponse::jsonError(401, "密码不正确", 401);
    }
    const long long ttl = (ctx.tokenTtlHours > 0 ? ctx.tokenTtlHours : 12) * 3600;
    const long long exp = nowSec() + ttl;
    CJsonValue d = CJsonValue::makeObject();
    d["token"] = CJsonValue::makeString(issueToken(ctx, exp));
    d["expiresIn"] = CJsonValue::makeInt(ttl);
    d["expiresAt"] = CJsonValue::makeInt(exp);
    LOG_INFO("登录成功，来源 " + req.clientIp());
    return CHttpResponse::jsonOk(d, "登录成功");
}

CHttpResponse hConfig(ApiContext& ctx, const CHttpRequest& req) {
    CHttpResponse out;
    if (authFailed(req, ctx, out)) return out;

    CJsonValue d = CJsonValue::makeObject();
    d["defaultSource"] = CJsonValue::makeString(ctx.defaultSource);
    d["defaultDestination"] = CJsonValue::makeString(ctx.defaultDestination);
    d["defaultAlgorithm"] = CJsonValue::makeString(ctx.defaultAlgorithm);
    d["dataRoot"] = CJsonValue::makeString(ctx.dataRoot);

    CJsonValue algs = CJsonValue::makeArray();
    for (int a = 0; a < ALG_COUNT; ++a)
        algs.push_back(CJsonValue::makeString(algorithmName(static_cast<AlgorithmId>(a))));
    d["algorithms"] = algs;

    CJsonValue cryptos = CJsonValue::makeArray();
    CJsonValue cr = CJsonValue::makeObject();
    cr["id"] = CJsonValue::makeString("none");    cr["name"] = CJsonValue::makeString("不加密");
    cryptos.push_back(cr);
    cr = CJsonValue::makeObject();
    cr["id"] = CJsonValue::makeString("aes256");  cr["name"] = CJsonValue::makeString("AES-256-CBC");
    cryptos.push_back(cr);
    cr = CJsonValue::makeObject();
    cr["id"] = CJsonValue::makeString("chacha20"); cr["name"] = CJsonValue::makeString("ChaCha20");
    cryptos.push_back(cr);
    d["cryptos"] = cryptos;

    CJsonValue sums = CJsonValue::makeArray();
    sums.push_back(CJsonValue::makeString("none"));
    sums.push_back(CJsonValue::makeString("crc64"));
    sums.push_back(CJsonValue::makeString("sha256"));
    d["checksums"] = sums;

    CJsonValue modes = CJsonValue::makeArray();
    modes.push_back(CJsonValue::makeString("auto"));
    modes.push_back(CJsonValue::makeString("archive"));
    modes.push_back(CJsonValue::makeString("copy"));
    d["modes"] = modes;

    d["filterFields"] = CJsonValue::makeString(
        "includePaths,excludePaths,nameGlobs,nameRejects,typeAllow,typeDeny,"
        "mtimeAfter,mtimeBefore,minSize,maxSize,maxDepth,followSymlinks,noCrossDevice,skipSpecials");
    return CHttpResponse::jsonOk(d);
}

CHttpResponse hBrowse(ApiContext& ctx, const CHttpRequest& req) {
    CHttpResponse denied;
    if (authFailed(req, ctx, denied)) return denied;

    const std::string want = req.query("path", ".");
    std::string abs;
    if (!pathWithinRoot(ctx.dataRoot, want, abs))
        return CHttpResponse::jsonError(403, "该路径不在允许浏览的范围内：" + ctx.dataRoot, 403);

    Platform::FileInfo fi;
    if (Platform::getInfo(abs, fi, true) != E_OK)
        return CHttpResponse::jsonError(E_SOURCE_NOT_FOUND, "目录不存在：" + abs, 404);
    if (fi.type != FT_DIR)
        return CHttpResponse::jsonError(E_INVALID_PARAMETER, "不是目录：" + abs, 400);

    std::vector<Platform::DirEntry> entries;
    const ErrCode ec = Platform::listDir(abs, entries);
    if (ec != E_OK)
        return CHttpResponse::jsonError(ec, "列目录失败：" + std::string(errCodeToString(ec)), 500);

    /* 目录在前、名字在后，前端 file input 体验更接近资源管理器 */
    std::sort(entries.begin(), entries.end(), [](const Platform::DirEntry& a, const Platform::DirEntry& b) {
        const bool ad = a.type == FT_DIR, bd = b.type == FT_DIR;
        if (ad != bd) return ad && !bd;
        return a.name < b.name;
    });

    const std::size_t kLimit = 1000;
    CJsonValue arr = CJsonValue::makeArray();
    for (std::size_t i = 0; i < entries.size() && i < kLimit; ++i) {
        const std::string child = abs + "/" + entries[i].name;
        Platform::FileInfo cfi;
        Platform::getInfo(child, cfi, false);
        CJsonValue e = CJsonValue::makeObject();
        e["name"] = CJsonValue::makeString(entries[i].name);
        e["type"] = CJsonValue::makeString(std::string(1, entries[i].type));
        e["isDir"] = CJsonValue::makeBool(entries[i].type == FT_DIR);
        e["size"] = CJsonValue::makeInt(cfi.size);
        e["mtime"] = CJsonValue::makeInt(cfi.mtimeSec);
        arr.push_back(e);
    }
    CJsonValue d = CJsonValue::makeObject();
    d["path"] = CJsonValue::makeString(abs);
    d["total"] = CJsonValue::makeInt(static_cast<int64_t>(entries.size()));
    d["truncated"] = CJsonValue::makeBool(entries.size() > kLimit);
    d["entries"] = arr;
    return CHttpResponse::jsonOk(d);
}

CHttpResponse hStat(ApiContext& ctx, const CHttpRequest& req) {
    CHttpResponse denied;
    if (authFailed(req, ctx, denied)) return denied;

    const std::string want = req.query("path", "");
    std::string abs;
    if (want.empty() || !pathWithinRoot(ctx.dataRoot, want, abs))
        return CHttpResponse::jsonError(403, "该路径不在允许访问的范围内", 403);

    CMyPack pack;
    ArchiveHeader hdr;
    ErrCode ec = pack.readHeader(abs, hdr);
    if (ec != E_OK)
        return CHttpResponse::jsonError(ec, "读取归档卷标失败：" + pack.lastErrorText(), 400);
    ArchiveStat st;
    pack.stat(abs, hdr, st);

    CJsonValue d = CJsonValue::makeObject();
    d["path"] = CJsonValue::makeString(abs);
    d["formatVersion"] = CJsonValue::makeInt(hdr.version);
    d["algorithm"] = CJsonValue::makeString(algorithmName(static_cast<AlgorithmId>(hdr.compAlg)));
    d["crypto"] = CJsonValue::makeString(cryptoName(static_cast<CryptoId>(hdr.cryptoAlg)));
    d["fileCount"] = CJsonValue::makeInt(static_cast<int64_t>(hdr.fileCount));
    d["rawBytes"] = CJsonValue::makeInt(static_cast<int64_t>(hdr.rawSize));
    d["storedBytes"] = CJsonValue::makeInt(static_cast<int64_t>(hdr.payloadSize));
    d["payloadCrc"] = CJsonValue::makeInt(static_cast<int64_t>(hdr.payloadCrc));
    d["createTime"] = CJsonValue::makeInt(static_cast<int64_t>(hdr.createTime));
    d["sourcePath"] = CJsonValue::makeString(hdr.sourcePath);
    d["comment"] = CJsonValue::makeString(hdr.comment);
    d["dirCount"] = CJsonValue::makeInt(st.dirCount);
    d["linkCount"] = CJsonValue::makeInt(st.linkCount);
    d["specialCount"] = CJsonValue::makeInt(st.specialCount);
    if (hdr.rawSize > 0)
        d["ratio"] = CJsonValue::makeDouble(static_cast<double>(hdr.payloadSize) /
                                            static_cast<double>(hdr.rawSize));
    return CHttpResponse::jsonOk(d);
}

bool parseId(const std::string& text, long long& id) {
    if (text.empty() || text.size() > 18) return false;
    for (std::size_t i = 0; i < text.size(); ++i)
        if (!std::isdigit(static_cast<unsigned char>(text[i]))) return false;
    id = std::strtoll(text.c_str(), nullptr, 10);
    return id > 0;
}

CHttpResponse hCreateJob(ApiContext& ctx, const CHttpRequest& req) {
    CHttpResponse denied;
    if (authFailed(req, ctx, denied)) return denied;

    CJsonValue body;
    std::string err;
    if (!req.json(body, err)) {
        LOG_WARN("建任务被拒：请求体不是合法 JSON（" + err + "），来源 " + req.clientIp());
        return CHttpResponse::jsonError(E_INVALID_PARAMETER, "请求体不是合法 JSON：" + err, 400);
    }
    Spec sp;
    if (!sp.parse(body, ctx)) {
        LOG_WARN("建任务被拒：" + sp.why + "，来源 " + req.clientIp());
        return CHttpResponse::jsonError(E_INVALID_PARAMETER, sp.why, 400);
    }

    /* 提交时就做基本检查：把"路径不存在"这种错误当场告诉用户，
       而不是让任务排队、开线程、失败，用户只看到一个 failed。 */
    if (Platform::exists(sp.source) != E_OK) {
        LOG_WARN("建任务被拒：来源不存在 " + sp.source);
        return CHttpResponse::jsonError(E_SOURCE_NOT_FOUND, "来源不存在：" + sp.source, 400);
    }
    if (sp.type == "verify" && sp.resolve() == MODE_COPY
        && !sp.destination.empty() && Platform::exists(sp.destination) != E_OK)
        return CHttpResponse::jsonError(E_SOURCE_NOT_FOUND, "对比目录不存在：" + sp.destination, 400);
    if (!ctx.jobs)
        return CHttpResponse::jsonError(E_INTERNAL, "任务管理器未就绪", 500);

    const long long id = ctx.jobs->submit(sp.type, sp.label, sp.source, sp.destination, makeTask(sp));
    if (id < 0)
        return CHttpResponse::jsonError(E_INTERNAL, "服务正在停止，任务未受理", 503);

    CJsonValue d = CJsonValue::makeObject();
    d["id"] = CJsonValue::makeInt(id);
    d["state"] = CJsonValue::makeString("queued");
    d["type"] = CJsonValue::makeString(sp.type);
    d["mode"] = CJsonValue::makeString(backupModeName(sp.resolve()));
    d["label"] = CJsonValue::makeString(sp.label);
    d["source"] = CJsonValue::makeString(sp.source);
    d["destination"] = CJsonValue::makeString(sp.destination);
    CHttpResponse r = CHttpResponse::jsonOk(d, "任务已受理");
    r.status = 201;
    r.setHeader("Location", "/api/jobs/" + std::to_string(id));
    LOG_INFO(std::string("受理任务 ") + sp.type + " #" + std::to_string(id) + "：" + sp.source);
    return r;
}

CHttpResponse hListJobs(ApiContext& ctx, const CHttpRequest& req) {
    CHttpResponse denied;
    if (authFailed(req, ctx, denied)) return denied;
    if (!ctx.jobs) return CHttpResponse::jsonError(E_INTERNAL, "任务管理器未就绪", 500);

    std::vector<CJobManager::Info> list;
    long long limit = 0;
    if (!parseId(req.query("limit", ""), limit)) limit = 50;
    ctx.jobs->list(list, static_cast<std::size_t>(limit));

    CJsonValue arr = CJsonValue::makeArray();
    for (std::size_t i = 0; i < list.size(); ++i)
        arr.push_back(CJobManager::toJson(list[i], false));
    CJsonValue d = CJsonValue::makeObject();
    d["revision"] = CJsonValue::makeInt(static_cast<int64_t>(ctx.jobs->revision()));
    d["count"] = CJsonValue::makeInt(static_cast<int64_t>(list.size()));
    d["jobs"] = arr;
    return CHttpResponse::jsonOk(d);
}

CHttpResponse hGetJob(ApiContext& ctx, const CHttpRequest& req) {
    CHttpResponse denied;
    if (authFailed(req, ctx, denied)) return denied;
    if (!ctx.jobs) return CHttpResponse::jsonError(E_INTERNAL, "任务管理器未就绪", 500);

    long long id = 0;
    CHttpRequest::TParams::const_iterator pit = req.params.find("id");
    if (pit == req.params.end() || !parseId(pit->second, id))
        return CHttpResponse::jsonError(E_INVALID_PARAMETER, "任务 id 不合法", 400);

    CJobManager::Info info;
    if (!ctx.jobs->get(id, info))
        return CHttpResponse::jsonError(E_NOT_FOUND, "没有这个任务（可能已被历史裁剪）", 404);
    const bool withLog = req.query("log", "0") != "0";
    return CHttpResponse::jsonOk(CJobManager::toJson(info, withLog));
}

CHttpResponse hCancelJob(ApiContext& ctx, const CHttpRequest& req) {
    CHttpResponse denied;
    if (authFailed(req, ctx, denied)) return denied;
    if (!ctx.jobs) return CHttpResponse::jsonError(E_INTERNAL, "任务管理器未就绪", 500);

    long long id = 0;
    CHttpRequest::TParams::const_iterator pit = req.params.find("id");
    if (pit == req.params.end() || !parseId(pit->second, id))
        return CHttpResponse::jsonError(E_INVALID_PARAMETER, "任务 id 不合法", 400);

    if (!ctx.jobs->cancel(id)) {
        CJobManager::Info info;
        if (!ctx.jobs->get(id, info))
            return CHttpResponse::jsonError(E_NOT_FOUND, "没有这个任务", 404);
        return CHttpResponse::jsonError(E_INVALID_PARAMETER,
                                        std::string("任务已结束（") +
                                        CJobManager::stateName(info.state) + "），无法取消", 409);
    }
    CJsonValue d = CJsonValue::makeObject();
    d["id"] = CJsonValue::makeInt(id);
    LOG_INFO("取消任务 #" + std::to_string(id));
    return CHttpResponse::jsonOk(d, "已请求取消，任务会在下一个条目边界停下");
}

/* ------------------------------------------------------------------ SSE */
/* 进度推送用"轮询 + 变化才发"而不是内核回调：
   内核只需要按条目汇报进度，事件由这里 400ms 一次的快照比对产生，
   这样内核完全不知道有 Web 层存在（分层不破），延迟对用户也无感。 */
CHttpResponse hEvents(ApiContext& ctx, const CHttpRequest& req) {
    CHttpResponse denied;
    if (authFailed(req, ctx, denied)) return denied;

    long long jobId = -1;
    const std::string idText = req.query("job", "");
    if (!idText.empty() && !parseId(idText, jobId))
        return CHttpResponse::jsonError(E_INVALID_PARAMETER, "job 参数不合法", 400);
    if (!ctx.jobs || !ctx.server)
        return CHttpResponse::jsonError(E_INTERNAL, "服务未就绪", 500);

    CHttpServer* srv = ctx.server;
    const CbkSocket sock = req.socket();
    CHttpResponse r;
    if (sock == kCbkInvalidSocket)
        return CHttpResponse::jsonError(E_INTERNAL, "该连接不支持流式输出", 500);
    if (!srv->writeRaw(sock, sseHead())) { r.streaming = true; return r; }

    CJsonValue hello = CJsonValue::makeObject();
    hello["event"] = CJsonValue::makeString("hello");
    hello["time"] = CJsonValue::makeInt(nowSec());
    hello["job"] = CJsonValue::makeInt(jobId);
    if (!srv->writeRaw(sock, sseEvent("hello", hello.dump()))) { r.streaming = true; return r; }

    const long long started = nowSec();
    std::string lastText;
    for (;;) {
        CJsonValue payload = CJsonValue::makeObject();
        payload["time"] = CJsonValue::makeInt(nowSec());
        bool terminal = false;

        if (jobId > 0) {
            CJobManager::Info info;
            if (ctx.jobs->get(jobId, info)) {
                payload["job"] = CJobManager::toJson(info, true);
                terminal = info.state != CJobManager::ST_QUEUED
                        && info.state != CJobManager::ST_RUNNING;
            } else {
                payload["error"] = CJsonValue::makeString("任务不存在或已被历史裁剪");
                terminal = true;
            }
        } else {
            std::vector<CJobManager::Info> list;
            ctx.jobs->list(list, 20);
            CJsonValue arr = CJsonValue::makeArray();
            for (std::size_t i = 0; i < list.size(); ++i)
                arr.push_back(CJobManager::toJson(list[i], false));
            payload["jobs"] = arr;
            payload["revision"] = CJsonValue::makeInt(static_cast<int64_t>(ctx.jobs->revision()));
        }

        const std::string text = payload.dump();
        if (text != lastText) {
            lastText = text;
            if (!srv->writeRaw(sock, sseEvent("tick", text))) break;   /* 客户端已关页面 */
        }
        if (terminal) { srv->writeRaw(sock, sseEvent("done", text)); break; }
        if (nowSec() - started >= 25) { srv->writeRaw(sock, sseEvent("ping", text)); break; }
        if (!srv->running()) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(400));
    }
    r.streaming = true;      /* 头和事件都发完了，服务器只负责关连接 */
    return r;
}

CHttpResponse hShutdown(ApiContext& ctx, const CHttpRequest& req) {
    CHttpResponse denied;
    if (authFailed(req, ctx, denied)) return denied;
    /* 只允许本机回环关服务：网页里的脚本如果能把服务关掉，
       就等于给了任意网站一个"拒绝服务"的入口。 */
    if (req.clientIp().compare(0, 4, "127.") != 0 && req.clientIp() != "::1")
        return CHttpResponse::jsonError(403, "只允许从本机关闭服务", 403);
    LOG_INFO("收到关闭请求，来源 " + req.clientIp());
    ctx.stopRequested.store(true);        /* 响应发完之后由 main 停服务 */
    return CHttpResponse::jsonOk(CJsonValue(), "服务即将退出");
}

} /* anonymous namespace */

/* ------------------------------------------------------------ 令牌/路径 */
std::string issueToken(const ApiContext& ctx, long long expireSec) {
    const std::string exp = std::to_string(expireSec);
    return hmacHex(ctx.secret, exp) + "." + exp;
}

bool verifyToken(const ApiContext& ctx, const std::string& token, std::string& why) {
    if (ctx.password.empty()) return true;             /* 免鉴权模式 */
    if (token.empty()) { why = "缺少访问令牌"; return false; }
    const std::size_t dot = token.rfind('.');
    if (dot == std::string::npos) { why = "令牌格式不正确"; return false; }
    const std::string sig = token.substr(0, dot);
    const std::string exp = token.substr(dot + 1);
    if (exp.empty() || sig.empty()) { why = "令牌格式不正确"; return false; }
    for (std::size_t i = 0; i < exp.size(); ++i)
        if (!std::isdigit(static_cast<unsigned char>(exp[i]))) { why = "令牌格式不正确"; return false; }
    const long long expire = std::strtoll(exp.c_str(), nullptr, 10);
    if (expire <= nowSec()) { why = "令牌已过期，请重新登录"; return false; }
    if (!constTimeEqual(sig, hmacHex(ctx.secret, exp))) { why = "令牌无效"; return false; }
    return true;
}

bool pathWithinRoot(const std::string& root, const std::string& path, std::string& resolved) {
    if (path.empty()) return false;
    if (!makeAbsolute(path, resolved)) return false;
    if (root.empty()) return true;                     /* 未设根目录 = 不限制 */
    std::string absRoot;
    if (!makeAbsolute(root, absRoot)) return false;
    const std::string a = lowerIfWin(absRoot);
    const std::string b = lowerIfWin(resolved);
    if (a == b) return true;
    const std::string withSlash = a == "/" ? a : a + "/";
    return b.compare(0, withSlash.size(), withSlash) == 0;
}

/* ------------------------------------------------------------ 路由注册 */
void registerApiRoutes(CRouter& router, ApiContext& ctx) {
    /* info/login 不鉴权：登录页在拿到 token 之前就必须能读到它 */
    router.get("/api/info", [&ctx](const CHttpRequest&) { return hInfo(ctx); });
    router.post("/api/login", [&ctx](const CHttpRequest& req) { return hLogin(ctx, req); });

    router.get("/api/config", [&ctx](const CHttpRequest& req) { return hConfig(ctx, req); });
    router.get("/api/browse", [&ctx](const CHttpRequest& req) { return hBrowse(ctx, req); });
    router.get("/api/stat", [&ctx](const CHttpRequest& req) { return hStat(ctx, req); });

    router.post("/api/jobs", [&ctx](const CHttpRequest& req) { return hCreateJob(ctx, req); });
    router.get("/api/jobs", [&ctx](const CHttpRequest& req) { return hListJobs(ctx, req); });
    router.get("/api/jobs/:id", [&ctx](const CHttpRequest& req) { return hGetJob(ctx, req); });
    router.post("/api/jobs/:id/cancel", [&ctx](const CHttpRequest& req) { return hCancelJob(ctx, req); });

    router.get("/api/events", [&ctx](const CHttpRequest& req) { return hEvents(ctx, req); });
    router.post("/api/shutdown", [&ctx](const CHttpRequest& req) { return hShutdown(ctx, req); });
}

/* API-GLOBAL-1 */

} /* namespace DBKP */
