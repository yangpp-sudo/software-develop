/* ============================================================================
 *  Api.cpp  -- 见 Api.h
 * ==========================================================================*/
#include "Web/Api.h"

#include "Backup/BackupEngine.h"
#include "Backup/Scheduler.h"
#include "Backup/Watcher.h"
#include "Crypto/Sha256.h"
#include "Enumerator/FilterOptions.h"
#include "Pack/MyPack.h"
#include "Platform/FS.h"
#include "Utils/CRC64.h"
#include "Utils/Logger.h"
#include "Utils/PathUtil.h"
#include "Web/HttpServer.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <map>
#include <mutex>
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

/* F1 修法第 3 点：把"词法意义上的绝对路径"换成"真实路径"。
   沿父链上溯到最近的存在祖先，用 canonicalPath（Windows 走
   GetFinalPathNameByHandleW，POSIX 走 realpath）把 junction/symlink 链
   全部展开，再把尚不存在的尾部拼回去。纯词法比较看得见 ".."，看不见
   链接：data-root 里放一个指向围栏外的 junction，字符串检查会一路放行，
   browse/restore 就从围栏里"名正言顺"地钻出去。失败返回 false，
   调用方退回原有的词法比较。 */
bool resolveRealPath(const std::string& absCollapsed, std::string& out) {
    std::string cur = absCollapsed;
    std::string rest;
    for (;;) {
        if (cur.empty()) return false;
        if (Platform::exists(cur) == E_OK) {
            std::string real;
            if (DBKP_IS_ERR(Platform::canonicalPath(cur, real)) || real.empty())
                return false;
            const bool trailing = real[real.size() - 1] == '/';
            out = rest.empty() ? real
                : (trailing ? real + rest : real + "/" + rest);
            /* 盘根解析结果带尾斜杠（"d:/"）；统一去掉，交给调用方的
               "根 + '/'" 拼接规则，避免 "d:" + "/" 变 "d://" 全部误拒。 */
            while (out.size() > 1 && out[out.size() - 1] == '/')
                out.erase(out.size() - 1);
            return true;
        }
        const std::size_t slash = cur.find_last_of('/');
        if (slash == std::string::npos) return false;   /* 不该有相对路径进来 */
        const std::string last = cur.substr(slash + 1);
        if (!last.empty()) rest = rest.empty() ? last : (last + "/" + rest);
        std::string parent = (slash == 0) ? std::string("/") : cur.substr(0, slash);
        if (parent.size() == 2 && parent[1] == ':') parent += '/';  /* "c:" -> "c:/" */
        if (parent == cur) return false;
        cur = parent;
    }
}

bool looksAbsolute(const std::string& slashed) {
    return !slashed.empty() &&
           (slashed[0] == '/' || (slashed.size() >= 2 && slashed[1] == ':'));
}

/**
 * @brief Web 层的相对路径解析：基准是 --data-root，不是进程的工作目录。
 *
 * 原来相对路径直接交给 makeAbsolute()，于是拼到 bkd 的启动目录上：同一个
 * "webview" 在 browse 里和提交任务里的落点不同，用户照着界面显示的 dataRoot
 * 写相对路径反而会 403。没配 dataRoot 时才退回 CWD 语义（和命令行一致）。
 */
bool resolveWithinRoot(const std::string& root, const std::string& in, std::string& out) {
    if (in.empty()) return false;
    std::string absRoot;
    if (root.empty() || looksAbsolute(toSlash(in)) || !makeAbsolute(root, absRoot))
        return makeAbsolute(in, out);
    return makeAbsolute(absRoot + "/" + toSlash(in), out);
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

/* F2（提交侧）：source 与 destination 指向同一目录、或 copy 模式下目标嵌在
   源里面，复制流程会一边读一边把源清空。任务线程里的 CBackupEngine::run
   也拦同一件事，但那是异步失败，用户只看到一个 failed；这里在受理当场就
   把话说清楚。real 解析失败时退回词法值，与 pathWithinRoot 的策略一致。 */
bool pathSameDir(const std::string& a, const std::string& b) {
    return lowerIfWin(a) == lowerIfWin(b);
}

/* F6：包含判定统一下沉到 Path::isSubPath（watch 的 CLI/API 入口与引擎
   重叠守卫共用一套）。这里保留"相等不算内部"的旧语义，因为调用方
   用 pathSameDir 单独区分"同一目录"和"嵌在里面"两种文案。 */
bool pathInside(const std::string& parent, const std::string& child) {
    if (pathSameDir(parent, child)) return false;
    return Path::isSubPath(parent, child);
}

void realOrLexical(const std::string& in, std::string& out) {
    out = in;
    std::string real;
    if (resolveRealPath(in, real) && !real.empty()) out = real;
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

/** 正整数解析（id/分页参数共用）；非法返回 false，out 不会被写脏 */
bool parseId(const std::string& text, long long& id) {
    if (text.empty() || text.size() > 18) return false;
    for (std::size_t i = 0; i < text.size(); ++i)
        if (!std::isdigit(static_cast<unsigned char>(text[i]))) return false;
    id = std::strtoll(text.c_str(), nullptr, 10);
    return id > 0;
}

/* 过滤条件：与 CLI 的 6 个维度一一对应，前端表单直接送同名 JSON 字段。
   尺寸/时间沿用 FilterOptions 的人类可读解析（"10MB"/"7d"），
   免得 Web 端和命令行出现两套语义。返回 false 时 why 里是可直接回显的原因。 */
bool applyFilterJson(const CJsonValue& f, FilterOptions& out, std::string& why) {
    if (!f.isObject()) return true;
    readStringArray(f.at("includePaths"), out.includePaths);
    readStringArray(f.at("excludePaths"), out.excludePaths);
    readStringArray(f.at("nameGlobs"), out.nameGlobs);
    readStringArray(f.at("nameRejects"), out.nameRejects);

    /* F8：坏 glob 语法（如 "["）会恒不匹配，最后产出 0 条目的"成功"空箱。
       与 CLI 同口径，在入口逐条校验，非法就当场 400。 */
    static const char* kGlobFields[] = { "includePaths", "excludePaths",
                                         "nameGlobs", "nameRejects" };
    const std::vector<std::string>* kGlobLists[] = { &out.includePaths, &out.excludePaths,
                                                     &out.nameGlobs, &out.nameRejects };
    for (int gi = 0; gi < 4; ++gi) {
        for (std::size_t k = 0; k < kGlobLists[gi]->size(); ++k) {
            std::string gWhy;
            if (!Path::validateGlob((*kGlobLists[gi])[k], gWhy)) {
                why = std::string(kGlobFields[gi]) + " 的 glob 模式非法：" + gWhy +
                      "（模式：" + (*kGlobLists[gi])[k] + "）";
                return false;
            }
        }
    }

    const std::string allow = jsonStr(f, "typeAllow", "");
    if (!allow.empty() && !out.setTypeSpec(allow)) { why = "typeAllow：" + out.lastError; return false; }
    const std::string deny = jsonStr(f, "typeDeny", "");
    if (!deny.empty() && !out.setTypeSpec(deny)) { why = "typeDeny：" + out.lastError; return false; }

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
    return true;
}

const char* checksumName(uint8_t id) {
    switch (id) {
    case CHK_CRC64:  return "crc64";
    case CHK_SHA256: return "sha256";
    default:         return "none";
    }
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
    bool skipPayloadVerify = false;   /* 还原时跳过落盘前的整卷校验 */
    std::string password;
    std::string why;                    /* 解析失败原因，直接回给前端 */

    bool parse(const CJsonValue& body, const ApiContext& ctx) {
        type = jsonStr(body, "type", "backup");
        if (type != "backup" && type != "restore" && type != "verify" && type != "compare") {
            why = "type 只能是 backup / restore / verify / compare";
            return false;
        }
        label = jsonStr(body, "label", "");
        source = jsonStr(body, "source", ctx.defaultSource);
        destination = jsonStr(body, "destination", ctx.defaultDestination);
        password = jsonStr(body, "password", "");
        if (source.empty()) { why = "source 不能为空"; return false; }
        if (type != "verify" && destination.empty()) { why = "destination 不能为空"; return false; }

        /* uid/owner 过滤在 Windows 上没有真实语义，以前是静默丢弃：现在当场说清，
           免得用户以为过滤生效了。POSIX 侧要支持的话应走 CLI 的 --uid/--owner。 */
        const CJsonValue& fl = body.at("filter");
        if (fl.isObject() && (fl.at("uids").isArray() || fl.at("ownerNames").isArray())) {
            why = "uids/ownerNames 过滤目前仅命令行支持（--uid/--owner），Web 接口暂不受理";
            return false;
        }

        /* 路径沙箱：配了 dataRoot 就不许越界读写。pathWithinRoot 会顺便把相对
           路径按 dataRoot 解析、折叠 ".."，失败时 out 里仍是解析后的绝对路径，
           直接拿去回显最有用。 */
        if (!pathWithinRoot(ctx.dataRoot, source, source)) {
            why = "source 超出允许访问的根目录：" + source + "（不在 " + ctx.dataRoot +
                  " 内；相对路径按 dataRoot 解析）";
            return false;
        }
        if (!destination.empty() && !pathWithinRoot(ctx.dataRoot, destination, destination)) {
            why = "destination 超出允许访问的根目录：" + destination + "（不在 " + ctx.dataRoot +
                  " 内；相对路径按 dataRoot 解析）";
            return false;
        }

        const std::string modeText = jsonStr(body, "mode", "auto");
        if (modeText == "auto") mode = MODE_AUTO;
        else if (modeText == "archive") mode = MODE_ARCHIVE;
        else if (modeText == "copy") mode = MODE_COPY;
        else { why = "mode 只能是 auto / archive / copy"; return false; }

        filter = FilterOptions();
        std::string whyFilter;
        if (!applyFilterJson(body.at("filter"), filter, whyFilter)) {
            why = "filter：" + whyFilter;
            return false;
        }
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
            why = "未知加密算法：" + cry + "（可选 none/aes256/des-ede/chacha20/xor，xor 仅供教学演示）";
            return false;
        }
        if (pack.crypto != CRY_NONE && password.empty()) {
            why = "选择了加密算法但没有给密码";
            return false;
        }
        /* F5：反向检查。只有 backup 需要拦——restore/verify/compare 的算法记在
           归档头里，带 -p 不带 crypto 是正常用法（与 CLI 各子命令口径一致）。 */
        if (type == "backup" && pack.crypto == CRY_NONE && !password.empty()) {
            why = "给了 password 但没选加密算法（crypto），拒绝生成未加密的归档；"
                  "请同时指定 crypto（aes256/des-ede/chacha20）或去掉 password";
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
        /* F4：与 CLI --force 双侧同口径——请求体 force 布尔字段，缺省 false。
           目标已存在或残留 .tmp 时拒绝备份，force=true 才覆盖/清残骸。 */
        pack.force = jsonBool(body, "force", false);
        skipPayloadVerify = jsonBool(body, "skipPayloadVerify", false);
        if (label.empty()) label = type + ":" + source;
        return true;
    }

    /* 备份看目标后缀、还原看来源后缀，和 CLI 判据完全一致；
       compare 固定针对归档（目录对比走 verify 任务已有的 verifyCopy） */
    BackupMode resolve() const {
        if (type == "compare") return MODE_ARCHIVE;
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
                u.skipPayloadVerify = s.skipPayloadVerify;
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

    /* verify：归档模式只验 CRC/解码，复制模式与源目录逐条对比。
       compare：归档 vs 原始目录逐条回源比对（内核早已实现，这里接上接口）。 */
    if (s.type == "compare") {
        return [s](IProgressSink& sink, std::string& msg) -> ErrCode {
            (void)sink;
            CMyPack pack;
            int diff = 0;
            const ErrCode ec = pack.compareWithSource(s.source, s.destination, s.password, diff);
            if (ec == E_OK)
                msg = diff == 0 ? "对比一致：归档与源目录逐条相同"
                                : "发现 " + std::to_string(diff) + " 处差异（详见服务端日志）";
            else
                msg = pack.lastErrorText().empty() ? errCodeToString(ec) : pack.lastErrorText();
            return ec;
        };
    }

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
    /* F12：先看该来源是否还在退避锁定期内——口令对不对都不再校验，
       否则限速就等于没做（正确口令还能照常登进去）。 */
    long long retryAfter = 0;
    if (!loginThrottleAllow(req.clientIp(), retryAfter)) {
        LOG_WARN("登录被限速拦下，来源 " + req.clientIp() +
                 "，还需 " + std::to_string(retryAfter) + " 秒");
        CHttpResponse r = CHttpResponse::jsonError(
            E_BUSY, "登录失败次数过多，请 " + std::to_string(retryAfter) + " 秒后重试", 429);
        r.setHeader("Retry-After", std::to_string(retryAfter));
        return r;
    }
    if (ctx.password.size() == 64) {
        /* 配置里给的是 sha256 十六进制摘要时，比对摘要，明文不落盘 */
        uint8_t digest[CSha256::kDigestSize];
        CSha256::hash(given.data(), given.size(), digest);
        ok = constTimeEqual(CSha256::toHex(digest), ctx.password);
    } else {
        ok = constTimeEqual(given, ctx.password);
    }
    if (!ok) {
        loginThrottleRecord(req.clientIp(), false);
        LOG_WARN("登录失败，来源 " + req.clientIp());
        return CHttpResponse::jsonError(401, "密码不正确", 401);
    }
    loginThrottleRecord(req.clientIp(), true);       /* 成功即清零该 IP 计数 */
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
    cr["id"] = CJsonValue::makeString("des-ede"); cr["name"] = CJsonValue::makeString("DES-EDE-CBC(3DES)");
    cryptos.push_back(cr);
    cr = CJsonValue::makeObject();
    cr["id"] = CJsonValue::makeString("chacha20"); cr["name"] = CJsonValue::makeString("ChaCha20");
    cryptos.push_back(cr);
    cr = CJsonValue::makeObject();   /* 内核一直支持 xor（CRY_XOR_TEST），白名单补齐；仅教学演示 */
    cr["id"] = CJsonValue::makeString("xor");     cr["name"] = CJsonValue::makeString("XOR（教学演示，勿用于生产）");
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
        "mtimeAfter,mtimeBefore,minSize,maxSize,maxDepth,followSymlinks,noCrossDevice,"
        "skipSpecials,includeDirs");
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
        /* 前端与文档里用的是短名 dir：两个都给，避免再出现"字段名对不上，
           目录被当文件渲染、点不进下一层"这类静默失配。 */
        e["dir"] = CJsonValue::makeBool(entries[i].type == FT_DIR);
        e["size"] = CJsonValue::makeInt(cfi.size);
        e["mtime"] = CJsonValue::makeInt(cfi.mtimeSec);
        arr.push_back(e);
    }
    CJsonValue d = CJsonValue::makeObject();
    d["path"] = CJsonValue::makeString(abs);
    /* parent 只在 dataRoot 内给；到根了就给空串，前端据此隐藏"上一级"，
       否则用户点一次就跳出边界，之后每次点击都是 403，弹窗彻底翻不动。 */
    std::string parentOut;
    {
        const std::string folded = collapsePath(abs);
        const std::size_t slash = folded.find_last_of('/');
        if (slash != std::string::npos && slash > 0) {
            const std::string p = folded.substr(0, slash);
            std::string chk;
            if (pathWithinRoot(ctx.dataRoot, p, chk)) parentOut = p;
        }
    }
    d["parent"] = CJsonValue::makeString(parentOut);
    d["dataRoot"] = CJsonValue::makeString(ctx.dataRoot);
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
    d["headerSize"] = CJsonValue::makeInt(hdr.headerSize);
    d["algorithm"] = CJsonValue::makeString(algorithmName(static_cast<AlgorithmId>(hdr.compAlg)));
    d["crypto"] = CJsonValue::makeString(cryptoName(static_cast<CryptoId>(hdr.cryptoAlg)));
    /* 把校验类型原样告诉前端：以前选了 sha256 卷标里却只看得到 CRC，根本看不出差异 */
    d["checksum"] = CJsonValue::makeString(checksumName(hdr.checksum));
    if (hdr.checksum == CHK_SHA256 && !hdr.payloadDigest.empty())
        d["payloadDigest"] = CJsonValue::makeString(CSha256::toHex(hdr.payloadDigest.data()));
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

    /* 条目清单：元数据早就在归档里，以前只是没地方看。默认不返（保持老
       调用方轻量），带 ?entries=1 才附前 200 条，?offset/&limit 分页（上限 1000）。 */
    if (req.query("entries", "0") != "0") {
        std::vector<FileRecord> recs;
        if (pack.list(abs, recs) == E_OK) {
            long long off = 0, lim = 200;
            if (!parseId(req.query("offset", ""), off)) off = 0;
            if (!parseId(req.query("limit", ""), lim)) lim = 200;
            if (lim > 1000) lim = 1000;
            if (off < 0) off = 0;
            CJsonValue arr = CJsonValue::makeArray();
            for (long long i = off; i < static_cast<long long>(recs.size()) && i < off + lim; ++i) {
                const FileRecord& r = recs[static_cast<size_t>(i)];
                CJsonValue e = CJsonValue::makeObject();
                e["path"] = CJsonValue::makeString(r.path);
                e["type"] = CJsonValue::makeString(std::string(1, r.type));
                e["size"] = CJsonValue::makeInt(r.size);
                e["storedSize"] = CJsonValue::makeInt(r.storedSize);
                e["mode"] = CJsonValue::makeInt(r.mode);
                e["uid"] = CJsonValue::makeInt(r.uid);
                e["gid"] = CJsonValue::makeInt(r.gid);
                e["mtime"] = CJsonValue::makeInt(r.mtimeSec);
                e["mtimeNs"] = CJsonValue::makeInt(r.mtimeNSec);
                e["nlink"] = CJsonValue::makeInt(r.nlink);
                e["algorithm"] = CJsonValue::makeString(algorithmName(static_cast<AlgorithmId>(r.compAlg)));
                e["crypto"] = CJsonValue::makeString(cryptoName(static_cast<CryptoId>(r.cryptoAlg)));
                e["crc64"] = CJsonValue::makeString(CRC64::toString(r.crc));
                if (!r.link.empty()) e["link"] = CJsonValue::makeString(r.link);
                arr.push_back(e);
            }
            d["entries"] = arr;
            d["entriesTotal"] = CJsonValue::makeInt(static_cast<int64_t>(recs.size()));
            d["entriesOffset"] = CJsonValue::makeInt(off);
        }
    }
    return CHttpResponse::jsonOk(d);
}

/* 同步的“归档 vs 源目录”对比：内核循环在干小时级作业，不适合丢进任务队列
   占 worker；前端本来就是“点一下等结果”，直接同步返回差异计数。 */
CHttpResponse hCompare(ApiContext& ctx, const CHttpRequest& req) {
    CHttpResponse denied;
    if (authFailed(req, ctx, denied)) return denied;

    std::string arcAbs, srcAbs;
    if (!pathWithinRoot(ctx.dataRoot, req.query("archive", ""), arcAbs)
        || !pathWithinRoot(ctx.dataRoot, req.query("origin", ""), srcAbs))
        return CHttpResponse::jsonError(403, "archive/origin 必须都在数据根范围内", 403);

    CMyPack pack;
    int diff = 0;
    const ErrCode ec = pack.compareWithSource(arcAbs, srcAbs, req.query("password", ""), diff);
    if (DBKP_IS_ERR(ec))
        return CHttpResponse::jsonError(ec,
            pack.lastErrorText().empty() ? errCodeToString(ec) : pack.lastErrorText(), 400);
    CJsonValue d = CJsonValue::makeObject();
    d["archive"] = CJsonValue::makeString(arcAbs);
    d["origin"] = CJsonValue::makeString(srcAbs);
    d["diffCount"] = CJsonValue::makeInt(diff);
    return CHttpResponse::jsonOk(d, diff == 0 ? "逐条一致" : ("发现 " + std::to_string(diff) + " 处差异"));
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
    /* F2：backup 任务在受理时就拒绝 source/dest 重叠（与引擎内守卫同口径，
       但这里能立刻回 400，而不是让任务异步失败）。 */
    if (sp.type == "backup") {
        std::string srcReal, dstReal;
        realOrLexical(sp.source, srcReal);
        realOrLexical(sp.destination, dstReal);
        const bool overlapSame = pathSameDir(srcReal, dstReal);
        const bool overlapInner = sp.resolve() == MODE_COPY
                                  && pathInside(srcReal, dstReal);
        if (overlapSame || overlapInner) {
            const std::string why = overlapSame
                ? "source 与 destination 是同一目录：" + srcReal
                : "copy 模式下 destination 位于 source 内部：" + dstReal;
            LOG_WARN("建任务被拒（F2 自毁防护）：" + why);
            return CHttpResponse::jsonError(E_INVALID_PARAMETER,
                why + "，拒绝执行（会把源数据清空）", 400);
        }
    }
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
    /* F12：SSE 头由本 handler 直接写 socket，CORS 结论同样要按 Origin 算。 */
    if (!srv->writeRaw(sock, sseHead(resolveCorsOrigin(srv->options().corsOrigin,
                                                       req.header("origin"))))) {
        r.streaming = true; return r;
    }

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

/* ------------------------------------------------------ 定时备份（后台单实例） */
/* CScheduler 早就在内核里，但只有 CLI 能用；这里给它接上接口：全局只跑一个
   定时器，用独立线程而非任务 worker（一次“每天 03:00”能挂几天，不能霸 worker）。 */
struct ScheduleState {
    std::mutex mtx;
    std::atomic<bool> running;
    std::atomic<bool> stopReq;
    std::thread worker;
    std::string source, archiveDir, prefix;
    int intervalSeconds = 0, times = 0, keep = 0;
    long long startedAt = 0;
    std::string lastError;
    ScheduleState() : running(false), stopReq(false) {}

    ~ScheduleState() { joinQuietly(); }

    void joinQuietly() {
        stopReq.store(true);
        if (worker.joinable()) worker.join();
    }

    CJsonValue snapshotLocked() {
        CJsonValue d = CJsonValue::makeObject();
        d["running"] = CJsonValue::makeBool(running.load());
        d["source"] = CJsonValue::makeString(source);
        d["archiveDir"] = CJsonValue::makeString(archiveDir);
        d["prefix"] = CJsonValue::makeString(prefix);
        d["intervalSeconds"] = CJsonValue::makeInt(intervalSeconds);
        d["times"] = CJsonValue::makeInt(times);
        d["keep"] = CJsonValue::makeInt(keep);
        d["startedAt"] = CJsonValue::makeInt(startedAt);
        d["lastError"] = CJsonValue::makeString(lastError);
        return d;
    }
};
ScheduleState g_schedule;

CHttpResponse hScheduleStart(ApiContext& ctx, const CHttpRequest& req) {
    CHttpResponse denied;
    if (authFailed(req, ctx, denied)) return denied;

    CJsonValue body;
    std::string err;
    if (!req.json(body, err))
        return CHttpResponse::jsonError(E_INVALID_PARAMETER, "请求体不是合法 JSON：" + err, 400);

    std::string src, dst;
    if (!pathWithinRoot(ctx.dataRoot, jsonStr(body, "source", ""), src)
        || !pathWithinRoot(ctx.dataRoot, jsonStr(body, "destination", ""), dst))
        return CHttpResponse::jsonError(403, "source/destination 必须都在数据根范围内", 403);
    if (Platform::exists(src) != E_OK)
        return CHttpResponse::jsonError(E_SOURCE_NOT_FOUND, "源目录不存在：" + src, 400);

    bool okInterval = false;
    const int interval = CScheduler::parseInterval(jsonStr(body, "interval", "5m"), &okInterval);
    if (!okInterval || interval <= 0)
        return CHttpResponse::jsonError(E_INVALID_PARAMETER, "interval 不合法（例 90s/5m/2h）", 400);

    ScheduleOptions so;
    so.intervalSeconds = interval;
    so.times = static_cast<int>(jsonInt(body, "times", 3));
    /* F7：与 CLI 同口径，次数必须 >= 1，不再把 <=0 当"一直跑" */
    if (so.times < 1)
        return CHttpResponse::jsonError(E_INVALID_PARAMETER,
                                        "times 需要 >= 1 的整数（常驻请用 /api/watch）", 400);
    so.keep = static_cast<int>(jsonInt(body, "keep", 0));
    so.prefix = jsonStr(body, "prefix", "");
    so.archiveDir = dst;
    so.backup.source = src;
    so.backup.destination = dst;          /* times=1 时文件名兜底用；调度内部会用 makeArchiveName */
    so.backup.mode = MODE_ARCHIVE;
    so.backup.verifyAfter = jsonBool(body, "verifyAfter", true);
    so.backup.pack.comp = algorithmFromName(jsonStr(body, "algorithm", ctx.defaultAlgorithm));
    so.backup.pack.crypto = cryptoFromName(jsonStr(body, "crypto", "none"));
    so.backup.pack.password = jsonStr(body, "password", "");
    std::string whyFilter;
    if (!applyFilterJson(body.at("filter"), so.backup.pack.filter, whyFilter))
        return CHttpResponse::jsonError(E_INVALID_PARAMETER, "filter：" + whyFilter, 400);
    ChecksumId cs = CHK_CRC64;
    if (!parseChecksum(jsonStr(body, "checksum", "crc64"), cs))
        return CHttpResponse::jsonError(E_INVALID_PARAMETER, "checksum 只能是 none/crc64/sha256", 400);
    so.backup.pack.checksum = cs;
    if (so.backup.pack.crypto != CRY_NONE && so.backup.pack.password.empty())
        return CHttpResponse::jsonError(E_INVALID_PARAMETER, "选择了加密算法但没有给密码", 400);

    std::lock_guard<std::mutex> lk(g_schedule.mtx);
    if (g_schedule.running.load())
        return CHttpResponse::jsonError(E_ALREADY_EXISTS,
                                        "已有定时任务在跑，先调 /api/schedule/stop", 409);
    g_schedule.joinQuietly();             /* 回收上一轮已结束的线程 */

    g_schedule.stopReq.store(false);
    g_schedule.source = src;
    g_schedule.archiveDir = dst;
    g_schedule.prefix = so.prefix;
    g_schedule.intervalSeconds = interval;
    g_schedule.times = so.times;
    g_schedule.keep = so.keep;
    g_schedule.startedAt = nowSec();
    g_schedule.lastError.clear();
    g_schedule.running.store(true);
    /* 线程自己把 running 拨回 false；主进程退出靠进程结束兑底（本机工具，不做强持久化） */
    g_schedule.worker = std::thread([so]() {
        CScheduler sched;
        const ErrCode ec = sched.run(so, &g_schedule.stopReq);
        std::lock_guard<std::mutex> lk2(g_schedule.mtx);
        g_schedule.running.store(false);
        if (DBKP_IS_ERR(ec)) g_schedule.lastError = errCodeToString(ec);
    });
    LOG_INFO("定时备份已启动：" + src + " 每 " + std::to_string(interval) + "s × " +
             std::to_string(so.times) + " 次，保留 " + std::to_string(so.keep) + " 份");

    CJsonValue d = g_schedule.snapshotLocked();
    return CHttpResponse::jsonOk(d, "定时备份已启动");   /* worker 保持 joinable：跑完后再启动时先 join */
}

CHttpResponse hScheduleStatus(ApiContext& ctx, const CHttpRequest& req) {
    CHttpResponse denied;
    if (authFailed(req, ctx, denied)) return denied;
    std::lock_guard<std::mutex> lk(g_schedule.mtx);
    return CHttpResponse::jsonOk(g_schedule.snapshotLocked());
}

CHttpResponse hScheduleStop(ApiContext& ctx, const CHttpRequest& req) {
    CHttpResponse denied;
    if (authFailed(req, ctx, denied)) return denied;
    std::lock_guard<std::mutex> lk(g_schedule.mtx);
    if (!g_schedule.running.load() && !g_schedule.worker.joinable())
        return CHttpResponse::jsonError(E_NOT_FOUND, "当前没有定时任务", 404);
    g_schedule.stopReq.store(true);
    return CHttpResponse::jsonOk(g_schedule.snapshotLocked(),
                                 "已请求停止，定时备份会在当前这轮跑完后停下");
}

/* ------------------------------------------------------ 实时备份（后台单实例） */
/* 把 CLI 的 bk watch 接上 Web：CDirWatcher 感知文件变化，上层 debounce 触发
   一次全量归档。与定时备份同理用独立线程而非任务 worker（监听会长期挂）。 */
struct WatchState {
    std::mutex mtx;
    std::atomic<bool> running;
    std::atomic<bool> stopReq;
    std::thread worker;
    CDirWatcher* watcher = nullptr;
    std::string source, archiveDir, prefix;
    int debounceSeconds = 2, keep = 0;
    bool native = false;
    long long startedAt = 0;
    long long backupCount = 0, failCount = 0;
    std::string lastArchive, lastError;

    WatchState() : running(false), stopReq(false) {}
    ~WatchState() { shutdown(); }

    /* 仅当 running==false（上一轮线程已退出）时调用：join 已结束的线程 + 销毁 watcher */
    void shutdown() {
        stopReq.store(true);
        if (worker.joinable()) worker.join();
        if (watcher) { watcher->stop(); delete watcher; watcher = nullptr; }
    }

    CJsonValue snapshotLocked() {
        CJsonValue d = CJsonValue::makeObject();
        d["running"] = CJsonValue::makeBool(running.load());
        d["stopping"] = CJsonValue::makeBool(stopReq.load() && running.load());
        d["native"] = CJsonValue::makeBool(native);
        d["source"] = CJsonValue::makeString(source);
        d["archiveDir"] = CJsonValue::makeString(archiveDir);
        d["prefix"] = CJsonValue::makeString(prefix);
        d["debounceSeconds"] = CJsonValue::makeInt(debounceSeconds);
        d["keep"] = CJsonValue::makeInt(keep);
        d["startedAt"] = CJsonValue::makeInt(startedAt);
        d["backupCount"] = CJsonValue::makeInt(backupCount);
        d["failCount"] = CJsonValue::makeInt(failCount);
        d["lastArchive"] = CJsonValue::makeString(lastArchive);
        d["lastError"] = CJsonValue::makeString(lastError);
        return d;
    }
};
WatchState g_watch;

/* 工作线程主体：轮询 takeDirty() → debounce → 跑一次归档 + retention */
static void watchWorkerLoop(BackupOptions base, std::string archiveDir, std::string prefix,
                            int debounceSeconds, int keep) {
    bool pending = false;
    std::time_t pendingSince = 0;
    while (!g_watch.stopReq.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        CDirWatcher* w = g_watch.watcher;
        if (w && w->takeDirty()) {
            if (!pending) { pending = true; pendingSince = std::time(nullptr); }
        }
        if (!pending) continue;
        if (static_cast<int>(std::time(nullptr) - pendingSince) < debounceSeconds) continue;
        pending = false;
        const std::string archive = CScheduler::makeArchiveName(archiveDir, prefix);
        BackupOptions each = base;
        each.destination = archive;
        CBackupEngine engine;
        const ErrCode e = engine.run(each);
        std::lock_guard<std::mutex> lk(g_watch.mtx);
        if (DBKP_IS_ERR(e)) {
            ++g_watch.failCount;
            g_watch.lastError = engine.lastError();
        } else {
            ++g_watch.backupCount;
            g_watch.lastArchive = archive;
            g_watch.lastError.clear();
            CScheduler::applyRetention(archiveDir, prefix, keep);
        }
    }
    if (g_watch.watcher) g_watch.watcher->stop();   /* 停掉内部监听线程 */
    std::lock_guard<std::mutex> lk(g_watch.mtx);
    g_watch.running.store(false);
}

CHttpResponse hWatchStart(ApiContext& ctx, const CHttpRequest& req) {
    CHttpResponse denied;
    if (authFailed(req, ctx, denied)) return denied;
    CJsonValue body;
    std::string err;
    if (!req.json(body, err))
        return CHttpResponse::jsonError(E_INVALID_PARAMETER, "请求体不是合法 JSON：" + err, 400);

    std::string src, dst;
    if (!pathWithinRoot(ctx.dataRoot, jsonStr(body, "source", ""), src)
        || !pathWithinRoot(ctx.dataRoot, jsonStr(body, "destination", ""), dst))
        return CHttpResponse::jsonError(403, "source/destination 必须都在数据根范围内", 403);
    if (Platform::exists(src) != E_OK)
        return CHttpResponse::jsonError(E_SOURCE_NOT_FOUND, "源目录不存在：" + src, 400);

    /* F6：与 CLI watch 同口径 —— 归档目录落在源目录内部（或与之相等）时，
       每生成一个箱都会被自己再触发一次，必须当场拒绝，不进监听循环。 */
    if (Path::isSubPath(src, dst)) {
        LOG_WARN("启动实时备份被拒（F6 自喂循环）：destination 在 source 内部 "
                 + dst + " under " + src);
        return CHttpResponse::jsonError(E_INVALID_PARAMETER,
            "destination 位于 source 内部（或与 source 相同），实时备份会把自己"
            "生成的归档当成源变化反复备份，拒绝启动", 400);
    }

    bool okDebounce = false;
    const int debounce = CScheduler::parseInterval(jsonStr(body, "debounce", "2s"), &okDebounce);
    if (!okDebounce || debounce < 0)
        return CHttpResponse::jsonError(E_INVALID_PARAMETER, "debounce 不合法（例 2s/1m）", 400);

    std::lock_guard<std::mutex> lk(g_watch.mtx);
    if (g_watch.running.load())
        return CHttpResponse::jsonError(E_ALREADY_EXISTS, "已有实时备份在监听，先调 /api/watch/stop", 409);
    g_watch.shutdown();                 /* 回收上一轮已结束的线程/watcher */

    BackupOptions base;
    base.source = src;
    base.destination = dst;
    base.mode = MODE_ARCHIVE;
    base.verifyAfter = jsonBool(body, "verifyAfter", true);
    base.pack.comp = algorithmFromName(jsonStr(body, "algorithm", ctx.defaultAlgorithm));
    base.pack.crypto = cryptoFromName(jsonStr(body, "crypto", "none"));
    base.pack.password = jsonStr(body, "password", "");
    base.password = base.pack.password;
    std::string whyFilter;
    if (!applyFilterJson(body.at("filter"), base.pack.filter, whyFilter))
        return CHttpResponse::jsonError(E_INVALID_PARAMETER, "filter：" + whyFilter, 400);
    ChecksumId cs = CHK_CRC64;
    if (!parseChecksum(jsonStr(body, "checksum", "crc64"), cs))
        return CHttpResponse::jsonError(E_INVALID_PARAMETER, "checksum 只能是 none/crc64/sha256", 400);
    base.pack.checksum = cs;
    if (base.pack.crypto != CRY_NONE && base.pack.password.empty())
        return CHttpResponse::jsonError(E_INVALID_PARAMETER, "选择了加密算法但没有给密码", 400);
    /* F5：反向检查，与 CLI 同口径 —— 只给 password 不给 crypto 会持续产出明文箱 */
    if (base.pack.crypto == CRY_NONE && !base.pack.password.empty())
        return CHttpResponse::jsonError(E_INVALID_PARAMETER,
                                        "给了 password 但没选加密算法（crypto），"
                                        "拒绝生成未加密的归档；请同时指定 crypto 或去掉 password", 400);

    std::string prefix = jsonStr(body, "prefix", "");
    if (prefix.empty()) prefix = Path::fileName(Path::normalize(src));
    if (prefix.empty() || prefix == ".") prefix = "backup";
    if (DBKP_IS_ERR(Platform::exists(dst))) Platform::makeDirTree(dst);

    /* 同步启动 watcher：目录不合法立即报错返回，不放进线程 */
    CDirWatcher* w = new CDirWatcher();
    const ErrCode we = w->start(src);
    if (DBKP_IS_ERR(we)) {
        const std::string msg = w->lastError();
        delete w;
        return CHttpResponse::jsonError(we, "启动监听失败：" + msg, 400);
    }
    g_watch.watcher = w;
    g_watch.source = src;
    g_watch.archiveDir = dst;
    g_watch.prefix = prefix;
    g_watch.debounceSeconds = debounce > 0 ? debounce : 2;
    g_watch.keep = static_cast<int>(jsonInt(body, "keep", 0));
    g_watch.native = w->nativeEventDriven();
    g_watch.startedAt = nowSec();
    g_watch.backupCount = 0;
    g_watch.failCount = 0;
    g_watch.lastArchive.clear();
    g_watch.lastError.clear();
    g_watch.stopReq.store(false);
    g_watch.running.store(true);

    g_watch.worker = std::thread(watchWorkerLoop, base, dst, prefix, g_watch.debounceSeconds, g_watch.keep);
    LOG_INFO("实时备份已启动：" + src + " -> " + dst + " [" +
             (g_watch.native ? "原生事件" : "轮询") + "]");
    return CHttpResponse::jsonOk(g_watch.snapshotLocked(), "实时备份监听已启动");
}

CHttpResponse hWatchStatus(ApiContext& ctx, const CHttpRequest& req) {
    CHttpResponse denied;
    if (authFailed(req, ctx, denied)) return denied;
    std::lock_guard<std::mutex> lk(g_watch.mtx);
    return CHttpResponse::jsonOk(g_watch.snapshotLocked());
}

CHttpResponse hWatchStop(ApiContext& ctx, const CHttpRequest& req) {
    CHttpResponse denied;
    if (authFailed(req, ctx, denied)) return denied;
    std::lock_guard<std::mutex> lk(g_watch.mtx);
    if (!g_watch.running.load() && !g_watch.worker.joinable())
        return CHttpResponse::jsonError(E_NOT_FOUND, "当前没有实时备份在监听", 404);
    g_watch.stopReq.store(true);
    return CHttpResponse::jsonOk(g_watch.snapshotLocked(),
                                 "已请求停止，监听会在当前这轮备份后退出");
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
    /* 相对路径以 dataRoot 为基准（配了 root 时），绝对路径原样折叠 */
    if (!resolveWithinRoot(root, path, resolved)) return false;
    if (root.empty()) return true;                     /* 未设根目录 = 不限制 */
    std::string absRoot;
    if (!makeAbsolute(root, absRoot)) return false;

    /* F1 修法第 3 点：词法折叠只防得住 ".."，防不住 data-root 里放的
       junction/symlink——字符串上"在根内"，真实位置在根外。browse/
       backup/restore/stat 全部走这一关，所以比较时两侧都解析成真实路径；
       任一解析失败（盘符/根不存在等）退回词法值。回显 resolved 保持词法
       结果不变：合法路径词法即真实，含"仍在根内"的 junction 时按词法路径
       操作也不越界，而越界的已在下面被拒。 */
    std::string cmpRoot = absRoot, cmpPath = resolved;
    std::string realRoot, realPath;
    if (resolveRealPath(absRoot, realRoot)) {
        cmpRoot = realRoot;
        if (resolveRealPath(resolved, realPath)) cmpPath = realPath;
    }
    const std::string a = lowerIfWin(cmpRoot);
    const std::string b = lowerIfWin(cmpPath);
    if (a == b) return true;
    const std::string withSlash = a == "/" ? a : a + "/";
    return b.compare(0, withSlash.size(), withSlash) == 0;
}

/* ---------------------------------------------------- F12：登录失败限速 */
/* 按来源 IP 记失败次数：连续 5 次失败上锁，之后指数退避 1s→2s→4s→…封顶
   300s；口令正确立刻清零该 IP 计数。到期自动放开，不做人工干预。
   时钟用 steady_clock——墙钟回拨会把锁定期拉满或提前放行，这里只关心
   "过了多久"，不关心"现在是几点"。
   表防爆破者伪造海量 IP 撑爆内存：上限 kMaxEntries，满了先清已解锁的
   旧条目，仍满再整表复位（最坏情况只是提前放开，不会锁死正常用户）。 */
namespace {

constexpr int       kFailLimit      = 5;    /* 连续失败到达此数即上锁 */
constexpr long long kBaseBackoffSec = 1;    /* 第 6 次尝试前的锁时长 */
constexpr long long kMaxBackoffSec  = 300;  /* 封顶 */
constexpr std::size_t kMaxEntries   = 4096; /* 计数表上限 */

struct SLoginThrottle {
    /* 单调时钟秒。entry 只在 Allow/Record 里访问，二者各自持锁 */
    long long now() const {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }
    struct Entry { int fails = 0; long long unlockAt = 0; };
    std::mutex mtx;
    std::map<std::string, Entry> byIp;

    /* 表满时先清掉已过锁定期（且无待观察意义）的旧条目；仍满就整表复位。
       最坏情况只是提前放开限速，也绝不让计数表无限吃内存。 */
    void makeRoomLocked(long long now) {
        if (byIp.size() < kMaxEntries) return;
        for (std::map<std::string, Entry>::iterator it = byIp.begin(); it != byIp.end();) {
            if (it->second.unlockAt <= now) {
                byIp.erase(it++);
            } else {
                ++it;
            }
        }
        if (byIp.size() >= kMaxEntries) byIp.clear();
    }
};
SLoginThrottle g_loginThrottle;

/* 指数退避：第 kFailLimit 次失败后锁 base 秒，往后每次翻倍，封顶 kMaxBackoffSec。
   移位超过 40 位直接取封顶值，避免 long long 溢出。 */
long long backoffSecFor(int fails) {
    const int exp = fails - kFailLimit;
    if (exp <= 0) return kBaseBackoffSec;
    if (exp >= 40) return kMaxBackoffSec;
    const long long raw = kBaseBackoffSec << exp;
    return (raw > kMaxBackoffSec) ? kMaxBackoffSec : raw;
}

} /* anonymous namespace */

bool loginThrottleAllow(const std::string& ip, long long& retryAfterSec) {
    retryAfterSec = 0;
    std::lock_guard<std::mutex> lk(g_loginThrottle.mtx);
    std::map<std::string, SLoginThrottle::Entry>::const_iterator it =
        g_loginThrottle.byIp.find(ip);
    if (it == g_loginThrottle.byIp.end()) return true;
    const long long now = g_loginThrottle.now();
    if (it->second.unlockAt <= now) return true;      /* 到期自动放开 */
    retryAfterSec = it->second.unlockAt - now;
    return false;
}

void loginThrottleRecord(const std::string& ip, bool success) {
    std::lock_guard<std::mutex> lk(g_loginThrottle.mtx);
    const long long now = g_loginThrottle.now();
    if (success) {
        g_loginThrottle.byIp.erase(ip);               /* 一次成功登录清零 */
        return;
    }
    g_loginThrottle.makeRoomLocked(now);
    SLoginThrottle::Entry& e = g_loginThrottle.byIp[ip];
    ++e.fails;
    if (e.fails >= kFailLimit) e.unlockAt = now + backoffSecFor(e.fails);
}

void resetLoginThrottleForTest() {
    std::lock_guard<std::mutex> lk(g_loginThrottle.mtx);
    g_loginThrottle.byIp.clear();
}

/* ------------------------------------------------------------ 路由注册 */
void registerApiRoutes(CRouter& router, ApiContext& ctx) {
    /* info/login 不鉴权：登录页在拿到 token 之前就必须能读到它 */
    router.get("/api/info", [&ctx](const CHttpRequest&) { return hInfo(ctx); });
    router.post("/api/login", [&ctx](const CHttpRequest& req) { return hLogin(ctx, req); });

    router.get("/api/config", [&ctx](const CHttpRequest& req) { return hConfig(ctx, req); });
    router.get("/api/browse", [&ctx](const CHttpRequest& req) { return hBrowse(ctx, req); });
    router.get("/api/stat", [&ctx](const CHttpRequest& req) { return hStat(ctx, req); });
    router.get("/api/compare", [&ctx](const CHttpRequest& req) { return hCompare(ctx, req); });

    router.post("/api/schedule", [&ctx](const CHttpRequest& req) { return hScheduleStart(ctx, req); });
    router.get("/api/schedule", [&ctx](const CHttpRequest& req) { return hScheduleStatus(ctx, req); });
    router.post("/api/schedule/stop", [&ctx](const CHttpRequest& req) { return hScheduleStop(ctx, req); });

    router.post("/api/watch", [&ctx](const CHttpRequest& req) { return hWatchStart(ctx, req); });
    router.get("/api/watch", [&ctx](const CHttpRequest& req) { return hWatchStatus(ctx, req); });
    router.post("/api/watch/stop", [&ctx](const CHttpRequest& req) { return hWatchStop(ctx, req); });

    router.post("/api/jobs", [&ctx](const CHttpRequest& req) { return hCreateJob(ctx, req); });
    router.get("/api/jobs", [&ctx](const CHttpRequest& req) { return hListJobs(ctx, req); });
    router.get("/api/jobs/:id", [&ctx](const CHttpRequest& req) { return hGetJob(ctx, req); });
    router.post("/api/jobs/:id/cancel", [&ctx](const CHttpRequest& req) { return hCancelJob(ctx, req); });

    router.get("/api/events", [&ctx](const CHttpRequest& req) { return hEvents(ctx, req); });
    router.post("/api/shutdown", [&ctx](const CHttpRequest& req) { return hShutdown(ctx, req); });
}

/* API-GLOBAL-1 */

} /* namespace DBKP */
