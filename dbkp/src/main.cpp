/* ============================================================================
 *  main.cpp  -- bk 命令行入口
 *
 *  bk backup  <src> <archive.dbkp> [-a algo] [-c crypto] [-p pass] [filters...]
 *  bk restore <archive.dbkp> <dst> [-p pass] [--force] [--no-meta]
 *  bk list|info|verify <archive.dbkp> [-p pass]
 *  bk compare <archive.dbkp> <src> [-p pass]      bk selftest
 * ==========================================================================*/
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <csignal>
#include <chrono>
#include <thread>
#include <string>
#include <vector>

#include "Backup/BackupEngine.h"
#include "Backup/Scheduler.h"
#include "Backup/Watcher.h"
#include "Codec/DataCodec.h"
#include "Common/Defs.h"
#include "Common/Serialize.h"
#include "Crypto/Algorithms.h"
#include "Crypto/Sha256.h"
#include "Enumerator/FilterOptions.h"
#include "Pack/MyPack.h"
#include "Platform/Args.h"
#include "Platform/FS.h"
#include "Utils/CRC64.h"
#include "Utils/Logger.h"
#include "Utils/PathUtil.h"

#if defined(DBKP_OS_WINDOWS)
#  include <windows.h>          /* SetConsoleOutputCP（在 Platform/Args.h 里也会设，这里保留给长路径用例） */
#endif

using namespace DBKP;

namespace {

void printUsage() {
    std::printf(
        "bk - Data Backup Toolkit (dbkp v%u)\n"
        "usage:\n"
        "  bk backup   <src-dir> <archive.dbkp|dst-dir> [options]\n"
        "  bk restore  <archive.dbkp|backup-dir> <dst-dir> [-p pass] [--force] [--no-meta]\n"
        "  bk watch    <src-dir> <archive-dir> [--debounce 2s] [--keep N] [--prefix P] [options]\n"
        "  bk schedule <src-dir> <archive-dir> --every 10s --times 5 --keep 3 [options]\n"
        "  bk list|info|verify <archive.dbkp> [-p pass]\n"
        "  bk restore 也支持 --skip-payload-verify（跳过落盘前的整卷校验）\n"
        "  bk compare  <archive.dbkp> <src-dir> [-p pass]\n"
        "  bk selftest                 (run built-in known-answer checks)\n"
        "  pack/unpack 是 backup/restore 的别名\n"
        "backup options:\n"
        "  -a|--algo NAME       huffman | lz77 | lzhuff | rle | none\n"
        "  -c|--crypto NAME     aes256 | des-ede | chacha20 | xor | none\n"
        "  --checksum NAME      none | crc64 | sha256 (整卷校验，默认 crc64；\n"
        "                       sha256 额外占用一个 512B 卷标扩展块存摘要)\n"
        "  -p|--password PASS   encryption password (PBKDF2-HMAC-SHA256 key wrap)\n"
        "  -m|--comment TEXT    archive comment\n"
        "  --include/--exclude GLOB    path filter (repeatable)\n"
        "  --name/--no-name GLOB       file-name filter (repeatable)\n"
        "  --type SPEC                  e.g. '-DL' or 'regular,dir'\n"
        "                       r/reg/regular/file=普通文件 d/dir=目录 l/link=符号链接\n"
        "                       h/hardlink=硬链接 f/fifo=管道(不是文件!) b=块设备 c=字符设备 s=套接字\n"
        "  --min-size/--max-size N      e.g. 10KB 4MB\n"
        "  --newer-than/--older-than T  2024-01-01 | 7d | 12h\n"
        "  --uid N | --owner NAME       owner filter\n"
        "  --follow-symlink --no-cross-device --max-depth N --skip-special\n"
        "  --no-hardlink --no-meta --copy --archive --no-verify\n"
        "  --force             目标归档已存在或存在未完成残骸(.tmp)时覆盖重写（F4）\n"
        "  --max-depth 口径同 find -maxdepth：根目录下的条目算第 1 层\n"
        "schedule options: --every T --times N --keep M --prefix P\n"
        "global switches:  -v debug log | -q quiet | -h help\n",
        unsigned(ARCHIVE_VERSION));
}

bool nextValue(int argc, char** argv, int& i, std::string& out) {
    if (i + 1 >= argc) { LOG_ERR("missing value for " + std::string(argv[i])); return false; }
    out = argv[++i];
    return true;
}

/** 命令行/API 共用同一套校验和名称；非法名字直接报错（以前 CLI 连 --checksum 都没有） */
bool checksumFromName(const std::string& name, ChecksumId& out) {
    if (name == "crc64")  { out = CHK_CRC64;  return true; }
    if (name == "sha256") { out = CHK_SHA256; return true; }
    if (name == "none")   { out = CHK_NONE;   return true; }
    return false;
}

const char* checksumName(uint8_t id) {
    switch (id) {
    case CHK_CRC64:  return "crc64";
    case CHK_SHA256: return "sha256";
    default:         return "none";
    }
}

bool sizeArg(const std::string& text, int64_t& out) {
    bool ok = false;
    out = FilterOptions::parseSize(text, &ok);
    return ok;
}

bool timeArg(const std::string& text, int64_t& out) {
    bool ok = false;
    out = FilterOptions::parseTime(text, &ok);
    return ok && out > 0;
}

int cmdBackup(int argc, char** argv) {
    std::vector<std::string> pos;
    PackOptions opt;
    bool forceCopy = false, forceArchive = false, noVerify = false;
    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i], v;
        if (a == "-a" || a == "--algo") { if (!nextValue(argc, argv, i, v)) return 2; opt.comp = algorithmFromName(v); }
        else if (a == "-c" || a == "--crypto") { if (!nextValue(argc, argv, i, v)) return 2; opt.crypto = cryptoFromName(v); }
        else if (a == "--checksum") {
            if (!nextValue(argc, argv, i, v) || !checksumFromName(v, opt.checksum)) {
                LOG_ERR("bad --checksum value: " + v + " (none|crc64|sha256)"); return 2;
            }
        }
        else if (a == "-p" || a == "--password") { if (!nextValue(argc, argv, i, opt.password)) return 2; }
        else if (a == "-m" || a == "--comment") { if (!nextValue(argc, argv, i, opt.comment)) return 2; }
        else if (a == "--include") { if (!nextValue(argc, argv, i, v)) return 2; opt.filter.includePaths.push_back(Path::normalize(v)); }
        else if (a == "--exclude") { if (!nextValue(argc, argv, i, v)) return 2; opt.filter.excludePaths.push_back(Path::normalize(v)); }
        else if (a == "--name") { if (!nextValue(argc, argv, i, v)) return 2; opt.filter.nameGlobs.push_back(v); }
        else if (a == "--no-name") { if (!nextValue(argc, argv, i, v)) return 2; opt.filter.nameRejects.push_back(v); }
        else if (a == "--type") { if (!nextValue(argc, argv, i, v) || !opt.filter.setTypeSpec(v)) return 2; }
        else if (a == "--min-size") { if (!nextValue(argc, argv, i, v) || !sizeArg(v, opt.filter.minSize)) return 2; }
        else if (a == "--max-size") { if (!nextValue(argc, argv, i, v) || !sizeArg(v, opt.filter.maxSize)) return 2; }
        else if (a == "--newer-than") { if (!nextValue(argc, argv, i, v) || !timeArg(v, opt.filter.mtimeAfter)) return 2; }
        else if (a == "--older-than") { if (!nextValue(argc, argv, i, v) || !timeArg(v, opt.filter.mtimeBefore)) return 2; }
        else if (a == "--uid") { if (!nextValue(argc, argv, i, v)) return 2; opt.filter.uids.push_back(static_cast<uint32_t>(std::strtoul(v.c_str(), nullptr, 10))); }
        else if (a == "--owner") { if (!nextValue(argc, argv, i, v)) return 2; opt.filter.ownerNames.push_back(v); }
        else if (a == "--follow-symlink")  opt.filter.followSymlinks = true;
        else if (a == "--no-cross-device") opt.filter.noCrossDevice = true;
        else if (a == "--skip-special")    opt.filter.skipSpecials = true;
        else if (a == "--max-depth") { if (!nextValue(argc, argv, i, v)) return 2; opt.filter.maxDepth = std::atoi(v.c_str()); }
        else if (a == "--no-hardlink") opt.hardlinkDedupe = false;
        else if (a == "--no-meta")     opt.preserveMeta = false;
        else if (a == "--force")       opt.force = true;   /* F4：覆盖已存在目标/清残骸 */
        else if (a == "--copy")        forceCopy = true;
        else if (a == "--archive")     forceArchive = true;
        else if (a == "--no-verify")   noVerify = true;
        else if (a == "-h" || a == "--help") { printUsage(); return 0; }
        else if (!a.empty() && a[0] == '-') { LOG_ERR("unknown option: " + a); return 2; }
        else pos.push_back(a);
    }
    if (pos.size() != 2) { LOG_ERR("backup needs <src-dir> <dst>"); return 2; }

    BackupOptions bo;
    bo.source = pos[0];
    bo.destination = pos[1];
    bo.pack = opt;
    bo.filter = opt.filter;
    bo.password = opt.password;
    bo.mode = forceCopy ? MODE_COPY : (forceArchive ? MODE_ARCHIVE : MODE_AUTO);
    bo.verifyAfter = !noVerify;
    bo.preserveMeta = opt.preserveMeta;

    CBackupEngine engine;
    ErrCode e = engine.run(bo);
    if (DBKP_IS_ERR(e)) {
        LOG_ERR("backup failed: " + engine.lastError() + " [" + errCodeToString(e) + "]");
        return 1;
    }
    const BackupMode mode = CBackupEngine::resolveMode(bo.destination, bo.mode);
    std::printf("backup ok (%s): %s\n", backupModeName(mode), pos[1].c_str());
    if (mode == MODE_ARCHIVE) {
        CMyPack packer;
        ArchiveHeader hdr;
        ArchiveStat st;
        if (DBKP_IS_ERR(packer.stat(pos[1], hdr, st))) return 0;
        std::printf("  entries : %lld files, %lld dirs, %lld links, %lld special\n",
                    static_cast<long long>(st.fileCount), static_cast<long long>(st.dirCount),
                    static_cast<long long>(st.linkCount), static_cast<long long>(st.specialCount));
        std::printf("  size    : %lld -> %lld bytes (%.2f%%)\n",
                    static_cast<long long>(st.rawBytes), static_cast<long long>(st.storedBytes),
                    st.rawBytes ? 100.0 * double(st.storedBytes) / double(st.rawBytes) : 0.0);
        std::printf("  codec   : %s + %s, payload crc64=%s\n",
                    algorithmName(AlgorithmId(hdr.compAlg)), cryptoName(CryptoId(hdr.cryptoAlg)),
                    CRC64::toString(hdr.payloadCrc).c_str());
    } else {
        std::printf("  warnings: %d, verify: %s\n", bo.warnings,
                    bo.verifyAfter ? "crc-checked" : "skipped");
    }
    return 0;
}

int cmdRestore(int argc, char** argv) {
    std::vector<std::string> pos;
    UnpackOptions opt;
    bool noMeta = false;
    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "-p" || a == "--password") { if (!nextValue(argc, argv, i, opt.password)) return 2; }
        else if (a == "--force")   opt.overwrite = true;
        else if (a == "--skip-payload-verify") opt.skipPayloadVerify = true;
        else if (a == "--no-meta") { opt.restoreMeta = false; noMeta = true; }
        else if (!a.empty() && a[0] == '-') { LOG_ERR("unknown option: " + a); return 2; }
        else pos.push_back(a);
    }
    DBKP_UNUSED(noMeta);
    if (pos.size() != 2) { LOG_ERR("restore needs <archive.dbkp|backup-dir> <dst-dir>"); return 2; }

    /* 目标目录如果是本次新建的，失败后顺手收掉：以前错误口令 restore 会留下
       一个空目录，用户分不清“还原了一半”还是“压根没开始”。
       只删空目录（removeDir 对非空目录会失败），半写入的现场保持原样供排查。 */
    const bool dstPreExisted = Platform::exists(pos[1]) == E_OK;
    auto sweepIfWeCreated = [&]() {
        if (!dstPreExisted) Platform::removeDir(pos[1]);
    };

    /* 目标是目录（复制模式的备份）时走逐文件还原 */
    if (Platform::isDirectory(pos[0])) {
        CBackupEngine engine;
        int warnings = 0;
        ErrCode e = engine.copyRestore(pos[0], pos[1], !noMeta, warnings);
        if (DBKP_IS_ERR(e)) {
            LOG_ERR("restore failed: " + engine.lastError() + " [" + errCodeToString(e) + "]");
            sweepIfWeCreated();
            return 1;
        }
        std::printf("restore ok (copy) -> %s (warnings: %d)\n", pos[1].c_str(), warnings);
        int diff = 0;
        FilterOptions all;
        engine.verifyCopy(pos[0], pos[1], all, diff);
        std::printf("  verify: %d difference(s)\n", diff);
        return diff == 0 ? 0 : 3;
    }

    CMyPack packer;
    ErrCode e = packer.unpack(pos[0], pos[1], opt);
    if (DBKP_IS_ERR(e)) {
        LOG_ERR("restore failed: " + packer.lastErrorText() + " [" + errCodeToString(e) + "]");
        sweepIfWeCreated();
        return 1;
    }
    std::printf("restore ok -> %s (warnings: %d)\n", pos[1].c_str(), opt.warnings);
    return 0;
}

int cmdSchedule(int argc, char** argv) {
    std::vector<std::string> pos;
    ScheduleOptions so;
    PackOptions& opt = so.backup.pack;
    bool ok = false;
    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i], v;
        if (a == "--every") {
            if (!nextValue(argc, argv, i, v)) return 2;
            so.intervalSeconds = CScheduler::parseInterval(v, &ok);
            if (!ok || so.intervalSeconds <= 0) { LOG_ERR("bad --every value"); return 2; }
        }
        else if (a == "--times") { if (!nextValue(argc, argv, i, v)) return 2; so.times = std::atoi(v.c_str()); }
        else if (a == "--keep")  { if (!nextValue(argc, argv, i, v)) return 2; so.keep = std::atoi(v.c_str()); }
        else if (a == "--prefix") { if (!nextValue(argc, argv, i, so.prefix)) return 2; }
        else if (a == "-a" || a == "--algo") { if (!nextValue(argc, argv, i, v)) return 2; opt.comp = algorithmFromName(v); }
        else if (a == "-c" || a == "--crypto") { if (!nextValue(argc, argv, i, v)) return 2; opt.crypto = cryptoFromName(v); }
        else if (a == "--checksum") {
            if (!nextValue(argc, argv, i, v) || !checksumFromName(v, opt.checksum)) {
                LOG_ERR("bad --checksum value: " + v + " (none|crc64|sha256)"); return 2;
            }
        }
        else if (a == "-p" || a == "--password") { if (!nextValue(argc, argv, i, opt.password)) return 2; }
        else if (a == "--exclude") { if (!nextValue(argc, argv, i, v)) return 2; opt.filter.excludePaths.push_back(Path::normalize(v)); }
        else if (a == "--name")    { if (!nextValue(argc, argv, i, v)) return 2; opt.filter.nameGlobs.push_back(v); }
        else if (a == "--no-name") { if (!nextValue(argc, argv, i, v)) return 2; opt.filter.nameRejects.push_back(v); }
        else if (!a.empty() && a[0] == '-') { LOG_ERR("unknown option: " + a); return 2; }
        else pos.push_back(a);
    }
    if (pos.size() != 2) {
        LOG_ERR("schedule needs <src-dir> <archive-dir>  (with --every/--times/--keep)");
        return 2;
    }
    so.backup.source = pos[0];
    so.backup.destination = pos[1];
    so.backup.mode = MODE_ARCHIVE;
    so.archiveDir = pos[1];
    so.backup.verifyAfter = true;
    CScheduler scheduler;
    ErrCode e = scheduler.run(so);
    if (DBKP_IS_ERR(e)) { LOG_ERR("scheduler finished with error"); return 1; }
    std::printf("schedule ok: %d backup(s) into %s, keep=%d\n", so.times, pos[1].c_str(), so.keep);
    return 0;
}

/* --- 实时联动 watch 的 Ctrl+C 优雅停止 --- */
static std::atomic<bool> g_watchStop{false};
static void watchSigHandler(int) { g_watchStop.store(true); }

int cmdWatch(int argc, char** argv) {
    std::vector<std::string> pos;
    BackupOptions bopt;
    int debounceSec = 2;
    int keep = 0;
    std::string prefix;
    bool ok = false;

    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i], v;
        if (a == "--debounce") {
            if (!nextValue(argc, argv, i, v)) return 2;
            int sec = CScheduler::parseInterval(v, &ok);
            if (!ok || sec < 0) { LOG_ERR("bad --debounce value"); return 2; }
            debounceSec = sec > 0 ? sec : 2;
        }
        else if (a == "--keep")    { if (!nextValue(argc, argv, i, v)) return 2; keep = std::atoi(v.c_str()); }
        else if (a == "--prefix")  { if (!nextValue(argc, argv, i, prefix)) return 2; }
        else if (a == "-a" || a == "--algo")   { if (!nextValue(argc, argv, i, v)) return 2; bopt.pack.comp = algorithmFromName(v); }
        else if (a == "-c" || a == "--crypto") { if (!nextValue(argc, argv, i, v)) return 2; bopt.pack.crypto = cryptoFromName(v); }
        else if (a == "--checksum") {
            if (!nextValue(argc, argv, i, v) || !checksumFromName(v, bopt.pack.checksum)) {
                LOG_ERR("bad --checksum value"); return 2;
            }
        }
        else if (a == "-p" || a == "--password") { if (!nextValue(argc, argv, i, bopt.password)) return 2; bopt.pack.password = bopt.password; }
        else if (a == "--exclude")  { if (!nextValue(argc, argv, i, v)) return 2; bopt.pack.filter.excludePaths.push_back(Path::normalize(v)); }
        else if (a == "--name")     { if (!nextValue(argc, argv, i, v)) return 2; bopt.pack.filter.nameGlobs.push_back(v); }
        else if (a == "--no-name")  { if (!nextValue(argc, argv, i, v)) return 2; bopt.pack.filter.nameRejects.push_back(v); }
        else if (!a.empty() && a[0] == '-') { LOG_ERR("unknown option: " + a); return 2; }
        else pos.push_back(a);
    }
    if (pos.size() != 2) {
        LOG_ERR("watch needs <src-dir> <archive-dir>  [--debounce 2s] [--keep N] [--prefix P]");
        return 2;
    }
    bopt.source      = pos[0];
    bopt.destination = pos[1];
    bopt.mode        = MODE_ARCHIVE;
    bopt.verifyAfter = true;

    std::string archiveDir = pos[1];
    if (prefix.empty()) prefix = Path::fileName(Path::normalize(pos[0]));
    if (prefix.empty() || prefix == ".") prefix = "backup";
    if (DBKP_IS_ERR(Platform::exists(archiveDir))) Platform::makeDirTree(archiveDir);

    /* 启动 watcher */
    CDirWatcher watcher;
    ErrCode we = watcher.start(pos[0]);
    if (DBKP_IS_ERR(we)) {
        LOG_ERR("watch start failed: " + watcher.lastError());
        return 1;
    }
    std::printf("watch started: %s -> %s [%s, debounce=%ds, keep=%d]\nCtrl+C to stop.\n",
                pos[0].c_str(), archiveDir.c_str(),
                watcher.nativeEventDriven() ? "native" : "polling",
                debounceSec, keep);
    std::fflush(stdout);

    /* 注册 SIGINT */
    g_watchStop.store(false);
    std::signal(SIGINT, watchSigHandler);

    int backupCount = 0;
    /* debounce 计时：首次 takeDirty 后等 debounceSec 秒再触发备份 */
    bool pending = false;
    std::time_t pendingSince = 0;

    while (!g_watchStop.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        if (watcher.takeDirty()) {
            if (!pending) {
                pending = true;
                pendingSince = std::time(nullptr);
            }
        }
        if (pending) {
            std::time_t now = std::time(nullptr);
            if (static_cast<int>(now - pendingSince) >= debounceSec) {
                /* 执行一次备份 */
                pending = false;
                std::string archive = CScheduler::makeArchiveName(archiveDir, prefix);
                BackupOptions each = bopt;
                each.destination = archive;
                CBackupEngine engine;
                ErrCode e = engine.run(each);
                ++backupCount;
                if (DBKP_IS_ERR(e)) {
                    std::printf("[#%d] FAILED: %s\n", backupCount, engine.lastError().c_str());
                } else {
                    std::printf("[#%d] -> %s\n", backupCount, archive.c_str());
                    CScheduler::applyRetention(archiveDir, prefix, keep);
                }
                std::fflush(stdout);
            }
        }
    }

    watcher.stop();
    std::signal(SIGINT, SIG_DFL);
    std::printf("watch stopped. total backups: %d\n", backupCount);
    return 0;
}


int cmdList(int argc, char** argv) {
    bool longForm = false;
    std::string archive;
    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "-l" || a == "--long") longForm = true;
        else if (!a.empty() && a[0] == '-') { LOG_ERR("unknown option: " + a); return 2; }
        else archive = a;
    }
    if (archive.empty()) { LOG_ERR("list needs <archive.dbkp>"); return 2; }
    std::vector<FileRecord> recs;
    CMyPack packer;
    ArchiveHeader hdr;
    packer.readHeader(archive, hdr);        /* 旧归档读不出也不拦住列表，只用来说明表头 */
    ErrCode e = packer.list(archive, recs);
    if (DBKP_IS_ERR(e)) { LOG_ERR(std::string("list failed: ") + errCodeToString(e)); return 1; }
    if (!longForm) {
        std::printf("%-3s %-8s %12s %12s  %s\n", "T", "ALG", "SIZE", "STORED", "PATH");
        for (size_t i = 0; i < recs.size(); ++i) {
            const FileRecord& r = recs[i];
            std::printf("%-3c %-8s %12lld %12lld  %s\n", r.type,
                        algorithmName(AlgorithmId(r.compAlg)),
                        static_cast<long long>(r.size), static_cast<long long>(r.storedSize),
                        r.path.c_str());
        }
        std::printf("total: %zu records\n", recs.size());
        return 0;
    }
    /* --long：元数据列全部见光。以前 mode/uid/gid/纳秒时间/ino/nlink 备得进去
       却没有任何地方能看到，现在 list 就是那个出口。 */
    std::printf("%-3s %-8s %-9s %6s %6s %19s %19s %10s %4s %18s  %s\n",
                "T", "ALG", "MODE", "UID", "GID", "MTIME", "ATIME", "SIZE", "NLK", "CRC64", "PATH");
    /* 秒制时间戳转本地时间字符串：localtime_s 在 MinGW 上不一定声明，
       这里统一走 std::localtime（CLI 单线程，静态缓冲可接受）。 */
    auto fmtLocal = [](int64_t sec, char* out, size_t n) {
        std::time_t t = static_cast<std::time_t>(sec);
        std::tm buf = {};
#if defined(_WIN32)
        const std::tm* p = std::localtime(&t);
        if (p) buf = *p; else return;
#else
        if (!localtime_r(&t, &buf)) return;
#endif
        std::strftime(out, n, "%Y-%m-%d %H:%M:%S", &buf);
    };
    for (size_t i = 0; i < recs.size(); ++i) {
        const FileRecord& r = recs[i];
        char mt[24] = "-", at[24] = "-";
        if (r.flags & RF_META_TIME) {
            fmtLocal(r.mtimeSec, mt, sizeof(mt));
            fmtLocal(r.atimeSec, at, sizeof(at));
        }
        char modeTxt[10];
        std::snprintf(modeTxt, sizeof(modeTxt), "%04o", r.mode & 07777u);
        std::printf("%-3c %-8s %-9s %6u %6u %19s %19s %10lld %4u %18s  %s\n",
                    r.type, algorithmName(AlgorithmId(r.compAlg)), modeTxt, r.uid, r.gid,
                    mt, at, static_cast<long long>(r.size), r.nlink,
                    (r.flags & RF_CRC_VALID) ? CRC64::toString(r.crc).c_str() : "-",
                    r.path.c_str());
        if (r.type == FT_SYMLINK || r.type == FT_HARDLINK)
            std::printf("      -> %s\n", r.link.c_str());
        /* 纳秒精度不丢：卷标里存的是完整 ns，列表行尾用 .%09d 补上 */
        if ((r.flags & RF_META_TIME) && r.mtimeNSec)
            std::printf("      mtime +%09lld ns\n", static_cast<long long>(r.mtimeNSec));
    }
    std::printf("total: %zu records (checksum=%s, headerSize=%u)\n",
                recs.size(), checksumName(hdr.checksum), hdr.headerSize);
    return 0;
}

int cmdInfo(int argc, char** argv) {
    (void)argc;
    CMyPack packer;
    ArchiveHeader hdr;
    ArchiveStat st;
    ErrCode e = packer.stat(argv[2], hdr, st);
    if (DBKP_IS_ERR(e)) { LOG_ERR(std::string("info failed: ") + errCodeToString(e)); return 1; }
    std::printf("archive     : %s\n", argv[2]);
    std::printf("version     : %u\n", hdr.version);
    std::printf("source      : %s\n", hdr.sourcePath.c_str());
    std::printf("created     : %llu\n", static_cast<unsigned long long>(hdr.createTime));
    std::printf("comment     : %s\n", hdr.comment.c_str());
    std::printf("compression : %s\n", algorithmName(AlgorithmId(hdr.compAlg)));
    std::printf("crypto      : %s\n", cryptoName(CryptoId(hdr.cryptoAlg)));
    std::printf("checksum    : %s\n", checksumName(hdr.checksum));
    if (hdr.checksum == CHK_SHA256 && !hdr.payloadDigest.empty())
        std::printf("sha256      : %s\n", CSha256::toHex(hdr.payloadDigest.data()).c_str());
    std::printf("records     : %llu (entries %llu)\n",
                static_cast<unsigned long long>(hdr.recordCount),
                static_cast<unsigned long long>(hdr.fileCount));
    std::printf("payload     : %llu bytes, crc64=%s\n",
                static_cast<unsigned long long>(hdr.payloadSize),
                CRC64::toString(hdr.payloadCrc).c_str());
    std::printf("content     : %lld files, %lld dirs, %lld links, %lld special\n",
                static_cast<long long>(st.fileCount), static_cast<long long>(st.dirCount),
                static_cast<long long>(st.linkCount), static_cast<long long>(st.specialCount));
    std::printf("bytes       : %lld raw -> %lld stored\n",
                static_cast<long long>(st.rawBytes), static_cast<long long>(st.storedBytes));
    return 0;
}

int cmdVerify(int argc, char** argv) {
    std::string pass, path;
    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "-p" || a == "--password") { if (!nextValue(argc, argv, i, pass)) return 2; }
        else if (!a.empty() && a[0] == '-') { LOG_ERR("unknown option: " + a); return 2; }
        else path = a;
    }
    if (path.empty()) { LOG_ERR("verify needs <archive.dbkp>"); return 2; }
    CMyPack packer;
    int bad = 0;
    ErrCode e = packer.verify(path, pass, bad);
    if (DBKP_IS_ERR(e)) { LOG_ERR(std::string("verify failed: ") + errCodeToString(e)); return 1; }
    std::printf("verify ok: archive is self-consistent (bad=%d)\n", bad);
    return 0;
}

int cmdCompare(int argc, char** argv) {
    std::vector<std::string> pos;
    std::string pass;
    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "-p" || a == "--password") { if (!nextValue(argc, argv, i, pass)) return 2; }
        else if (!a.empty() && a[0] == '-') { LOG_ERR("unknown option: " + a); return 2; }
        else pos.push_back(a);
    }
    if (pos.size() != 2) { LOG_ERR("compare needs <archive.dbkp> <src-dir>"); return 2; }
    CMyPack packer;
    int diff = 0;
    ErrCode e = packer.compareWithSource(pos[0], pos[1], pass, diff);
    if (DBKP_IS_ERR(e)) { LOG_ERR(std::string("compare failed: ") + errCodeToString(e)); return 1; }
    std::printf("compare: %d difference(s)\n", diff);
    return diff == 0 ? 0 : 3;
}

int cmdSelftest() {
    std::printf("platform        : %s\n", Platform::osName().c_str());
    std::printf("symlink/hardlink: %s / %s\n", Platform::supportsSymlink() ? "yes" : "no",
                Platform::supportsHardlink() ? "yes" : "no");
    std::printf("fifo/device     : %s / %s\n", Platform::supportsFifo() ? "yes" : "no",
                Platform::supportsDeviceNode() ? "yes" : "no");
    std::printf("owner/nsec      : %s / %s\n", Platform::supportsOwner() ? "yes" : "no",
                Platform::supportsNanoTime() ? "yes" : "no");
    std::printf("block size      : %zu bytes (extend payload %zu)\n",
                BLOCK_SIZE, REC_EXTEND_PAYLOAD);
    const char* msg = "hello dbkp hello dbkp hello";
    std::printf("crc64(msg)      : %s\n",
                CRC64::toString(CRC64::compute(msg, std::strlen(msg))).c_str());
    const char* abc = "abc";
    uint8_t d[32];
    CSha256::hash(abc, 3, d);
    std::printf("sha256(\"abc\")   : %s\n", CSha256::toHex(d).c_str());

    FileRecord rec;
    rec.type = FT_REGULAR;
    rec.path = std::string(300, 'x');
    rec.link = std::string(150, 'y');
    rec.size = 1234;
    std::vector<uint8_t> bytes;
    ErrCode e = encodeRecord(rec, bytes);
    FileRecord back;
    e = DBKP_FAIL(e, decodeRecordBlocks(bytes, back));
    const bool ok = (e == E_OK && back.path == rec.path && back.link == rec.link && back.size == 1234);
    std::printf("long-path rt    : %s (%zu blocks, path %zu, link %zu)\n",
                ok ? "ok" : "FAIL", bytes.size() / BLOCK_SIZE, back.path.size(), back.link.size());
    return ok ? 0 : 1;
}

} /* anonymous namespace */

int main(int argc, char** argv) {
    /* argv 是 ANSI 码页字节 + 控制台默认 GBK：统一换成 UTF-8 参数与输出码页
       （实现见 Platform/Args.h，bkd 用的是同一份，避免两处各写一遍） */
    std::vector<std::string> argStore;
    Platform::useUtf8Args(argc, argv, argStore);
    for (int i = 1; i < argc; ++i) {
        if (!std::strcmp(argv[i], "-v")) Logger::instance().setLevel(LL_DEBUG);
        else if (!std::strcmp(argv[i], "-q")) Logger::instance().setLevel(LL_QUIET);
    }
    /* -v/-q 是全局开关：先从参数表里摘掉，避免各子命令把它们当成未知选项 */
    {
        int kept = 1;
        for (int i = 1; i < argc; ++i) {
            if (!std::strcmp(argv[i], "-v") || !std::strcmp(argv[i], "-q")) continue;
            argv[kept++] = argv[i];
        }
        argv[kept] = nullptr;
        argc = kept;
    }
    CRC64::initTable();
    CAes256::initTables();
    if (argc < 2) { printUsage(); return 2; }
    const std::string cmd = argv[1];
    if (cmd == "backup")   return cmdBackup(argc, argv);
    if (cmd == "pack")     return cmdBackup(argc, argv);
    if (cmd == "schedule") return cmdSchedule(argc, argv);
    if (cmd == "watch")    return cmdWatch(argc, argv);
    if (cmd == "restore")  return cmdRestore(argc, argv);
    if (cmd == "unpack")   return cmdRestore(argc, argv);
    if (cmd == "list")     return argc < 3 ? 2 : cmdList(argc, argv);
    if (cmd == "info")     return argc < 3 ? 2 : cmdInfo(argc, argv);
    if (cmd == "verify")   return cmdVerify(argc, argv);
    if (cmd == "compare")  return cmdCompare(argc, argv);
    if (cmd == "selftest") return cmdSelftest();
    if (cmd == "-h" || cmd == "--help" || cmd == "help") { printUsage(); return 0; }
    LOG_ERR("unknown command: " + cmd);
    printUsage();
    return 2;
}



