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
#include <string>
#include <vector>

#include "Backup/BackupEngine.h"
#include "Backup/Scheduler.h"
#include "Codec/DataCodec.h"
#include "Common/Defs.h"
#include "Common/Serialize.h"
#include "Crypto/Algorithms.h"
#include "Crypto/Sha256.h"
#include "Enumerator/FilterOptions.h"
#include "Pack/MyPack.h"
#include "Platform/FS.h"
#include "Utils/CRC64.h"
#include "Utils/Logger.h"
#include "Utils/PathUtil.h"

using namespace DBKP;

namespace {

void printUsage() {
    std::printf(
        "bk - Data Backup Toolkit (dbkp v%u)\n"
        "usage:\n"
        "  bk backup  <src-dir> <archive.dbkp> [options]\n"
        "  bk restore <archive.dbkp> <dst-dir> [-p pass] [--force]\n"
        "  bk list|info|verify <archive.dbkp> [-p pass]\n"
        "  bk compare <archive.dbkp> <src-dir> [-p pass]\n"
        "  bk selftest\n"
        "backup options:\n"
        "  -a|--algo NAME       huffman | lz77 | lzhuff | rle | none\n"
        "  -c|--crypto NAME     aes256 | chacha20 | xor | none\n"
        "  -p|--password PASS   encryption password\n"
        "  -m|--comment TEXT    archive comment\n"
        "  --include/--exclude GLOB    path filter (repeatable)\n"
        "  --name/--no-name GLOB       file-name filter (repeatable)\n"
        "  --type SPEC                  e.g. '-DL' or 'reg,dir'\n"
        "  --min-size/--max-size N      e.g. 10KB 4MB\n"
        "  --newer-than/--older-than T  2024-01-01 | 7d | 12h\n"
        "  --uid N | --owner NAME       owner filter\n"
        "  --follow-symlink --no-cross-device --max-depth N --skip-special\n"
        "  --no-hardlink --no-meta -q -v -h\n",
        unsigned(ARCHIVE_VERSION));
}

bool nextValue(int argc, char** argv, int& i, std::string& out) {
    if (i + 1 >= argc) { LOG_ERR("missing value for " + std::string(argv[i])); return false; }
    out = argv[++i];
    return true;
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
        else if (a == "--no-meta") { opt.restoreMeta = false; noMeta = true; }
        else if (!a.empty() && a[0] == '-') { LOG_ERR("unknown option: " + a); return 2; }
        else pos.push_back(a);
    }
    DBKP_UNUSED(noMeta);
    if (pos.size() != 2) { LOG_ERR("restore needs <archive.dbkp|backup-dir> <dst-dir>"); return 2; }

    /* 目标是目录（复制模式的备份）时走逐文件还原 */
    if (Platform::isDirectory(pos[0])) {
        CBackupEngine engine;
        int warnings = 0;
        ErrCode e = engine.copyRestore(pos[0], pos[1], !noMeta, warnings);
        if (DBKP_IS_ERR(e)) {
            LOG_ERR("restore failed: " + engine.lastError() + " [" + errCodeToString(e) + "]");
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


int cmdList(int argc, char** argv) {
    std::vector<FileRecord> recs;
    CMyPack packer;
    ErrCode e = packer.list(argv[2], recs);
    if (DBKP_IS_ERR(e)) { LOG_ERR(std::string("list failed: ") + errCodeToString(e)); return 1; }
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

int cmdInfo(int argc, char** argv) {
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



