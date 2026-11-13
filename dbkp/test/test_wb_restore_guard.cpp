/* ============================================================================
 *  test_wb_restore_guard.cpp -- 批次10 任务B1：还原路径/链接越权防御白盒单测
 *
 *  白盒目标（函数 + 文件行号）：
 *    CMyPack::restoreEntry        src/Pack/MyPack.cpp:548
 *      - path 关卡                MyPack.cpp:551
 *      - link 关卡                MyPack.cpp:600
 *      - verifyOnly 早退          MyPack.cpp:557 / 571 / 590 / 624
 *    CMyPack::unpack              src/Pack/MyPack.cpp:833（错误码向上传播）
 *    Path::isPathTraversalSafe    src/Utils/PathUtil.cpp:176
 *    Path::isAbsolute             src/Utils/PathUtil.cpp:31
 *    Path::normalize              src/Utils/PathUtil.cpp:37
 *
 *  覆盖标准：语句覆盖 + 判定覆盖（restoreEntry 两个安全关卡的"真/假"两侧
 *  各自命中）+ 条件组合（path 为空 / 为 "." / 含 ".." / 绝对路径 四条件组合）。
 *
 *  手法：不经过打包器，直接手工拼归档字节（encodeArchiveHeader +
 *  encodeRecord），把恶意 path/link 写进 FileRecord，再调 unpack，断言
 *  错误码 + "越界文件绝对没有落到不该落的地方"。
 *
 *  诚实记录（实现现状，非本批次改动）：
 *    isPathTraversalSafe 只按 '/' 切段找 ".."，因此反斜杠变体（"..\..\x"）
 *    与混合分隔符（"a/../\evil"）判为"安全"，而 normalize 会真把它们折叠出
 *    目标目录。下面 t4/t13/t14 用例按实现实际行为断言，并在注释里写明理由。
 * ==========================================================================*/
#include "TestFramework.h"

#include <cstdint>
#include <string>
#include <vector>

#include "Common/Defs.h"
#include "Common/Serialize.h"
#include "Pack/MyPack.h"
#include "Platform/FS.h"
#include "Utils/CRC64.h"
#include "Utils/PathUtil.h"
#include "Utils/SimpleFile.h"

namespace {

using namespace DBKP;

int g_seq = 0;

/* 递归删除（Platform 没有 removeTree，这里自己写，仅测试用） */
void wbRemoveTree(const std::string& p) {
    std::vector<Platform::DirEntry> items;
    if (DBKP_IS_ERR(Platform::listDir(p, items))) {
        Platform::removeFile(p);
        return;
    }
    for (size_t i = 0; i < items.size(); ++i) {
        const std::string c = Path::join(p, items[i].name);
        if (items[i].type == FT_DIR) wbRemoveTree(c);
        else Platform::removeFile(c);
    }
    Platform::removeDir(p);
}

/* 一个用例的目录骨架：
 *   root/box.dbkp   手工构造的归档（在还原目标之外，避免"目标非空"干扰）
 *   root/out        还原目标（不存在，由 unpack 自己创建 -> 便于断言"零落地"）
 */
struct WbSandbox {
    std::string root;
    std::string arc;
    std::string dest;
    explicit WbSandbox(const char* tag) {
        root = std::string("twb_rg_") + tag + "_" + std::to_string(g_seq++);
        arc  = Path::join(root, "box.dbkp");
        dest = Path::join(root, "out");
        wbRemoveTree(root);
        Platform::makeDirTree(root);
    }
    ~WbSandbox() { wbRemoveTree(root); }
};

struct Part {
    FileRecord rec;
    std::vector<uint8_t> payload;
};

/* 一条 CRC/size 都自洽的普通文件记录 */
Part wbRegular(const std::string& relPath, const std::string& content) {
    Part p;
    p.rec.path = relPath;
    p.rec.type = FT_REGULAR;
    p.rec.compAlg   = ALG_NONE;
    p.rec.cryptoAlg = CRY_NONE;
    p.rec.flags     = RF_CRC_VALID;
    p.payload.assign(content.begin(), content.end());
    p.rec.size       = int64_t(p.payload.size());
    p.rec.storedSize = int64_t(p.payload.size());
    p.rec.crc = CRC64::compute(p.payload.data(), p.payload.size());
    return p;
}

/* 一条符号链接记录（无载荷） */
Part wbSymlink(const std::string& relPath, const std::string& linkTarget) {
    Part p;
    p.rec.path = relPath;
    p.rec.type = FT_SYMLINK;
    p.rec.link = linkTarget;
    p.rec.flags = RF_NONE;
    return p;
}

uint64_t wbBlocksFor(int64_t n) { return uint64_t((n + BLOCK_SIZE - 1) / BLOCK_SIZE); }

/* 手工拼一个"未压缩未加密、所有校验字段都真实"的归档 */
std::vector<uint8_t> wbBuildArchive(const std::vector<Part>& parts) {
    /* 1. 先拼载荷区：每条 = 头记录块(+数据块) */
    std::vector<uint8_t> region;
    for (size_t i = 0; i < parts.size(); ++i) {
        ErrCode ee = encodeRecord(parts[i].rec, region);
        if (DBKP_IS_ERR(ee)) return std::vector<uint8_t>();
        const int64_t bytes = parts[i].rec.storedSize;
        if (bytes > 0) {
            const uint64_t blocks = wbBlocksFor(bytes);
            const size_t before = region.size();
            region.resize(before + size_t(blocks * BLOCK_SIZE), 0);
            for (size_t b = 0; b < size_t(bytes); ++b) region[before + b] = parts[i].payload[b];
        }
    }

    /* 2. 卷标字段按真实载荷计算 */
    ArchiveHeader hdr;
    hdr.compAlg       = ALG_NONE;
    hdr.cryptoAlg     = CRY_NONE;
    hdr.checksum      = CHK_CRC64;
    hdr.payloadOffset = BLOCK_SIZE;
    hdr.payloadSize   = region.size();
    hdr.recordCount   = parts.size();
    hdr.fileCount     = parts.size();
    uint64_t raw = 0;
    for (size_t i = 0; i < parts.size(); ++i) raw += uint64_t(parts[i].rec.size);
    hdr.rawSize    = raw;
    hdr.payloadCrc = CRC64::compute(region.data(), region.size());

    /* 3. 头 + 载荷 */
    std::vector<uint8_t> out;
    if (DBKP_IS_ERR(encodeArchiveHeader(hdr, out))) return std::vector<uint8_t>();
    out.insert(out.end(), region.begin(), region.end());
    return out;
}

void wbWriteArchive(const std::string& path, const std::vector<uint8_t>& bytes) {
    ASSERT_TRUE(!bytes.empty());
    ASSERT_EQ(int(CSimpleFile::writeWhole(path, bytes)), int(E_OK));
}

/* 还原一个"只含一条恶意普通文件记录"的归档；返回错误码 */
ErrCode wbRestoreOneBadPath(WbSandbox& sb, const std::string& evilPath,
                            std::string& errText) {
    std::vector<Part> parts;
    parts.push_back(wbRegular(evilPath, "EVIL"));
    wbWriteArchive(sb.arc, wbBuildArchive(parts));

    CMyPack pack;
    UnpackOptions opt;
    ErrCode e = pack.unpack(sb.arc, sb.dest, opt);
    errText = pack.lastErrorText();
    return e;
}

/* 还原一个"含一条恶意符号链接记录"的归档 */
ErrCode wbRestoreOneBadLink(WbSandbox& sb, const std::string& evilLink, int& warnings) {
    std::vector<Part> parts;
    parts.push_back(wbSymlink("link.txt", evilLink));
    wbWriteArchive(sb.arc, wbBuildArchive(parts));

    CMyPack pack;
    UnpackOptions opt;
    opt.skipPayloadVerify = false;
    ErrCode e = pack.unpack(sb.arc, sb.dest, opt);
    warnings = opt.warnings;
    return e;
}

/* 目标目录里的条目数（不存在返回 -1） */
int wbCountEntries(const std::string& dir) {
    std::vector<Platform::DirEntry> items;
    if (DBKP_IS_ERR(Platform::listDir(dir, items))) return -1;
    return int(items.size());
}

} /* namespace */

/* ---------------------------------------------------------------------------
 * B1-1 判定"真"分支：path 含 ".." 段 -> restoreEntry@551 拒绝
 * 覆盖：MyPack.cpp:551 的 !isPathTraversalSafe(rec.path) 为真 -> E_INVALID_PARAMETER
 * 期望：错误码 E_INVALID_PARAMETER；还原目标 0 条目（越界文件没落盘）
 * ------------------------------------------------------------------------ */
TEST(WbRestoreGuard, traversalParentPathRejected) {
    WbSandbox sb("par");
    std::string err;
    ErrCode e = wbRestoreOneBadPath(sb, "../../evil.txt", err);
    EXPECT_EQ(int(e), int(E_INVALID_PARAMETER));
    EXPECT_TRUE(err.find("restore failed") != std::string::npos);
    EXPECT_EQ(wbCountEntries(sb.dest), 0);
    EXPECT_NE(int(Platform::exists("../../evil.txt")), int(E_OK));
}

/* B1-2 深层 "../" 变体：同一分支，不同输入（"a/../../evil.txt"） */
TEST(WbRestoreGuard, traversalDeepParentRejected) {
    WbSandbox sb("deep");
    std::string err;
    ErrCode e = wbRestoreOneBadPath(sb, "a/../../evil.txt", err);
    EXPECT_EQ(int(e), int(E_INVALID_PARAMETER));
    EXPECT_EQ(wbCountEntries(sb.dest), 0);
    EXPECT_NE(int(Platform::exists(Path::join(sb.root, "evil.txt"))), int(E_OK));
}

/* B1-3 Unix 风格绝对路径：PathUtil.cpp:33 的 p[0]=='/' -> isAbsolute 真 */
TEST(WbRestoreGuard, absoluteUnixPathRejected) {
    WbSandbox sb("absu");
    std::string err;
    ErrCode e = wbRestoreOneBadPath(sb, "/etc/evil.txt", err);
    EXPECT_EQ(int(e), int(E_INVALID_PARAMETER));
    EXPECT_EQ(wbCountEntries(sb.dest), 0);
    EXPECT_NE(int(Platform::exists("/etc/evil.txt")), int(E_OK));
}

/* B1-4 盘符绝对路径 "C:/Windows/evil.txt"：PathUtil.cpp:34 的 p[1]==':' 分支 */
TEST(WbRestoreGuard, absoluteWindowsDrivePathRejected) {
    WbSandbox sb("absw");
    std::string err;
    ErrCode e = wbRestoreOneBadPath(sb, "C:/Windows/evil.txt", err);
    EXPECT_EQ(int(e), int(E_INVALID_PARAMETER));
    EXPECT_EQ(wbCountEntries(sb.dest), 0);
    EXPECT_NE(int(Platform::exists("C:/Windows/evil.txt")), int(E_OK));
}

/* B1-5 盘符"相对"形式 "C:evil.txt"：同样落进 isAbsolute 的 p[1]==':' 分支，
 * 实现按绝对路径拒绝（理由：Windows 下 "C:x" 会解析到 C 盘当前目录，
 * 与归档"相对还原根"的语义不符，拒掉是正确行为）。 */
TEST(WbRestoreGuard, driveRelativePathRejected) {
    WbSandbox sb("driv");
    EXPECT_TRUE(Path::isAbsolute("C:evil.txt"));
    EXPECT_FALSE(Path::isPathTraversalSafe("C:evil.txt"));

    std::string err;
    ErrCode e = wbRestoreOneBadPath(sb, "C:evil.txt", err);
    EXPECT_EQ(int(e), int(E_INVALID_PARAMETER));
    EXPECT_EQ(wbCountEntries(sb.dest), 0);
}

/* B1-6 "\\?\" 扩展前缀：PathUtil.cpp:33 的 p[0]=='\\' -> 绝对 -> 拒绝 */
TEST(WbRestoreGuard, extendedPrefixPathRejected) {
    WbSandbox sb("extp");
    EXPECT_TRUE(Path::isAbsolute("\\\\?\\C:\\evil.txt"));
    std::string err;
    ErrCode e = wbRestoreOneBadPath(sb, "\\\\?\\C:\\evil.txt", err);
    EXPECT_EQ(int(e), int(E_INVALID_PARAMETER));
    EXPECT_EQ(wbCountEntries(sb.dest), 0);
}

/* B1-7 判定"假"分支对照组：合法深层路径必须正常落盘，
 * 否则上面所有"被拒绝"的断言都可能是"全都拒绝"造成的假绿。 */
TEST(WbRestoreGuard, legalDeepPathStillRestores) {
    WbSandbox sb("ok");
    std::vector<Part> parts;
    parts.push_back(wbRegular("a/b/c/d.txt", "hello"));
    wbWriteArchive(sb.arc, wbBuildArchive(parts));

    CMyPack pack;
    UnpackOptions opt;
    ASSERT_EQ(int(pack.unpack(sb.arc, sb.dest, opt)), int(E_OK));
    EXPECT_EQ(int(Platform::exists(Path::join(sb.dest, "a/b/c/d.txt"))), int(E_OK));
    EXPECT_EQ(opt.warnings, 0);
}

/* B1-8 判定两侧命中：实现比 normalize 更保守 —— "a/../b.txt" 经 normalize
 * 后仍在目标目录内（本应合法），但 isPathTraversalSafe 只要见到 ".." 段就拒。
 * 这里按实现实际行为断言（拒绝），并留注释说明"保守拒绝"不是缺陷。 */
TEST(WbRestoreGuard, singleDotDotSegmentRejectedConservatively) {
    WbSandbox sb("cons");
    EXPECT_EQ(Path::normalize("a/../b.txt"), std::string("b.txt"));   /* 词法上合法 */
    EXPECT_FALSE(Path::isPathTraversalSafe("a/../b.txt"));            /* 实现仍拒绝 */

    std::string err;
    ErrCode e = wbRestoreOneBadPath(sb, "a/../b.txt", err);
    EXPECT_EQ(int(e), int(E_INVALID_PARAMETER));
    EXPECT_EQ(wbCountEntries(sb.dest), 0);
}

/* B1-9 边界：空路径。isPathTraversalSafe("") -> false（PathUtil.cpp:177），
 * 且 rec.path != "." 成立 -> 走拒绝分支，不能崩溃、不能落盘。 */
TEST(WbRestoreGuard, emptyPathRejected) {
    WbSandbox sb("empty");
    EXPECT_FALSE(Path::isPathTraversalSafe(""));
    std::string err;
    ErrCode e = wbRestoreOneBadPath(sb, "", err);
    EXPECT_EQ(int(e), int(E_INVALID_PARAMETER));
    EXPECT_EQ(wbCountEntries(sb.dest), 0);
}

/* B1-10 边界：path 恰为 "." 是打包器写根目录记录用的合法值，
 * restoreEntry@551 的 rec.path != "." 短路必须放行（判定另一侧）。 */
TEST(WbRestoreGuard, dotPathIsAllowedAsRoot) {
    WbSandbox sb("dot");
    std::vector<Part> parts;
    Part d;
    d.rec.path = ".";
    d.rec.type = FT_DIR;
    parts.push_back(d);
    wbWriteArchive(sb.arc, wbBuildArchive(parts));

    CMyPack pack;
    UnpackOptions opt;
    ASSERT_EQ(int(pack.unpack(sb.arc, sb.dest, opt)), int(E_OK));
    EXPECT_EQ(int(Platform::exists(sb.dest)), int(E_OK));
}

/* B1-11 边界：path 恰为 ".." */
TEST(WbRestoreGuard, bareDotDotRejected) {
    WbSandbox sb("bare");
    EXPECT_FALSE(Path::isPathTraversalSafe(".."));
    std::string err;
    ErrCode e = wbRestoreOneBadPath(sb, "..", err);
    EXPECT_EQ(int(e), int(E_INVALID_PARAMETER));
}

/* B1-12 link 关卡（MyPack.cpp:600）：绝对路径的符号链接目标 -> 记警告 +
 * E_INVALID_PARAMETER，且不得在目标目录里创建该链接。 */
TEST(WbRestoreGuard, symlinkAbsoluteTargetRejectedWithWarning) {
    WbSandbox sb("lnka");
    int warnings = 0;
    ErrCode e = wbRestoreOneBadLink(sb, "/etc/shadow", warnings);
    EXPECT_EQ(int(e), int(E_INVALID_PARAMETER));
    EXPECT_GE(warnings, 1);
    EXPECT_EQ(wbCountEntries(sb.dest), 0);
}

/* B1-13 link 关卡另一侧 + Windows 绝对形态 */
TEST(WbRestoreGuard, symlinkWindowsTargetRejected) {
    WbSandbox sb("lnkw");
    int warnings = 0;
    ErrCode e = wbRestoreOneBadLink(sb, "C:/Windows/win.ini", warnings);
    EXPECT_EQ(int(e), int(E_INVALID_PARAMETER));
    EXPECT_GE(warnings, 1);
    EXPECT_NE(int(Platform::exists(Path::join(sb.dest, "link.txt"))), int(E_OK));
}

/* B1-14 verifyOnly 早退分支（MyPack.cpp:590）：符号链接条目在只校验模式下
 * 先于 link 关卡返回 E_OK —— 这是"判定顺序"的路径覆盖，也说明 verifyOnly
 * 根本不碰磁盘（目标目录保持 0 条目）。 */
TEST(WbRestoreGuard, verifyOnlySkipsLinkGuardAndWritesNothing) {
    WbSandbox sb("vonly");
    std::vector<Part> parts;
    parts.push_back(wbSymlink("link.txt", "/etc/shadow"));
    Part f = wbRegular("f.txt", "data");
    parts.push_back(f);
    wbWriteArchive(sb.arc, wbBuildArchive(parts));

    CMyPack pack;
    UnpackOptions opt;
    opt.verifyOnly = true;
    ASSERT_EQ(int(pack.unpack(sb.arc, sb.dest, opt)), int(E_OK));
    EXPECT_EQ(wbCountEntries(sb.dest), -1);   /* 目录都没被创建 */
}

/* B1-15 反斜杠变体 "..\..\evil.txt"：实现按 '/' 切段（PathUtil.cpp:181），
 * 整串只是一个段，不等于 ".." -> 判为"安全"，而 absOf/normalize 会真把它
 * 折叠到目标目录之外。本用例把这一实现现状钉在测试里（沙箱内两层目录，
 * 逃逸落点仍在 root 之内，跑完自清），整改建议见 doc/05。 */
TEST(WbRestoreGuard, backslashDotDotCurrentlyAllowedByPredicate) {
    const std::string evil = "..\\..\\twb_escape.txt";
    EXPECT_TRUE(Path::isPathTraversalSafe(evil));              /* 实现：允许 */
    EXPECT_EQ(Path::normalize("a/b/" + evil), std::string("twb_escape.txt"));

    WbSandbox sb("bs");
    std::vector<Part> parts;
    parts.push_back(wbRegular(evil, "ESC"));
    wbWriteArchive(sb.arc, wbBuildArchive(parts));

    CMyPack pack;
    UnpackOptions opt;
    /* 目标设为 root/a/b：越出两层后落在 root/ 内，测试可控且必被自清 */
    const std::string deepDest = Path::join(sb.root, "a/b");
    Platform::makeDirTree(deepDest);
    ErrCode e = pack.unpack(sb.arc, deepDest, opt);

    EXPECT_EQ(int(e), int(E_OK));                              /* 实现放行 */
    EXPECT_EQ(int(Platform::exists(Path::join(sb.root, "twb_escape.txt"))), int(E_OK));
    EXPECT_EQ(wbCountEntries(deepDest), 0);                    /* 未在目标内落地 */
}

/* B1-16 判定覆盖条件组合表（PathUtil.cpp:176-186，实测值，逐格钉住现状）：
 *   "a/../\evil"  -> 拒：按 '/' 切段得 a / ".." / "\evil"，中间那段**正好等于** ".."
 *   "a/..\evil"   -> 允：切段得 a / "..\evil"，该段 != ".."（反斜杠盲区）
 *   "a/../../evil"-> 拒：两个独立 ".." 段
 *   "a//b"        -> 允：空段被 continue 跳过（PathUtil.cpp:181）
 *   "./a"         -> 允："." 段不等于 ".."
 * normalize 会把两种写法都折叠，说明"允许"那格是真实的判定缺口。 */
TEST(WbRestoreGuard, traversalPredicateDecisionTable) {
    EXPECT_FALSE(Path::isPathTraversalSafe("a/../\\evil"));
    EXPECT_TRUE (Path::isPathTraversalSafe("a/..\\evil"));
    EXPECT_FALSE(Path::isPathTraversalSafe("a/../../evil"));
    EXPECT_TRUE (Path::isPathTraversalSafe("a//b"));
    EXPECT_TRUE (Path::isPathTraversalSafe("./a"));

    EXPECT_EQ(Path::normalize("a/../\\evil"), std::string("evil"));
    EXPECT_EQ(Path::normalize("a/..\\evil"),  std::string("evil"));
    EXPECT_EQ(Path::normalize("a//b"),        std::string("a/b"));
    EXPECT_EQ(Path::normalize("./a"),         std::string("a"));
}
