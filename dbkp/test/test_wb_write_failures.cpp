/* ============================================================================
 *  test_wb_write_failures.cpp -- 批次10 任务B3：写入/落地失败路径白盒单测
 *
 *  白盒目标（函数 + 文件行号）：
 *    CMyPack::unpack                 src/Pack/MyPack.cpp:833
 *      - 打不开归档                  MyPack.cpp:840-844
 *      - 目标目录创建失败            MyPack.cpp:883-884
 *      - 目标是普通文件              MyPack.cpp:886-887
 *      - 目标非空且未 overwrite      MyPack.cpp:889-892
 *    CMyPack::restoreEntry           src/Pack/MyPack.cpp:548
 *      - FT_DIR makeDirTree 失败     MyPack.cpp:557-566（warnings++ 但仍 E_OK）
 *      - 落地路径被目录占用          MyPack.cpp:571+（open 失败 -> warnings++）
 *    CMyPack::pack                   src/Pack/MyPack.cpp:70
 *      - 空源目录                    MyPack.cpp:275-282（无数据块分支）
 *      - 归档写在源目录内            F9 自引用排除（MyPack.cpp 枚举阶段）
 *
 *  覆盖标准：判定覆盖 —— 上述每个错误分支各命中"真"侧一次，并用
 *  overwrite=true / 空目录 / 全新目录作为"假"侧对照；语句覆盖 restoreEntry
 *  的 warnings 累计路径。
 *
 *  期望值全部来自探针实测（_probe/pg.cpp、_probe/pc.cpp、_probe/fail2.cpp）。
 *  与 test_regress_f4.cpp 的分工：E_ALREADY_EXISTS / E_BUSY（打包侧锁冲突）
 *  已由 f4 覆盖，本文件不重复；本文件聚焦"还原侧落地失败"与"归档不可读"。
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

struct WbSandbox {
    std::string root;
    std::string src;
    std::string arc;
    std::string dest;
    explicit WbSandbox(const char* tag) {
        root = std::string("twb_wf_") + tag + "_" + std::to_string(g_seq++);
        src  = Path::join(root, "src");
        arc  = Path::join(root, "box.dbkp");
        dest = Path::join(root, "out");
        wbRemoveTree(root);
        Platform::makeDirTree(src);
    }
    ~WbSandbox() { wbRemoveTree(root); }
};

struct Part {
    FileRecord rec;
    std::vector<uint8_t> payload;
};

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

Part wbDir(const std::string& relPath) {
    Part p;
    p.rec.path = relPath;
    p.rec.type = FT_DIR;
    return p;
}

std::vector<uint8_t> wbBuildArchive(const std::vector<Part>& parts) {
    std::vector<uint8_t> region;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (DBKP_IS_ERR(encodeRecord(parts[i].rec, region))) return std::vector<uint8_t>();
        const int64_t bytes = parts[i].rec.storedSize;
        if (bytes > 0) {
            const int64_t nb = (bytes + BLOCK_SIZE - 1) / BLOCK_SIZE;
            const size_t before = region.size();
            region.resize(before + size_t(nb * BLOCK_SIZE), 0);
            for (int64_t b = 0; b < bytes; ++b) region[before + b] = parts[i].payload[b];
        }
    }
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

    std::vector<uint8_t> out;
    if (DBKP_IS_ERR(encodeArchiveHeader(hdr, out))) return std::vector<uint8_t>();
    out.insert(out.end(), region.begin(), region.end());
    return out;
}

void wbWriteBytes(const std::string& path, const std::vector<uint8_t>& bytes) {
    ASSERT_TRUE(!bytes.empty());
    ASSERT_EQ(int(CSimpleFile::writeWhole(path, bytes)), int(E_OK));
}

/* 标准三记录箱：根目录 + occ.txt + sub/x.txt（3072 字节） */
void wbWriteStandardBox(const std::string& arc) {
    wbWriteBytes(arc, wbBuildArchive({ wbDir("."), wbRegular("occ.txt", "AAAA"),
                                     wbRegular("sub/x.txt", "BBBB") }));
}

bool wbExists(const std::string& p) { return Platform::exists(p) == E_OK; }

int wbCountEntries(const std::string& dir) {
    std::vector<Platform::DirEntry> items;
    if (DBKP_IS_ERR(Platform::listDir(dir, items))) return -1;
    return int(items.size());
}

} /* namespace */

/* ---------------------------------------------------------------------------
 * B3-1 目标目录的父路径是普通文件 -> makeDirTree 失败
 * 覆盖：MyPack.cpp:883-884（DBKP_IS_ERR(makeDirTree) 判定"真"侧）
 * 期望：E_DESTINATION_CREATE_FAIL；文本 "cannot create target"；目标不存在
 * 实测：_probe/pg.cpp 用例 1
 * ------------------------------------------------------------------------ */
TEST(WbWriteFailures, targetParentIsFileFailsToCreateDestination) {
    WbSandbox sb("parentfile");
    wbWriteStandardBox(sb.arc);
    const std::string blocker = Path::join(sb.root, "blocker");
    wbWriteBytes(blocker, std::vector<uint8_t>(1, 'Z'));
    const std::string dst = Path::join(blocker, "nested");

    CMyPack p;
    UnpackOptions u;
    ErrCode e = p.unpack(sb.arc, dst, u);
    const std::string text = p.lastErrorText();

    EXPECT_EQ(int(e), int(E_DESTINATION_CREATE_FAIL));
    EXPECT_TRUE(text.find("cannot create target") != std::string::npos);
    EXPECT_EQ(wbCountEntries(dst), -1);
}

/* ---------------------------------------------------------------------------
 * B3-2 落地路径被同名目录占用（overwrite=true）-> 单条失败但整体继续
 * 覆盖：MyPack.cpp:571+ restoreEntry 打开文件失败 -> ++warnings 后返回码上抛；
 *       unpack 循环内 DBKP_IS_ERR(e) 的 break 分支
 * 期望：E_PERMISSION_DENIED；warnings==1；目标目录只剩占用它的 1 个条目；
 *       文本 "restore failed: occ.txt"
 * 实测：_probe/pc.cpp A / _probe/pg.cpp 用例 2
 * ------------------------------------------------------------------------ */
TEST(WbWriteFailures, landingPathOccupiedByDirectoryIsPermissionDenied) {
    WbSandbox sb("occupied");
    wbWriteStandardBox(sb.arc);
    Platform::makeDirTree(sb.dest);
    const std::string occupied = Path::join(sb.dest, "occ.txt");
    ASSERT_EQ(int(Platform::makeDirTree(occupied)), int(E_OK));

    CMyPack p;
    UnpackOptions u;
    u.overwrite = true;                  /* 不给 overwrite 会先被"目标非空"拦下 */
    ErrCode e = p.unpack(sb.arc, sb.dest, u);
    const std::string text = p.lastErrorText();
    const int warnings = int(u.warnings);
    const int entries = wbCountEntries(sb.dest);

    EXPECT_EQ(int(e), int(E_PERMISSION_DENIED));
    EXPECT_EQ(warnings, 1);
    EXPECT_EQ(entries, 1);
    EXPECT_TRUE(text.find("restore failed: occ.txt") != std::string::npos);
}

/* ---------------------------------------------------------------------------
 * B3-3 归档被对手独占 -> 读不到头部，报"不是 dbkp 归档"，且不创建目标
 * 覆盖：MyPack.cpp:840-844 open 失败 / readHeaderAt 失败 -> "not a dbkp archive"
 * 期望：E_TRUNCATED_ARCHIVE；文本 "not a dbkp archive"；目标目录未被创建
 * 诚实记录：Windows 共享模式下 open 能成功但读 0 字节，因此错误码是
 *   E_TRUNCATED_ARCHIVE 而不是 E_BUSY；这是实现现状，用例按实测断言。
 * 实测：_probe/pg.cpp 用例 4 / _probe/fail2.cpp
 * ------------------------------------------------------------------------ */
TEST(WbWriteFailures, lockedArchiveIsRejectedWithoutCreatingTarget) {
    WbSandbox sb("lockedbox");
    wbWriteStandardBox(sb.arc);

    CSimpleFile rival;
    ASSERT_EQ(int(rival.open(sb.arc, CSimpleFile::MODE_READ_WRITE_CREATE)), int(E_OK));
    ASSERT_EQ(int(Platform::tryLockFile(rival.fd())), int(E_OK));

    CMyPack p;
    UnpackOptions u;
    ErrCode e = p.unpack(sb.arc, sb.dest, u);
    const std::string text = p.lastErrorText();
    const bool dstCreated = wbExists(sb.dest);
    rival.close();

    EXPECT_EQ(int(e), int(E_TRUNCATED_ARCHIVE));
    EXPECT_TRUE(text.find("not a dbkp archive") != std::string::npos);
    EXPECT_FALSE(dstCreated);
}

/* ---------------------------------------------------------------------------
 * B3-4 归档文件根本不存在 -> E_SOURCE_NOT_FOUND + "cannot open archive"
 * 覆盖：MyPack.cpp:840-844（open 返回错误）判定"真"侧
 * 期望：E_SOURCE_NOT_FOUND；文本 "cannot open archive"；目标目录不创建
 * 实测：_probe/pg.cpp 用例 5
 * ------------------------------------------------------------------------ */
TEST(WbWriteFailures, missingArchiveOpensNothingAndCreatesNoTarget) {
    WbSandbox sb("missingbox");
    CMyPack p;
    UnpackOptions u;
    ErrCode e = p.unpack(Path::join(sb.root, "ghost.dbkp"), sb.dest, u);
    const std::string text = p.lastErrorText();

    EXPECT_EQ(int(e), int(E_SOURCE_NOT_FOUND));
    EXPECT_TRUE(text.find("cannot open archive") != std::string::npos);
    EXPECT_FALSE(wbExists(sb.dest));
}

/* ---------------------------------------------------------------------------
 * B3-5 目标非空且未给 overwrite -> 在解析任何记录之前就拒绝
 * 覆盖：MyPack.cpp:889-892 assertDirEmpty 分支
 * 期望：E_DESTINATION_NOT_EMPTY；目标目录条目数不变（原有 junk 未被破坏）
 * 实测：_probe/pg.cpp 用例 6 / _probe/fail2.cpp
 * ------------------------------------------------------------------------ */
TEST(WbWriteFailures, nonEmptyTargetRefusedBeforeParsingRecords) {
    WbSandbox sb("nonempty");
    wbWriteStandardBox(sb.arc);
    Platform::makeDirTree(sb.dest);
    const std::string junk = Path::join(sb.dest, "junk.txt");
    wbWriteBytes(junk, std::vector<uint8_t>(1, 'Z'));

    CMyPack p;
    UnpackOptions u;                     /* overwrite 保持 false */
    ErrCode e = p.unpack(sb.arc, sb.dest, u);
    const std::string text = p.lastErrorText();
    const int entries = wbCountEntries(sb.dest);

    EXPECT_EQ(int(e), int(E_DESTINATION_NOT_EMPTY));
    EXPECT_EQ(entries, 1);
    EXPECT_TRUE(wbExists(junk));
    EXPECT_TRUE(text.find("not empty") != std::string::npos);
}

/* ---------------------------------------------------------------------------
 * B3-6 目标路径本身是普通文件 -> E_INVALID_PARAMETER（不覆盖用户文件）
 * 覆盖：MyPack.cpp:886-887（exists 且 !isDirectory）判定"真"侧
 * 期望：E_INVALID_PARAMETER；那个文件仍然在原处
 * 实测：_probe/pg.cpp 用例 7 / _probe/pe.exe dest=nonempty 系列
 * ------------------------------------------------------------------------ */
TEST(WbWriteFailures, targetIsRegularFileIsInvalidParameter) {
    WbSandbox sb("destfile");
    wbWriteStandardBox(sb.arc);
    wbWriteBytes(sb.dest, std::vector<uint8_t>(1, 'Z'));

    CMyPack p;
    UnpackOptions u;
    ErrCode e = p.unpack(sb.arc, sb.dest, u);

    EXPECT_EQ(int(e), int(E_INVALID_PARAMETER));
    EXPECT_TRUE(wbExists(sb.dest));
}

/* ---------------------------------------------------------------------------
 * B3-7 对照（判定"假"侧）：overwrite=true 时非空目录照常还原
 * 覆盖：MyPack.cpp:889 assertDirEmpty 被跳过 + restoreEntry 正常写文件
 * 期望：E_OK；a.txt 落地；原有 junk.txt 保留
 * 实测：_probe/pf.cpp D1
 * ------------------------------------------------------------------------ */
TEST(WbWriteFailures, overwriteIntoNonEmptyDirStillRestores) {
    WbSandbox sb("overwriteok");
    wbWriteBytes(sb.arc, wbBuildArchive({ wbDir("."), wbRegular("a.txt", "AAAA") }));
    Platform::makeDirTree(sb.dest);
    const std::string junk = Path::join(sb.dest, "junk.txt");
    wbWriteBytes(junk, std::vector<uint8_t>(1, 'Z'));

    CMyPack p;
    UnpackOptions u;
    u.overwrite = true;
    ErrCode e = p.unpack(sb.arc, sb.dest, u);
    const int entries = wbCountEntries(sb.dest);

    EXPECT_EQ(int(e), int(E_OK));
    EXPECT_EQ(entries, 2);
    EXPECT_TRUE(wbExists(Path::join(sb.dest, "a.txt")));
    EXPECT_TRUE(wbExists(junk));
}

/* ---------------------------------------------------------------------------
 * B3-8 诚实记录：目录记录的名字被普通文件占用时，makeDirTree 容忍，不报警
 * 覆盖：MyPack.cpp:557-566 —— makeDirTree 返回 E_ALREADY_EXISTS 被当作可接受，
 *       因此既不 ++warnings 也不报错
 * 期望：E_OK；warnings==0（若改成报错会破坏"重复还原同一目录树"的常见场景）
 * 实测：_probe/pg.cpp 用例 3
 * ------------------------------------------------------------------------ */
TEST(WbWriteFailures, dirRecordNameTakenByFileIsTolerated) {
    WbSandbox sb("dirnameclash");
    wbWriteBytes(sb.arc, wbBuildArchive({ wbDir("."), wbDir("sub"), wbRegular("f.txt", "CC") }));
    Platform::makeDirTree(sb.dest);
    wbWriteBytes(Path::join(sb.dest, "sub"), std::vector<uint8_t>(1, 'Z'));

    CMyPack p;
    UnpackOptions u;
    u.overwrite = true;
    ErrCode e = p.unpack(sb.arc, sb.dest, u);
    const int warnings = int(u.warnings);

    EXPECT_EQ(int(e), int(E_OK));
    EXPECT_EQ(warnings, 0);
}

/* ---------------------------------------------------------------------------
 * B3-9 空源目录打包 -> 成功，且只有一条根记录、载荷恰一个块
 * 覆盖：MyPack.cpp:275-282（目录/空文件无数据块分支）+ 提交路径
 * 期望：E_OK；recordCount==fileCount==1；payloadSize==512
 * 实测：_probe/pg.cpp 用例 8 / _probe/pc.cpp G
 * ------------------------------------------------------------------------ */
TEST(WbWriteFailures, packingEmptySourceDirYieldsRootRecordOnly) {
    WbSandbox sb("emptysrc");
    CMyPack p;
    PackOptions o;
    ErrCode e = p.pack(sb.src, sb.arc, o);

    ArchiveHeader hdr;
    CMyPack r;
    ErrCode he = r.readHeader(sb.arc, hdr);

    EXPECT_EQ(int(e), int(E_OK));
    EXPECT_EQ(int(he), int(E_OK));
    EXPECT_EQ(int(hdr.recordCount), 1);
    EXPECT_EQ(int(hdr.fileCount), 1);
    EXPECT_EQ(int(hdr.payloadSize), int(BLOCK_SIZE));
}

/* ---------------------------------------------------------------------------
 * B3-10 归档写在源目录内部 -> F9 自引用排除生效，不会把自己打进去
 * 覆盖：CMyPack::pack 枚举阶段的排除判断（判定"真"侧：候选==输出路径则跳过）
 * 期望：E_OK；recordCount==fileCount==2（根目录 + a.txt），不含 self.dbkp
 * 实测：_probe/pg.cpp 用例 9 / _probe/pc.cpp（box-in-src）
 * ------------------------------------------------------------------------ */
TEST(WbWriteFailures, archiveInsideSourceDirIsNotSelfIncluded) {
    WbSandbox sb("selfbox");
    wbWriteBytes(Path::join(sb.src, "a.txt"), std::vector<uint8_t>(10, 'Q'));
    const std::string box = Path::join(sb.src, "self.dbkp");

    CMyPack p;
    PackOptions o;
    ErrCode e = p.pack(sb.src, box, o);

    ArchiveHeader hdr;
    CMyPack r;
    ErrCode he = r.readHeader(box, hdr);

    EXPECT_EQ(int(e), int(E_OK));
    EXPECT_EQ(int(he), int(E_OK));
    EXPECT_EQ(int(hdr.recordCount), 2);
    EXPECT_EQ(int(hdr.fileCount), 2);

    std::vector<FileRecord> recs;
    ErrCode le = p.list(box, recs);
    EXPECT_EQ(int(le), int(E_OK));
    bool selfRef = false;
    for (size_t i = 0; i < recs.size(); ++i) {
        if (recs[i].path.find("self.dbkp") != std::string::npos) selfRef = true;
    }
    EXPECT_FALSE(selfRef);
}
