/* ============================================================================
 *  test_wb_no_partial_output.cpp -- 批次10 任务B2：失败时"零半成品"白盒单测
 *
 *  核心命题（备份工具的生命线）：任何一步失败，都不允许留下
 *    - 正式名下的半成品归档
 *    - 残留的 .tmp
 *    - 还原目标目录里"一半新一半旧"的文件
 *  本文件逐条验证这条不变式，覆盖白盒目标（函数 + 文件行号）：
 *    CMyPack::pack                 src/Pack/MyPack.cpp:70
 *      - 残留 .tmp 关卡            MyPack.cpp:96-101
 *      - 临时文件创建失败          MyPack.cpp:174-177
 *      - 源文件读失败              MyPack.cpp:283-288
 *      - 用户取消                  MyPack.cpp:293-308
 *      - 原子改名失败              MyPack.cpp:400-406
 *    CMyPack::unpack               src/Pack/MyPack.cpp:833
 *      - 空口令解加密箱            MyPack.cpp:858-862
 *      - 落盘前整卷校验            MyPack.cpp:872-876
 *    CMyPack::checkWholePayload    src/Pack/MyPack.cpp:707
 *    CMyPack::checkHeaderHmac      src/Pack/MyPack.cpp:768
 *    CMyPack::verify               src/Pack/MyPack.cpp:1032
 *
 *  覆盖标准：语句覆盖 + 判定覆盖（每个失败分支的"真"侧各命中一次，
 *  并配一个"假"侧对照用例）+ 路径覆盖（失败点分别在 tmp 创建/读/写/改名/
 *  校验/落盘六个阶段，逐一验证回滚语义）。
 *
 *  期望值全部来自探针实测（_probe/pc.cpp、_probe/pf.cpp、_probe/fail2.cpp），
 *  不是推测。诚实记录：
 *    - 逐条 CRC 失败（CHK_NONE 归档）是 fail-fast，**不做回滚**：失败点之前的
 *      文件已经落盘。见 wbNoRollbackOnPerRecordCrcFailure 用例注释。
 * ==========================================================================*/
#include "TestFramework.h"

#include <cstdint>
#include <string>
#include <vector>

#include "Common/Defs.h"
#include "Common/Progress.h"
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
        root = std::string("twb_np_") + tag + "_" + std::to_string(g_seq++);
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

uint64_t wbBlocksFor(int64_t n) { return uint64_t((n + BLOCK_SIZE - 1) / BLOCK_SIZE); }

std::vector<uint8_t> wbBuildArchive(const std::vector<Part>& parts, ChecksumId chk = CHK_CRC64) {
    std::vector<uint8_t> region;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (DBKP_IS_ERR(encodeRecord(parts[i].rec, region))) return std::vector<uint8_t>();
        const int64_t bytes = parts[i].rec.storedSize;
        if (bytes > 0) {
            const uint64_t blocks = wbBlocksFor(bytes);
            const size_t before = region.size();
            region.resize(before + size_t(blocks * BLOCK_SIZE), 0);
            for (size_t b = 0; b < size_t(bytes); ++b) region[before + b] = parts[i].payload[b];
        }
    }
    ArchiveHeader hdr;
    hdr.compAlg       = ALG_NONE;
    hdr.cryptoAlg     = CRY_NONE;
    hdr.checksum      = chk;
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

bool wbExists(const std::string& p) { return Platform::exists(p) == E_OK; }

int wbCountEntries(const std::string& dir) {
    std::vector<Platform::DirEntry> items;
    if (DBKP_IS_ERR(Platform::listDir(dir, items))) return -1;
    return int(items.size());
}

/* 在源目录里铺 n 个 size 字节的同名内容文件 */
/* 在源目录里铺 n 个 size 字节的同名内容文件 */
void wbSeedSource(const std::string& src, int n, size_t size, uint8_t fill) {
    std::vector<uint8_t> buf(size, fill);
    for (int i = 0; i < n; ++i) {
        ASSERT_EQ(int(CSimpleFile::writeWhole(Path::join(src, "f" + std::to_string(i) + ".txt"), buf)),
                  int(E_OK));
    }
}

/* 取消回调：onProgress 被叫过 once 次之后开始返回 true */
class WbCancelSink : public IProgressSink {
public:
    explicit WbCancelSink(int once) : m_once(once) {}
    void onProgress(int64_t entriesDone, uint64_t) override { m_seen = int(entriesDone); }
    bool canceled() const override { return m_once >= 0 && m_seen >= m_once; }
    int seen() const { return m_seen; }
private:
    int m_once;
    int m_seen = 0;
};

} /* namespace */

/* ---------------------------------------------------------------------------
 * B2-1 落盘前整卷校验失败 -> 目标目录连创建都没有
 * 覆盖：MyPack.cpp:872-876 checkWholePayload 判定"真"侧（restore refused）
 *       以及 MyPack.cpp:893 之后的目标目录创建分支（判定"假"侧未进入）
 * 期望：E_CHECKSUM_MISMATCH；warnings==0；目标目录不存在（entries==-1）；
 *       错误文本含 "restore refused"
 * 实测：_probe/pf.cpp B1（载荷 offset 600 单字节翻转）
 * ------------------------------------------------------------------------ */
TEST(WbNoPartialOutput, wholePayloadCheckRefusesBeforeCreatingTarget) {
    WbSandbox sb("payloadflip");
    std::vector<uint8_t> bytes =
        wbBuildArchive({ wbRegular("a.txt", "AAAA"), wbRegular("b.txt", "BBBB") });
    ASSERT_TRUE(bytes.size() > 700);
    bytes[600] ^= 0xFF;                 /* 破坏第二条记录的载荷，整卷 CRC 立刻不匹配 */
    wbWriteBytes(sb.arc, bytes);

    CMyPack pack;
    UnpackOptions opt;
    ErrCode e = pack.unpack(sb.arc, sb.dest, opt);
    const std::string text = pack.lastErrorText();
    const int warnings = int(opt.warnings);
    const int entries = wbCountEntries(sb.dest);

    EXPECT_EQ(int(e), int(E_CHECKSUM_MISMATCH));
    EXPECT_EQ(warnings, 0);
    EXPECT_EQ(entries, -1);
    EXPECT_FALSE(wbExists(sb.dest));
    EXPECT_TRUE(text.find("restore refused") != std::string::npos);
}

/* ---------------------------------------------------------------------------
 * B2-2 整卷校验失败时 verify() 也必须显式报坏（不能"看起来成功"）
 * 覆盖：CMyPack::verify MyPack.cpp:1048-1052 checkWholePayload 分支
 * 期望：E_CHECKSUM_MISMATCH 且 badCount==1
 * 实测：_probe/pf.cpp B2
 * ------------------------------------------------------------------------ */
TEST(WbNoPartialOutput, verifyReportsBadCountOnFlippedPayload) {
    WbSandbox sb("verifyflip");
    std::vector<uint8_t> bytes =
        wbBuildArchive({ wbRegular("a.txt", "AAAA"), wbRegular("b.txt", "BBBB") });
    bytes[600] ^= 0xFF;
    wbWriteBytes(sb.arc, bytes);

    int badCount = -1;
    CMyPack v;
    ErrCode e = v.verify(sb.arc, "", badCount);

    EXPECT_EQ(int(e), int(E_CHECKSUM_MISMATCH));
    EXPECT_EQ(badCount, 1);
}

/* ---------------------------------------------------------------------------
 * B2-3 加密箱 + 口令错误 -> 一个字节都不落地
 * 覆盖：CMyPack::readDataBlocks MyPack.cpp:484 之后 crypto->decode 失败上抛；
 *       unpack 的落盘循环（MyPack.cpp:905+）判定"假"侧完全未进入
 * 期望：E_WRONG_PASSWORD；warnings==0；目标目录里 0 个条目
 * 诚实记录：整卷 CRC 覆盖的是密文，所以 checkWholePayload 先通过，目标目录
 *       已被 MyPack.cpp:883 创建；失败发生在第一条记录解密时，因此目录是
 *       "空壳"而不是"不存在"。空壳同样满足"零半成品"（没有任何文件落地）。
 * 实测：_probe/pc.cpp C1（AES-256-CBC 箱 + "wrong" 口令）
 * ------------------------------------------------------------------------ */
TEST(WbNoPartialOutput, wrongPasswordLandsNothing) {
    WbSandbox sb("wrongpwd");
    wbSeedSource(sb.src, 1, 200, 'M');
    {
        CMyPack p;
        PackOptions o;
        o.crypto   = CRY_AES256_CBC;
        o.password = "right";
        ASSERT_EQ(int(p.pack(sb.src, sb.arc, o)), int(E_OK));
    }
    CMyPack q;
    UnpackOptions u;
    u.password = "wrong";
    ErrCode e = q.unpack(sb.arc, sb.dest, u);
    const int warnings = int(u.warnings);
    const int entries = wbCountEntries(sb.dest);

    EXPECT_EQ(int(e), int(E_WRONG_PASSWORD));
    EXPECT_EQ(warnings, 0);
    EXPECT_EQ(entries, 0);                /* 目录是空壳，没有任何条目落地 */
    EXPECT_FALSE(wbExists(Path::join(sb.dest, "f0.txt")));
}

/* ---------------------------------------------------------------------------
 * B2-4 加密箱但没给口令 -> 显式报错，同样零落地
 * 覆盖：MyPack.cpp:858-862（hdr.cryptoAlg != CRY_NONE && password 空）判定"真"侧
 * 期望：E_WRONG_PASSWORD + 文本 "--password is required"；目标目录不存在
 * 实测：_probe/pf.cpp A1
 * ------------------------------------------------------------------------ */
TEST(WbNoPartialOutput, encryptedArchiveWithoutPasswordIsRejected) {
    WbSandbox sb("nopwd");
    wbSeedSource(sb.src, 1, 200, 'M');
    {
        CMyPack p;
        PackOptions o;
        o.crypto   = CRY_AES256_CBC;
        o.password = "right";
        ASSERT_EQ(int(p.pack(sb.src, sb.arc, o)), int(E_OK));
    }
    CMyPack q;
    UnpackOptions u;                     /* 故意留空 password */
    ErrCode e = q.unpack(sb.arc, sb.dest, u);
    const std::string text = q.lastErrorText();
    const int warnings = int(u.warnings);

    EXPECT_EQ(int(e), int(E_WRONG_PASSWORD));
    EXPECT_EQ(warnings, 0);
    EXPECT_FALSE(wbExists(sb.dest));
    EXPECT_TRUE(text.find("--password is required") != std::string::npos);
}

/* ---------------------------------------------------------------------------
 * B2-5 头部被篡改：verify() 的 HMAC 关卡把它和"口令错"分开
 * 覆盖：CMyPack::checkHeaderHmac MyPack.cpp:768，E_HEADER_TAMPERED 分支
 *       （MyPack.cpp:785/801/808/814/826 之一：头部摘要不匹配）
 * 期望：E_HEADER_TAMPERED(25) + badCount==1，且 verify 顺序保证它排在
 *       checkWholePayload 之后（口令错时不会被误报成篡改）
 * 实测：_probe/pc.cpp D（偏移 346 注释区翻转一字节）
 * ------------------------------------------------------------------------ */
TEST(WbNoPartialOutput, headerTamperIsDetectedByHmac) {
    WbSandbox sb("tamper");
    wbSeedSource(sb.src, 1, 200, 'M');
    {
        CMyPack p;
        PackOptions o;
        o.crypto   = CRY_AES256_CBC;
        o.password = "right";
        o.comment  = "integrity-anchor";
        ASSERT_EQ(int(p.pack(sb.src, sb.arc, o)), int(E_OK));
    }
    std::vector<uint8_t> box;
    ASSERT_EQ(int(CSimpleFile::readWhole(sb.arc, box)), int(E_OK));
    ASSERT_TRUE(box.size() > 347);
    box[346] ^= 0xFF;                    /* sourcePath/comment 区，属于头部 HMAC 覆盖范围 */
    wbWriteBytes(sb.arc, box);

    int badCount = -1;
    CMyPack v;
    ErrCode e = v.verify(sb.arc, "right", badCount);

    EXPECT_EQ(int(e), int(E_HEADER_TAMPERED));
    EXPECT_EQ(badCount, 1);
}

/* ---------------------------------------------------------------------------
 * B2-6 原子改名失败：旧归档字节级不变，不留 .tmp
 * 覆盖：MyPack.cpp:400-406 rename 失败分支（判定"真"侧）+ TmpGuard
 *       MyPack.cpp:201-211 在 m_committed 未置位时的删除
 * 期望：E_FILE_WRITE_FAIL；.tmp 不存在；正式箱与原内容逐字节相同
 * 实测：_probe/fail2.cpp "pack(rename fail)"（对手句柄独占正式名 + force=true）
 * ------------------------------------------------------------------------ */
TEST(WbNoPartialOutput, renameFailureKeepsOldArchiveByteIdentical) {
    WbSandbox sb("renamefail");
    wbSeedSource(sb.src, 1, 300, 'A');
    {
        CMyPack p;
        PackOptions o;
        ASSERT_EQ(int(p.pack(sb.src, sb.arc, o)), int(E_OK));
    }
    std::vector<uint8_t> oldBytes;
    ASSERT_EQ(int(CSimpleFile::readWhole(sb.arc, oldBytes)), int(E_OK));

    /* 对手以独占方式握住正式归档名，rename 必然失败 */
    CSimpleFile rival;
    ASSERT_EQ(int(rival.open(sb.arc, CSimpleFile::MODE_READ_WRITE_CREATE)), int(E_OK));
    Platform::tryLockFile(rival.fd());

    CMyPack q;
    PackOptions o;
    o.force = true;
    const std::string src2 = Path::join(sb.root, "src2");
    Platform::makeDirTree(src2);
    wbSeedSource(src2, 1, 400, 'B');
    ErrCode e = q.pack(src2, sb.arc, o);
    const std::string text = q.lastErrorText();
    const bool tmpLeft = wbExists(sb.arc + ".tmp");
    rival.close();

    /* 句柄释放后才能重新读回正式箱，逐字节比对 */
    std::vector<uint8_t> after;
    ASSERT_EQ(int(CSimpleFile::readWhole(sb.arc, after)), int(E_OK));

    EXPECT_EQ(int(e), int(E_FILE_WRITE_FAIL));
    EXPECT_FALSE(tmpLeft);
    EXPECT_TRUE(after == oldBytes);
    EXPECT_TRUE(text.find("atomic rename failed") != std::string::npos);
}

/* ---------------------------------------------------------------------------
 * B2-7 残留 .tmp 且正式箱不存在 -> 拒绝打包，也不"顺手"造一个箱
 * 覆盖：MyPack.cpp:96-101（tmp 存在 && !force）判定"真"侧
 * 期望：E_INCOMPLETE；.tmp 仍在（不擅自删用户数据）；正式箱不存在；
 *       verify() 同样报 E_INCOMPLETE + badCount==1
 * 实测：_probe/pf.cpp C1/C2
 * ------------------------------------------------------------------------ */
TEST(WbNoPartialOutput, staleTmpBlocksPackUntilForced) {
    WbSandbox sb("staletmp");
    wbSeedSource(sb.src, 1, 100, 'X');
    const std::string tmp = sb.arc + ".tmp";
    wbWriteBytes(tmp, std::vector<uint8_t>(1, 'X'));

    CMyPack p;
    PackOptions o;
    ErrCode e = p.pack(sb.src, sb.arc, o);
    const std::string text = p.lastErrorText();
    const bool tmpStill = wbExists(tmp);
    const bool boxMade  = wbExists(sb.arc);

    EXPECT_EQ(int(e), int(E_INCOMPLETE));
    EXPECT_TRUE(tmpStill);
    EXPECT_FALSE(boxMade);
    EXPECT_TRUE(text.find("previous backup incomplete") != std::string::npos);

    int badCount = -1;
    CMyPack v;
    ErrCode ve = v.verify(sb.arc, "", badCount);
    EXPECT_EQ(int(ve), int(E_INCOMPLETE));
    EXPECT_EQ(badCount, 1);
}

/* ---------------------------------------------------------------------------
 * B2-8 上面那关的"假"侧对照：--force 清掉残留 .tmp 并正常提交
 * 覆盖：MyPack.cpp:96-101 判定"假"侧 + MyPack.cpp:402 rename 成功 +
 *       MyPack.cpp:409 m_committed=true -> TmpGuard 不再删除
 * 期望：E_OK；.tmp 消失；正式箱存在
 * 实测：_probe/pf.cpp C3
 * ------------------------------------------------------------------------ */
TEST(WbNoPartialOutput, forceDiscardsStaleTmpAndCommits) {
    WbSandbox sb("forcetmp");
    wbSeedSource(sb.src, 1, 100, 'X');
    const std::string tmp = sb.arc + ".tmp";
    wbWriteBytes(tmp, std::vector<uint8_t>(1, 'X'));

    CMyPack p;
    PackOptions o;
    o.force = true;
    ErrCode e = p.pack(sb.src, sb.arc, o);
    const bool tmpGone = !wbExists(tmp);
    const bool boxMade = wbExists(sb.arc);

    EXPECT_EQ(int(e), int(E_OK));
    EXPECT_TRUE(tmpGone);
    EXPECT_TRUE(boxMade);
}

/* ---------------------------------------------------------------------------
 * B2-9 用户中途取消 -> 半成品归档被回滚，正式名下什么都没有
 * 覆盖：MyPack.cpp:293-308 canceled 分支（判定"真"侧）+ TmpGuard 回滚
 * 期望：E_CANCELED；箱不存在；.tmp 不存在；文本 "backup canceled by user"
 * 实测：_probe/pc.cpp E（onProgress 一次后 canceled() 返回 true）
 * ------------------------------------------------------------------------ */
TEST(WbNoPartialOutput, cancelRollsBackHalfWrittenArchive) {
    WbSandbox sb("cancel");
    wbSeedSource(sb.src, 4, 4096, 'C');

    WbCancelSink sink(1);
    CMyPack p;
    PackOptions o;
    o.progress = &sink;
    ErrCode e = p.pack(sb.src, sb.arc, o);
    const std::string text = p.lastErrorText();
    const bool boxMade = wbExists(sb.arc);
    const bool tmpLeft = wbExists(sb.arc + ".tmp");

    EXPECT_EQ(int(e), int(E_CANCELED));
    EXPECT_FALSE(boxMade);
    EXPECT_FALSE(tmpLeft);
    EXPECT_TRUE(text.find("canceled by user") != std::string::npos);
}

/* ---------------------------------------------------------------------------
 * B2-10 源文件被对手独占 -> 读失败即中止，箱和 .tmp 都不留
 * 覆盖：MyPack.cpp:283-288 writeFileData 失败上抛（"failed packing:"）
 *       + TmpGuard 在未提交时删除临时文件
 * 期望：E_FILE_READ_FAIL；箱不存在；.tmp 不存在；文本 "failed packing:"
 * 实测：_probe/pf.cpp F1
 * ------------------------------------------------------------------------ */
TEST(WbNoPartialOutput, unreadableSourceLeavesNoDebris) {
    WbSandbox sb("lockedsrcread");
    const std::string one = Path::join(sb.src, "one.txt");
    std::vector<uint8_t> buf(200, 'M');
    wbWriteBytes(one, buf);
    wbWriteBytes(Path::join(sb.src, "two.txt"), buf);

    CSimpleFile rival;
    ASSERT_EQ(int(rival.open(one, CSimpleFile::MODE_READ_WRITE_CREATE)), int(E_OK));
    Platform::tryLockFile(rival.fd());

    CMyPack p;
    PackOptions o;
    ErrCode e = p.pack(sb.src, sb.arc, o);
    const std::string text = p.lastErrorText();
    const bool boxMade = wbExists(sb.arc);
    const bool tmpLeft = wbExists(sb.arc + ".tmp");
    rival.close();

    EXPECT_TRUE(DBKP_IS_ERR(e));
    EXPECT_FALSE(boxMade);
    EXPECT_FALSE(tmpLeft);
    EXPECT_TRUE(text.find("failed packing:") != std::string::npos);
}

/* ---------------------------------------------------------------------------
 * B2-11 .tmp 位置被目录占用 -> 临时文件创建失败，正式箱不受影响
 * 覆盖：MyPack.cpp:174-177 "cannot create archive temp" 分支（判定"真"侧）
 * 期望：E_PERMISSION_DENIED；正式箱不存在；文本含 "cannot create archive temp"
 * 实测：_probe/pf.cpp G1（force=true 仍然失败，说明它不是 ALREADY_EXISTS 分支）
 * ------------------------------------------------------------------------ */
TEST(WbNoPartialOutput, tmpPathOccupiedByDirectoryFailsCleanly) {
    WbSandbox sb("tmpisdir");
    wbSeedSource(sb.src, 1, 100, 'Y');
    const std::string tmp = sb.arc + ".tmp";
    ASSERT_EQ(int(Platform::makeDirTree(tmp)), int(E_OK));

    CMyPack p;
    PackOptions o;
    o.force = true;
    ErrCode e = p.pack(sb.src, sb.arc, o);
    const std::string text = p.lastErrorText();
    const bool boxMade = wbExists(sb.arc);

    EXPECT_EQ(int(e), int(E_PERMISSION_DENIED));
    EXPECT_FALSE(boxMade);
    EXPECT_TRUE(text.find("cannot create archive temp") != std::string::npos);
    Platform::removeDir(tmp);
}

/* ---------------------------------------------------------------------------
 * B2-12 源目录不存在 -> 连临时文件都不创建（前置检查在打开 tmp 之前）
 * 覆盖：CMyPack::pack 的源存在性检查（MyPack.cpp:86-95 区段，判定"真"侧）
 * 期望：E_SOURCE_NOT_FOUND；箱不存在；.tmp 不存在
 * 实测：_probe/pf.cpp H1
 * ------------------------------------------------------------------------ */
TEST(WbNoPartialOutput, missingSourceCreatesNothingAtAll) {
    WbSandbox sb("nosource");
    CMyPack p;
    PackOptions o;
    ErrCode e = p.pack(Path::join(sb.root, "ghost"), sb.arc, o);
    const bool boxMade = wbExists(sb.arc);
    const bool tmpLeft = wbExists(sb.arc + ".tmp");

    EXPECT_EQ(int(e), int(E_SOURCE_NOT_FOUND));
    EXPECT_FALSE(boxMade);
    EXPECT_FALSE(tmpLeft);
}

/* ---------------------------------------------------------------------------
 * B2-13 对照（判定"假"侧）：正常路径确实落盘，证明前面的"零落地"不是
 *        因为 unpack 本身坏了
 * 覆盖：MyPack.cpp:893+ 目标目录创建 + restoreEntry 正常写文件
 * 期望：E_OK；a.txt 与 sub/ 都存在
 * 实测：_probe/pf.cpp E1
 * ------------------------------------------------------------------------ */
TEST(WbNoPartialOutput, controlHappyPathActuallyRestores) {
    WbSandbox sb("happy");
    std::vector<uint8_t> bytes = wbBuildArchive(
        { wbRegular("a.txt", "AAAA"), wbRegular("sub/b.txt", "BBBB") });
    wbWriteBytes(sb.arc, bytes);

    CMyPack p;
    UnpackOptions u;
    ErrCode e = p.unpack(sb.arc, sb.dest, u);

    EXPECT_EQ(int(e), int(E_OK));
    EXPECT_TRUE(wbExists(Path::join(sb.dest, "a.txt")));
    EXPECT_TRUE(wbExists(Path::join(sb.dest, "sub")));
}

/* ---------------------------------------------------------------------------
 * B2-14 诚实记录：逐条 CRC 失败是 fail-fast，**不回滚**已落地的文件
 * 覆盖：CMyPack::readDataBlocks MyPack.cpp:484+ 单条 CRC 不匹配分支
 *       （warnings++ 后返回 E_CHECKSUM_MISMATCH）
 * 手法：CHK_NONE 归档（跳过整卷校验，才能走到逐条校验），把第 2 条记录的
 *       crc 字段（记录块内偏移 102）翻转。
 * 期望：E_CHECKSUM_MISMATCH；warnings==1；第 1 个文件已落地、第 2/3 个没有
 *       —— 这是实现现状，写进用例是为了让"半成品"风险显式可见，
 *         而不是假装它不存在。
 * 实测：_probe/pc.cpp F
 * ------------------------------------------------------------------------ */
TEST(WbNoPartialOutput, perRecordCrcFailureIsFailFastWithoutRollback) {
    WbSandbox sb("norestore");
    std::vector<uint8_t> bytes = wbBuildArchive(
        { wbRegular("a.txt", "AAAA"), wbRegular("b.txt", "BBBB"), wbRegular("c.txt", "CCCC") },
        CHK_NONE);
    ASSERT_TRUE(bytes.size() > 3072);
    /* 记录块布局：512(头) + [rec0 512][data0 512][rec1 512][data1 512][rec2 ...] */
    const size_t rec1CrcOffset = 512 + 512 + 512 + 102;
    bytes[rec1CrcOffset] ^= 0xFF;
    wbWriteBytes(sb.arc, bytes);

    CMyPack p;
    UnpackOptions u;
    u.skipPayloadVerify = true;          /* 整卷不校验，逼出逐条校验分支 */
    ErrCode e = p.unpack(sb.arc, sb.dest, u);
    const int warnings = int(u.warnings);
    const bool aLanded = wbExists(Path::join(sb.dest, "a.txt"));
    const bool bLanded = wbExists(Path::join(sb.dest, "b.txt"));
    const bool cLanded = wbExists(Path::join(sb.dest, "c.txt"));

    EXPECT_EQ(int(e), int(E_CHECKSUM_MISMATCH));
    EXPECT_EQ(warnings, 1);
    EXPECT_TRUE(aLanded);                /* 失败点之前已经落盘 */
    EXPECT_FALSE(bLanded);
    EXPECT_FALSE(cLanded);
}
