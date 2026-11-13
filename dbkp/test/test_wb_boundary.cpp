/* ============================================================================
 *  test_wb_boundary.cpp -- 批次10 任务B4：判定/条件组合 + 边界值白盒单测
 *
 *  白盒目标（函数 + 文件行号）：
 *    encodeArchiveHeader / decodeArchiveHeader  src/Common/Serialize.cpp:69 / :148
 *      - headerSize 自描述判定  Serialize.cpp:157-158（<512 或 %512!=0 -> E_INVALID_HEADER_RECORD）
 *      - srcLen/comLen 上界判定  Serialize.cpp:151（>256 / >166 -> E_INVALID_HEADER_RECORD）
 *      - 摘要块/HMAC 块幻数校验  Serialize.cpp:162 / :166
 *      - sourcePath(256)/comment(160) 静默截断  Serialize.cpp:100-103
 *    writeMainRecord / encodeRecord  src/Common/Serialize.cpp:175+
 *      - pathLen/linkLen 内联槽位溢出 -> FT_EXTEND 扩展记录（判定各侧）
 *      - path 绝对上界 65535/65536 -> E_PATH_TOO_LONG
 *    CMyPack::readHeader  src/Pack/MyPack.cpp（魔数/版本/算法合法性）
 *      - magic 错 1 字节 / 全错 / 旧版 "DBKP" 字面 -> E_INVALID_HEADER_RECORD
 *    FilterOptions::parseSize / parseTime  src/Enumerator/FilterOptions.cpp
 *    FilterOptions::setTypeSpec  src/Enumerator/FilterOptions.cpp（8 字符逐格映射）
 *    CMyPack::pack  maxDepth 边界（0/1/2/超大）
 *
 *  覆盖标准：判定覆盖 + 条件组合覆盖 + 边界值分析（每个阈值取其 -1/==/+1 三点，
 *  矩阵逐格独立 TEST，不合并成循环）。
 *
 *  期望值全部来自探针实测（_probe/pe.cpp、_probe/pd.cpp、_probe/ph.cpp）。
 *  诚实说明：parseTime 对 "2024-13-45"/"9999-99-99" 一类越界日期，底层 mktime
 *  会做规范化而非报错（实测 ok=1），本文件如实断言，不假装它被拒绝。
 * ==========================================================================*/
#include "TestFramework.h"

#include <cstdint>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

#include "Common/Defs.h"
#include "Common/Serialize.h"
#include "Enumerator/FilterOptions.h"
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
        root = std::string("twb_bd_") + tag + "_" + std::to_string(g_seq++);
        src  = Path::join(root, "src");
        arc  = Path::join(root, "box.dbkp");
        dest = Path::join(root, "out");
        wbRemoveTree(root);
        Platform::makeDirTree(src);
    }
    ~WbSandbox() { wbRemoveTree(root); }
};


int wbCountEntries(const std::string& dir) {
    std::vector<Platform::DirEntry> items;
    if (DBKP_IS_ERR(Platform::listDir(dir, items))) return -1;
    return int(items.size());
}

/* 用 CMyPack::pack 生成一个最小合法明文箱（供打补丁做 headerSize/魔数变体） */
void wbPackPlainBox(WbSandbox& sb) {
    CSimpleFile::writeWhole(Path::join(sb.src, "a.txt"), std::vector<uint8_t>(64, 'A'));
    CMyPack p;
    PackOptions o;
    ASSERT_EQ(int(p.pack(sb.src, sb.arc, o)), int(E_OK));
}

/* 编一条 FileRecord 并回读，返回落盘字节数（-1 表示编码失败） */
int64_t wbRoundTripRecord(const FileRecord& in, bool* sameOut) {
    std::vector<uint8_t> out;
    if (DBKP_IS_ERR(encodeRecord(in, out))) {
        if (sameOut) *sameOut = false;
        return -1;
    }
    FileRecord back;
    if (DBKP_IS_ERR(decodeRecordBlocks(out, back))) {
        if (sameOut) *sameOut = false;
        return -1;
    }
    if (sameOut) *sameOut = (back.path == in.path && back.link == in.link && back.type == in.type);
    return int64_t(out.size());
}

} /* namespace */

/* ==========================================================================
 * 一、headerSize 自描述：不同算法组合下卷标实际占块数（判定"真/假"两侧各命中）
 * ==========================================================================*/

/* B4-1 明文(CRC64) 箱 -> headerSize==512, payloadOffset==512（无扩展块分支）
 * 覆盖：Serialize.cpp:83-86 withDigest=false,withHmac=false 的 total=512
 *       MyPack readHeader 按 headerSize 判长（向后兼容旧格式）
 * 实测：_probe/pe.cpp hdr plain */
TEST(WbBoundary, plainBoxHeaderIsOneBlock) {
    WbSandbox sb("hdrplain");
    CSimpleFile::writeWhole(Path::join(sb.src, "a.txt"), std::vector<uint8_t>(100, 'A'));
    CMyPack p;
    PackOptions o;  /* 默认 CHK_CRC64 / CRY_NONE */
    ASSERT_EQ(int(p.pack(sb.src, sb.arc, o)), int(E_OK));
    ArchiveHeader h;
    ASSERT_EQ(int(p.readHeader(sb.arc, h)), int(E_OK));
    EXPECT_EQ(int(h.headerSize), int(BLOCK_SIZE));
    EXPECT_EQ(int(h.payloadOffset), int(BLOCK_SIZE));
}

/* B4-2 sha256 箱 -> headerSize==1024, payloadOffset==1024（withDigest 分支）
 * 覆盖：Serialize.cpp:83 withDigest=true 追加摘要块
 * 实测：_probe/pe.cpp hdr sha */
TEST(WbBoundary, sha256BoxHeaderIsTwoBlocks) {
    WbSandbox sb("hdrsha");
    CSimpleFile::writeWhole(Path::join(sb.src, "a.txt"), std::vector<uint8_t>(100, 'A'));
    CMyPack p;
    PackOptions o;
    o.checksum = CHK_SHA256;
    ASSERT_EQ(int(p.pack(sb.src, sb.arc, o)), int(E_OK));
    ArchiveHeader h;
    ASSERT_EQ(int(p.readHeader(sb.arc, h)), int(E_OK));
    EXPECT_EQ(int(h.headerSize), int(ARCHIVE_HEADER_EXT));
    EXPECT_EQ(int(h.payloadOffset), int(ARCHIVE_HEADER_EXT));
}

/* B4-3 AES 加密箱 -> headerSize==1024（基础头 + HMAC 块，withHmac 分支）
 * 覆盖：Serialize.cpp:84 withHmac=true（headerHmac 非空即预留块，不看 cryptoAlg）
 * 实测：_probe/pe.cpp hdr enc */
TEST(WbBoundary, encryptedBoxHeaderCarriesHmacBlock) {
    WbSandbox sb("hdrenc");
    CSimpleFile::writeWhole(Path::join(sb.src, "a.txt"), std::vector<uint8_t>(100, 'A'));
    CMyPack p;
    PackOptions o;
    o.crypto   = CRY_AES256_CBC;
    o.password = "pw";
    ASSERT_EQ(int(p.pack(sb.src, sb.arc, o)), int(E_OK));
    ArchiveHeader h;
    ASSERT_EQ(int(p.readHeader(sb.arc, h)), int(E_OK));
    EXPECT_EQ(int(h.headerSize), int(ARCHIVE_HEADER_EXT));
    EXPECT_EQ(int(h.payloadOffset), int(ARCHIVE_HEADER_EXT));
    EXPECT_EQ(int(h.headerHmac.size()), int(ARCHIVE_HEADER_HMAC_SIZE));
}

/* B4-4 sha256 + AES 双箱 -> headerSize==1536（三块：基础+摘要+HMAC）
 * 覆盖：Serialize.cpp:83-86 withDigest && withHmac 同时为真的组合格
 * 实测：_probe/pe.cpp hdr encsha */
TEST(WbBoundary, sha256PlusEncryptedHeaderIsThreeBlocks) {
    WbSandbox sb("hdrencsha");
    CSimpleFile::writeWhole(Path::join(sb.src, "a.txt"), std::vector<uint8_t>(100, 'A'));
    CMyPack p;
    PackOptions o;
    o.checksum = CHK_SHA256;
    o.crypto   = CRY_AES256_CBC;
    o.password = "pw";
    ASSERT_EQ(int(p.pack(sb.src, sb.arc, o)), int(E_OK));
    ArchiveHeader h;
    ASSERT_EQ(int(p.readHeader(sb.arc, h)), int(E_OK));
    EXPECT_EQ(int(h.headerSize), int(ARCHIVE_HEADER_EXT_HMAC));
    EXPECT_EQ(int(h.payloadOffset), int(ARCHIVE_HEADER_EXT_HMAC));
}

/* ==========================================================================
 * 二、headerSize 声明值边界（把合法箱的 headerSize 字段改成各种值 -> 判定覆盖）
 * ==========================================================================*/

/* B4-5 headerSize 非 512 倍数（513）-> E_INVALID_HEADER_RECORD
 * 覆盖：Serialize.cpp:157 (headerSize % BLOCK_SIZE)!=0 判定"真"侧
 * 实测：_probe/ph.cpp headerSize=513 */
TEST(WbBoundary, headerSizeNotMultipleOfBlockRejected) {
    WbSandbox sb("hs513");
    wbPackPlainBox(sb);
    std::vector<uint8_t> hb;
    ASSERT_EQ(int(CSimpleFile::readWhole(sb.arc, hb)), int(E_OK));
    const uint16_t v = 513;
    hb[6] = uint8_t(v & 0xFF);
    hb[7] = uint8_t((v >> 8) & 0xFF);
    ASSERT_EQ(int(CSimpleFile::writeWhole(sb.arc, hb)), int(E_OK));
    CMyPack r;
    ArchiveHeader h;
    EXPECT_EQ(int(r.readHeader(sb.arc, h)), int(E_INVALID_HEADER_RECORD));
}

/* B4-6 headerSize==0 -> E_INVALID_HEADER_RECORD（< BLOCK_SIZE 判定"真"侧）
 * 覆盖：Serialize.cpp:156 hdr.headerSize < BLOCK_SIZE
 * 实测：_probe/ph.cpp headerSize=0, _probe/pd.cpp 5f */
TEST(WbBoundary, headerSizeZeroRejected) {
    WbSandbox sb("hs0");
    wbPackPlainBox(sb);
    std::vector<uint8_t> hb;
    ASSERT_EQ(int(CSimpleFile::readWhole(sb.arc, hb)), int(E_OK));
    hb[6] = 0; hb[7] = 0;
    ASSERT_EQ(int(CSimpleFile::writeWhole(sb.arc, hb)), int(E_OK));
    CMyPack r;
    ArchiveHeader h;
    EXPECT_EQ(int(r.readHeader(sb.arc, h)), int(E_INVALID_HEADER_RECORD));
}

/* B4-7 明文箱谎称 headerSize==1024 -> 读取端把首个数据块当 HMAC 块，幻数不符报错
 * 覆盖：Serialize.cpp:166 readLE32(h)!=ARCHIVE_HEADER_HMAC_TAG 判定"真"侧
 * 实测：_probe/ph.cpp headerSize=1024 (read=invalid header record) */
TEST(WbBoundary, plainBoxClaimingExtendedHeaderRejected) {
    WbSandbox sb("hs1024");
    wbPackPlainBox(sb);
    std::vector<uint8_t> hb;
    ASSERT_EQ(int(CSimpleFile::readWhole(sb.arc, hb)), int(E_OK));
    const uint16_t v = 1024;
    hb[6] = uint8_t(v & 0xFF);
    hb[7] = uint8_t((v >> 8) & 0xFF);
    ASSERT_EQ(int(CSimpleFile::writeWhole(sb.arc, hb)), int(E_OK));
    CMyPack r;
    ArchiveHeader h;
    EXPECT_EQ(int(r.readHeader(sb.arc, h)), int(E_INVALID_HEADER_RECORD));
}

/* ==========================================================================
 * 三、srcLen/comLen 上界 + 静默截断（条件组合）
 * ==========================================================================*/

/* B4-8 srcLen 越界（>256）-> E_INVALID_HEADER_RECORD
 * 覆盖：Serialize.cpp:151 srcLen > 256 判定"真"侧
 * 实测：_probe/pd.cpp 5g (srcLen=1023) */
TEST(WbBoundary, sourceLengthFieldOverCapRejected) {
    WbSandbox sb("srclen");
    wbPackPlainBox(sb);
    std::vector<uint8_t> hb;
    ASSERT_EQ(int(CSimpleFile::readWhole(sb.arc, hb)), int(E_OK));
    hb[86] = 255; hb[87] = 3;   /* LE = 3*256+255 = 1023 */
    ASSERT_EQ(int(CSimpleFile::writeWhole(sb.arc, hb)), int(E_OK));
    CMyPack r;
    ArchiveHeader h;
    EXPECT_EQ(int(r.readHeader(sb.arc, h)), int(E_INVALID_HEADER_RECORD));
}

/* B4-9 comLen 越界（>166）-> E_INVALID_HEADER_RECORD
 * 覆盖：Serialize.cpp:151 comLen > 166 判定"真"侧
 * 实测：_probe/pd.cpp 5h (comLen=200) */
TEST(WbBoundary, commentLengthFieldOverCapRejected) {
    WbSandbox sb("comlen");
    wbPackPlainBox(sb);
    std::vector<uint8_t> hb;
    ASSERT_EQ(int(CSimpleFile::readWhole(sb.arc, hb)), int(E_OK));
    hb[88] = 200; hb[89] = 0;
    ASSERT_EQ(int(CSimpleFile::writeWhole(sb.arc, hb)), int(E_OK));
    CMyPack r;
    ArchiveHeader h;
    EXPECT_EQ(int(r.readHeader(sb.arc, h)), int(E_INVALID_HEADER_RECORD));
}

/* B4-10 超长 sourcePath(300)/comment(300) 编码时被静默截断到 256/160
 * 覆盖：Serialize.cpp:100-103 三目取 min 的"截断"分支
 * 实测：_probe/pd.cpp #8 (size=512 src=256 com=160)
 * 诚实说明：这是"信息字段"的既定行为，不报错，只截断 */
TEST(WbBoundary, longSourceAndCommentAreSilentlyTruncated) {
    ArchiveHeader h;
    h.sourcePath = std::string(300, 'S');
    h.comment    = std::string(300, 'C');
    std::vector<uint8_t> out;
    ASSERT_EQ(int(encodeArchiveHeader(h, out)), int(E_OK));
    EXPECT_EQ(int(out.size()), int(BLOCK_SIZE));
    ArchiveHeader d;
    ASSERT_EQ(int(decodeArchiveHeader(out.data(), d, nullptr)), int(E_OK));
    EXPECT_EQ(int(d.sourcePath.size()), 256);
    EXPECT_EQ(int(d.comment.size()), 160);
}

/* ==========================================================================
 * 四、魔数变体（错 1 字节 / 全错 / 旧版 "DBKP" 字面）
 * ==========================================================================*/

/* B4-11 魔数错 1 字节 -> E_INVALID_HEADER_RECORD，且 unpack 不创建目标目录
 * 覆盖：Serialize.cpp:149 readLE32(in512)!=ARCHIVE_MAGIC 判定"真"侧
 * 实测：_probe/pd.cpp 6b (read=invalid, unpack dst=-1) */
TEST(WbBoundary, magicOneByteFlipRejectedAndNoTarget) {
    WbSandbox sb("magic1");
    wbPackPlainBox(sb);
    std::vector<uint8_t> hb;
    ASSERT_EQ(int(CSimpleFile::readWhole(sb.arc, hb)), int(E_OK));
    hb[0] ^= 0x01;
    ASSERT_EQ(int(CSimpleFile::writeWhole(sb.arc, hb)), int(E_OK));
    CMyPack r;
    ArchiveHeader h;
    EXPECT_EQ(int(r.readHeader(sb.arc, h)), int(E_INVALID_HEADER_RECORD));
    UnpackOptions u;
    const std::string dst = Path::join(sb.root, "out");
    EXPECT_EQ(int(r.unpack(sb.arc, dst, u)), int(E_INVALID_HEADER_RECORD));
    EXPECT_EQ(wbCountEntries(dst), -1);
}

/* B4-12 全非魔数（2048 个 'z'）-> E_INVALID_HEADER_RECORD
 * 覆盖：同 readLE32!=ARCHIVE_MAGIC，另一"全错"输入格
 * 实测：_probe/pd.cpp 6c */
TEST(WbBoundary, allWrongMagicRejected) {
    WbSandbox sb("notarchive");
    const std::string f = Path::join(sb.root, "junk.dbkp");
    CSimpleFile::writeWhole(f, std::vector<uint8_t>(2048, 'z'));
    CMyPack r;
    ArchiveHeader h;
    EXPECT_EQ(int(r.readHeader(f, h)), int(E_INVALID_HEADER_RECORD));
}

/* B4-13 旧版 "DBKP" 大端字面 -> 与本机小端 ARCHIVE_MAGIC 不符 -> 拒绝
 * 覆盖：条件组合（magic 字段字节序），对应规格"旧版 magic"格
 * 实测：_probe/pd.cpp 6d (old-style magic = invalid header record) */
TEST(WbBoundary, bigEndianMagicLiteralRejected) {
    WbSandbox sb("oldmagic");
    wbPackPlainBox(sb);
    std::vector<uint8_t> hb;
    ASSERT_EQ(int(CSimpleFile::readWhole(sb.arc, hb)), int(E_OK));
    hb[0] = 'D'; hb[1] = 'B'; hb[2] = 'K'; hb[3] = 'P';
    ASSERT_EQ(int(CSimpleFile::writeWhole(sb.arc, hb)), int(E_OK));
    CMyPack r;
    ArchiveHeader h;
    EXPECT_EQ(int(r.readHeader(sb.arc, h)), int(E_INVALID_HEADER_RECORD));
}

/* ==========================================================================
 * 五、encodeRecord：path/link 内联槽位边界（矩阵逐格，边界值 -1/==/+1）
 *   REC_INLINE_PATH=160, REC_INLINE_LINK=96, REC_EXTEND_PAYLOAD=398
 * ==========================================================================*/

/* B4-14 path=254 -> 2 块(1024B)，回读逐字节一致（内联满 + 首块溢出）
 * 覆盖：writeMainRecord pathLen 内联槽位裁切，触发 FT_EXTEND 判定"真"侧
 * 实测：_probe/pe.cpp path=254 bytes=1024 same=1 */
TEST(WbBoundary, recordPath254UsesExtendBlock) {
    FileRecord r;
    r.type = FT_REGULAR;
    r.path = std::string(254, 'p');
    bool same = false;
    const int64_t bytes = wbRoundTripRecord(r, &same);
    EXPECT_EQ(int(bytes), 1024);
    EXPECT_TRUE(same);
}

/* B4-15 path=255 -> 1024B（边界 +1）
 * 实测：_probe/pe.cpp path=255 bytes=1024 same=1 */
TEST(WbBoundary, recordPath255UsesExtendBlock) {
    FileRecord r;
    r.type = FT_REGULAR;
    r.path = std::string(255, 'p');
    bool same = false;
    const int64_t bytes = wbRoundTripRecord(r, &same);
    EXPECT_EQ(int(bytes), 1024);
    EXPECT_TRUE(same);
}

/* B4-16 path=257 -> 1024B（跨入第二扩展区间前的判定）
 * 实测：_probe/pe.cpp path=257 bytes=1024 same=1 */
TEST(WbBoundary, recordPath257UsesExtendBlock) {
    FileRecord r;
    r.type = FT_REGULAR;
    r.path = std::string(257, 'p');
    bool same = false;
    const int64_t bytes = wbRoundTripRecord(r, &same);
    EXPECT_EQ(int(bytes), 1024);
    EXPECT_TRUE(same);
}

/* B4-17 path=650 -> 1536B（第二块扩展记录，判定进入第 2 个 X 块）
 * 实测：_probe/pe.cpp path=650 bytes=1536 same=1 */
TEST(WbBoundary, recordPath650UsesTwoExtendBlocks) {
    FileRecord r;
    r.type = FT_REGULAR;
    r.path = std::string(650, 'p');
    bool same = false;
    const int64_t bytes = wbRoundTripRecord(r, &same);
    EXPECT_EQ(int(bytes), 1536);
    EXPECT_TRUE(same);
}

/* B4-18 path=651 -> 1536B（650 的 +1 邻格）
 * 实测：_probe/pe.cpp path=651 bytes=1536 same=1 */
TEST(WbBoundary, recordPath651UsesTwoExtendBlocks) {
    FileRecord r;
    r.type = FT_REGULAR;
    r.path = std::string(651, 'p');
    bool same = false;
    const int64_t bytes = wbRoundTripRecord(r, &same);
    EXPECT_EQ(int(bytes), 1536);
    EXPECT_TRUE(same);
}

/* B4-19 path=1049 -> 2048B（第三块扩展记录，边界 -1）
 * 实测：_probe/pe.cpp path=1049 bytes=2048 same=1 */
TEST(WbBoundary, recordPath1049UsesThreeExtendBlocks) {
    FileRecord r;
    r.type = FT_REGULAR;
    r.path = std::string(1049, 'p');
    bool same = false;
    const int64_t bytes = wbRoundTripRecord(r, &same);
    EXPECT_EQ(int(bytes), 2048);
    EXPECT_TRUE(same);
}

/* B4-20 path=1050 -> 2048B（1049 的 +1 邻格）
 * 实测：_probe/pe.cpp path=1050 bytes=2048 same=1 */
TEST(WbBoundary, recordPath1050UsesThreeExtendBlocks) {
    FileRecord r;
    r.type = FT_REGULAR;
    r.path = std::string(1050, 'p');
    bool same = false;
    const int64_t bytes = wbRoundTripRecord(r, &same);
    EXPECT_EQ(int(bytes), 2048);
    EXPECT_TRUE(same);
}

/* B4-21 link=159/160/161 三格 -> 均 1024B（link 内联槽位 REC_INLINE_LINK=96，
 *      超出后与 path 共用扩展区，边界值命中）
 * 实测：_probe/pe.cpp link=159/160/161 bytes=1024 same=1 */
TEST(WbBoundary, recordLink159FitsInExtend) {
    FileRecord r;
    r.type = FT_SYMLINK;
    r.path = "l";
    r.link = std::string(159, 'q');
    bool same = false;
    EXPECT_EQ(int(wbRoundTripRecord(r, &same)), 1024);
    EXPECT_TRUE(same);
}

TEST(WbBoundary, recordLink160FitsInExtend) {
    FileRecord r;
    r.type = FT_SYMLINK;
    r.path = "l";
    r.link = std::string(160, 'q');
    bool same = false;
    EXPECT_EQ(int(wbRoundTripRecord(r, &same)), 1024);
    EXPECT_TRUE(same);
}

TEST(WbBoundary, recordLink161FitsInExtend) {
    FileRecord r;
    r.type = FT_SYMLINK;
    r.path = "l";
    r.link = std::string(161, 'q');
    bool same = false;
    EXPECT_EQ(int(wbRoundTripRecord(r, &same)), 1024);
    EXPECT_TRUE(same);
}

/* B4-22 link=398/399 两格（REC_EXTEND_PAYLOAD 边界）-> 1024B
 * 实测：_probe/pe.cpp link=398/399 bytes=1024 same=1 */
TEST(WbBoundary, recordLink398AtExtendPayloadBoundary) {
    FileRecord r;
    r.type = FT_SYMLINK;
    r.path = "l";
    r.link = std::string(398, 'q');
    bool same = false;
    EXPECT_EQ(int(wbRoundTripRecord(r, &same)), 1024);
    EXPECT_TRUE(same);
}

TEST(WbBoundary, recordLink399PastExtendPayloadBoundary) {
    FileRecord r;
    r.type = FT_SYMLINK;
    r.path = "l";
    r.link = std::string(399, 'q');
    bool same = false;
    EXPECT_EQ(int(wbRoundTripRecord(r, &same)), 1024);
    EXPECT_TRUE(same);
}

/* B4-23 path=65535（uint16_t 上界）-> E_OK
 * 覆盖：pathLen 字段能表示的最大值仍在扩展区可容纳范围
 * 实测：_probe/pd.cpp 7g 及 pe 序列 path=65535 enc=success */
TEST(WbBoundary, recordPathMaxUint16Encodes) {
    FileRecord r;
    r.type = FT_REGULAR;
    r.path = std::string(65535, 'p');
    std::vector<uint8_t> out;
    EXPECT_EQ(int(encodeRecord(r, out)), int(E_OK));
}

/* B4-24 path=65536（超 uint16_t 上界）-> E_PATH_TOO_LONG
 * 覆盖：encodeRecord pathLen 溢出判定"真"侧
 * 实测：_probe/pe.cpp path=65536 enc=path too long */
TEST(WbBoundary, recordPathOverMaxUint16Rejected) {
    FileRecord r;
    r.type = FT_REGULAR;
    r.path = std::string(65536, 'p');
    std::vector<uint8_t> out;
    EXPECT_EQ(int(encodeRecord(r, out)), int(E_PATH_TOO_LONG));
}

/* ==========================================================================
 * 六、FilterOptions::parseSize 边界值矩阵（逐格独立 TEST）
 * ==========================================================================*/

/* B4-25 空串 -> -1, ok=false（无输入判定"真"侧）
 * 实测：_probe/pe.cpp size '' -> -1 ok=0 */
TEST(WbBoundary, parseSizeEmptyIsFailure) {
    bool ok = true;
    EXPECT_EQ(int(FilterOptions::parseSize("", &ok)), int(-1));
    EXPECT_FALSE(ok);
}

/* B4-26 纯数字 "4096" -> 4096, ok=true（无单位分支）
 * 实测：_probe/pe.cpp size '4096' -> 4096 ok=1 */
TEST(WbBoundary, parseSizePlainBytes) {
    bool ok = false;
    EXPECT_EQ(int64_t(FilterOptions::parseSize("4096", &ok)), int64_t(4096));
    EXPECT_TRUE(ok);
}

/* B4-27 "10KB" 与 "10K" 同值 10240（单位大小写/多字母）
 * 实测：_probe/pe.cpp size '10KB'/'10K' -> 10240 ok=1 */
TEST(WbBoundary, parseSizeKiloBothSpellings) {
    bool ok1 = false, ok2 = false;
    const int64_t a = FilterOptions::parseSize("10KB", &ok1);
    const int64_t b = FilterOptions::parseSize("10K", &ok2);
    EXPECT_EQ(int64_t(a), int64_t(10240));
    EXPECT_EQ(int64_t(b), int64_t(10240));
    EXPECT_TRUE(ok1);
    EXPECT_TRUE(ok2);
}

/* B4-28 小数 "1.5M" -> 1572864（小数×单位组合格）
 * 实测：_probe/pe.cpp size '1.5M' -> 1572864 ok=1 */
TEST(WbBoundary, parseSizeFractionalMega) {
    bool ok = false;
    EXPECT_EQ(int64_t(FilterOptions::parseSize("1.5M", &ok)), int64_t(1572864));
    EXPECT_TRUE(ok);
}

/* B4-29 "1G"/"7T" 大单位（G=2^30, T=2^40）
 * 实测：_probe/pe.cpp size '1G'->1073741824, '7T'->7696581394432 */
TEST(WbBoundary, parseSizeGigaAndTera) {
    bool ok1 = false, ok2 = false;
    EXPECT_EQ(int64_t(FilterOptions::parseSize("1G", &ok1)), int64_t(1073741824));
    EXPECT_EQ(int64_t(FilterOptions::parseSize("7T", &ok2)), int64_t(7696581394432));
    EXPECT_TRUE(ok1);
    EXPECT_TRUE(ok2);
}

/* B4-30 非法单位 "10X" / 纯字母 "b" -> -1, ok=false（尾字符判定"真"侧）
 * 实测：_probe/pe.cpp size '10X'->-1 ok=0, 'b'->-1 ok=0 */
TEST(WbBoundary, parseSizeUnknownUnitFails) {
    bool ok1 = true, ok2 = true;
    EXPECT_EQ(int64_t(FilterOptions::parseSize("10X", &ok1)), int64_t(-1));
    EXPECT_FALSE(ok1);
    EXPECT_EQ(int64_t(FilterOptions::parseSize("b", &ok2)), int64_t(-1));
    EXPECT_FALSE(ok2);
}

/* B4-31 "0" -> 0, ok=true（零值边界，非失败）
 * 实测：_probe/pe.cpp size '0' -> 0 ok=1 */
TEST(WbBoundary, parseSizeZeroIsSuccess) {
    bool ok = false;
    EXPECT_EQ(int64_t(FilterOptions::parseSize("0", &ok)), int64_t(0));
    EXPECT_TRUE(ok);
}

/* B4-32 溢出："99999999999999999999" 超过 int64 -> 回绕为 LLONG_MIN 且实现仍报 ok=1
 * 诚实说明：这是实现的既定行为（无溢出检测），如实记录，不假装拒绝
 * 实测：_probe/ph.cpp size '99999999999999999999' -> -9223372036854775808 ok=1 */
TEST(WbBoundary, parseSizeOverflowWrapsHonestly) {
    bool ok = false;
    const int64_t v = FilterOptions::parseSize("99999999999999999999", &ok);
    EXPECT_EQ(int64_t(v), int64_t((-9223372036854775807LL - 1)));
    EXPECT_TRUE(ok);   /* 实测 ok=1：实现未做溢出校验，作为已知缺口记入 doc/05 */
}

/* ==========================================================================
 * 七、FilterOptions::parseTime 条件组合（逐格独立 TEST）
 * ==========================================================================*/

/* B4-33 空串 -> 0, ok=false
 * 实测：_probe/pe.cpp time '' -> 0 ok=0 */
TEST(WbBoundary, parseTimeEmptyIsFailure) {
    bool ok = true;
    EXPECT_EQ(int64_t(FilterOptions::parseTime("", &ok)), int64_t(0));
    EXPECT_FALSE(ok);
}

/* B4-34 相对时间 7d/12h/30m/45s 全部 ok=true 且落在"过去"（now-delta，最近 N）
 * 覆盖：相对单位分支 d/h/m/s（4 条件格，实测值随运行时刻变化，只断言单调与量级）
 * 实测：_probe/pe.cpp time '7d'/'12h'/'30m'/'45s' ok=1，且 7d<12h<30m<45s<now */
TEST(WbBoundary, parseTimeRelativeUnitsAllAccepted) {
    bool ok = false;
    const int64_t now = int64_t(std::time(nullptr));
    const int64_t d = FilterOptions::parseTime("7d", &ok);
    EXPECT_TRUE(ok);
    EXPECT_LT(d, now);   /* 最近 7 天 => now-7*86400 */

    bool o1 = false, o2 = false, o3 = false;
    const int64_t h = FilterOptions::parseTime("12h", &o1);
    const int64_t m = FilterOptions::parseTime("30m", &o2);
    const int64_t s = FilterOptions::parseTime("45s", &o3);
    EXPECT_TRUE(o1 && o2 && o3);
    EXPECT_LT(d, h);     /* 越久远的时间戳越小 */
    EXPECT_LT(h, m);
    EXPECT_LT(m, s);
    EXPECT_LT(s, now);
}

/* B4-35 绝对日期三种写法都归一到同一 epoch 1704081600（2024-01-01 本地 0 点）
 * 覆盖：日期格式 T/空格分隔 与 纯日期 的组合格
 * 实测：_probe/pe.cpp '2024-01-01'/'2024-01-01T12:00:00'/'2024-01-01 12:00:00' -> 1704081600 */
TEST(WbBoundary, parseTimeAbsoluteFormatsNormalize) {
    bool o1 = false, o2 = false, o3 = false;
    const int64_t a = FilterOptions::parseTime("2024-01-01", &o1);
    const int64_t b = FilterOptions::parseTime("2024-01-01T12:00:00", &o2);
    const int64_t c = FilterOptions::parseTime("2024-01-01 12:00:00", &o3);
    EXPECT_EQ(int64_t(a), int64_t(1704081600));
    EXPECT_EQ(int64_t(b), int64_t(1704081600));
    EXPECT_EQ(int64_t(c), int64_t(1704081600));
    EXPECT_TRUE(o1 && o2 && o3);
}

/* B4-36 非法串 "abc" -> 0, ok=false（解析失败判定"真"侧）
 * 实测：_probe/pe.cpp time 'abc' -> 0 ok=0 */
TEST(WbBoundary, parseTimeGarbageFails) {
    bool ok = true;
    EXPECT_EQ(int64_t(FilterOptions::parseTime("abc", &ok)), int64_t(0));
    EXPECT_FALSE(ok);
}

/* B4-37 越界日期 "2024-13-45"：mktime 规范化后仍 ok=1（诚实缺口）
 * 覆盖：月/日越界 -> 底层归一，实现不报错。规格"非法日期"格实测为"接受"
 * 实测：_probe/pe.cpp time '2024-13-45' -> 1739505600 ok=1 */
TEST(WbBoundary, parseTimeOutOfRangeDateIsNormalizedNotRejected) {
    bool ok = false;
    const int64_t v = FilterOptions::parseTime("2024-13-45", &ok);
    EXPECT_TRUE(ok);        /* 实测 ok=1 */
    EXPECT_GT(v, int64_t(0));
    /* 作为已知缺口如实记录：越界月日未被视为错误 */
}

/* ==========================================================================
 * 八、setTypeSpec 字母映射 8 字符逐格（规格明确要求 8 个独立 TEST）
 *   r->'-'  d->'D'  l->'L'  h->'H'  f->'F'  b->'B'  c->'C'  s->'S'
 * ==========================================================================*/

TEST(WbBoundary, typeLetterRMapsToRegular) {
    FilterOptions f;
    ASSERT_TRUE(f.setTypeSpec("r"));
    ASSERT_EQ(int(f.typeAllow.size()), 1);
    EXPECT_EQ(int(f.typeAllow[0]), int(FT_REGULAR));
}

TEST(WbBoundary, typeLetterDMapsToDir) {
    FilterOptions f;
    ASSERT_TRUE(f.setTypeSpec("d"));
    ASSERT_EQ(int(f.typeAllow.size()), 1);
    EXPECT_EQ(int(f.typeAllow[0]), int(FT_DIR));
}

TEST(WbBoundary, typeLetterLMapsToSymlink) {
    FilterOptions f;
    ASSERT_TRUE(f.setTypeSpec("l"));
    ASSERT_EQ(int(f.typeAllow.size()), 1);
    EXPECT_EQ(int(f.typeAllow[0]), int(FT_SYMLINK));
}

TEST(WbBoundary, typeLetterHMapsToHardlink) {
    FilterOptions f;
    ASSERT_TRUE(f.setTypeSpec("h"));
    ASSERT_EQ(int(f.typeAllow.size()), 1);
    EXPECT_EQ(int(f.typeAllow[0]), int(FT_HARDLINK));
}

TEST(WbBoundary, typeLetterFMapsToFifo) {
    FilterOptions f;
    ASSERT_TRUE(f.setTypeSpec("f"));
    ASSERT_EQ(int(f.typeAllow.size()), 1);
    EXPECT_EQ(int(f.typeAllow[0]), int(FT_FIFO));
}

TEST(WbBoundary, typeLetterBMapsToBlock) {
    FilterOptions f;
    ASSERT_TRUE(f.setTypeSpec("b"));
    ASSERT_EQ(int(f.typeAllow.size()), 1);
    EXPECT_EQ(int(f.typeAllow[0]), int(FT_BLOCK));
}

TEST(WbBoundary, typeLetterCMapsToChar) {
    FilterOptions f;
    ASSERT_TRUE(f.setTypeSpec("c"));
    ASSERT_EQ(int(f.typeAllow.size()), 1);
    EXPECT_EQ(int(f.typeAllow[0]), int(FT_CHAR));
}

TEST(WbBoundary, typeLetterSMapsToSocket) {
    FilterOptions f;
    ASSERT_TRUE(f.setTypeSpec("s"));
    ASSERT_EQ(int(f.typeAllow.size()), 1);
    EXPECT_EQ(int(f.typeAllow[0]), int(FT_SOCKET));
}

/* B4-38 前缀 +/- 语义：'-dl' -> deny "DL"，'+r' -> allow '-'（判定两侧对照）
 * 实测：_probe/pe.cpp '-dl' ok=1 deny='DL'; '+r' ok=1 allow='-' */
TEST(WbBoundary, typeSpecDenyAndAllowPrefixes) {
    FilterOptions deny;
    ASSERT_TRUE(deny.setTypeSpec("-dl"));
    std::string d;
    for (size_t i = 0; i < deny.typeDeny.size(); ++i) d += deny.typeDeny[i];
    EXPECT_EQ(d, std::string("DL"));
    EXPECT_EQ(int(deny.typeAllow.size()), 0);

    FilterOptions allow;
    ASSERT_TRUE(allow.setTypeSpec("+r"));
    ASSERT_EQ(int(allow.typeAllow.size()), 1);
    EXPECT_EQ(int(allow.typeAllow[0]), int(FT_REGULAR));
}

/* B4-39 空/仅符号 ""/"-"/"+" -> ok=false（无有效 token 判定"真"侧）
 * 实测：_probe/pe.cpp type ''/'-'/'+' -> ok=0 */
TEST(WbBoundary, typeSpecEmptyOrSymbolOnlyFails) {
    FilterOptions f1, f2, f3;
    EXPECT_FALSE(f1.setTypeSpec(""));
    EXPECT_FALSE(f2.setTypeSpec("-"));
    EXPECT_FALSE(f3.setTypeSpec("+"));
}

/* B4-40 未知字母 "zz"/"x" -> ok=false + lastError 记录原因
 * 覆盖：setTypeSpec 未知 token 拒绝分支（旧版只告警静默忽略，现已修复）
 * 实测：_probe/pe.cpp type 'zz'/'x' -> ok=0 err='unknown file type: ...' */
TEST(WbBoundary, typeSpecUnknownLetterFailsWithError) {
    FilterOptions f;
    EXPECT_FALSE(f.setTypeSpec("zz"));
    EXPECT_TRUE(f.lastError.find("unknown file type") != std::string::npos);
    FilterOptions g;
    EXPECT_FALSE(g.setTypeSpec("x"));
    EXPECT_TRUE(g.lastError.find("unknown file type") != std::string::npos);
}

/* ==========================================================================
 * 九、maxDepth 边界（0/1/2/超大；对应用例规格"目录深度边界"）
 *   深树：deep/{top.txt, l1/, l1/l2/, l1/l2/f.txt, l1/l2/l3/, ...} 共 6 条
 * ==========================================================================*/

/* B4-41 maxDepth=-1 不限 -> 6 条；maxDepth=99 超大 -> 同样 6 条（对照）
 * 覆盖：passTraversal 深度判定"不限"与"足够大"两侧
 * 实测：_probe/pe.cpp maxDepth=-1 recs=6, maxDepth=99 recs=6 */
TEST(WbBoundary, maxDepthUnlimitedAndHugeBothFull) {
    WbSandbox sb("depthfull");
    const std::string d3 = Path::join(sb.src, "deep");
    Platform::makeDirTree(Path::join(Path::join(Path::join(d3, "l1"), "l2"), "l3"));
    CSimpleFile::writeWhole(Path::join(Path::join(Path::join(d3, "l1"), "l2"), "f.txt"),
                            std::vector<uint8_t>(100, 'A'));
    CSimpleFile::writeWhole(Path::join(d3, "top.txt"), std::vector<uint8_t>(100, 'A'));

    CMyPack p;
    ArchiveHeader h;
    { PackOptions o; o.filter.maxDepth = -1;
      const std::string arc = Path::join(sb.root, "md-1.dbkp");
      ASSERT_EQ(int(p.pack(d3, arc, o)), int(E_OK));
      ASSERT_EQ(int(p.readHeader(arc, h)), int(E_OK));
      EXPECT_EQ(int(h.recordCount), 6); }
    { PackOptions o; o.filter.maxDepth = 99;
      const std::string arc = Path::join(sb.root, "md99.dbkp");
      ASSERT_EQ(int(p.pack(d3, arc, o)), int(E_OK));
      ASSERT_EQ(int(p.readHeader(arc, h)), int(E_OK));
      EXPECT_EQ(int(h.recordCount), 6); }
}

/* B4-42 maxDepth=0 只含根 -> 1 条（深度下界）
 * 实测：_probe/pe.cpp maxDepth=0 recs=1 */
TEST(WbBoundary, maxDepthZeroOnlyRoot) {
    WbSandbox sb("depth0");
    const std::string d3 = Path::join(sb.src, "deep");
    Platform::makeDirTree(Path::join(Path::join(Path::join(d3, "l1"), "l2"), "l3"));
    CSimpleFile::writeWhole(Path::join(Path::join(Path::join(d3, "l1"), "l2"), "f.txt"),
                            std::vector<uint8_t>(100, 'A'));
    CSimpleFile::writeWhole(Path::join(d3, "top.txt"), std::vector<uint8_t>(100, 'A'));
    CMyPack p;
    PackOptions o;
    o.filter.maxDepth = 0;
    const std::string arc = Path::join(sb.root, "md0.dbkp");
    ASSERT_EQ(int(p.pack(d3, arc, o)), int(E_OK));
    ArchiveHeader h;
    ASSERT_EQ(int(p.readHeader(arc, h)), int(E_OK));
    EXPECT_EQ(int(h.recordCount), 1);
}

/* B4-43 maxDepth=1 -> 3 条，maxDepth=2 -> 4 条（逐层展开边界）
 * 实测：_probe/pe.cpp maxDepth=1 recs=3, maxDepth=2 recs=4 */
TEST(WbBoundary, maxDepthOneAndTwoProgressive) {
    WbSandbox sb("depth12");
    const std::string d3 = Path::join(sb.src, "deep");
    Platform::makeDirTree(Path::join(Path::join(Path::join(d3, "l1"), "l2"), "l3"));
    CSimpleFile::writeWhole(Path::join(Path::join(Path::join(d3, "l1"), "l2"), "f.txt"),
                            std::vector<uint8_t>(100, 'A'));
    CSimpleFile::writeWhole(Path::join(d3, "top.txt"), std::vector<uint8_t>(100, 'A'));
    CMyPack p;
    ArchiveHeader h;
    { PackOptions o; o.filter.maxDepth = 1;
      const std::string arc = Path::join(sb.root, "md1.dbkp");
      ASSERT_EQ(int(p.pack(d3, arc, o)), int(E_OK));
      ASSERT_EQ(int(p.readHeader(arc, h)), int(E_OK));
      EXPECT_EQ(int(h.recordCount), 3); }
    { PackOptions o; o.filter.maxDepth = 2;
      const std::string arc = Path::join(sb.root, "md2.dbkp");
      ASSERT_EQ(int(p.pack(d3, arc, o)), int(E_OK));
      ASSERT_EQ(int(p.readHeader(arc, h)), int(E_OK));
      EXPECT_EQ(int(h.recordCount), 4); }
}
