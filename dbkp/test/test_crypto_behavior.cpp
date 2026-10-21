/* ============================================================================
 *  test_crypto_behavior.cpp  -- 加密在归档层的行为（口令 / 明文隐藏 / 损坏）
 * ==========================================================================*/
#include "TestFramework.h"

#include <string>
#include <vector>

#include "Pack/MyPack.h"
#include "Platform/FS.h"
#include "Utils/PathUtil.h"
#include "Utils/SimpleFile.h"

using namespace DBKP;

namespace {
const char* const kSrc = "ttest_cry";
const char* const kArc = "ttest_cry.dbkp";
const char* const kDst = "ttest_cry_out";

void writeText(const std::string& abs, const std::string& text) {
    const std::string parent = Path::parentDir(abs);
    if (!parent.empty()) Platform::makeDirTree(parent);
    CSimpleFile::writeWhole(abs, std::vector<uint8_t>(text.begin(), text.end()));
}
void removeTree(const std::string& p) {
    std::vector<Platform::DirEntry> items;
    if (DBKP_IS_ERR(Platform::listDir(p, items))) return;
    for (size_t i = 0; i < items.size(); ++i) {
        const std::string c = Path::join(p, items[i].name);
        if (items[i].type == FT_DIR) removeTree(c);
        else Platform::removeFile(c);
    }
    Platform::removeDir(p);
}
} /* anonymous namespace */

class CryFixture {
public:
    CryFixture() {
        removeTree(kSrc); removeTree(kDst); Platform::removeFile(kArc);
        Platform::makeDirTree(kSrc);
        writeText(Path::join(kSrc, "one.txt"), "one two three");
        writeText(Path::join(kSrc, "sub/two.txt"), "four five six");
        writeText(Path::join(kSrc, "three.txt"), std::string(5000, 'k'));
    }
    ~CryFixture() {
        removeTree(kSrc); removeTree(kDst); Platform::removeFile(kArc);
    }
};

TEST(CryptoBehavior, WrongPasswordIsRejected) {
    CryFixture f;
    CMyPack packer;
    PackOptions po;
    po.crypto = CRY_AES256_CBC;
    po.password = "correct horse";
    ASSERT_EQ(packer.pack(kSrc, kArc, po), E_OK);

    UnpackOptions uo;
    EXPECT_EQ(packer.unpack(kArc, kDst, uo), E_WRONG_PASSWORD);     /* 没给口令 */
    uo.password = "wrong horse";
    EXPECT_EQ(packer.unpack(kArc, kDst, uo), E_WRONG_PASSWORD);     /* 口令错误 */
    uo.password = "correct horse";
    EXPECT_EQ(packer.unpack(kArc, kDst, uo), E_OK);                 /* 口令正确 */
}

TEST(CryptoBehavior, EncryptionHidesPlaintext) {
    CryFixture f;
    CMyPack packer;
    PackOptions po;
    po.crypto = CRY_CHACHA20;
    po.password = "secret";
    ASSERT_EQ(packer.pack(kSrc, kArc, po), E_OK);
    std::vector<uint8_t> blob;
    ASSERT_EQ(CSimpleFile::readWhole(kArc, blob), E_OK);
    const std::string hay(blob.begin(), blob.end());
    EXPECT_EQ(hay.find("one two three"), std::string::npos);
    EXPECT_EQ(hay.find("four five six"), std::string::npos);
}

TEST(CryptoBehavior, CompressThenEncryptOrderIsObserved) {
    CryFixture f;
    CMyPack packer;
    PackOptions plain, compOnly, cryptoOnly, both;
    plain.crypto = CRY_NONE;
    compOnly.comp = ALG_LZ77;
    cryptoOnly.crypto = CRY_AES256_CBC;
    cryptoOnly.password = "p";
    both.comp = ALG_LZ77;
    both.crypto = CRY_AES256_CBC;
    both.password = "p";

    /* 用"编码后字节数"而不是文件大小比较：后者会被 512B 块对齐掩盖差异 */
    const char* names[4] = {"t_a.dbkp", "t_b.dbkp", "t_c.dbkp", "t_d.dbkp"};
    PackOptions* opts[4] = {&plain, &compOnly, &cryptoOnly, &both};
    int64_t stored[4] = {0, 0, 0, 0};
    for (int i = 0; i < 4; ++i) {
        ASSERT_EQ(packer.pack(kSrc, names[i], *opts[i]), E_OK);
        ArchiveHeader hdr;
        ArchiveStat st;
        ASSERT_EQ(packer.stat(names[i], hdr, st), E_OK);
        stored[i] = st.storedBytes;
        EXPECT_EQ(st.rawBytes, 5026);              /* 原始字节数始终一致 */
        Platform::removeFile(names[i]);
    }
    EXPECT_LT(stored[1], stored[0]);      /* 压缩有效 */
    EXPECT_GT(stored[2], stored[0]);      /* 加密带来 IV+标签+填充开销 */
    EXPECT_GT(stored[3], stored[1]);      /* 先压后密：密文不可再压，故比只压大 */
    EXPECT_LT(stored[3], stored[2]);      /* 但比只密小（压缩发生在加密之前） */
}

TEST(CryptoBehavior, CorruptedByteIsAlwaysDetected) {
    CryFixture f;
    CMyPack packer;
    PackOptions po;
    po.comp = ALG_HUFFMAN;
    po.crypto = CRY_AES256_CBC;
    po.password = "pw";
    ASSERT_EQ(packer.pack(kSrc, kArc, po), E_OK);
    std::vector<uint8_t> all;
    ASSERT_EQ(CSimpleFile::readWhole(kArc, all), E_OK);

    int detected = 0, total = 0;
    for (size_t off = 600; off < all.size(); off += 512) {
        std::vector<uint8_t> bad = all;
        bad[off] = static_cast<uint8_t>(bad[off] ^ 0x01);
        ASSERT_EQ(CSimpleFile::writeWhole(kArc, bad), E_OK);
        ++total;
        int n = 0;
        if (DBKP_IS_ERR(packer.verify(kArc, "pw", n))) ++detected;
    }
    EXPECT_GT(total, 3);
    EXPECT_EQ(detected, total);         /* CRC 覆盖整个载荷，任何字节被改都能发现 */
}

TEST(CryptoBehavior, VerifyPassesOnHealthyArchive) {
    CryFixture f;
    CMyPack packer;
    PackOptions po;
    po.comp = ALG_LZHUFF;
    po.crypto = CRY_CHACHA20;
    po.password = "ok";
    ASSERT_EQ(packer.pack(kSrc, kArc, po), E_OK);
    int bad = 0;
    EXPECT_EQ(packer.verify(kArc, "ok", bad), E_OK);
    EXPECT_EQ(bad, 0);
}

TEST(CryptoBehavior, EncryptedArchiveRecordsAlgorithm) {
    CryFixture f;
    CMyPack packer;
    PackOptions po;
    po.comp = ALG_LZ77;
    po.crypto = CRY_AES256_CBC;
    po.password = "tag";
    ASSERT_EQ(packer.pack(kSrc, kArc, po), E_OK);
    ArchiveHeader hdr;
    ASSERT_EQ(packer.readHeader(kArc, hdr), E_OK);
    EXPECT_EQ(hdr.compAlg, ALG_LZ77);
    EXPECT_EQ(hdr.cryptoAlg, CRY_AES256_CBC);
    EXPECT_GT(hdr.kdfRounds, 0);
    bool saltNonZero = false;
    for (int i = 0; i < 16; ++i) if (hdr.salt[i]) saltNonZero = true;
    EXPECT_TRUE(saltNonZero);            /* 每条归档随机 salt，防彩虹表 */
}
