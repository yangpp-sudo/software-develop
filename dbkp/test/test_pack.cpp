/* ============================================================================
 *  test_pack.cpp  -- 归档打包/解包：算法矩阵往返
 * ==========================================================================*/
#include "TestFramework.h"

#include <cstring>
#include <string>
#include <vector>

#include "Common/Serialize.h"
#include "Pack/MyPack.h"
#include "Platform/FS.h"
#include "Utils/CRC64.h"
#include "Utils/PathUtil.h"
#include "Utils/SimpleFile.h"

using namespace DBKP;

namespace {

const char* const kSrc = "ttest_pack";
const char* const kArc = "ttest_pack.dbkp";
const char* const kDst = "ttest_pack_out";

void writeText(const std::string& abs, const std::string& text) {
    const std::string parent = Path::parentDir(abs);
    if (!parent.empty()) Platform::makeDirTree(parent);
    CSimpleFile::writeWhole(abs, std::vector<uint8_t>(text.begin(), text.end()));
}

void removeTree(const std::string& p) {
    std::vector<Platform::DirEntry> items;
    if (DBKP_IS_ERR(Platform::listDir(p, items))) return;
    for (size_t i = 0; i < items.size(); ++i) {
        const std::string child = Path::join(p, items[i].name);
        if (items[i].type == FT_DIR) removeTree(child);
        else Platform::removeFile(child);
    }
    Platform::removeDir(p);
}

std::string readText(const std::string& abs) {
    std::vector<uint8_t> v;
    if (DBKP_IS_ERR(CSimpleFile::readWhole(abs, v))) return "<missing>";
    return std::string(v.begin(), v.end());
}

uint64_t crcOf(const std::string& abs) {
    std::vector<uint8_t> v;
    if (DBKP_IS_ERR(CSimpleFile::readWhole(abs, v))) return 0;
    return CRC64::compute(v.data(), v.size());
}

/* 覆盖：空文件 / 文本 / 二进制 / 深层嵌套 / 含空格 / 超长文件名 / 空目录 */
void fillTree() {
    removeTree(kSrc);
    Platform::makeDirTree(kSrc);
    writeText(Path::join(kSrc, "small.txt"), "hello");
    writeText(Path::join(kSrc, "empty.txt"), "");
    std::string text;
    for (int i = 0; i < 400; ++i) text += "compressible text line 12345\n";
    writeText(Path::join(kSrc, "big.txt"), text);
    std::vector<uint8_t> bin;
    uint32_t x = 1234567;
    for (int i = 0; i < 3000; ++i) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        bin.push_back(static_cast<uint8_t>(x));
    }
    CSimpleFile::writeWhole(Path::join(kSrc, "data.bin"), bin);
    writeText(Path::join(kSrc, "a/b/c/d/deep.txt"), "nested");
    writeText(Path::join(kSrc, "dir with spaces/file name.txt"), "spaces are fine");
    writeText(Path::join(kSrc, std::string(120, 'L') + ".log"), "long name");
    Platform::makeDirTree(Path::join(kSrc, "empty_dir"));
}

} /* anonymous namespace */

class PackFixture {
public:
    PackFixture() { fillTree(); removeTree(kDst); Platform::removeFile(kArc); }
    ~PackFixture() {
        removeTree(kSrc);
        removeTree(kDst);
        Platform::removeFile(kArc);
    }
};

static void RoundTripWith(AlgorithmId alg, CryptoId crypto, const char* password) {
    PackOptions po;
    po.comp = alg;
    po.crypto = crypto;
    po.password = password ? password : "";
    po.comment = "unit test";
    CMyPack packer;
    ASSERT_EQ(packer.pack(kSrc, kArc, po), E_OK);

    ArchiveHeader hdr;
    ASSERT_EQ(packer.readHeader(kArc, hdr), E_OK);
    EXPECT_EQ(hdr.version, ARCHIVE_VERSION);
    EXPECT_GT(hdr.payloadSize, 0u);
    EXPECT_GT(hdr.fileCount, 5u);
    EXPECT_STREQ(hdr.comment.c_str(), "unit test");

    UnpackOptions uo;
    uo.password = password ? password : "";
    ASSERT_EQ(packer.unpack(kArc, kDst, uo), E_OK);
    EXPECT_EQ(uo.warnings, 0);

    EXPECT_EQ(readText(Path::join(kDst, "small.txt")), std::string("hello"));
    EXPECT_EQ(readText(Path::join(kDst, "empty.txt")), std::string(""));
    EXPECT_EQ(readText(Path::join(kDst, "big.txt")), readText(Path::join(kSrc, "big.txt")));
    EXPECT_EQ(readText(Path::join(kDst, "a/b/c/d/deep.txt")), std::string("nested"));
    EXPECT_EQ(readText(Path::join(kDst, "dir with spaces/file name.txt")),
              std::string("spaces are fine"));
    EXPECT_EQ(readText(Path::join(kDst, std::string(120, 'L') + ".log")), std::string("long name"));
    EXPECT_EQ(crcOf(Path::join(kDst, "data.bin")), crcOf(Path::join(kSrc, "data.bin")));
    EXPECT_TRUE(Platform::isDirectory(Path::join(kDst, "empty_dir")));
}

TEST(Pack, RoundTripNoCodec)   { PackFixture f; RoundTripWith(ALG_NONE,    CRY_NONE,       nullptr); }
TEST(Pack, RoundTripHuffman)   { PackFixture f; RoundTripWith(ALG_HUFFMAN, CRY_NONE,       nullptr); }
TEST(Pack, RoundTripLz77)      { PackFixture f; RoundTripWith(ALG_LZ77,    CRY_NONE,       nullptr); }
TEST(Pack, RoundTripLzHuff)    { PackFixture f; RoundTripWith(ALG_LZHUFF,  CRY_NONE,       nullptr); }
TEST(Pack, RoundTripRle)       { PackFixture f; RoundTripWith(ALG_RLE,     CRY_NONE,       nullptr); }
TEST(Pack, RoundTripAes)       { PackFixture f; RoundTripWith(ALG_NONE,    CRY_AES256_CBC, "pw1"); }
TEST(Pack, RoundTripChaCha)    { PackFixture f; RoundTripWith(ALG_HUFFMAN, CRY_CHACHA20,   "pw2"); }
TEST(Pack, RoundTripAllLayers) { PackFixture f; RoundTripWith(ALG_LZHUFF,  CRY_AES256_CBC, "pw3"); }
