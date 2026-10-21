/* ============================================================================
 *  test_pack_err.cpp  -- 归档错误路径（非空目标 / 缺文件 / 非归档 / 截断）
 * ==========================================================================*/
#include "TestFramework.h"

#include <string>
#include <vector>

#include "Common/Serialize.h"
#include "Pack/MyPack.h"
#include "Platform/FS.h"
#include "Utils/PathUtil.h"
#include "Utils/SimpleFile.h"

using namespace DBKP;

namespace {

const char* const kSrc = "ttest_pack2";
const char* const kArc = "ttest_pack2.dbkp";
const char* const kDst = "ttest_pack2_out";

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

} /* anonymous namespace */

class ErrFixture {
public:
    ErrFixture() {
        removeTree(kSrc);
        removeTree(kDst);
        Platform::removeFile(kArc);
        Platform::makeDirTree(kSrc);
        writeText(Path::join(kSrc, "one.txt"), "one two three");
        writeText(Path::join(kSrc, "sub/two.txt"), "four five six");
        writeText(Path::join(kSrc, "big.txt"), std::string(200000, 'x'));
    }
    ~ErrFixture() {
        removeTree(kSrc);
        removeTree(kDst);
        Platform::removeFile(kArc);
    }
};

TEST(PackErr, TargetNotEmptyIsRejected) {
    ErrFixture f;
    CMyPack packer;
    PackOptions po;
    ASSERT_EQ(packer.pack(kSrc, kArc, po), E_OK);
    Platform::makeDirTree(kDst);
    writeText(Path::join(kDst, "occupant.txt"), "blocker");

    UnpackOptions uo;
    EXPECT_EQ(packer.unpack(kArc, kDst, uo), E_DESTINATION_NOT_EMPTY);
    uo.overwrite = true;                       /* 只有 --force 才允许覆盖 */
    EXPECT_EQ(packer.unpack(kArc, kDst, uo), E_OK);
}

TEST(PackErr, MissingArchiveIsReported) {
    CMyPack packer;
    UnpackOptions uo;
    EXPECT_EQ(packer.unpack("no_such_file.dbkp", "whatever", uo), E_SOURCE_NOT_FOUND);
    ArchiveHeader hdr;
    EXPECT_EQ(packer.readHeader("no_such_file.dbkp", hdr), E_SOURCE_NOT_FOUND);
}

TEST(PackErr, ForeignFileIsRejected) {
    const char* fake = "ttest_fake.dbkp";
    /* 必须 ≥512 字节，否则会先被"太短"拦下，测不到魔数校验 */
    writeText(fake, std::string(600, 'z') + " this is plain text and not a dbkp archive");
    CMyPack packer;
    ArchiveHeader hdr;
    EXPECT_EQ(packer.readHeader(fake, hdr), E_INVALID_HEADER_RECORD);
    UnpackOptions uo;
    EXPECT_EQ(packer.unpack(fake, "ttest_never", uo), E_INVALID_HEADER_RECORD);
    Platform::removeFile(fake);
    removeTree("ttest_never");
}

TEST(PackErr, TruncatedArchiveIsDetected) {
    ErrFixture f;
    CMyPack packer;
    PackOptions po;
    ASSERT_EQ(packer.pack(kSrc, kArc, po), E_OK);
    std::vector<uint8_t> all;
    ASSERT_EQ(CSimpleFile::readWhole(kArc, all), E_OK);
    all.resize(all.size() / 2);
    ASSERT_EQ(CSimpleFile::writeWhole(kArc, all), E_OK);

    int bad = 0;
    EXPECT_NE(packer.verify(kArc, "", bad), E_OK);
    UnpackOptions uo;
    EXPECT_NE(packer.unpack(kArc, kDst, uo), E_OK);
}

TEST(PackErr, ListSkipsDataBlocksCorrectly) {
    ErrFixture f;
    CMyPack packer;
    PackOptions po;
    po.comp = ALG_LZ77;
    ASSERT_EQ(packer.pack(kSrc, kArc, po), E_OK);
    std::vector<FileRecord> recs;
    ASSERT_EQ(packer.list(kArc, recs), E_OK);
    bool foundBig = false;
    for (size_t i = 0; i < recs.size(); ++i) {
        if (recs[i].path == "big.txt") {
            foundBig = true;
            EXPECT_EQ(recs[i].size, 200000);
            EXPECT_NE(recs[i].compAlg, ALG_NONE);
        }
    }
    EXPECT_TRUE(foundBig);
    ArchiveHeader hdr;
    ArchiveStat st;
    ASSERT_EQ(packer.stat(kArc, hdr, st), E_OK);
    EXPECT_EQ(recs.size(), static_cast<size_t>(hdr.fileCount));
}
