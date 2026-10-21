/* ============================================================================
 *  test_serialize.cpp  -- 归档结构编解码（含超长路径的扩展记录）
 * ==========================================================================*/
#include "TestFramework.h"

#include <cstring>
#include <string>
#include <vector>

#include "Common/Defs.h"
#include "Common/Serialize.h"

using namespace DBKP;

static FileRecord sampleRecord(const std::string& path) {
    FileRecord r;
    r.path = path;
    r.type = FT_REGULAR;
    r.mode = 0100644;
    r.uid = 1000; r.gid = 1001;
    r.mtimeSec = 1700000000; r.mtimeNSec = 123456789;
    r.atimeSec = 1699999999; r.atimeNSec = 987654321;
    r.ctimeSec = 1699999000;
    r.ino = 424242; r.nlink = 3; r.dev = 7;
    r.size = 1024; r.storedSize = 900; r.crc = 0xdeadbeefcafebabeull;
    r.compAlg = ALG_HUFFMAN; r.cryptoAlg = CRY_AES256_CBC;
    r.flags = RF_META_MODE | RF_META_TIME | RF_CRC_VALID;
    return r;
}

TEST(Serialize, RecordRoundTripShortPath) {
    FileRecord in = sampleRecord("sub1/sub2/file.txt");
    std::vector<uint8_t> bytes;
    ASSERT_EQ(encodeRecord(in, bytes), E_OK);
    EXPECT_EQ(bytes.size(), BLOCK_SIZE);   /* 短路径不需要扩展记录 */

    FileRecord out;
    ASSERT_EQ(decodeRecordBlocks(bytes, out), E_OK);
    EXPECT_EQ(out.path, in.path);
    EXPECT_EQ(out.type, in.type);
    EXPECT_EQ(out.mode, in.mode);
    EXPECT_EQ(out.uid, in.uid);
    EXPECT_EQ(out.gid, in.gid);
    EXPECT_EQ(out.mtimeSec, in.mtimeSec);
    EXPECT_EQ(out.mtimeNSec, in.mtimeNSec);
    EXPECT_EQ(out.ino, in.ino);
    EXPECT_EQ(out.nlink, in.nlink);
    EXPECT_EQ(out.size, in.size);
    EXPECT_EQ(out.storedSize, in.storedSize);
    EXPECT_EQ(out.crc, in.crc);
    EXPECT_EQ(out.compAlg, in.compAlg);
    EXPECT_EQ(out.cryptoAlg, in.cryptoAlg);
}

TEST(Serialize, LongPathUsesExtendRecords) {
    /* 讲义缺陷 #1：路径超过固定字段会被截断。这里必须完整保留。 */
    std::string deep;
    for (int i = 0; i < 30; ++i) deep += "dir" + std::to_string(i) + "/";
    deep += std::string(200, 'x') + ".log";
    ASSERT_GT(deep.size(), REC_INLINE_PATH);

    FileRecord in = sampleRecord(deep);
    std::vector<uint8_t> bytes;
    ASSERT_EQ(encodeRecord(in, bytes), E_OK);
    EXPECT_GT(bytes.size(), BLOCK_SIZE);

    FileRecord out;
    ASSERT_EQ(decodeRecordBlocks(bytes, out), E_OK);
    EXPECT_EQ(out.path.size(), in.path.size());
    EXPECT_TRUE(out.path == in.path);
    EXPECT_TRUE(out.flags & RF_HAS_EXTEND);
}

TEST(Serialize, LongSymlinkTargetRoundTrip) {
    FileRecord in = sampleRecord("link");
    in.type = FT_SYMLINK;
    in.link = std::string(400, 't');            /* 超过内联 link 槽位 */
    std::vector<uint8_t> bytes;
    ASSERT_EQ(encodeRecord(in, bytes), E_OK);
    FileRecord out;
    ASSERT_EQ(decodeRecordBlocks(bytes, out), E_OK);
    EXPECT_EQ(out.link.size(), in.link.size());
    EXPECT_TRUE(out.link == in.link);
    EXPECT_EQ(out.path, in.path);
}

TEST(Serialize, CorruptMagicIsRejected) {
    FileRecord in = sampleRecord("a.txt");
    std::vector<uint8_t> bytes;
    ASSERT_EQ(encodeRecord(in, bytes), E_OK);
    bytes[3] ^= 0xFF;                            /* 打坏 recMagic */
    FileRecord out;
    EXPECT_NE(decodeRecordBlocks(bytes, out), E_OK);
}

TEST(Serialize, TruncatedExtendStreamIsRejected) {
    FileRecord in = sampleRecord(std::string(500, 'p'));
    std::vector<uint8_t> bytes;
    ASSERT_EQ(encodeRecord(in, bytes), E_OK);
    bytes.resize(bytes.size() - BLOCK_SIZE);     /* 丢掉最后一条记录 */
    FileRecord out;
    EXPECT_NE(decodeRecordBlocks(bytes, out), E_OK);
}

TEST(Serialize, ArchiveHeaderRoundTrip) {
    ArchiveHeader in;
    in.compAlg = ALG_LZHUFF;
    in.cryptoAlg = CRY_CHACHA20;
    in.checksum = CHK_CRC64;
    in.payloadCrc = 0x1122334455667788ull;
    in.payloadSize = 655360;
    in.rawSize = 1048576;
    in.recordCount = 77;
    in.fileCount = 60;
    in.createTime = 1717171717;
    in.sourcePath = "/home/user/data";
    in.comment = "weekly full backup";
    for (int i = 0; i < 16; ++i) in.salt[i] = static_cast<uint8_t>(i * 3);

    std::vector<uint8_t> bytes;
    ASSERT_EQ(encodeArchiveHeader(in, bytes), E_OK);
    EXPECT_EQ(bytes.size(), BLOCK_SIZE);

    ArchiveHeader out;
    ASSERT_EQ(decodeArchiveHeader(bytes.data(), out), E_OK);
    EXPECT_EQ(out.version, ARCHIVE_VERSION);
    EXPECT_EQ(out.compAlg, in.compAlg);
    EXPECT_EQ(out.cryptoAlg, in.cryptoAlg);
    EXPECT_EQ(out.payloadCrc, in.payloadCrc);
    EXPECT_EQ(out.payloadSize, in.payloadSize);
    EXPECT_EQ(out.rawSize, in.rawSize);
    EXPECT_EQ(out.recordCount, in.recordCount);
    EXPECT_EQ(out.fileCount, in.fileCount);
    EXPECT_EQ(out.createTime, in.createTime);
    EXPECT_TRUE(out.sourcePath == in.sourcePath);
    EXPECT_TRUE(out.comment == in.comment);
    EXPECT_EQ(std::memcmp(out.salt, in.salt, 16), 0);
}

TEST(Serialize, HeaderRejectsForeignMagic) {
    std::vector<uint8_t> bytes(BLOCK_SIZE, 0);
    ArchiveHeader out;
    EXPECT_EQ(decodeArchiveHeader(bytes.data(), out), E_INVALID_HEADER_RECORD);
}

TEST(Serialize, LittleEndianIsPlatformIndependent) {
    /* 磁盘格式强制小端：不同 CPU 字节序下也必须得到相同字节 */
    std::string buf;
    appendLE32(buf, 0x12345678u);
    ASSERT_EQ(buf.size(), 4u);
    EXPECT_EQ(static_cast<uint8_t>(buf[0]), 0x78);
    EXPECT_EQ(static_cast<uint8_t>(buf[1]), 0x56);
    EXPECT_EQ(static_cast<uint8_t>(buf[2]), 0x34);
    EXPECT_EQ(static_cast<uint8_t>(buf[3]), 0x12);
    std::string b64;
    appendLE64(b64, 0x0102030405060708ull);
    EXPECT_EQ(static_cast<uint8_t>(b64[7]), 0x01);
    EXPECT_EQ(readLE32(reinterpret_cast<const uint8_t*>(buf.data())), 0x12345678u);
    EXPECT_EQ(readLE64(reinterpret_cast<const uint8_t*>(b64.data())), 0x0102030405060708ull);
}
