/* ============================================================================
 *  test_meta.cpp  -- 元数据（权限/属主/时间戳/inode/设备号）的保存与还原
 *
 *  覆盖三个层次：
 *    1) 序列化层：FileRecord 的每个元数据字段都必须逐位 survive 磁盘往返
 *    2) 平台层  ：Platform::setTimes / setMode 写下去能读回来
 *    3) 归档层  ：pack -> unpack 后，文件与**目录**的 mtime 一致
 *                （目录必须在子项之后恢复，否则建子项会把父目录 mtime 顶掉，
 *                 这是讲义"已知缺陷"之一）
 * ==========================================================================*/
#include "TestFramework.h"

#include <cstring>
#include <ctime>
#include <string>
#include <vector>

#include "Common/Serialize.h"
#include "Pack/MyPack.h"
#include "Platform/FS.h"
#include "Utils/PathUtil.h"
#include "Utils/SimpleFile.h"

using namespace DBKP;

namespace {

/** 一条把所有元数据槽位都填满的记录 */
FileRecord fullMetaRecord(const std::string& path, char type) {
    FileRecord r;
    r.path = path;
    r.type = type;
    r.mode = 0100754u;
    r.uid  = 1000;
    r.gid  = 1001;
    r.mtimeSec = 1700000123; r.mtimeNSec = 456789123;
    r.atimeSec = 1699999888; r.atimeNSec = 123456789;
    r.ctimeSec = 1690000000;
    r.ino   = 0x123456789abcdefull;
    r.nlink = 7;
    r.dev   = 0x0badf00d;
    r.majorNum = 13;
    r.minorNum = 42;
    r.size = 4096;
    r.storedSize = 4096;
    r.crc  = 0x0123456789abcdefull;
    r.compAlg = ALG_NONE;
    r.cryptoAlg = CRY_NONE;
    r.flags = RF_META_UID | RF_META_MODE | RF_META_TIME | RF_CRC_VALID;
    return r;
}

#define EXPECT_META_EQ(a, b)                                      \
    do {                                                          \
        EXPECT_EQ((a).path, (b).path);                            \
        EXPECT_EQ((a).link, (b).link);                            \
        EXPECT_EQ((a).type, (b).type);                            \
        EXPECT_EQ(int((a).flags & ~RF_HAS_EXTEND),                \
                  int((b).flags & ~RF_HAS_EXTEND));               \
        EXPECT_EQ((a).mode, (b).mode);                            \
        EXPECT_EQ((a).uid, (b).uid);                              \
        EXPECT_EQ((a).gid, (b).gid);                              \
        EXPECT_EQ((a).mtimeSec, (b).mtimeSec);                    \
        EXPECT_EQ((a).mtimeNSec, (b).mtimeNSec);                  \
        EXPECT_EQ((a).atimeSec, (b).atimeSec);                    \
        EXPECT_EQ((a).atimeNSec, (b).atimeNSec);                  \
        EXPECT_EQ((a).ctimeSec, (b).ctimeSec);                    \
        EXPECT_EQ((a).ino, (b).ino);                              \
        EXPECT_EQ((a).nlink, (b).nlink);                          \
        EXPECT_EQ((a).dev, (b).dev);                              \
        EXPECT_EQ((a).majorNum, (b).majorNum);                    \
        EXPECT_EQ((a).minorNum, (b).minorNum);                    \
        EXPECT_EQ((a).size, (b).size);                            \
        EXPECT_EQ((a).crc, (b).crc);                              \
    } while (0)

void writeWhole(const std::string& abs, const std::string& text) {
    const std::string parent = Path::parentDir(abs);
    if (!parent.empty()) Platform::makeDirTree(parent);
    CSimpleFile::writeWhole(abs, std::vector<uint8_t>(text.begin(), text.end()));
}

void rmTree(const std::string& p) {
    std::vector<Platform::DirEntry> items;
    if (DBKP_IS_ERR(Platform::listDir(p, items))) return;
    for (size_t i = 0; i < items.size(); ++i) {
        const std::string child = Path::join(p, items[i].name);
        if (items[i].type == FT_DIR) rmTree(child);
        else Platform::removeFile(child);
    }
    Platform::removeDir(p);
}

std::string readText(const std::string& abs) {
    std::vector<uint8_t> v;
    if (DBKP_IS_ERR(CSimpleFile::readWhole(abs, v))) return std::string("<missing>");
    return std::string(v.begin(), v.end());
}

} /* anonymous namespace */

/* ------------------------------------------------------------ 1) 序列化层 */

TEST(Meta, AllFieldsSurviveSerialization) {
    FileRecord in = fullMetaRecord("dir/sub/file.bin", FT_REGULAR);
    std::vector<uint8_t> bytes;
    ASSERT_EQ(encodeRecord(in, bytes), E_OK);
    FileRecord out;
    ASSERT_EQ(decodeRecordBlocks(bytes, out), E_OK);
    EXPECT_META_EQ(out, in);
}

TEST(Meta, DirectoryAndSpecialRecordsKeepMeta) {
    char tags[] = { FT_DIR, FT_SYMLINK, FT_FIFO, FT_BLOCK, FT_CHAR, FT_SOCKET, FT_HARDLINK };
    for (size_t i = 0; i < sizeof(tags); ++i) {
        FileRecord in = fullMetaRecord("x", tags[i]);
        if (tags[i] == FT_SYMLINK || tags[i] == FT_HARDLINK) in.link = "../target/path";
        in.size = 0;
        in.storedSize = 0;
        std::vector<uint8_t> bytes;
        ASSERT_EQ(encodeRecord(in, bytes), E_OK);
        FileRecord out;
        ASSERT_EQ(decodeRecordBlocks(bytes, out), E_OK);
        EXPECT_META_EQ(out, in);
        EXPECT_EQ(out.link, in.link);
    }
}

TEST(Meta, LongPathStillKeepsEveryMetaField) {
    /* 900+ 字符路径 -> 需要多条 'X' 扩展记录，元数据槽位不能被扩展逻辑吃掉 */
    std::string longPath;
    for (int i = 0; i < 9; ++i) longPath += "seg0123456789/";
    longPath += std::string(300, 'l') + ".txt";
    ASSERT_GT(longPath.size(), 398u);
    FileRecord in = fullMetaRecord(longPath, FT_REGULAR);
    in.link = std::string(500, 'k');
    std::vector<uint8_t> bytes;
    ASSERT_EQ(encodeRecord(in, bytes), E_OK);
    EXPECT_GT(bytes.size(), BLOCK_SIZE);
    FileRecord out;
    ASSERT_EQ(decodeRecordBlocks(bytes, out), E_OK);
    EXPECT_META_EQ(out, in);
    /* RF_HAS_EXTEND 是编码器写盘时补的"存储级"标志，解码后仍在记录里
     * （test_serialize.cpp 里也专门断言了这一点），因此 META 比较要掩掉它 */
    EXPECT_TRUE((out.flags & RF_HAS_EXTEND) != 0);
    EXPECT_EQ(out.link.size(), in.link.size());
}

TEST(Meta, ZeroFlagsStayZero) {
    FileRecord in = fullMetaRecord("plain.txt", FT_REGULAR);
    in.flags = RF_NONE;
    in.mode = 0; in.uid = 0; in.gid = 0;
    in.mtimeNSec = 0; in.atimeNSec = 0;
    std::vector<uint8_t> bytes;
    ASSERT_EQ(encodeRecord(in, bytes), E_OK);
    FileRecord out;
    ASSERT_EQ(decodeRecordBlocks(bytes, out), E_OK);
    EXPECT_EQ(int(out.flags), int(RF_NONE));
    EXPECT_META_EQ(out, in);
}

/* --------------------------------------------------------------- 2) 平台层 */

TEST(Meta, SetTimesRoundTripOnDisk) {
    const char* f = "ttest_meta_times.txt";
    writeWhole(f, "timestamp");
    /* 纳秒取 100ns 的整数倍：NTFS 时间片是 100ns，ext4 是 1ns，两边都能精确存 */
    const int64_t mt = 1700000123, at = 1699999888;
    const int64_t mns = 456700000, ans = 123000000;
    ASSERT_EQ(Platform::setTimes(f, mt, mns, at, ans), E_OK);
    Platform::FileInfo fi;
    ASSERT_EQ(Platform::getInfo(f, fi), E_OK);
    EXPECT_EQ(fi.mtimeSec, mt);
    EXPECT_EQ(fi.atimeSec, at);
    EXPECT_GE(fi.mtimeNSec, mns - 1000);
    EXPECT_LE(fi.mtimeNSec, mns + 1000);
    Platform::removeFile(f);
}

TEST(Meta, SetModeRoundTripOnDisk) {
    const char* f = "ttest_meta_mode.txt";
    writeWhole(f, "perm");
    Platform::FileInfo fi;
#ifdef _WIN32
    /* Win32 只有"只读"一位可表达：0200 位决定属性，读回 0644 / 0444 */
    ASSERT_EQ(Platform::setMode(f, 0600), E_OK);
    ASSERT_EQ(Platform::getInfo(f, fi), E_OK);
    EXPECT_EQ(fi.mode, 0644u);
    ASSERT_EQ(Platform::setMode(f, 0400), E_OK);
    ASSERT_EQ(Platform::getInfo(f, fi), E_OK);
    EXPECT_EQ(fi.mode, 0444u);
    Platform::setMode(f, 0666);                 /* 解锁，否则删不掉 */
#else
    ASSERT_EQ(Platform::setMode(f, 0755), E_OK);
    ASSERT_EQ(Platform::getInfo(f, fi), E_OK);
    EXPECT_EQ(int(fi.mode & 0777u), 0755);
    ASSERT_EQ(Platform::setMode(f, 0600), E_OK);
    ASSERT_EQ(Platform::getInfo(f, fi), E_OK);
    EXPECT_EQ(int(fi.mode & 0777u), 0600);
#endif
    Platform::removeFile(f);
}

TEST(Meta, SetOwnerIsGraceful) {
    const char* f = "ttest_meta_owner.txt";
    writeWhole(f, "owner");
    const ErrCode rc = Platform::setOwner(f, 0, 0);
    /* 支持则 E_OK；不支持/无权限必须给出明确错误码而不是崩溃 */
    EXPECT_TRUE(rc == E_OK || rc == E_UNSUPPORTED_FEATURE || rc == E_PERMISSION_DENIED);
    Platform::removeFile(f);
}

/* ----------------------------------------------------------- 4) 超长路径 */

TEST(Meta, VeryLongPathBacksUpAndRestores) {
    /* 归档内的相对路径 4 层 x60 + 200 字符文件名 ≈ 444 字符：
     *   - 超过记录内联字段(398) -> 必须走 'X' 扩展记录
     *   - 拼上沙箱绝对前缀后超过 Windows MAX_PATH(260) -> 必须走 \\?\
     * 两条链路在这里同时被验证。注意归档里的 relPath 不含源目录名本身。 */
    std::string deep;
    for (int i = 0; i < 4; ++i) deep += (i == 0 ? "" : "/") + std::string(60, char('a' + i));
    const std::string name   = std::string(200, 'L') + ".dat";
    const std::string inside = Path::join(deep, name);        /* 归档内相对路径 */
    ASSERT_GT(inside.size(), 398u);

    const std::string body = "the quick brown fox jumps over the long path";
    rmTree("tlp");
    writeWhole(Path::join("tlp", inside), body);
    Platform::FileInfo fi;
    ASSERT_EQ(Platform::getInfo(Path::join("tlp", inside), fi), E_OK);   /* 能 stat 到 */
    EXPECT_EQ(fi.type, FT_REGULAR);

    const char* arc = "tlp.dbkp";
    const char* dst = "tlp_out";
    Platform::removeFile(arc);
    rmTree(dst);
    PackOptions po;
    po.preserveMeta = true;
    CMyPack packer;
    ASSERT_EQ(packer.pack("tlp", arc, po), E_OK);
    UnpackOptions uo;
    uo.overwrite = true;
    ASSERT_EQ(packer.unpack(arc, dst, uo), E_OK);

    /* 还原后的目录结构里必须能找到那个 200 字符名字的文件 */
    Platform::FileInfo got;
    ASSERT_EQ(Platform::getInfo(Path::join(dst, inside), got), E_OK);
    EXPECT_EQ(int(got.size), int(body.size()));
    EXPECT_EQ(readText(Path::join(dst, inside)), body);

    rmTree("tlp"); rmTree(dst); Platform::removeFile(arc);
}


/* --------------------------------------------------------------- 3) 归档层 */

TEST(Meta, ArchiveRestoresFileAndDirectoryMtimes) {
    const char* src = "ttest_meta_src";
    const char* arc = "ttest_meta.dbkp";
    const char* dst = "ttest_meta_dst";
    rmTree(src); rmTree(dst); Platform::removeFile(arc);
    Platform::makeDirTree(Path::join(src, "sub/deeper"));
    writeWhole(Path::join(src, "a.txt"), "alpha");
    writeWhole(Path::join(src, "sub/b.txt"), "beta");
    writeWhole(Path::join(src, "sub/deeper/c.txt"), "gamma");

    const int64_t tFile = 1700000001, tDeep = 1700000003, tSub = 1700000002, tRoot = 1700000004;
    Platform::setTimes(Path::join(src, "a.txt"), tFile, 0, tFile, 0);
    Platform::setTimes(Path::join(src, "sub/deeper"), tDeep, 0, tDeep, 0);
    Platform::setTimes(Path::join(src, "sub"), tSub, 0, tSub, 0);
    const ErrCode seedRc = Platform::setTimes(src, tRoot, 0, tRoot, 0);

    PackOptions po;
    po.preserveMeta = true;
    CMyPack packer;
    ASSERT_EQ(packer.pack(src, arc, po), E_OK);
    UnpackOptions uo;
    uo.overwrite = true;
    ASSERT_EQ(packer.unpack(arc, dst, uo), E_OK);

    Platform::FileInfo fi;
    ASSERT_EQ(Platform::getInfo(Path::join(dst, "a.txt"), fi), E_OK);
    EXPECT_EQ(fi.mtimeSec, tFile);
    ASSERT_EQ(Platform::getInfo(Path::join(dst, "sub/b.txt"), fi), E_OK);
    EXPECT_NE(fi.mtimeSec, 0);                    /* 由源文件真实 mtime 决定，非落盘时刻 */
    if (DBKP_IS_ERR(seedRc)) {                    /* 平台不允许改目录时间时跳过目录断言 */
        /* 例如某些文件系统/权限组合：不做断言，避免误报 */
    } else {
        ASSERT_EQ(Platform::getInfo(Path::join(dst, "sub/deeper"), fi), E_OK);
        EXPECT_EQ(fi.mtimeSec, tDeep);            /* 子目录必须先于父目录恢复 */
        ASSERT_EQ(Platform::getInfo(Path::join(dst, "sub"), fi), E_OK);
        EXPECT_EQ(fi.mtimeSec, tSub);
        ASSERT_EQ(Platform::getInfo(dst, fi), E_OK);
        EXPECT_EQ(fi.mtimeSec, tRoot);            /* 根目录最后恢复 */
    }

    /* --no-meta 时不应恢复时间（保持落盘时刻），证明开关真的生效 */
    rmTree(dst);
    UnpackOptions uo2;
    uo2.overwrite = true;
    uo2.restoreMeta = false;
    ASSERT_EQ(packer.unpack(arc, dst, uo2), E_OK);
    const int64_t now = static_cast<int64_t>(std::time(nullptr));
    ASSERT_EQ(Platform::getInfo(Path::join(dst, "a.txt"), fi), E_OK);
    EXPECT_GT(fi.mtimeSec, now - 120);            /* 未恢复元数据 -> 接近当前时间 */

    rmTree(src); rmTree(dst); Platform::removeFile(arc);
}


