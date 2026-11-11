/* ============================================================================
 *  test_regress_f6b.cpp  -- F6b（空壳箱 verify 拒绝 + 孤儿 .tmp 检测）的
 *                          命名回归测试
 *
 *  背景（整改清单 F6b）：
 *    原 checkWholePayload() 对 payloadSize==0 直接返回 E_OK——一个人造/半成
 *    品的"空壳箱"（卷标声称有记录、载荷区却是空的）能绿灯通过 verify。
 *    F4 落地后 .tmp 即天然"进行中"标记：启动（pack）与 verify 都要检测它。
 *  修法：
 *    ① payloadSize==0 且记录区非空（recordCount/fileCount 非零）-> 报错；
 *    ② pack 启动时目标旁残留 .tmp 且未 --force -> E_INCOMPLETE；
 *       verify 时目标旁残留 .tmp -> E_INCOMPLETE（只报告不删除）。
 * ==========================================================================*/
#include "TestFramework.h"

#include <cstring>
#include <string>
#include <vector>

#include "Common/Serialize.h"
#include "Pack/MyPack.h"
#include "Platform/FS.h"
#include "Utils/PathUtil.h"
#include "Utils/SimpleFile.h"

using namespace DBKP;

namespace {

void removeTree(const std::string& p) {
    std::vector<Platform::DirEntry> items;
    if (DBKP_IS_ERR(Platform::listDir(p, items))) { Platform::removeFile(p); return; }
    for (size_t i = 0; i < items.size(); ++i) {
        const std::string c = Path::join(p, items[i].name);
        if (items[i].type == FT_DIR) removeTree(c);
        else Platform::removeFile(c);
    }
    Platform::removeDir(p);
}

/* 人造"空壳箱"：卷标声明 recordCount/fileCount 非零、payloadSize=0，
   后面再跟一个 512B 垃圾块冒充"记录区非空"。旧实现会 verify 绿灯。 */
void writeEmptyShell(const std::string& arcPath) {
    ArchiveHeader hdr;                       /* checksum 默认 crc64 */
    hdr.recordCount = 1;
    hdr.fileCount   = 1;
    hdr.payloadSize = 0;
    std::vector<uint8_t> bytes;
    encodeArchiveHeader(hdr, bytes);
    /* 追加一个伪装记录块，让"记录区非空"在物理上也成立 */
    std::vector<uint8_t> junk(BLOCK_SIZE, 0xAB);
    bytes.insert(bytes.end(), junk.begin(), junk.end());
    CSimpleFile::writeWhole(arcPath, bytes);
}

} /* anonymous namespace */

/* ① 空壳箱必须被 verify 拒掉（非零错误），而不是绿灯通过 */
TEST(RegressF6b, empty_shell_rejected_by_verify) {
    const std::string root = "treg_f6b_shell";
    const std::string arc  = Path::join(root, "shell.dbkp");
    removeTree(root);
    Platform::makeDirTree(root);
    writeEmptyShell(arc);

    CMyPack p;
    int bad = 0;
    ErrCode e = p.verify(arc, "", bad);
    EXPECT_NE(int(e), int(E_OK));
    EXPECT_TRUE(bad >= 1);
    /* restore 同样必须在落盘前拒绝（unpack 前置整卷校验走同一判据） */
    UnpackOptions u;
    ErrCode re = p.unpack(arc, Path::join(root, "out"), u);
    EXPECT_NE(int(re), int(E_OK));

    removeTree(root);
}

/* ② verify 时目标旁残留 .tmp（上次备份未完成的天然标记）-> E_INCOMPLETE */
TEST(RegressF6b, verify_detects_orphan_tmp) {
    const std::string root = "treg_f6b_orphan";
    const std::string src  = Path::join(root, "src");
    const std::string arc  = Path::join(root, "box.dbkp");
    removeTree(root);
    Platform::makeDirTree(src);
    CSimpleFile::writeWhole(Path::join(src, "a.txt"),
                            std::vector<uint8_t>(8, 'x'));

    CMyPack p;
    PackOptions o;
    ASSERT_EQ(int(p.pack(src, arc, o)), int(E_OK));

    /* 人工放一个孤儿 tmp：模拟"上次备份被打断留下的进行中标记" */
    ASSERT_EQ(int(CSimpleFile::writeWhole(arc + ".tmp",
                std::vector<uint8_t>(64, 0x5A))), int(E_OK));

    int bad = 0;
    ErrCode e = p.verify(arc, "", bad);
    EXPECT_EQ(int(e), int(E_INCOMPLETE));
    EXPECT_TRUE(bad >= 1);
    /* verify 只报告不删除（删除责任在 pack --force，避免两套清理机制） */
    EXPECT_EQ(int(Platform::exists(arc + ".tmp")), int(E_OK));

    removeTree(root);
}

/* ② pack 启动时残留 .tmp 且未 --force -> E_INCOMPLETE；--force 清残骸重试成功 */
TEST(RegressF6b, pack_detects_orphan_tmp_and_force_recovers) {
    const std::string root = "treg_f6b_startup";
    const std::string src  = Path::join(root, "src");
    const std::string arc  = Path::join(root, "box.dbkp");
    removeTree(root);
    Platform::makeDirTree(src);
    CSimpleFile::writeWhole(Path::join(src, "a.txt"),
                            std::vector<uint8_t>(8, 'y'));

    /* 先留一个孤儿 tmp（正式箱尚不存在，模拟上次被 kill 的现场） */
    ASSERT_EQ(int(CSimpleFile::writeWhole(arc + ".tmp",
                std::vector<uint8_t>(64, 0x11))), int(E_OK));

    CMyPack p;
    PackOptions o;
    ErrCode e = p.pack(src, arc, o);
    EXPECT_EQ(int(e), int(E_INCOMPLETE));
    EXPECT_TRUE(p.lastErrorText().find("--force") != std::string::npos);
    /* 拒绝路径不得创建正式箱，也不得动 tmp */
    EXPECT_NE(int(Platform::exists(arc)), int(E_OK));

    PackOptions of;
    of.force = true;
    CMyPack p2;
    EXPECT_EQ(int(p2.pack(src, arc, of)), int(E_OK));
    EXPECT_EQ(int(Platform::exists(arc)), int(E_OK));
    /* 提交后正式名旁干干净净 */
    EXPECT_NE(int(Platform::exists(arc + ".tmp")), int(E_OK));
    int bad = 0;
    EXPECT_EQ(int(p2.verify(arc, "", bad)), int(E_OK));

    removeTree(root);
}

/* 合法空目录备份（零条目、payloadSize==0 且 recordCount==0）不得被误杀 */
TEST(RegressF6b, genuinely_empty_archive_still_passes) {
    const std::string root = "treg_f6b_legit";
    const std::string src  = Path::join(root, "src");
    const std::string arc  = Path::join(root, "box.dbkp");
    removeTree(root);
    Platform::makeDirTree(src);

    CMyPack p;
    PackOptions o;
    o.filter.includeDirs = false;   /* 连根目录 "." 都不入档 -> 真正零记录 */
    ASSERT_EQ(int(p.pack(src, arc, o)), int(E_OK));
    ArchiveHeader hdr;
    ASSERT_EQ(int(p.readHeader(arc, hdr)), int(E_OK));
    EXPECT_EQ(int(hdr.recordCount), 0);
    int bad = 0;
    EXPECT_EQ(int(p.verify(arc, "", bad)), int(E_OK));   /* 不误杀 */

    removeTree(root);
}
