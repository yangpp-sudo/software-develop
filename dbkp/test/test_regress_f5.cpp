/* ============================================================================
 *  test_regress_f5.cpp  -- F5（只给 -p 不给 -c 时"加密假象"）的命名回归测试
 *
 *  背景（整改清单 F5）：
 *    bk backup src out.dbkp -p 'S3cret!' 不带 -c 时，crypto 仍是 CRY_NONE，
 *    口令被静默丢弃，产出一只明文箱 —— 用户以为备份是加密的，这是最危险的
 *    一类"成功"。
 *  修法：打包路径上"有口令且最终 crypto==CRY_NONE"直接拒绝（E_INVALID_PARAMETER）。
 *    解包/校验/对比仍允许只带 -p（算法号存在箱头里），不在本项范围内。
 * ==========================================================================*/
#include "TestFramework.h"

#include <string>
#include <vector>

#include "Common/Defs.h"
#include "Pack/MyPack.h"
#include "Platform/FS.h"
#include "Utils/PathUtil.h"
#include "Utils/SimpleFile.h"

using namespace DBKP;

namespace {

void writeText(const std::string& abs, const std::string& text) {
    const std::string parent = Path::parentDir(abs);
    if (!parent.empty()) Platform::makeDirTree(parent);
    CSimpleFile::writeWhole(abs, std::vector<uint8_t>(text.begin(), text.end()));
}

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

} /* anonymous namespace */

/* 核心回归：口令 + CRY_NONE 必须被拒绝，且不落盘任何箱 */
TEST(RegressF5, password_without_crypto_is_refused) {
    const std::string root = "treg_f5_plain";
    const std::string arc  = Path::join(root, "out.dbkp");
    removeTree(root);
    writeText(Path::join(root, "a.txt"), "alpha");

    CMyPack p;
    PackOptions o;
    o.crypto   = CRY_NONE;          /* 没有 -c */
    o.password = "S3cret!";         /* 却有 -p */
    EXPECT_EQ(int(p.pack(root, arc, o)), int(E_INVALID_PARAMETER));
    EXPECT_FALSE(p.lastErrorText().empty());
    /* 拒绝必须发生在写文件之前：不能留下半成品箱骗过用户 */
    Platform::FileInfo fi;
    EXPECT_NE(int(Platform::getInfo(arc, fi)), int(E_OK));

    removeTree(root);
}

/* 未知算法名会被映射成 CRY_NONE（那是 F13 的范畴），顺带也必须走同一条拒绝 */
TEST(RegressF5, unknown_crypto_id_also_refused_when_password_given) {
    const std::string root = "treg_f5_unknown";
    const std::string arc  = Path::join(root, "out.dbkp");
    removeTree(root);
    writeText(Path::join(root, "a.txt"), "alpha");

    CMyPack p;
    PackOptions o;
    o.crypto   = static_cast<CryptoId>(999);   /* 越界/未知 */
    o.password = "pw";
    EXPECT_NE(int(p.pack(root, arc, o)), int(E_OK));

    removeTree(root);
}

/* 反面对照：不配口令时明文归档照旧合法（回归不能把老行为打死） */
TEST(RegressF5, no_password_plain_archive_still_allowed) {
    const std::string root = "treg_f5_nopw";
    const std::string arc  = Path::join(Path::join(root, "sub"), "out.dbkp");
    removeTree(root);
    Platform::makeDirTree(Path::join(root, "sub"));
    writeText(Path::join(root, "a.txt"), "alpha");

    CMyPack p;
    PackOptions o;
    o.crypto   = CRY_NONE;
    o.password = "";
    ASSERT_EQ(int(p.pack(root, arc, o)), int(E_OK));

    removeTree(root);
}

/* 正面对照：-c 与 -p 成对出现时加密归档正常工作，且能被同口令还原 */
TEST(RegressF5, crypto_with_password_round_trips) {
    const std::string root = "treg_f5_pair";
    const std::string arc  = Path::join(Path::join(root, "sub"), "out.dbkp");
    const std::string back = Path::join(root, "back");
    removeTree(root);
    Platform::makeDirTree(Path::join(root, "sub"));
    writeText(Path::join(root, "a.txt"), "alpha-bravo-charlie");

    CMyPack p;
    PackOptions o;
    o.crypto   = CRY_AES256_CBC;
    o.password = "S3cret!";
    ASSERT_EQ(int(p.pack(root, arc, o)), int(E_OK));

    UnpackOptions u;
    u.password = "S3cret!";
    u.overwrite = true;
    ASSERT_EQ(int(p.unpack(arc, back, u)), int(E_OK));

    /* 还原只带 -p（不带算法）是合法用法，不该被 F5 拒绝 */
    UnpackOptions v;
    v.password = "S3cret!";
    v.overwrite = true;
    const std::string back2 = Path::join(root, "back2");
    ASSERT_EQ(int(p.unpack(arc, back2, v)), int(E_OK));

    removeTree(root);
}
