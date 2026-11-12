/* ============================================================================
 *  test_regress_f2.cpp  -- F2（copy 模式 source==dest / dest 在 source 内自毁）
 *
 *  背景（整改清单 F2）：
 *    bk backup selfdir selfdir（目标不是 .dbkp，走 copy 模式）时，streamCopy
 *    以 CREATE|TRUNC 打开目标 —— 目标与源是同一个文件，先把源清成 0 字节，
 *    随后 verify 拿同一文件跟自己比恒等，于是报"备份成功"，数据实际没了。
 *  修法：CBackupEngine::run 在分派前做重叠检查：
 *    ① 源与目标解析后同一路径 —— 任何模式都拒绝；
 *    ② 目标在源目录内部 —— 只在 copy 模式拒绝（归档模式的目标只是一个新文件，
 *       且 F9 已把它排除出扫描）。
 * ==========================================================================*/
#include "TestFramework.h"

#include <string>
#include <vector>

#include "Backup/BackupEngine.h"
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

int64_t fileSizeOf(const std::string& abs) {
    Platform::FileInfo fi;
    if (DBKP_IS_ERR(Platform::getInfo(abs, fi))) return -1;
    return fi.size;
}

} /* anonymous namespace */

/* 核心回归：source==dest 的 copy 备份必须被拒绝，且源文件一个字节都不能少 */
TEST(RegressF2, copy_same_source_and_dest_refused) {
    const std::string root = "treg_f2_same";
    const std::string file = Path::join(root, "f.txt");
    removeTree(root);
    writeText(file, "PRECIOUS-DATA");

    CBackupEngine eng;
    BackupOptions o;
    o.source      = root;
    o.destination = root;              /* 目标是目录 -> MODE_AUTO 解析成 copy */
    o.verifyAfter = false;
    EXPECT_EQ(int(eng.run(o)), int(E_INVALID_PARAMETER));
    EXPECT_FALSE(eng.lastError().empty());

    /* 拒绝必须发生在任何写入之前：源内容完好 */
    EXPECT_EQ(fileSizeOf(file), (int64_t)sizeof("PRECIOUS-DATA") - 1);

    removeTree(root);
}

/* 显式 MODE_COPY 也要拦住（绕开 AUTO 解析的路径同样受保护） */
TEST(RegressF2, explicit_copy_mode_same_path_refused) {
    const std::string root = "treg_f2_explicit";
    const std::string file = Path::join(root, "keep.bin");
    removeTree(root);
    writeText(file, std::string(2048, 'K'));

    CBackupEngine eng;
    BackupOptions o;
    o.source      = root;
    o.destination = root;
    o.mode        = MODE_COPY;
    o.verifyAfter = false;
    EXPECT_EQ(int(eng.run(o)), int(E_INVALID_PARAMETER));
    EXPECT_EQ(fileSizeOf(file), (int64_t)2048);

    removeTree(root);
}

/* 目标在源内部（copy 模式）：会边扫边写自己，同样拒绝 */
TEST(RegressF2, copy_dest_inside_source_refused) {
    const std::string root = "treg_f2_inside";
    const std::string dst  = Path::join(root, "mirror");
    removeTree(root);
    writeText(Path::join(root, "a.txt"), "alpha");

    CBackupEngine eng;
    BackupOptions o;
    o.source      = root;
    o.destination = dst;               /* 无 .dbkp 后缀 -> copy */
    o.verifyAfter = false;
    EXPECT_EQ(int(eng.run(o)), int(E_INVALID_PARAMETER));
    EXPECT_TRUE(eng.lastError().find("inside") != std::string::npos);

    removeTree(root);
}

/* 反面对照①：copy 到兄弟目录是合法用法，不能被打死 */
TEST(RegressF2, copy_to_sibling_dir_still_works) {
    const std::string root = "treg_f2_ok";
    const std::string src  = Path::join(root, "src");
    const std::string dst  = Path::join(root, "dst");
    removeTree(root);
    writeText(Path::join(src, "a.txt"), "alpha");
    writeText(Path::join(src, "sub/b.txt"), "bravo");

    CBackupEngine eng;
    BackupOptions o;
    o.source      = src;
    o.destination = dst;
    o.verifyAfter = true;
    ASSERT_EQ(int(eng.run(o)), int(E_OK));
    EXPECT_EQ(fileSizeOf(Path::join(dst, "a.txt")), (int64_t)5);

    removeTree(root);
}

/* 反面对照②：归档模式即使箱放在源目录里也允许（由 F9 负责排除，不属 F2） */
TEST(RegressF2, archive_mode_dest_inside_source_still_allowed) {
    const std::string root = "treg_f2_arch";
    const std::string arc  = Path::join(Path::join(root, "in"), "box.dbkp");
    removeTree(root);
    Platform::makeDirTree(Path::join(root, "in"));
    writeText(Path::join(root, "a.txt"), "alpha");

    CBackupEngine eng;
    BackupOptions o;
    o.source      = root;
    o.destination = arc;
    o.verifyAfter = false;
    ASSERT_EQ(int(eng.run(o)), int(E_OK));
    EXPECT_TRUE(fileSizeOf(arc) > 0);

    removeTree(root);
}
