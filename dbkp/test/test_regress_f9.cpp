/* ============================================================================
 *  test_regress_f9.cpp  -- F9（归档目标落在源目录内导致递归膨胀）的命名回归测试
 *
 *  背景（整改清单 F9）：
 *    把箱写到被备份目录内部（如 bk backup root root\box.dbkp）时，扫描器会
 *    把上一轮的箱（以及本轮正在写的 .tmp）当作普通文件装进新箱：箱里套箱、
 *    体积每轮翻倍，永远备不完。
 *  修法：枚举时排除 dest 与 dest.tmp 的规范化绝对路径（既不入档也不下探）。
 * ==========================================================================*/
#include "TestFramework.h"

#include <string>
#include <vector>

#include "Enumerator/FileEnumerator.h"
#include "Pack/MyPack.h"
#include "Platform/FS.h"
#include "Utils/PathUtil.h"
#include "Utils/SimpleFile.h"

using namespace DBKP;

namespace {

std::string absOf(const std::string& rel) {
    std::string cur;
    if (Platform::currentDir(cur) != E_OK) cur = ".";
    return Path::join(cur, rel);
}

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

bool anyPathContains(const std::vector<FileRecord>& recs, const std::string& needle) {
    for (size_t i = 0; i < recs.size(); ++i)
        if (recs[i].path.find(needle) != std::string::npos) return true;
    return false;
}

} /* anonymous namespace */

/* 验收①：同一 dest 连跑两次（第二次 --force），新箱 list 不得含旧箱记录 */
TEST(RegressF9, archive_inside_source_excluded_second_run) {
    const std::string root  = "treg_f9_inside";
    const std::string arc   = Path::join(root, "box.dbkp");   /* 箱就在源里 */
    removeTree(root);
    writeText(Path::join(root, "a.txt"), "alpha");
    writeText(Path::join(root, "sub/b.txt"), "bravo");

    CMyPack p1;
    PackOptions o1;
    ASSERT_EQ(int(p1.pack(root, arc, o1)), int(E_OK));

    CMyPack p2;
    PackOptions o2;
    o2.force = true;                     /* 第二次：目标已存在，--force */
    ASSERT_EQ(int(p2.pack(root, arc, o2)), int(E_OK));

    std::vector<FileRecord> recs;
    ASSERT_EQ(int(p2.list(arc, recs)), int(E_OK));
    EXPECT_FALSE(anyPathContains(recs, "box.dbkp"));
    EXPECT_FALSE(anyPathContains(recs, ".tmp"));
    /* 正常内容仍在 */
    EXPECT_TRUE(anyPathContains(recs, "a.txt"));
    EXPECT_TRUE(anyPathContains(recs, "sub/b.txt"));

    removeTree(root);
}

/* 体积不膨胀：第二轮箱大小与第一轮同量级（旧实现里第二轮会把整只旧箱装进去） */
TEST(RegressF9, no_size_bloat_across_runs) {
    const std::string root = "treg_f9_bloat";
    const std::string arc  = Path::join(Path::join(root, "inner"), "box.dbkp");
    removeTree(root);
    Platform::makeDirTree(Path::join(root, "inner"));   /* pack 不代建归档父目录 */
    writeText(Path::join(root, "data.txt"), std::string(4096, 'D'));

    CMyPack p;
    PackOptions o;
    ASSERT_EQ(int(p.pack(root, arc, o)), int(E_OK));
    int64_t s1 = 0;
    { Platform::FileInfo fi; ASSERT_EQ(int(Platform::getInfo(arc, fi)), int(E_OK));
      s1 = fi.size; }

    o.force = true;
    ASSERT_EQ(int(p.pack(root, arc, o)), int(E_OK));
    int64_t s2 = 0;
    { Platform::FileInfo fi; ASSERT_EQ(int(Platform::getInfo(arc, fi)), int(E_OK));
      s2 = fi.size; }

    /* 允许小幅波动，但绝不能装进整只旧箱（旧实现 s2 >= 2*s1） */
    EXPECT_TRUE(s2 < s1 + s1 / 2);

    removeTree(root);
}

/* 枚举器层：setExcludedAbsPaths 命中的绝对路径既不入档也不下探 */
TEST(RegressF9, enumerator_skips_excluded_paths) {
    const std::string root = "treg_f9_enum";
    const std::string skip = absOf(Path::join(root, "skipme"));
    removeTree(root);
    writeText(Path::join(root, "keep.txt"), "keep");
    writeText(Path::join(skip, "inside.txt"), "should-not-appear");

    CFileEnumerator en;
    std::set<std::string> ex;
    ex.insert(Path::normalize(skip));
    en.setExcludedAbsPaths(ex);
    FilterOptions f;
    std::vector<EnumeratedEntry> out;
    ASSERT_EQ(int(en.enumerateFiles(root, f, out)), int(E_OK));
    for (size_t i = 0; i < out.size(); ++i) {
        EXPECT_TRUE(out[i].relPath.find("skipme") == std::string::npos);
    }
    removeTree(root);
}
