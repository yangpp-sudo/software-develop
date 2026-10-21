/* ============================================================================
 *  test_enumerator.cpp  -- 先序遍历与类型/名称过滤
 * ==========================================================================*/
#include "TestFramework.h"

#include <cstdio>
#include <ctime>
#include <string>
#include <vector>

#include "Enumerator/FileEnumerator.h"
#include "Enumerator/FilterOptions.h"
#include "Platform/FS.h"
#include "Utils/PathUtil.h"
#include "Utils/SimpleFile.h"

using namespace DBKP;

namespace {

const char* const kRoot = "ttest_enum";

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

std::vector<std::string> relPaths(const std::vector<EnumeratedEntry>& v) {
    std::vector<std::string> out;
    for (size_t i = 0; i < v.size(); ++i) out.push_back(v[i].relPath);
    return out;
}

bool has(const std::vector<std::string>& v, const std::string& s) {
    for (size_t i = 0; i < v.size(); ++i) if (v[i] == s) return true;
    return false;
}

} /* anonymous namespace */

/** RAII：每个用例自建自毁样例目录 */
class EnumFixture {
public:
    EnumFixture() {
        removeTree(kRoot);
        Platform::makeDirTree(kRoot);
        writeText(Path::join(kRoot, "a.txt"), std::string(200, 'a'));
        writeText(Path::join(kRoot, "b.log"), std::string(2000, 'b'));
        writeText(Path::join(kRoot, "c.tmp"), "tiny");
        writeText(Path::join(kRoot, "sub1/d.txt"), "deep file");
        writeText(Path::join(kRoot, "sub1/sub2/e.dat"), std::string(5000, 'e'));
        Platform::makeDirTree(Path::join(kRoot, "emptydir"));
    }
    ~EnumFixture() { removeTree(kRoot); }
};

TEST(Enumerator, PreOrderIncludesSelfAndAllChildren) {
    EnumFixture f;
    CFileEnumerator en;
    FilterOptions none;
    std::vector<EnumeratedEntry> out;
    ASSERT_EQ(en.enumerateFiles(kRoot, none, out), E_OK);
    std::vector<std::string> p = relPaths(out);
    ASSERT_GT(p.size(), 0u);
    EXPECT_EQ(p[0], std::string("."));               /* 根目录最先 */
    EXPECT_TRUE(has(p, "a.txt"));
    EXPECT_TRUE(has(p, "sub1"));
    EXPECT_TRUE(has(p, "sub1/d.txt"));
    EXPECT_TRUE(has(p, "sub1/sub2/e.dat"));
    EXPECT_TRUE(has(p, "emptydir"));
    EXPECT_EQ(out.size(), 9u);                       /* . + 5 文件 + 3 目录 */

    int idxSub1 = -1, idxDeep = -1;
    for (size_t i = 0; i < p.size(); ++i) {
        if (p[i] == "sub1") idxSub1 = static_cast<int>(i);
        if (p[i] == "sub1/sub2/e.dat") idxDeep = static_cast<int>(i);
    }
    EXPECT_GT(idxDeep, idxSub1);                     /* 子项在父目录之后 */
}

TEST(Enumerator, RejectsNonDirectorySource) {
    EnumFixture f;
    CFileEnumerator en;
    FilterOptions none;
    std::vector<EnumeratedEntry> out;
    EXPECT_EQ(en.enumerateFiles(Path::join(kRoot, "a.txt"), none, out), E_INVALID_PARAMETER);
    EXPECT_EQ(en.enumerateFiles("no_such_dir_xyz", none, out), E_SOURCE_NOT_FOUND);
}

TEST(Enumerator, MetadataIsCaptured) {
    EnumFixture f;
    CFileEnumerator en;
    FilterOptions none;
    std::vector<EnumeratedEntry> out;
    ASSERT_EQ(en.enumerateFiles(kRoot, none, out), E_OK);
    for (size_t i = 0; i < out.size(); ++i) {
        const EnumeratedEntry& e = out[i];
        if (e.relPath == "b.log") {
            EXPECT_EQ(e.info.type, FT_REGULAR);
            EXPECT_EQ(e.info.size, 2000);
            EXPECT_GT(e.info.mtimeSec, 0);
            EXPECT_NE(e.info.ino, 0u);
            EXPECT_EQ(e.info.nlink >= 1, true);
        }
        if (e.relPath == "emptydir") EXPECT_EQ(e.info.type, FT_DIR);
    }
}

TEST(Enumerator, TypeFilter) {
    EnumFixture f;
    CFileEnumerator en;
    FilterOptions noDirs;
    ASSERT_TRUE(noDirs.setTypeSpec("-D"));           /* 排除目录条目 */
    std::vector<EnumeratedEntry> out;
    ASSERT_EQ(en.enumerateFiles(kRoot, noDirs, out), E_OK);
    for (size_t i = 0; i < out.size(); ++i) EXPECT_NE(out[i].info.type, FT_DIR);
    EXPECT_EQ(out.size(), 5u);

    FilterOptions onlyDirs;
    ASSERT_TRUE(onlyDirs.setTypeSpec("dir"));
    out.clear();
    ASSERT_EQ(en.enumerateFiles(kRoot, onlyDirs, out), E_OK);
    for (size_t i = 0; i < out.size(); ++i) EXPECT_EQ(out[i].info.type, FT_DIR);
}

TEST(Enumerator, NameGlobFilter) {
    EnumFixture f;
    CFileEnumerator en;
    FilterOptions opt;
    opt.nameGlobs.push_back("*.txt");
    std::vector<EnumeratedEntry> out;
    ASSERT_EQ(en.enumerateFiles(kRoot, opt, out), E_OK);
    std::vector<std::string> p = relPaths(out);
    EXPECT_TRUE(has(p, "a.txt"));
    EXPECT_TRUE(has(p, "sub1/d.txt"));
    EXPECT_FALSE(has(p, "b.log"));
    EXPECT_FALSE(has(p, "c.tmp"));

    FilterOptions opt2;
    opt2.nameRejects.push_back("*.tmp");
    out.clear();
    ASSERT_EQ(en.enumerateFiles(kRoot, opt2, out), E_OK);
    EXPECT_FALSE(has(relPaths(out), "c.tmp"));
}
