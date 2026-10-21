/* ============================================================================
 *  test_filters.cpp  -- 尺寸/时间/路径/深度过滤与计数
 * ==========================================================================*/
#include "TestFramework.h"

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

const char* const kRoot = "ttest_filt";

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

class FiltFixture {
public:
    FiltFixture() {
        removeTree(kRoot);
        Platform::makeDirTree(kRoot);
        writeText(Path::join(kRoot, "a.txt"), std::string(200, 'a'));
        writeText(Path::join(kRoot, "b.log"), std::string(2000, 'b'));
        writeText(Path::join(kRoot, "c.tmp"), "tiny");
        writeText(Path::join(kRoot, "sub1/d.txt"), "deep file");
        writeText(Path::join(kRoot, "sub1/sub2/e.dat"), std::string(5000, 'e'));
    }
    ~FiltFixture() { removeTree(kRoot); }
};

TEST(Filter, SizeBounds) {
    FiltFixture f;
    CFileEnumerator en;
    FilterOptions big;
    big.minSize = 1000;
    std::vector<EnumeratedEntry> out;
    ASSERT_EQ(en.enumerateFiles(kRoot, big, out), E_OK);
    std::vector<std::string> p = relPaths(out);
    EXPECT_TRUE(has(p, "b.log"));
    EXPECT_TRUE(has(p, "sub1/sub2/e.dat"));
    EXPECT_FALSE(has(p, "a.txt"));
    EXPECT_FALSE(has(p, "c.tmp"));

    FilterOptions small;
    small.maxSize = 100;
    out.clear();
    ASSERT_EQ(en.enumerateFiles(kRoot, small, out), E_OK);
    EXPECT_TRUE(has(relPaths(out), "c.tmp"));
    EXPECT_FALSE(has(relPaths(out), "b.log"));
}

TEST(Filter, MtimeWindow) {
    FiltFixture f;
    CFileEnumerator en;
    const int64_t far = FilterOptions::parseTime("2099-01-01", nullptr);
    ASSERT_GT(far, 0);

    FilterOptions future;
    future.mtimeAfter = far;
    std::vector<EnumeratedEntry> out;
    ASSERT_EQ(en.enumerateFiles(kRoot, future, out), E_OK);
    for (size_t i = 0; i < out.size(); ++i) {
        if (out[i].info.type == FT_REGULAR) EXPECT_TRUE(false);   /* 文件都该被过滤 */
    }

    FilterOptions before;
    before.mtimeBefore = far;
    out.clear();
    ASSERT_EQ(en.enumerateFiles(kRoot, before, out), E_OK);
    EXPECT_TRUE(has(relPaths(out), "a.txt"));
}

TEST(Filter, ExcludePathPrunesSubtree) {
    FiltFixture f;
    CFileEnumerator en;
    FilterOptions opt;
    opt.excludePaths.push_back("sub1/*");
    std::vector<EnumeratedEntry> out;
    ASSERT_EQ(en.enumerateFiles(kRoot, opt, out), E_OK);
    std::vector<std::string> p = relPaths(out);
    EXPECT_FALSE(has(p, "sub1/sub2/e.dat"));
    EXPECT_TRUE(has(p, "a.txt"));
}

TEST(Filter, IncludePathKeepsParents) {
    FiltFixture f;
    CFileEnumerator en;
    FilterOptions opt;
    opt.includePaths.push_back("sub1/sub2/*");
    std::vector<EnumeratedEntry> out;
    ASSERT_EQ(en.enumerateFiles(kRoot, opt, out), E_OK);
    std::vector<std::string> p = relPaths(out);
    EXPECT_TRUE(has(p, "sub1/sub2/e.dat"));
    EXPECT_FALSE(has(p, "a.txt"));
    EXPECT_TRUE(has(p, "sub1"));             /* 为抵达 sub2，父目录必须放行 */
}

TEST(Filter, MaxDepth) {
    FiltFixture f;
    CFileEnumerator en;
    FilterOptions opt;
    opt.maxDepth = 1;
    std::vector<EnumeratedEntry> out;
    ASSERT_EQ(en.enumerateFiles(kRoot, opt, out), E_OK);
    std::vector<std::string> p = relPaths(out);
    EXPECT_TRUE(has(p, "sub1/d.txt"));
    EXPECT_FALSE(has(p, "sub1/sub2/e.dat"));
}

TEST(Filter, Counters) {
    FiltFixture f;
    CFileEnumerator en;
    FilterOptions opt;
    opt.nameGlobs.push_back("*.txt");
    std::vector<EnumeratedEntry> out;
    ASSERT_EQ(en.enumerateFiles(kRoot, opt, out), E_OK);
    EXPECT_GE(en.scanned(), 5);
    EXPECT_GE(en.filtered(), 1);
    EXPECT_EQ(en.errors(), 0);
}
