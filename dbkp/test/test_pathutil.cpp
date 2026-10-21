/* ============================================================================
 *  test_pathutil.cpp  -- 路径归一化 / 相对化 / glob / 越界防护
 * ==========================================================================*/
#include "TestFramework.h"

#include <string>
#include <vector>

#include "Utils/PathUtil.h"

using DBKP::Path::normalize;
using DBKP::Path::join;
using DBKP::Path::relative;
using DBKP::Path::fileName;
using DBKP::Path::parentDir;
using DBKP::Path::extension;
using DBKP::Path::isAbsolute;
using DBKP::Path::isPathTraversalSafe;
using DBKP::Path::matchGlob;
using DBKP::Path::iequals;

TEST(PathUtil, Normalize) {
    EXPECT_STREQ(normalize("a/./b/../c/").c_str(), "a/c");
    EXPECT_STREQ(normalize("/x//y/").c_str(), "/x/y");
    EXPECT_STREQ(normalize("a\\b\\c").c_str(), "a/b/c");
    EXPECT_STREQ(normalize(".").c_str(), ".");
    EXPECT_STREQ(normalize("").c_str(), "");
    EXPECT_STREQ(normalize("../../a").c_str(), "../../a");
    EXPECT_STREQ(normalize("/../a").c_str(), "/a");     /* 绝对路径不被 .. 顶穿 */
    EXPECT_STREQ(normalize("a/b/../..").c_str(), ".");
}

TEST(PathUtil, JoinAndSplit) {
    EXPECT_STREQ(join("a", "b").c_str(), "a/b");
    EXPECT_STREQ(join("a/", "b").c_str(), "a/b");
    EXPECT_STREQ(join("", "b").c_str(), "b");
    EXPECT_STREQ(fileName("a/b/c.txt").c_str(), "c.txt");
    EXPECT_STREQ(parentDir("a/b/c.txt").c_str(), "a/b");
    EXPECT_STREQ(parentDir("/a").c_str(), "/");
    EXPECT_STREQ(extension("a/b/c.tar.gz").c_str(), ".gz");
    EXPECT_STREQ(extension("noext").c_str(), "");
    EXPECT_TRUE(isAbsolute("/a/b"));
    EXPECT_FALSE(isAbsolute("a/b"));
    EXPECT_FALSE(isAbsolute("./a"));      /* 以 ./ 开头仍是相对路径 */
    EXPECT_TRUE(isAbsolute("C:/x"));      /* Windows 盘符 */
}

TEST(PathUtil, Relative) {
    EXPECT_STREQ(relative("/data/src", "/data/src/a/b.txt").c_str(), "a/b.txt");
    EXPECT_STREQ(relative("/data/src", "/data/src").c_str(), "");
    EXPECT_STREQ(relative("/data/src", "/other/x").c_str(), "");
    EXPECT_STREQ(relative("/data/src/", "/data/src/x").c_str(), "x");
}

TEST(PathUtil, TraversalSafety) {
    EXPECT_TRUE(isPathTraversalSafe("a/b/c.txt"));
    EXPECT_TRUE(isPathTraversalSafe("a"));
    EXPECT_FALSE(isPathTraversalSafe("../a"));
    EXPECT_FALSE(isPathTraversalSafe("a/../../etc/passwd"));
    EXPECT_FALSE(isPathTraversalSafe("/etc/passwd"));
    EXPECT_FALSE(isPathTraversalSafe(""));
}

TEST(PathUtil, Glob) {
    EXPECT_TRUE(matchGlob("*.txt", "a.txt"));
    EXPECT_FALSE(matchGlob("*.txt", "a.md"));
    EXPECT_TRUE(matchGlob("a?c", "abc"));
    EXPECT_FALSE(matchGlob("a?c", "ac"));
    EXPECT_TRUE(matchGlob("[ab]c", "ac"));
    EXPECT_TRUE(matchGlob("[ab]c", "bc"));
    EXPECT_FALSE(matchGlob("[ab]c", "cc"));
    EXPECT_FALSE(matchGlob("[ab]c", "abc"));      /* 字符类只匹配 1 个字符 */
    EXPECT_TRUE(matchGlob("[!ab]c", "cc"));
    EXPECT_FALSE(matchGlob("[!ab]c", "ac"));
    EXPECT_TRUE(matchGlob("a[0-9]b", "a7b"));
    EXPECT_FALSE(matchGlob("a[0-9]b", "axb"));
    EXPECT_TRUE(matchGlob("log.*", "log.txt"));
    EXPECT_FALSE(matchGlob("log.*", "mylog.txt"));
    EXPECT_TRUE(matchGlob("*", "anything"));
    EXPECT_TRUE(matchGlob("*.tar.gz", "a.tar.gz"));
    EXPECT_TRUE(matchGlob("a*b*c", "aXXbYYc"));
    EXPECT_TRUE(matchGlob("src/**/*.cpp", "src/a/b/c.cpp"));
}

TEST(PathUtil, CaseInsensitiveCompare) {
    EXPECT_TRUE(iequals("ABC", "abc"));
    EXPECT_FALSE(iequals("ABCD", "abc"));
    EXPECT_FALSE(iequals("ab", "abc"));
}
