/* ============================================================================
 *  test_options.cpp  -- FilterOptions 的参数解析（CLI 友好性）
 * ==========================================================================*/
#include "TestFramework.h"

#include <ctime>
#include <string>

#include "Enumerator/FilterOptions.h"

using DBKP::FilterOptions;

TEST(FilterOptions, SizeParsing) {
    bool ok = false;
    EXPECT_EQ(FilterOptions::parseSize("4096", &ok), 4096);
    EXPECT_TRUE(ok);
    EXPECT_EQ(FilterOptions::parseSize("1KB", &ok), 1024);
    EXPECT_EQ(FilterOptions::parseSize("2mb", &ok), 2 * 1024 * 1024);
    EXPECT_EQ(FilterOptions::parseSize("1G", &ok), 1024 * 1024 * 1024);
    EXPECT_EQ(FilterOptions::parseSize("1.5K", &ok), 1536);
    EXPECT_EQ(FilterOptions::parseSize("junk", &ok), -1);
    EXPECT_FALSE(ok);
    EXPECT_EQ(FilterOptions::parseSize("", &ok), -1);
}

TEST(FilterOptions, TimeParsing) {
    bool ok = false;
    const int64_t now = static_cast<int64_t>(std::time(nullptr));
    const int64_t rel = FilterOptions::parseTime("7d", &ok);
    EXPECT_TRUE(ok);
    EXPECT_LT(rel, now);
    EXPECT_GT(rel, now - 9 * 86400);
    EXPECT_EQ(FilterOptions::parseTime("2h", &ok), FilterOptions::parseTime("120m", &ok));
    const int64_t abs = FilterOptions::parseTime("2024-01-02", &ok);
    EXPECT_TRUE(ok);
    EXPECT_GT(abs, 0);
    EXPECT_EQ(FilterOptions::parseTime("nonsense", &ok), 0);
}

TEST(FilterOptions, TypeSpec) {
    FilterOptions a;
    EXPECT_TRUE(a.setTypeSpec("-DL"));
    EXPECT_EQ(a.typeDeny.size(), 2u);
    EXPECT_TRUE(a.typeAllow.empty());

    FilterOptions b;
    EXPECT_TRUE(b.setTypeSpec("regular,dir"));
    EXPECT_EQ(b.typeAllow.size(), 2u);

    FilterOptions c;
    EXPECT_FALSE(c.setTypeSpec(""));

    FilterOptions d;
    EXPECT_TRUE(d.setTypeSpec("-bogus"));   /* 非法类型名被忽略，但语法合法 */
    EXPECT_TRUE(d.typeDeny.empty());
}

TEST(FilterOptions, DescribeAndIsEmpty) {
    FilterOptions o;
    EXPECT_TRUE(o.isEmpty());
    EXPECT_STREQ(o.describe().c_str(), "none");

    o.nameGlobs.push_back("*.txt");
    o.excludePaths.push_back("build/*");
    o.minSize = 10;
    o.followSymlinks = true;
    EXPECT_FALSE(o.isEmpty());
    const std::string d = o.describe();
    EXPECT_NE(d.find("name=1"), std::string::npos);
    EXPECT_NE(d.find("exclude-path=1"), std::string::npos);
    EXPECT_NE(d.find("size=["), std::string::npos);
    EXPECT_NE(d.find("follow-symlink"), std::string::npos);
}

TEST(Defs, NameTablesRoundTrip) {
    using namespace DBKP;
    EXPECT_STREQ(algorithmName(ALG_HUFFMAN), "huffman");
    EXPECT_EQ(algorithmFromName("huffman"), ALG_HUFFMAN);
    EXPECT_EQ(algorithmFromName("lz77"), ALG_LZ77);
    EXPECT_EQ(algorithmFromName("lzhuff"), ALG_LZHUFF);
    EXPECT_EQ(algorithmFromName("unknown-alg"), ALG_NONE);
    EXPECT_EQ(cryptoFromName("aes256"), CRY_AES256_CBC);
    EXPECT_EQ(cryptoFromName("chacha20"), CRY_CHACHA20);
    EXPECT_STREQ(cryptoName(CRY_NONE), "none");
    EXPECT_STREQ(errCodeToString(E_DESTINATION_NOT_EMPTY),
                 "destination is not an empty directory");
    EXPECT_STREQ(fileTypeToDesc(FT_SYMLINK), "symbolic link");
    EXPECT_TRUE(DBKP_IS_ERR(E_FILE_OPEN_FAIL));
    EXPECT_FALSE(DBKP_IS_ERR(E_OK));
    EXPECT_EQ(DBKP_FAIL(E_OK, E_INTERNAL), E_INTERNAL);
    EXPECT_EQ(DBKP_FAIL(E_FILE_READ_FAIL, E_INTERNAL), E_FILE_READ_FAIL);
}
