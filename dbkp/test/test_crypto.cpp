/* ============================================================================
 *  test_crypto.cpp  -- 自实现 SHA-256 / HMAC / PBKDF2 的已知答案测试
 *  （能自洽不等于正确，因此这里全部对照标准文档 / Python hashlib 的结果）
 * ==========================================================================*/
#include "TestFramework.h"

#include <cstring>
#include <string>
#include <vector>

#include "Crypto/Sha256.h"

using DBKP::CSha256;

TEST(Sha256, KnownVectors) {
    struct { const char* text; size_t len; const char* hex; } cases[] = {
        {"",       0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"abc",    3, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {"hello",  5, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint8_t d[32];
        CSha256::hash(cases[i].text, cases[i].len, d);
        EXPECT_STREQ(CSha256::toHex(d).c_str(), cases[i].hex);
    }
}

TEST(Sha256, PaddingBoundaries) {
    /* 56 / 64 字节分别让填充落在"新块"与"再下一个新块"，最易写错 */
    uint8_t d[32];
    const std::string a56(56, 'a'), a64(64, 'a');
    CSha256::hash(a56.data(), a56.size(), d);
    EXPECT_STREQ(CSha256::toHex(d).c_str(),
                 "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a");
    CSha256::hash(a64.data(), a64.size(), d);
    EXPECT_STREQ(CSha256::toHex(d).c_str(),
                 "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb");
}

TEST(Sha256, StreamingEqualsOneShot) {
    std::vector<uint8_t> data;
    for (int i = 0; i < 1000; ++i) data.push_back(static_cast<uint8_t>(i & 0xFF));
    uint8_t one[32], acc[32];
    CSha256::hash(data.data(), data.size(), one);
    CSha256 h;
    for (size_t i = 0; i < data.size(); ++i) h.update(data.data() + i, 1);
    h.finish(acc);
    EXPECT_EQ(std::memcmp(one, acc, 32), 0);
}

TEST(HmacSha256, Rfc4231TestCase1) {
    uint8_t key[20];
    std::memset(key, 0x0b, sizeof(key));
    uint8_t mac[32];
    CSha256::hmac(key, sizeof(key), "Hi There", 8, mac);
    EXPECT_STREQ(CSha256::toHex(mac).c_str(),
                 "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
}

TEST(HmacSha256, LongKeyIsHashedFirst) {
    std::vector<uint8_t> key(200, 0x0b);
    uint8_t a[32], b[32];
    CSha256::hmac(key.data(), key.size(), "abc", 3, a);
    CSha256::hmac(key.data(), key.size(), "abd", 3, b);
    EXPECT_NE(std::memcmp(a, b, 32), 0);
}

TEST(Pbkdf2, KnownVectors) {
    const std::string salt = "salt";
    const uint8_t* s = reinterpret_cast<const uint8_t*>(salt.data());
    uint8_t dk[32];
    CSha256::pbkdf2("password", s, salt.size(), 1, 32, dk);
    EXPECT_STREQ(CSha256::toHex(dk).c_str(),
                 "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
    CSha256::pbkdf2("password", s, salt.size(), 2, 32, dk);
    EXPECT_STREQ(CSha256::toHex(dk).c_str(),
                 "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43");
    CSha256::pbkdf2("password", s, salt.size(), 4096, 32, dk);
    EXPECT_STREQ(CSha256::toHex(dk).c_str(),
                 "db6e32560d10581bd85b575ee62a5673df187a9f83f4d329ab83e39ef09880ee");
}

TEST(Pbkdf2, MultiBlockDerivedKey) {
    const std::string salt = "salt";
    const uint8_t* s = reinterpret_cast<const uint8_t*>(salt.data());
    uint8_t dk64[64], dk32[32];
    CSha256::pbkdf2("password", s, salt.size(), 2, 64, dk64);
    CSha256::pbkdf2("password", s, salt.size(), 2, 32, dk32);
    EXPECT_EQ(std::memcmp(dk64, dk32, 32), 0);            /* 第一个块必须一致 */
    bool nonZero = false;
    for (int i = 32; i < 64; ++i) if (dk64[i]) nonZero = true;
    EXPECT_TRUE(nonZero);
}

TEST(Pbkdf2, SaltChangesResult) {
    uint8_t a[32], b[32];
    const std::string s1 = "salt1", s2 = "salt2";
    CSha256::pbkdf2("same", reinterpret_cast<const uint8_t*>(s1.data()), 5, 100, 32, a);
    CSha256::pbkdf2("same", reinterpret_cast<const uint8_t*>(s2.data()), 5, 100, 32, b);
    EXPECT_NE(std::memcmp(a, b, 32), 0);
}
