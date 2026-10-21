/* ============================================================================
 *  test_cipher.cpp  -- AES-256-CBC 与 ChaCha20 的已知答案 / 往返 / 防篡改
 * ==========================================================================*/
#include "TestFramework.h"

#include <cstring>
#include <string>
#include <vector>

#include "Crypto/Algorithms.h"

using namespace DBKP;

TEST(Aes256, SboxMatchesFips197) {
    EXPECT_EQ(CAes256::sbox(0x00), 0x63);
    EXPECT_EQ(CAes256::sbox(0x01), 0x7c);
    EXPECT_EQ(CAes256::sbox(0x53), 0xed);
    EXPECT_EQ(CAes256::sbox(0xff), 0x16);
}

TEST(Aes256, Fips197KnownAnswer) {
    uint8_t key[32], pt[16], ct[16], back[16];
    for (int i = 0; i < 32; ++i) key[i] = static_cast<uint8_t>(i);
    const uint8_t plain[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                               0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    std::memcpy(pt, plain, 16);
    CAes256 aes(key);
    aes.encryptBlock(pt, ct);
    /* 由独立实现（按 FIPS-197 文字规范另写的参考程序）交叉验证 */
    const uint8_t expect[16] = {0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
                                0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89};
    EXPECT_EQ(std::memcmp(ct, expect, 16), 0);
    aes.decryptBlock(ct, back);
    EXPECT_EQ(std::memcmp(back, pt, 16), 0);
}

static void makeKeys(const std::string& pw, uint8_t enc[32], uint8_t mac[32]) {
    uint8_t salt[16];
    for (int i = 0; i < 16; ++i) salt[i] = static_cast<uint8_t>(0xA0 + i);
    deriveCipherKeys(pw, salt, 1000, enc, mac);
}

TEST(Aes256Cbc, RoundTrip) {
    uint8_t enc[32], mac[32];
    makeKeys("passphrase", enc, mac);
    std::vector<uint8_t> plain;
    for (int i = 0; i < 1000; ++i) plain.push_back(static_cast<uint8_t>(i % 251));
    std::vector<uint8_t> cipher, back;
    ASSERT_EQ(AesCbcEncrypt(enc, mac, plain, cipher), E_OK);
    /* 12 头 + 16 IV + 进 16 取整的密文 + 16 标签 */
    EXPECT_EQ(cipher.size(), plain.size() + 16 + (16 - plain.size() % 16) + 16 + 12);
    ASSERT_EQ(AesCbcDecrypt(enc, mac, cipher, back), E_OK);
    EXPECT_TRUE(back == plain);
}

TEST(Aes256Cbc, EmptyAndBlockAlignedSizes) {
    uint8_t enc[32], mac[32];
    makeKeys("k", enc, mac);
    for (int n = 0; n <= 48; n += 16) {
        std::vector<uint8_t> plain(n, static_cast<uint8_t>(n));
        std::vector<uint8_t> cipher, back;
        ASSERT_EQ(AesCbcEncrypt(enc, mac, plain, cipher), E_OK);
        ASSERT_EQ(AesCbcDecrypt(enc, mac, cipher, back), E_OK);
        EXPECT_TRUE(back == plain);
    }
}

TEST(Aes256Cbc, WrongPasswordIsRejected) {
    uint8_t enc[32], mac[32], bad1[32], bad2[32];
    makeKeys("right", enc, mac);
    makeKeys("wrong", bad1, bad2);
    std::vector<uint8_t> plain(100, 0x5a), cipher, out;
    ASSERT_EQ(AesCbcEncrypt(enc, mac, plain, cipher), E_OK);
    EXPECT_EQ(AesCbcDecrypt(bad1, bad2, cipher, out), E_WRONG_PASSWORD);
}

TEST(Aes256Cbc, TamperedCiphertextIsRejected) {
    uint8_t enc[32], mac[32];
    makeKeys("pw", enc, mac);
    std::vector<uint8_t> plain(64, 0x11), cipher, out;
    ASSERT_EQ(AesCbcEncrypt(enc, mac, plain, cipher), E_OK);
    for (size_t i = 12; i < cipher.size(); i += 7) {
        std::vector<uint8_t> bad = cipher;
        bad[i] = static_cast<uint8_t>(bad[i] ^ 0x80);
        EXPECT_NE(AesCbcDecrypt(enc, mac, bad, out), E_OK);
    }
}

TEST(Aes256Cbc, SamePlaintextDifferentCiphertext) {
    uint8_t enc[32], mac[32];
    makeKeys("pw", enc, mac);
    std::vector<uint8_t> plain(32, 0), c1, c2;
    ASSERT_EQ(AesCbcEncrypt(enc, mac, plain, c1), E_OK);
    ASSERT_EQ(AesCbcEncrypt(enc, mac, plain, c2), E_OK);
    EXPECT_NE(c1, c2);                    /* 每文件独立随机 IV */
}

TEST(ChaCha20, KeystreamIsDeterministicAndNonZero) {
    uint8_t key[32], nonce[12];
    for (int i = 0; i < 32; ++i) key[i] = static_cast<uint8_t>(i);
    std::memset(nonce, 0, sizeof(nonce));
    std::vector<uint8_t> a(64, 0), b(64, 0), z(64, 0);
    CChaCha20(key, nonce, 0).crypt(a.data(), a.data(), a.size());
    CChaCha20(key, nonce, 0).crypt(b.data(), b.data(), b.size());
    EXPECT_TRUE(a == b);
    EXPECT_FALSE(a == z);
    std::vector<uint8_t> c(64, 0);
    nonce[11] = 1;
    CChaCha20(key, nonce, 0).crypt(c.data(), c.data(), c.size());
    EXPECT_NE(a, c);                      /* 换 nonce 必须换密钥流 */
}

TEST(ChaCha20, RoundTripAndWrongPassword) {
    uint8_t enc[32], mac[32], bad1[32], bad2[32];
    makeKeys("secret", enc, mac);
    makeKeys("Secret", bad1, bad2);
    std::vector<uint8_t> plain;
    for (int i = 0; i < 4096; ++i) plain.push_back(static_cast<uint8_t>(i * 31 + 7));
    std::vector<uint8_t> c1, c2, back;
    ASSERT_EQ(ChaChaEncrypt(enc, mac, plain, c1), E_OK);
    ASSERT_EQ(ChaChaEncrypt(enc, mac, plain, c2), E_OK);
    EXPECT_NE(c1, c2);
    ASSERT_EQ(ChaChaDecrypt(enc, mac, c1, back), E_OK);
    EXPECT_TRUE(back == plain);
    EXPECT_EQ(ChaChaDecrypt(bad1, bad2, c1, back), E_WRONG_PASSWORD);
}

TEST(ChaCha20, EmptyInputAndTruncatedStream) {
    uint8_t enc[32], mac[32];
    makeKeys("k", enc, mac);
    std::vector<uint8_t> plain, cipher, back;
    ASSERT_EQ(ChaChaEncrypt(enc, mac, plain, cipher), E_OK);
    ASSERT_EQ(ChaChaDecrypt(enc, mac, cipher, back), E_OK);
    EXPECT_TRUE(back.empty());
    /* 截断（少了标签）必须报错，不能悄悄返回部分内容 */
    std::vector<uint8_t> shortCipher = cipher;
    shortCipher.resize(cipher.size() - 1);
    EXPECT_NE(ChaChaDecrypt(enc, mac, shortCipher, back), E_OK);
}

TEST(CryptoFactory, UnknownAlgorithmReturnsNull) {
    uint8_t salt[16] = {0};
    EXPECT_EQ(CryptoFactory::create(CRY_NONE, "pw", salt, 100), nullptr);
    EXPECT_EQ(CryptoFactory::create(CRY_AES256_CBC, "", salt, 100), nullptr);
    EXPECT_NE(CryptoFactory::create(CRY_AES256_CBC, "pw", salt, 100), nullptr);
    EXPECT_NE(CryptoFactory::create(CRY_CHACHA20, "pw", salt, 100), nullptr);
    IDataCodec* c = CryptoFactory::create(CRY_AES256_CBC, "pw", salt, 100);
    EXPECT_STREQ(c->name().c_str(), "aes256-cbc");
    delete c;
    EXPECT_EQ(CompressionFactory::create(ALG_COUNT), nullptr);
}
