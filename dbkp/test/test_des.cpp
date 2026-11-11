/* ============================================================================
 *  test_des.cpp  -- 自实现 DES 的已知答案 / 3DES-EDE-CBC 往返 / 防篡改
 *
 *  单 DES 用两条公开 KAT 钉死核心（证明 S 盒与各置换表没抄错）；EDE 与 CBC 的
 *  正确性靠"分组可逆 + 随机 IV 往返 + 篡改/HMAC 拦截"分层保证。
 * ==========================================================================*/
#include "TestFramework.h"

#include <cstring>
#include <string>
#include <vector>

#include "Crypto/Algorithms.h"

using namespace DBKP;

TEST(Des, SingleBlockKnownAnswer) {
    /* 经典教科书向量：key=133457799BBCDFF1, pt=0123456789ABCDEF -> ct=85E813540F0AB405 */
    const uint8_t key[8] = {0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1};
    const uint8_t pt[8]  = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    const uint8_t expect[8] = {0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05};
    uint8_t ct[8], back[8];
    CDes des(key);
    des.encryptBlock(pt, ct);
    EXPECT_EQ(std::memcmp(ct, expect, 8), 0);
    des.decryptBlock(ct, back);
    EXPECT_EQ(std::memcmp(back, pt, 8), 0);
}

TEST(Des, WeakKeyAllZero) {
    /* 全零弱密钥自反：key=pt=0 -> ct=8CA64DE9C1B123A7 */
    uint8_t key[8] = {0}, pt[8] = {0}, ct[8], back[8];
    const uint8_t expect[8] = {0x8C, 0xA6, 0x4D, 0xE9, 0xC1, 0xB1, 0x23, 0xA7};
    CDes des(key);
    des.encryptBlock(pt, ct);
    EXPECT_EQ(std::memcmp(ct, expect, 8), 0);
    des.decryptBlock(ct, back);
    EXPECT_EQ(std::memcmp(back, pt, 8), 0);
}

static void makeKeys(const std::string& pw, uint8_t enc[32], uint8_t mac[32]) {
    uint8_t salt[16];
    for (int i = 0; i < 16; ++i) salt[i] = static_cast<uint8_t>(0x30 + i);
    deriveCipherKeys(pw, salt, 1000, enc, mac);
}

TEST(DesEdeCbc, RoundTripAllSizes) {
    uint8_t enc[32], mac[32];
    makeKeys("passphrase", enc, mac);
    for (int n = 0; n <= 40; ++n) {
        std::vector<uint8_t> plain(n, static_cast<uint8_t>(n + 1));
        std::vector<uint8_t> cipher, back;
        ASSERT_EQ(DesEdeCbcEncrypt(enc, mac, plain, cipher), E_OK);
        const std::size_t pad = 8 - (plain.size() % 8);   /* PKCS#7 总是补 1..8 */
        EXPECT_EQ(cipher.size(), plain.size() + pad + 8 + 12 + 16);
        ASSERT_EQ(DesEdeCbcDecrypt(enc, mac, cipher, back), E_OK);
        EXPECT_TRUE(back == plain);
    }
}

TEST(DesEdeCbc, RandomIvChangesCiphertext) {
    uint8_t enc[32], mac[32];
    makeKeys("k", enc, mac);
    std::vector<uint8_t> plain(64, 0x42), c1, c2, back;
    ASSERT_EQ(DesEdeCbcEncrypt(enc, mac, plain, c1), E_OK);
    ASSERT_EQ(DesEdeCbcEncrypt(enc, mac, plain, c2), E_OK);
    EXPECT_NE(c1, c2);                    /* 每次独立随机 IV */
    ASSERT_EQ(DesEdeCbcDecrypt(enc, mac, c2, back), E_OK);
    EXPECT_TRUE(back == plain);
}

TEST(DesEdeCbc, WrongPasswordAndTamper) {
    uint8_t enc[32], mac[32], bad1[32], bad2[32];
    makeKeys("secret", enc, mac);
    makeKeys("Secret", bad1, bad2);        /* 大小写不同 -> 派生密钥不同 */
    std::vector<uint8_t> plain(100, 0x77), cipher, back;
    ASSERT_EQ(DesEdeCbcEncrypt(enc, mac, plain, cipher), E_OK);
    /* 错口令：HMAC 先失败，绝不吐垃圾明文 */
    EXPECT_EQ(DesEdeCbcDecrypt(bad1, bad2, cipher, back), E_WRONG_PASSWORD);
    /* 篡改密文任意字节：encrypt-then-MAC 拦截 */
    std::vector<uint8_t> tampered = cipher;
    tampered[12 + 8 + 5] ^= 0x01;
    EXPECT_EQ(DesEdeCbcDecrypt(enc, mac, tampered, back), E_WRONG_PASSWORD);
    /* 篡改标签 */
    tampered = cipher;
    tampered[tampered.size() - 1] ^= 0xFF;
    EXPECT_EQ(DesEdeCbcDecrypt(enc, mac, tampered, back), E_WRONG_PASSWORD);
}

TEST(DesEdeCbc, FactoryProducesNamedCodec) {
    uint8_t salt[16];
    for (int i = 0; i < 16; ++i) salt[i] = static_cast<uint8_t>(i);
    IDataCodec* c = CryptoFactory::create(CRY_DESEDE_CBC, "pw", salt, 100);
    ASSERT_TRUE(c != nullptr);
    EXPECT_STREQ(c->name().c_str(), "des-ede-cbc");
    EXPECT_TRUE(c->needsPaddedInput());
    delete c;
    /* 空口令必须造不出编解码器 */
    EXPECT_EQ(CryptoFactory::create(CRY_DESEDE_CBC, "", salt, 100), nullptr);
}

TEST(DesEdeCbc, CrossRoundTripThroughCodec) {
    uint8_t salt[16];
    for (int i = 0; i < 16; ++i) salt[i] = static_cast<uint8_t>(0xC0 + i);
    IDataCodec* enc = CryptoFactory::create(CRY_DESEDE_CBC, "pw", salt, 512);
    IDataCodec* dec = CryptoFactory::create(CRY_DESEDE_CBC, "pw", salt, 512);
    ASSERT_TRUE(enc != nullptr && dec != nullptr);
    std::vector<uint8_t> plain;
    for (int i = 0; i < 500; ++i) plain.push_back(static_cast<uint8_t>(i * 7));
    std::vector<uint8_t> cipher, back;
    ASSERT_EQ(enc->encode(plain, cipher), E_OK);
    ASSERT_EQ(dec->decode(cipher, back), E_OK);
    EXPECT_TRUE(back == plain);
    delete enc; delete dec;
}
