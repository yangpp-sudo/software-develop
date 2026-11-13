/* ============================================================================
 *  test_wb_crypto.cpp  -- 批次10 白盒单测 B6：三种加密算法的往返 / 错口令 / KDF
 *
 *  覆盖目标（白盒，逐分支）：
 *    CCryptoCodec::encode/decode  src/Crypto/CryptoCodecs.cpp:27 / :32
 *      -> AesCbcEncrypt/Decrypt   src/Crypto/Aes.cpp
 *      -> ChaChaEncrypt/Decrypt   src/Crypto/ChaCha20.cpp
 *      -> DesEdeCbcEncrypt/Decrypt src/Crypto/Des.cpp
 *    CryptoFactory::create        src/Codec/CodecFactory.cpp:33（switch 全分支）
 *    deriveCipherKeys / fillRandom src/Crypto/CryptoCodecs.cpp / Algorithms
 *  判据：语句覆盖 + 分支覆盖。尺寸专门挑 1B / 15B / 16B / 17B 命中 CBC 的
 *  PKCS#7 补齐分支（15=不足一块、16=刚好一块要补整块、17=一块有余）；
 *  错口令命中 encrypt-then-HMAC 的标签比对失败分支（E_WRONG_PASSWORD）；
 *  截断命中 E_TRUNCATED_ARCHIVE 分支。
 * ==========================================================================*/
#include "TestFramework.h"

#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "Codec/DataCodec.h"
#include "Common/Defs.h"
#include "Crypto/Algorithms.h"

using namespace DBKP;

namespace {

const uint8_t kSalt[16] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
};

std::vector<uint8_t> pattern(std::size_t n) {
    std::vector<uint8_t> v(n);
    for (size_t i = 0; i < n; ++i) v[i] = uint8_t((i * 31 + 7) & 0xFF);
    return v;
}

/* 加密往返：同口令 enc->dec 必须逐字节还原；密文必须与明文不同且含 16B 标签 */
void cryptoRoundTrip(CryptoId id, std::size_t n) {
    const std::string pw = "correct horse battery staple";
    std::vector<uint8_t> plain = pattern(n);
    std::unique_ptr<IDataCodec> enc(CryptoFactory::create(id, pw, kSalt, 4096));
    std::unique_ptr<IDataCodec> dec(CryptoFactory::create(id, pw, kSalt, 4096));
    ASSERT_TRUE(enc.get() != nullptr);
    ASSERT_TRUE(dec.get() != nullptr);

    std::vector<uint8_t> ct, back;
    ASSERT_EQ(int(enc->encode(plain, ct)), int(E_OK));
    if (n > 0) {
        /* 密文长度 = 头 + IV/nonce + 密文体 + 16B HMAC 标签，必然大于明文 */
        EXPECT_GT((int)ct.size(), (int)plain.size());
        EXPECT_NE(0, std::memcmp(ct.data(), plain.data(),
                                 plain.size() < ct.size() ? plain.size() : ct.size()));
    }
    ASSERT_EQ(int(dec->decode(ct, back)), int(E_OK));
    ASSERT_EQ((int)back.size(), (int)plain.size());
    if (n) EXPECT_EQ(0, std::memcmp(back.data(), plain.data(), n));
}

/* 错口令必须被拒（encrypt-then-HMAC 的标签校验分支） */
void wrongPasswordRejected(CryptoId id) {
    const std::string good = "pw-right";
    std::vector<uint8_t> plain = pattern(100);
    std::unique_ptr<IDataCodec> enc(CryptoFactory::create(id, good, kSalt, 4096));
    std::unique_ptr<IDataCodec> bad(CryptoFactory::create(id, "pw-wrong", kSalt, 4096));
    ASSERT_TRUE(enc.get() != nullptr);
    ASSERT_TRUE(bad.get() != nullptr);
    std::vector<uint8_t> ct, out;
    ASSERT_EQ(int(enc->encode(plain, ct)), int(E_OK));
    ErrCode e = bad->decode(ct, out);
    EXPECT_EQ(int(e), int(E_WRONG_PASSWORD));
}

/* 密文被改一个 bit 也必须被拒（同一标签分支，与错口令不同的触发路径） */
void tamperedCiphertextRejected(CryptoId id) {
    const std::string pw = "pw";
    std::vector<uint8_t> plain = pattern(64);
    std::unique_ptr<IDataCodec> enc(CryptoFactory::create(id, pw, kSalt, 4096));
    std::unique_ptr<IDataCodec> dec(CryptoFactory::create(id, pw, kSalt, 4096));
    ASSERT_TRUE(enc.get() != nullptr);
    std::vector<uint8_t> ct, out;
    ASSERT_EQ(int(enc->encode(plain, ct)), int(E_OK));
    /* 翻转载荷中部一个 bit（避开头部，头部不符另有错误码） */
    ct[ct.size() / 2] ^= 0x01;
    ErrCode e = dec->decode(ct, out);
    EXPECT_NE(int(e), int(E_OK));
}

} /* anonymous namespace */

/* ---------------------------------------------- 3 算法 × 3 尺寸往返（9 条） */
TEST(WbCryptoAes, roundTrip1B)   { cryptoRoundTrip(CRY_AES256_CBC, 1); }
TEST(WbCryptoAes, roundTrip17B)  { cryptoRoundTrip(CRY_AES256_CBC, 17); }
TEST(WbCryptoAes, roundTrip1000B){ cryptoRoundTrip(CRY_AES256_CBC, 1000); }

TEST(WbCryptoChaCha, roundTrip1B)   { cryptoRoundTrip(CRY_CHACHA20, 1); }
TEST(WbCryptoChaCha, roundTrip17B)  { cryptoRoundTrip(CRY_CHACHA20, 17); }
TEST(WbCryptoChaCha, roundTrip1000B){ cryptoRoundTrip(CRY_CHACHA20, 1000); }

TEST(WbCrypto3Des, roundTrip1B)   { cryptoRoundTrip(CRY_DESEDE_CBC, 1); }
TEST(WbCrypto3Des, roundTrip17B)  { cryptoRoundTrip(CRY_DESEDE_CBC, 17); }
TEST(WbCrypto3Des, roundTrip1000B){ cryptoRoundTrip(CRY_DESEDE_CBC, 1000); }

/* ------------------------------------------------------ 3 算法错口令（3 条） */
TEST(WbCryptoAes, wrongPasswordRejected)   { wrongPasswordRejected(CRY_AES256_CBC); }
TEST(WbCryptoChaCha, wrongPasswordRejected){ wrongPasswordRejected(CRY_CHACHA20); }
TEST(WbCrypto3Des, wrongPasswordRejected)  { wrongPasswordRejected(CRY_DESEDE_CBC); }

/* ------------------------------------------------ 密文篡改（3 算法各一条） */
TEST(WbCryptoAes, tamperedCiphertextRejected)   { tamperedCiphertextRejected(CRY_AES256_CBC); }
TEST(WbCryptoChaCha, tamperedCiphertextRejected){ tamperedCiphertextRejected(CRY_CHACHA20); }
TEST(WbCrypto3Des, tamperedCiphertextRejected)  { tamperedCiphertextRejected(CRY_DESEDE_CBC); }

/* ------------------------------------------------------------ CBC 边界尺寸 */
/* 0B / 15B / 16B：PKCS#7 的三条补齐分支（空、不足一块、刚好一块要补整块） */
TEST(WbCryptoAes, cbcPaddingBoundaries) {
    cryptoRoundTrip(CRY_AES256_CBC, 0);
    cryptoRoundTrip(CRY_AES256_CBC, 15);
    cryptoRoundTrip(CRY_AES256_CBC, 16);
}
TEST(WbCrypto3Des, cbcPaddingBoundaries) {
    cryptoRoundTrip(CRY_DESEDE_CBC, 0);
    cryptoRoundTrip(CRY_DESEDE_CBC, 7);
    cryptoRoundTrip(CRY_DESEDE_CBC, 8);
}

/* 截断的密文必须报错而不是越界读（decode 的长度检查分支） */
TEST(WbCryptoAes, truncatedCiphertextRejected) {
    std::unique_ptr<IDataCodec> enc(CryptoFactory::create(CRY_AES256_CBC, "p", kSalt, 4096));
    std::unique_ptr<IDataCodec> dec(CryptoFactory::create(CRY_AES256_CBC, "p", kSalt, 4096));
    ASSERT_TRUE(enc.get() != nullptr);
    std::vector<uint8_t> ct, out;
    ASSERT_EQ(int(enc->encode(pattern(80), ct)), int(E_OK));
    ct.resize(ct.size() / 2);                       /* 砍掉后半（含标签） */
    EXPECT_NE(int(dec->decode(ct, out)), int(E_OK));
    std::vector<uint8_t> none;
    EXPECT_NE(int(dec->decode(none, out)), int(E_OK));
}

/* ------------------------------------------------------- KDF 边界（3 条+） */
/* 同口令+同 salt+同轮数 -> 同密钥（确定性）；改任一项 -> 密钥不同 */
TEST(WbCryptoKdf, deterministicAndSaltSensitive) {
    uint8_t k1[32], m1[32], k2[32], m2[32], k3[32], m3[32];
    deriveCipherKeys("secret", kSalt, 4096, k1, m1);
    deriveCipherKeys("secret", kSalt, 4096, k2, m2);
    const uint8_t salt2[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };
    deriveCipherKeys("secret", salt2, 4096, k3, m3);
    EXPECT_EQ(0, std::memcmp(k1, k2, 32));
    EXPECT_EQ(0, std::memcmp(m1, m2, 32));
    EXPECT_NE(0, std::memcmp(k1, k3, 32));
    /* 加密密钥与认证密钥不得相同（EtM 双密钥派生） */
    EXPECT_NE(0, std::memcmp(k1, m1, 32));
}

TEST(WbCryptoKdf, roundsChangeDerivedKey) {
    uint8_t k1[32], m1[32], k2[32], m2[32];
    deriveCipherKeys("secret", kSalt, 1000, k1, m1);
    deriveCipherKeys("secret", kSalt, 1001, k2, m2);
    EXPECT_NE(0, std::memcmp(k1, k2, 32));
}

TEST(WbCryptoKdf, passwordChangeDerivedKey) {
    uint8_t k1[32], m1[32], k2[32], m2[32];
    deriveCipherKeys("secret", kSalt, 4096, k1, m1);
    deriveCipherKeys("secreT", kSalt, 4096, k2, m2);
    EXPECT_NE(0, std::memcmp(k1, k2, 32));
}

/* rounds<=0 时 CCryptoCodec 内部回落 4096（CryptoCodecs.cpp:19 三元分支） */
TEST(WbCryptoKdf, zeroRoundsFallsBackToDefault) {
    std::unique_ptr<IDataCodec> a(CryptoFactory::create(CRY_AES256_CBC, "p", kSalt, 0));
    std::unique_ptr<IDataCodec> b(CryptoFactory::create(CRY_AES256_CBC, "p", kSalt, 4096));
    ASSERT_TRUE(a.get() != nullptr);
    ASSERT_TRUE(b.get() != nullptr);
    std::vector<uint8_t> ct, out;
    ASSERT_EQ(int(a->encode(pattern(32), ct)), int(E_OK));
    EXPECT_EQ(int(b->decode(ct, out)), int(E_OK));   /* 0 轮 == 4096 轮，可互解 */
}

/* -------------------------------------------------------- 工厂 / 随机源 */
TEST(WbCryptoFactory, emptyPasswordGivesNullAndUnknownId) {
    EXPECT_TRUE(CryptoFactory::create(CRY_NONE, "p", kSalt, 4096) == nullptr);
    EXPECT_TRUE(CryptoFactory::create(CRY_AES256_CBC, "", kSalt, 4096) == nullptr);
    EXPECT_TRUE(CryptoFactory::create(CRY_CHACHA20, "", kSalt, 4096) == nullptr);
    EXPECT_TRUE(CryptoFactory::create(CRY_DESEDE_CBC, "", kSalt, 4096) == nullptr);
    EXPECT_TRUE(CryptoFactory::create(CRY_XOR_TEST, "", kSalt, 4096) == nullptr);
    EXPECT_TRUE(CryptoFactory::create(CRY_COUNT, "p", kSalt, 4096) == nullptr);
    EXPECT_TRUE(CryptoFactory::description(CRY_AES256_CBC) != nullptr);
    EXPECT_TRUE(CryptoFactory::description(CRY_COUNT) != nullptr);
}

/* F3：fillRandom 走系统 CSPRNG，两次输出不得相同，且非全零 */
TEST(WbCryptoRandom, fillRandomNonRepeating) {
    uint8_t a[32], b[32];
    std::memset(a, 0, sizeof(a));
    std::memset(b, 0, sizeof(b));
    fillRandom(a, sizeof(a));
    fillRandom(b, sizeof(b));
    EXPECT_NE(0, std::memcmp(a, b, sizeof(a)));
    bool anyNonZero = false;
    for (int i = 0; i < 32; ++i) if (a[i]) { anyNonZero = true; break; }
    EXPECT_TRUE(anyNonZero);
}
