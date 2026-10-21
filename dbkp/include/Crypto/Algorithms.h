/* ============================================================================
 *  Algorithms.h  -- 自实现对称加密（AES-256-CBC / ChaCha20）+ 编解码封装
 *
 *  安全设计：
 *    - 口令 -> PBKDF2-HMAC-SHA256(salt, rounds) -> 32B 主密钥 + 16B 认证密钥
 *    - 每个文件独立随机 IV，密文格式：hdr | IV/nonce | ciphertext | tag(16)
 *    - encrypt-then-HMAC：口令错误/数据损坏都会得到 E_WRONG_PASSWORD，不会解出垃圾
 * ==========================================================================*/
#ifndef DBKP_CRYPTO_ALGORITHMS_H
#define DBKP_CRYPTO_ALGORITHMS_H

#include <cstdint>
#include <string>
#include <vector>

#include "Codec/DataCodec.h"

namespace DBKP {

/* --------------------------------------------------------- AES-256 原语 */
class CAes256 {
public:
    static const int kBlockSize = 16;
    static const int kKeySize   = 32;

    explicit CAes256(const uint8_t key[kKeySize]);

    void encryptBlock(const uint8_t in[16], uint8_t out[16]) const;
    void decryptBlock(const uint8_t in[16], uint8_t out[16]) const;

    /** S盒由 GF(2^8) 求逆 + 仿射变换在线生成（避免手抄表出错） */
    static void initTables();
    static uint8_t sbox(uint8_t b);

private:
    uint32_t m_enc[60];      /* 15 轮 x 4 字 */
    uint32_t m_dec[60];
};

/* ------------------------------------------------------- ChaCha20 原语 */
class CChaCha20 {
public:
    static const int kKeySize = 32;
    static const int kNonceSize = 12;

    CChaCha20(const uint8_t key[kKeySize], const uint8_t nonce[kNonceSize], uint32_t counter);

    /** 对字节流做 XOR  keystream（原地） */
    void crypt(const uint8_t* in, uint8_t* out, std::size_t len);

private:
    void block(uint32_t out[16]);

    uint32_t m_state[16];
};

/* -------------------------------------------------------- 密码模式封装 */
ErrCode AesCbcEncrypt(const uint8_t key[32], const uint8_t macKey[32],
                      const std::vector<uint8_t>& plain, std::vector<uint8_t>& cipher);
ErrCode AesCbcDecrypt(const uint8_t key[32], const uint8_t macKey[32],
                      const std::vector<uint8_t>& cipher, std::vector<uint8_t>& plain);
ErrCode ChaChaEncrypt(const uint8_t key[32], const uint8_t macKey[32],
                      const std::vector<uint8_t>& plain, std::vector<uint8_t>& cipher);
ErrCode ChaChaDecrypt(const uint8_t key[32], const uint8_t macKey[32],
                      const std::vector<uint8_t>& cipher, std::vector<uint8_t>& plain);

/** IDataCodec 工厂函数（被 CryptoFactory 调用） */
IDataCodec* NewAesCbcCodec(const std::string& password, const uint8_t salt[16], int rounds);
IDataCodec* NewChaCha20Codec(const std::string& password, const uint8_t salt[16], int rounds);
IDataCodec* newXorTestCodec(const std::string& password);

/** 供测试：由口令派生加密密钥与认证密钥 */
void deriveCipherKeys(const std::string& password, const uint8_t salt[16], int rounds,
                      uint8_t encKey[32], uint8_t macKey[32]);
/** 供测试：生成随机字节（时间+地址播种的 xorshift，非密码学强随机） */
void fillRandom(uint8_t* out, std::size_t n);

} /* namespace DBKP */

#endif /* DBKP_CRYPTO_ALGORITHMS_H */
