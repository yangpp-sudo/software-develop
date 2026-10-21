/* ============================================================================
 *  Sha256.h  -- 自实现 SHA-256（FIPS 180-4），用于口令派生与内容摘要
 * ==========================================================================*/
#ifndef DBKP_CRYPTO_SHA256_H
#define DBKP_CRYPTO_SHA256_H

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace DBKP {

class CSha256 {
public:
    static const std::size_t kDigestSize = 32;

    CSha256() { reset(); }

    void reset();
    void update(const void* data, std::size_t len);
    void finish(uint8_t out[kDigestSize]);

    static void hash(const void* data, std::size_t len, uint8_t out[kDigestSize]);
    static std::vector<uint8_t> hash(const std::vector<uint8_t>& data);
    static std::string toHex(const uint8_t digest[kDigestSize]);

    /** 口令派生：iterated SHA-256(password || salt)，返回 32B 主密钥 */
    static void deriveKey(const std::string& password, const uint8_t salt[16],
                          int rounds, uint8_t outKey[32]);

    /** HMAC-SHA256（自实现，供 PBKDF2 与口令校验标签使用） */
    static void hmac(const void* key, std::size_t keyLen,
                     const void* msg, std::size_t msgLen, uint8_t out[kDigestSize]);
    /** PBKDF2-HMAC-SHA256（RFC 2898），自己实现不用 openssl */
    static void pbkdf2(const std::string& password, const uint8_t* salt, std::size_t saltLen,
                       int rounds, std::size_t dkLen, uint8_t* dk);

private:
    void transform(const uint8_t* block);

    uint32_t m_state[8];
    uint64_t m_bitLen;
    uint8_t  m_buf[64];
    std::size_t m_bufLen;
};

} /* namespace DBKP */

#endif /* DBKP_CRYPTO_SHA256_H */
