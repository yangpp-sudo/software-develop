/* ============================================================================
 *  Blob.h  -- 密文/密钥流块的公共小头（magic|ver|flags|rawLen(8) = 12B）
 *             与压缩码流头保持同样的字段布局，便于统一调试与工具解析。
 * ==========================================================================*/
#ifndef DBKP_CRYPTO_BLOB_H
#define DBKP_CRYPTO_BLOB_H

#include <cstdint>
#include <cstring>
#include <vector>

namespace DBKP {
namespace Crypto {

static const uint16_t kMagicAes = 0x4145u;   /* 'AE' */
static const uint16_t kMagicCha = 0x4343u;   /* 'CC' */
static const uint16_t kMagicXor = 0x5852u;   /* 'XR' */
static const std::size_t kBlobHeaderSize = 12;
static const std::size_t kTagSize = 16;      /* HMAC-SHA256 截断标签 */

inline void putCipherHeader(std::vector<uint8_t>& out, uint16_t magic, uint64_t rawLen) {
    out.push_back(static_cast<uint8_t>(magic & 0xFF));
    out.push_back(static_cast<uint8_t>((magic >> 8) & 0xFF));
    out.push_back(1);
    out.push_back(0);
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<uint8_t>((rawLen >> (8 * i)) & 0xFF));
}

inline bool readCipherHeader(const std::vector<uint8_t>& in, uint16_t magic,
                             uint64_t& rawLen, std::size_t& start) {
    if (in.size() < kBlobHeaderSize) return false;
    const uint16_t got = static_cast<uint16_t>(in[0]) |
                         static_cast<uint16_t>(static_cast<uint16_t>(in[1]) << 8);
    if (got != magic) return false;
    if (in[2] != 1 || in[3] != 0) return false;
    rawLen = 0;
    for (int i = 0; i < 8; ++i) rawLen |= static_cast<uint64_t>(in[4 + i]) << (8 * i);
    start = kBlobHeaderSize;
    return true;
}

} /* namespace Crypto */
} /* namespace DBKP */

#endif /* DBKP_CRYPTO_BLOB_H */
