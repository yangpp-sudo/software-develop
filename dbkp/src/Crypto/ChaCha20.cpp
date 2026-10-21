/* ============================================================================
 *  ChaCha20.cpp  -- 自实现 ChaCha20 流密码（Daniel Bernstein 规范）+ HMAC 标签
 * ==========================================================================*/
#include "Crypto/Algorithms.h"
#include "Crypto/Blob.h"

#include <cstring>

#include "Crypto/Sha256.h"

namespace DBKP {

namespace {

inline uint32_t rotl32(uint32_t v, int c) { return (v << c) | (v >> (32 - c)); }

void quarterRound(uint32_t s[16], int a, int b, int c, int d) {
    s[a] += s[b]; s[d] ^= s[a]; s[d] = rotl32(s[d], 16);
    s[c] += s[d]; s[b] ^= s[c]; s[b] = rotl32(s[b], 12);
    s[a] += s[b]; s[d] ^= s[a]; s[d] = rotl32(s[d], 8);
    s[c] += s[d]; s[b] ^= s[c]; s[b] = rotl32(s[b], 7);
}

uint32_t le32(const uint8_t* p) {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}

void putLe32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v); p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16); p[3] = static_cast<uint8_t>(v >> 24);
}

} /* anonymous namespace */

CChaCha20::CChaCha20(const uint8_t key[kKeySize], const uint8_t nonce[kNonceSize],
                     uint32_t counter) {
    m_state[0] = 0x61707865u;   /* "expa" */
    m_state[1] = 0x3320646eu;   /* "nd 3" */
    m_state[2] = 0x79622d32u;   /* "2-by" */
    m_state[3] = 0x6b206574u;   /* "te k" */
    for (int i = 0; i < 8; ++i) m_state[4 + i] = le32(key + 4 * i);
    m_state[12] = counter;
    for (int i = 0; i < 3; ++i) m_state[13 + i] = le32(nonce + 4 * i);
}

void CChaCha20::block(uint32_t out[16]) {
    uint32_t s[16];
    std::memcpy(s, m_state, sizeof(s));
    for (int r = 0; r < 10; ++r) {                 /* 20 轮 = 10 次双轮 */
        quarterRound(s, 0, 4, 8, 12);
        quarterRound(s, 1, 5, 9, 13);
        quarterRound(s, 2, 6, 10, 14);
        quarterRound(s, 3, 7, 11, 15);
        quarterRound(s, 0, 5, 10, 15);
        quarterRound(s, 1, 6, 11, 12);
        quarterRound(s, 2, 7, 8, 13);
        quarterRound(s, 3, 4, 9, 14);
    }
    for (int i = 0; i < 16; ++i) out[i] = s[i] + m_state[i];
    ++m_state[12];
    if (m_state[12] == 0) ++m_state[13];           /* 计数器进位到 nonce 低位 */
}

void CChaCha20::crypt(const uint8_t* in, uint8_t* out, std::size_t len) {
    uint32_t ks[16];
    uint8_t keyStream[64];
    while (len) {
        block(ks);
        for (int i = 0; i < 16; ++i) putLe32(keyStream + 4 * i, ks[i]);
        const std::size_t take = len < 64 ? len : 64;
        for (std::size_t i = 0; i < take; ++i) out[i] = static_cast<uint8_t>(in[i] ^ keyStream[i]);
        in += take; out += take; len -= take;
    }
}

ErrCode ChaChaEncrypt(const uint8_t key[32], const uint8_t macKey[32],
                      const std::vector<uint8_t>& plain, std::vector<uint8_t>& cipher) {
    uint8_t nonce[CChaCha20::kNonceSize];
    fillRandom(nonce, sizeof(nonce));
    cipher.clear();
    Crypto::putCipherHeader(cipher, Crypto::kMagicCha, static_cast<uint64_t>(plain.size()));
    cipher.insert(cipher.end(), nonce, nonce + sizeof(nonce));
    const std::size_t head = cipher.size();
    cipher.resize(head + plain.size());
    CChaCha20 cc(key, nonce, 1);
    cc.crypt(plain.data(), cipher.data() + head, plain.size());
    uint8_t tag[32];
    CSha256::hmac(macKey, 32, cipher.data(), cipher.size(), tag);
    cipher.insert(cipher.end(), tag, tag + Crypto::kTagSize);
    return E_OK;
}

ErrCode ChaChaDecrypt(const uint8_t key[32], const uint8_t macKey[32],
                      const std::vector<uint8_t>& cipher, std::vector<uint8_t>& plain) {
    uint64_t rawLen = 0;
    std::size_t start = 0;
    if (!Crypto::readCipherHeader(cipher, Crypto::kMagicCha, rawLen, start)) return E_CRYPTO_FAIL;
    const std::size_t noncePos = start;
    const std::size_t ctStart = noncePos + CChaCha20::kNonceSize;
    if (cipher.size() < ctStart + Crypto::kTagSize) return E_TRUNCATED_ARCHIVE;
    if (cipher.size() - ctStart - Crypto::kTagSize != rawLen) return E_CRYPTO_FAIL;
    if (rawLen > (1ull << 40)) return E_CRYPTO_FAIL;

    uint8_t tag[32];
    CSha256::hmac(macKey, 32, cipher.data(), ctStart + rawLen, tag);
    if (std::memcmp(tag, cipher.data() + cipher.size() - Crypto::kTagSize, Crypto::kTagSize) != 0) {
        return E_WRONG_PASSWORD;
    }
    plain.resize(static_cast<size_t>(rawLen));
    CChaCha20 cc(key, cipher.data() + noncePos, 1);
    if (rawLen) cc.crypt(cipher.data() + ctStart, plain.data(), static_cast<size_t>(rawLen));
    return E_OK;
}

} /* namespace DBKP */
