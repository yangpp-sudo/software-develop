/* ============================================================================
 *  Sha256.cpp  -- FIPS 180-4 SHA-256 + HMAC + PBKDF2（全部自实现）
 * ==========================================================================*/
#include "Crypto/Sha256.h"

#include <algorithm>
#include <cstring>

namespace DBKP {

namespace {

const uint32_t kK[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
    0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
    0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
    0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

} /* anonymous namespace */

void CSha256::reset() {
    m_state[0] = 0x6a09e667u; m_state[1] = 0xbb67ae85u;
    m_state[2] = 0x3c6ef372u; m_state[3] = 0xa54ff53au;
    m_state[4] = 0x510e527fu; m_state[5] = 0x9b05688cu;
    m_state[6] = 0x1f83d9abu; m_state[7] = 0x5be0cd19u;
    m_bitLen = 0;
    m_bufLen = 0;
}

void CSha256::transform(const uint8_t* block) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = (uint32_t(block[i * 4]) << 24) | (uint32_t(block[i * 4 + 1]) << 16) |
               (uint32_t(block[i * 4 + 2]) << 8) | uint32_t(block[i * 4 + 3]);
    }
    for (int i = 16; i < 64; ++i) {
        const uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = m_state[0], b = m_state[1], c = m_state[2], d = m_state[3];
    uint32_t e = m_state[4], f = m_state[5], g = m_state[6], h = m_state[7];
    for (int i = 0; i < 64; ++i) {
        const uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const uint32_t ch = (e & f) ^ ((~e) & g);
        const uint32_t t1 = h + S1 + ch + kK[i] + w[i];
        const uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    m_state[0] += a; m_state[1] += b; m_state[2] += c; m_state[3] += d;
    m_state[4] += e; m_state[5] += f; m_state[6] += g; m_state[7] += h;
}

void CSha256::update(const void* data, std::size_t len) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    m_bitLen += static_cast<uint64_t>(len) * 8;
    while (len) {
        const std::size_t take = std::min<std::size_t>(len, 64 - m_bufLen);
        std::memcpy(m_buf + m_bufLen, p, take);
        m_bufLen += take; p += take; len -= take;
        if (m_bufLen == 64) { transform(m_buf); m_bufLen = 0; }
    }
}

void CSha256::finish(uint8_t out[kDigestSize]) {
    /* 填充：0x80 + 0 + 64bit 大端长度 */
    const uint64_t bits = m_bitLen;
    uint8_t pad = 0x80;
    update(&pad, 1);
    pad = 0x00;
    while (m_bufLen != 56) update(&pad, 1);
    uint8_t lenbe[8];
    for (int i = 0; i < 8; ++i) lenbe[i] = static_cast<uint8_t>((bits >> (56 - 8 * i)) & 0xFF);
    /* 注意：update 会累加 m_bitLen，这里直接落块避免污染长度字段 */
    std::memcpy(m_buf + 56, lenbe, 8);
    transform(m_buf);
    m_bufLen = 0;
    for (int i = 0; i < 8; ++i) {
        out[i * 4]     = static_cast<uint8_t>(m_state[i] >> 24);
        out[i * 4 + 1] = static_cast<uint8_t>(m_state[i] >> 16);
        out[i * 4 + 2] = static_cast<uint8_t>(m_state[i] >> 8);
        out[i * 4 + 3] = static_cast<uint8_t>(m_state[i]);
    }
    reset();
}

void CSha256::hash(const void* data, std::size_t len, uint8_t out[kDigestSize]) {
    CSha256 h;
    h.update(data, len);
    h.finish(out);
}

std::vector<uint8_t> CSha256::hash(const std::vector<uint8_t>& data) {
    uint8_t d[kDigestSize];
    hash(data.data(), data.size(), d);
    return std::vector<uint8_t>(d, d + kDigestSize);
}

std::string CSha256::toHex(const uint8_t digest[kDigestSize]) {
    static const char* hex = "0123456789abcdef";
    std::string s;
    s.reserve(64);
    for (std::size_t i = 0; i < kDigestSize; ++i) {
        s.push_back(hex[digest[i] >> 4]);
        s.push_back(hex[digest[i] & 0x0F]);
    }
    return s;
}

/* --------------------------------------------------------------- HMAC */
void CSha256::hmac(const void* key, std::size_t keyLen,
                   const void* msg, std::size_t msgLen, uint8_t out[kDigestSize]) {
    uint8_t k[64];
    std::memset(k, 0, sizeof(k));
    if (keyLen > 64) {
        hash(key, keyLen, k);                 /* 长密钥先哈希到 32 字节 */
    } else {
        std::memcpy(k, key, keyLen);
    }
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; ++i) {
        ipad[i] = static_cast<uint8_t>(k[i] ^ 0x36);
        opad[i] = static_cast<uint8_t>(k[i] ^ 0x5c);
    }
    uint8_t inner[32];
    {
        CSha256 h;
        h.update(ipad, 64);
        h.update(msg, msgLen);
        h.finish(inner);
    }
    CSha256 h2;
    h2.update(opad, 64);
    h2.update(inner, 32);
    h2.finish(out);
    std::memset(k, 0, sizeof(k));
    std::memset(ipad, 0, sizeof(ipad));
    std::memset(opad, 0, sizeof(opad));
}

/* -------------------------------------------------------------- PBKDF2 */
void CSha256::pbkdf2(const std::string& password, const uint8_t* salt, std::size_t saltLen,
                     int rounds, std::size_t dkLen, uint8_t* dk) {
    if (rounds < 1) rounds = 1;
    const std::size_t pwLen = password.size();
    const uint8_t* pw = reinterpret_cast<const uint8_t*>(password.data());
    std::vector<uint8_t> buf(saltLen + 4);
    if (saltLen) std::memcpy(buf.data(), salt, saltLen);

    std::size_t done = 0;
    uint32_t blockIdx = 1;
    while (done < dkLen) {
        buf[saltLen + 0] = static_cast<uint8_t>(blockIdx >> 24);
        buf[saltLen + 1] = static_cast<uint8_t>(blockIdx >> 16);
        buf[saltLen + 2] = static_cast<uint8_t>(blockIdx >> 8);
        buf[saltLen + 3] = static_cast<uint8_t>(blockIdx);
        uint8_t u[32], t[32];
        hmac(pw, pwLen, buf.data(), buf.size(), u);
        std::memcpy(t, u, 32);
        for (int i = 2; i <= rounds; ++i) {
            hmac(pw, pwLen, u, 32, u);
            for (int j = 0; j < 32; ++j) t[j] ^= u[j];
        }
        const std::size_t take = std::min<std::size_t>(32, dkLen - done);
        std::memcpy(dk + done, t, take);
        done += take;
        ++blockIdx;
    }
    std::memset(buf.data(), 0, buf.size());
}

void CSha256::deriveKey(const std::string& password, const uint8_t salt[16],
                        int rounds, uint8_t outKey[32]) {
    pbkdf2(password, salt, 16, rounds > 0 ? rounds : 4096, 32, outKey);
}

} /* namespace DBKP */

