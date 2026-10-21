/* ============================================================================
 *  Aes.cpp  -- AES-256（FIPS-197）原语 + CBC/PKCS#7 + Encrypt-then-MAC
 *
 *  特点：S 盒与逆 S 盒由 GF(2^8) 运算在线生成，不内嵌查找表常量，
 *        避免抄表出错，同时满足"自己实现加解密算法"的要求。
 * ==========================================================================*/
#include "Crypto/Algorithms.h"
#include "Crypto/Blob.h"

#include <cstring>
#include <ctime>

#include "Common/Serialize.h"
#include "Crypto/Sha256.h"

namespace DBKP {

namespace {

uint8_t g_sbox[256];
uint8_t g_invbox[256];
uint8_t g_log[256];
uint8_t g_alog[512];
bool    g_tablesReady = false;

inline uint8_t xtime(uint8_t b) {
    return static_cast<uint8_t>((b << 1) ^ ((b & 0x80) ? 0x1B : 0x00));
}

/* GF(2^8)（模 0x11B）乘法，仅用于建表 */
inline uint8_t gmulSlow(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) p ^= a;
        const uint8_t hi = static_cast<uint8_t>(a & 0x80);
        a = static_cast<uint8_t>(a << 1);
        if (hi) a ^= 0x1B;
        b = static_cast<uint8_t>(b >> 1);
    }
    return p;
}

inline uint8_t rotl8(uint8_t b, int n) {
    return static_cast<uint8_t>((b << n) | (b >> (8 - n)));
}

void buildTables() {
    if (g_tablesReady) return;
    uint8_t x = 1;
    for (int i = 0; i < 255; ++i) {
        g_alog[i] = x;
        g_log[x] = static_cast<uint8_t>(i);
        x = static_cast<uint8_t>(gmulSlow(x, 3));      /* 3 是 GF(2^8) 的本原元 */
    }
    for (int i = 255; i < 512; ++i) g_alog[i] = g_alog[i - 255];
    g_log[0] = 0;

    for (int i = 0; i < 256; ++i) {
        const uint8_t inv = (i == 0) ? 0 : g_alog[255 - g_log[i]];
        const uint8_t s = static_cast<uint8_t>(inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^
                                               rotl8(inv, 3) ^ rotl8(inv, 4) ^ 0x63);
        g_sbox[i] = s;
        g_invbox[s] = static_cast<uint8_t>(i);
    }
    g_tablesReady = true;
}

inline uint8_t gmul(uint8_t a, uint8_t b) {
    if (a == 0 || b == 0) return 0;
    return g_alog[g_log[a] + g_log[b]];
}

void addRoundKey(uint8_t s[16], const uint32_t* w) {
    for (int c = 0; c < 4; ++c) {
        const uint32_t k = w[c];
        s[0 + 4 * c] ^= static_cast<uint8_t>(k >> 24);
        s[1 + 4 * c] ^= static_cast<uint8_t>(k >> 16);
        s[2 + 4 * c] ^= static_cast<uint8_t>(k >> 8);
        s[3 + 4 * c] ^= static_cast<uint8_t>(k);
    }
}

void subBytes(uint8_t s[16])    { for (int i = 0; i < 16; ++i) s[i] = g_sbox[s[i]]; }
void invSubBytes(uint8_t s[16]) { for (int i = 0; i < 16; ++i) s[i] = g_invbox[s[i]]; }

void shiftRows(uint8_t s[16]) {
    uint8_t t;
    t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
    t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
}

void invShiftRows(uint8_t s[16]) {
    uint8_t t;
    t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
    t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;
}

void mixColumns(uint8_t s[16]) {
    for (int c = 0; c < 4; ++c) {
        const uint8_t a0 = s[4 * c], a1 = s[4 * c + 1], a2 = s[4 * c + 2], a3 = s[4 * c + 3];
        s[4 * c]     = static_cast<uint8_t>(gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3);
        s[4 * c + 1] = static_cast<uint8_t>(a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3);
        s[4 * c + 2] = static_cast<uint8_t>(a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3));
        s[4 * c + 3] = static_cast<uint8_t>(gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2));
    }
}

void invMixColumns(uint8_t s[16]) {
    for (int c = 0; c < 4; ++c) {
        const uint8_t a0 = s[4 * c], a1 = s[4 * c + 1], a2 = s[4 * c + 2], a3 = s[4 * c + 3];
        s[4 * c]     = static_cast<uint8_t>(gmul(a0, 0x0E) ^ gmul(a1, 0x0B) ^
                                            gmul(a2, 0x0D) ^ gmul(a3, 0x09));
        s[4 * c + 1] = static_cast<uint8_t>(gmul(a0, 0x09) ^ gmul(a1, 0x0E) ^
                                            gmul(a2, 0x0B) ^ gmul(a3, 0x0D));
        s[4 * c + 2] = static_cast<uint8_t>(gmul(a0, 0x0D) ^ gmul(a1, 0x09) ^
                                            gmul(a2, 0x0E) ^ gmul(a3, 0x0B));
        s[4 * c + 3] = static_cast<uint8_t>(gmul(a0, 0x0B) ^ gmul(a1, 0x0D) ^
                                            gmul(a2, 0x09) ^ gmul(a3, 0x0E));
    }
}

const int kRounds = 14;
const int kKeyWords = 4 * (kRounds + 1);      /* 60 */

uint32_t subWord(uint32_t w) {
    return (uint32_t(g_sbox[(w >> 24) & 0xFF]) << 24) |
           (uint32_t(g_sbox[(w >> 16) & 0xFF]) << 16) |
           (uint32_t(g_sbox[(w >> 8) & 0xFF]) << 8) |
           uint32_t(g_sbox[w & 0xFF]);
}
uint32_t rotWord(uint32_t w) { return (w << 8) | (w >> 24); }

} /* anonymous namespace */

/* -------------------------------------------------- 密文块公共小头结构 */
static const uint16_t kAesMagic = 0x4145u;   /* 'AE' —— 与 Crypto/Blob.h 保持一致 */

/* 薄封装：格式定义只在 Crypto/Blob.h 里存在一份 */
static void putBlobHeader(std::vector<uint8_t>& out, uint16_t magic, uint64_t rawLen) {
    Crypto::putCipherHeader(out, magic, rawLen);
}

static bool readBlobHeader(const std::vector<uint8_t>& in, uint16_t magic,
                           uint64_t& rawLen, std::size_t& start) {
    return Crypto::readCipherHeader(in, magic, rawLen, start);
}

void fillRandom(uint8_t* out, std::size_t n) {
    static uint64_t s_state = 0;
    if (s_state == 0) {
        s_state = static_cast<uint64_t>(std::time(nullptr)) * 0x9E3779B97F4A7C15ull ^
                  (static_cast<uint64_t>(reinterpret_cast<uintptr_t>(out)) << 1);
    }
    for (std::size_t i = 0; i < n; ++i) {
        s_state ^= s_state << 13;
        s_state ^= s_state >> 7;
        s_state ^= s_state << 17;
        out[i] = static_cast<uint8_t>(s_state >> 24);
    }
}

void deriveCipherKeys(const std::string& password, const uint8_t salt[16], int rounds,
                      uint8_t encKey[32], uint8_t macKey[32]) {
    uint8_t dk[64];
    CSha256::pbkdf2(password, salt, 16, rounds > 0 ? rounds : 4096, 64, dk);
    std::memcpy(encKey, dk, 32);
    std::memcpy(macKey, dk + 32, 32);
    std::memset(dk, 0, sizeof(dk));
}

/* --------------------------------------------------------- AES-256 原语 */
void CAes256::initTables() { buildTables(); }
uint8_t CAes256::sbox(uint8_t b) { buildTables(); return g_sbox[b]; }

CAes256::CAes256(const uint8_t key[kKeySize]) {
    buildTables();
    uint32_t* w = m_enc;
    for (int i = 0; i < 8; ++i) {
        w[i] = (uint32_t(key[4 * i]) << 24) | (uint32_t(key[4 * i + 1]) << 16) |
               (uint32_t(key[4 * i + 2]) << 8) | uint32_t(key[4 * i + 3]);
    }
    uint8_t rcon = 1;
    for (int i = 8; i < kKeyWords; ++i) {
        uint32_t t = w[i - 1];
        if (i % 8 == 0) { t = subWord(rotWord(t)) ^ (uint32_t(rcon) << 24); rcon = xtime(rcon); }
        else if (i % 8 == 4) { t = subWord(t); }
        w[i] = w[i - 8] ^ t;
    }
    std::memset(m_dec, 0, sizeof(m_dec));       /* 直接逆密码：不需要等价调度表 */
}

void CAes256::encryptBlock(const uint8_t in[16], uint8_t out[16]) const {
    uint8_t s[16];
    std::memcpy(s, in, 16);
    addRoundKey(s, m_enc);
    for (int r = 1; r < kRounds; ++r) {
        subBytes(s); shiftRows(s); mixColumns(s);
        addRoundKey(s, m_enc + 4 * r);
    }
    subBytes(s); shiftRows(s);
    addRoundKey(s, m_enc + 4 * kRounds);
    std::memcpy(out, s, 16);
}

void CAes256::decryptBlock(const uint8_t in[16], uint8_t out[16]) const {
    uint8_t s[16];
    std::memcpy(s, in, 16);
    addRoundKey(s, m_enc + 4 * kRounds);
    for (int r = kRounds - 1; r >= 1; --r) {
        invShiftRows(s); invSubBytes(s);
        addRoundKey(s, m_enc + 4 * r);
        invMixColumns(s);
    }
    invShiftRows(s); invSubBytes(s);
    addRoundKey(s, m_enc);
    std::memcpy(out, s, 16);
}

/* ------------------------------------------------------------- CBC 模式 */
ErrCode AesCbcEncrypt(const uint8_t key[32], const uint8_t macKey[32],
                      const std::vector<uint8_t>& plain, std::vector<uint8_t>& cipher) {
    CAes256 aes(key);
    cipher.clear();
    putBlobHeader(cipher, kAesMagic, static_cast<uint64_t>(plain.size()));

    uint8_t iv[16];
    fillRandom(iv, 16);
    cipher.insert(cipher.end(), iv, iv + 16);

    /* PKCS#7：总是补 1..16 字节 */
    const std::size_t pad = 16 - (plain.size() % 16);
    std::vector<uint8_t> buf(plain.size() + pad, static_cast<uint8_t>(pad));
    if (!plain.empty()) std::memcpy(buf.data(), plain.data(), plain.size());

    const size_t blocks = buf.size() / 16;
    const size_t head = cipher.size();
    cipher.resize(head + buf.size());
    uint8_t chain[16];
    std::memcpy(chain, iv, 16);
    for (size_t b = 0; b < blocks; ++b) {
        uint8_t in[16], out[16];
        for (int i = 0; i < 16; ++i) in[i] = static_cast<uint8_t>(buf[b * 16 + i] ^ chain[i]);
        aes.encryptBlock(in, out);
        std::memcpy(cipher.data() + head + b * 16, out, 16);
        std::memcpy(chain, out, 16);
    }
    /* Encrypt-then-MAC：tag = HMAC-SHA256(macKey, 全部密文)[0..15] */
    uint8_t tag[32];
    CSha256::hmac(macKey, 32, cipher.data(), cipher.size(), tag);
    cipher.insert(cipher.end(), tag, tag + 16);
    std::memset(chain, 0, sizeof(chain));
    return E_OK;
}

ErrCode AesCbcDecrypt(const uint8_t key[32], const uint8_t macKey[32],
                      const std::vector<uint8_t>& cipher, std::vector<uint8_t>& plain) {
    uint64_t rawLen = 0;
    std::size_t start = 0;
    if (!readBlobHeader(cipher, kAesMagic, rawLen, start)) return E_CRYPTO_FAIL;
    /* 12 + IV16 + 密文(>=16) + tag16 */
    if (cipher.size() < start + 16 + 16 + 16) return E_TRUNCATED_ARCHIVE;
    const std::size_t ctStart = start + 16;
    const std::size_t ctLen = cipher.size() - ctStart - 16;
    if (ctLen % 16) return E_CRYPTO_FAIL;

    uint8_t tag[32];
    CSha256::hmac(macKey, 32, cipher.data(), ctStart + ctLen, tag);
    if (std::memcmp(tag, cipher.data() + cipher.size() - 16, 16) != 0) {
        return E_WRONG_PASSWORD;                     /* 口令错或数据被篡改 */
    }

    CAes256 aes(key);
    uint8_t chain[16];
    std::memcpy(chain, cipher.data() + start, 16);
    std::vector<uint8_t> buf(ctLen);
    for (size_t b = 0; b < ctLen / 16; ++b) {
        uint8_t out[16];
        aes.decryptBlock(cipher.data() + ctStart + b * 16, out);
        for (int i = 0; i < 16; ++i) buf[b * 16 + i] = static_cast<uint8_t>(out[i] ^ chain[i]);
        std::memcpy(chain, cipher.data() + ctStart + b * 16, 16);
    }
    const uint8_t pad = buf.empty() ? 0 : buf[buf.size() - 1];
    if (pad == 0 || pad > 16 || buf.size() < rawLen + pad) return E_CRYPTO_FAIL;
    for (std::size_t i = buf.size() - pad; i < buf.size(); ++i) {
        if (buf[i] != pad) return E_CRYPTO_FAIL;
    }
    buf.resize(buf.size() - pad);
    if (buf.size() != rawLen) return E_CRYPTO_FAIL;
    plain.swap(buf);
    return E_OK;
}

} /* namespace DBKP */


