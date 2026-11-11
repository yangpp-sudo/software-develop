/* ============================================================================
 *  Des.cpp  -- 自实现 DES(FIPS 46-3) + 3DES-EDE + CBC 模式
 *
 *  为什么自己写：课件《加密解密》第 6 章的 CDES 用 OpenSSL EVP，而本工程一贯
 *  零第三方依赖（AES/ChaCha/SHA 全是自实现）。这里按同样的比特表实现，并用
 *  已知答案向量(KAT)在单测里把正确性钉死——DES 的 S 盒与置换表是固定表、无法
 *  像 AES S 盒那样用 GF(2^8) 求逆生成，一旦手抄错就只有 KAT 能抓出来。
 *
 *  密文布局与 AES-256-CBC 完全同构，只是分组换成 8 字节：
 *    header(magic|ver|flags|rawLen) | IV(8) | CBC 密文 | HMAC-SHA256[0..15]
 *  口令->密钥仍走 deriveCipherKeys(PBKDF2)，取其前 16 字节当两密钥 3DES 的
 *  K1||K2（K3=K1），与课件"3DES(DES-EDE) 密钥 16 字节"一致。
 * ==========================================================================*/
#include "Crypto/Algorithms.h"
#include "Crypto/Blob.h"
#include "Crypto/Sha256.h"

#include <cstring>
#include <vector>

namespace DBKP {
namespace {

/* -------------------------------------------------- 标准 DES 置换表(0 基) */
const uint8_t kIP[64] = {
    57, 49, 41, 33, 25, 17, 9, 1,  59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
    56, 48, 40, 32, 24, 16, 8, 0,  58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6
};

const uint8_t kFP[64] = {
    39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9,  49, 17, 57, 25, 32, 0, 40, 8, 48, 16, 56, 24
};

const uint8_t kPC1[56] = {
    56, 48, 40, 32, 24, 16, 8,  0, 57, 49, 41, 33, 25, 17,
    9,  1,  58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35,
    62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21,
    13, 5,  60, 52, 44, 36, 28, 20, 12, 4, 27, 19, 11, 3
};

const uint8_t kPC2[48] = {
    13, 16, 10, 23, 0,  4,  2,  27, 14, 5,  20, 9,
    22, 18, 11, 3,  25, 7,  15, 6,  26, 19, 12, 1,
    40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
    43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31
};

const uint8_t kSHIFT[16] = {
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

const uint8_t kEXP[48] = {
    31, 0,  1,  2,  3,  4,  3,  4,  5,  6,  7,  8,
    7,  8,  9,  10, 11, 12, 11, 12, 13, 14, 15, 16,
    15, 16, 17, 18, 19, 20, 19, 20, 21, 22, 23, 24,
    23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31, 0
};

const uint8_t kPP[32] = {
    15, 6,  19, 20, 28, 11, 27, 16, 0,  14, 22, 25, 4,  17, 30, 9,
    1,  7,  23, 13, 31, 26, 2,  8,  18, 12, 29, 5,  21, 10, 3,  24
};

/* 8 个 S 盒，每个 4 行 x 16 列展平存 64 项 */
const uint8_t kSBOX[8][64] = {
    { /* S1 */
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 },
    { /* S2 */
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 },
    { /* S3 */
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 },
    { /* S4 */
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 },
    { /* S5 */
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 },
    { /* S6 */
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 },
    { /* S7 */
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 },
    { /* S8 */
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 }
};

/* 字节 <-> 比特串（MSB 先行），全程用 0/1 的 vector 走标准表置换 */
std::vector<uint8_t> bytesToBits(const uint8_t* b, std::size_t n) {
    std::vector<uint8_t> bits(n * 8);
    for (std::size_t i = 0; i < n; ++i)
        for (int k = 0; k < 8; ++k)
            bits[i * 8 + k] = static_cast<uint8_t>((b[i] >> (7 - k)) & 1);
    return bits;
}

void bitsToBytes(const std::vector<uint8_t>& bits, uint8_t* out) {
    const std::size_t n = bits.size() / 8;
    std::memset(out, 0, n);
    for (std::size_t i = 0; i < bits.size(); ++i)
        out[i / 8] = static_cast<uint8_t>(out[i / 8] | ((bits[i] & 1) << (7 - (i % 8))));
}

std::vector<uint8_t> permute(const uint8_t* tab, std::size_t tn, const std::vector<uint8_t>& in) {
    std::vector<uint8_t> out(tn);
    for (std::size_t i = 0; i < tn; ++i) out[i] = in[tab[i]];
    return out;
}

/** Feistel 主体：dec=false 正序轮密钥（加密），true 逆序（解密） */
std::vector<uint8_t> desBlock(const std::vector<uint8_t> sub[16],
                              const std::vector<uint8_t>& bits64, bool dec) {
    std::vector<uint8_t> blk = permute(kIP, 64, bits64);
    std::vector<uint8_t> L(blk.begin(), blk.begin() + 32);
    std::vector<uint8_t> R(blk.begin() + 32, blk.end());
    for (int r = 0; r < 16; ++r) {
        const int round = dec ? 15 - r : r;
        std::vector<uint8_t> rc = R;                       /* 暂存旧 R */
        std::vector<uint8_t> e = permute(kEXP, 48, R);      /* 32 -> 48 */
        for (int i = 0; i < 48; ++i) e[i] = static_cast<uint8_t>(e[i] ^ sub[round][i]);
        /* 8 个 S 盒：6 位 -> 4 位 */
        std::vector<uint8_t> s(32);
        for (int j = 0; j < 8; ++j) {
            const uint8_t row = static_cast<uint8_t>((e[j * 6] << 1) | e[j * 6 + 5]);
            const uint8_t col = static_cast<uint8_t>((e[j * 6 + 1] << 3) | (e[j * 6 + 2] << 2) |
                                                     (e[j * 6 + 3] << 1) | e[j * 6 + 4]);
            const uint8_t v = kSBOX[j][row * 16 + col];
            s[j * 4]     = static_cast<uint8_t>((v >> 3) & 1);
            s[j * 4 + 1] = static_cast<uint8_t>((v >> 2) & 1);
            s[j * 4 + 2] = static_cast<uint8_t>((v >> 1) & 1);
            s[j * 4 + 3] = static_cast<uint8_t>(v & 1);
        }
        std::vector<uint8_t> f = permute(kPP, 32, s);       /* P 置换 */
        for (int i = 0; i < 32; ++i) R[i] = static_cast<uint8_t>(f[i] ^ L[i]);
        L = rc;
    }
    std::vector<uint8_t> pre;                              /* 末轮后再拼 R||L */
    pre.insert(pre.end(), R.begin(), R.end());
    pre.insert(pre.end(), L.begin(), L.end());
    return permute(kFP, 64, pre);
}

/* --------------------------------------------------- 3DES-EDE 单块(两密钥) */
void edeEncrypt(const CDes& k1, const CDes& k2, const uint8_t in[8], uint8_t out[8]) {
    uint8_t t[8];
    k1.encryptBlock(in, t);
    k2.decryptBlock(t, t);
    k1.encryptBlock(t, out);
}
void edeDecrypt(const CDes& k1, const CDes& k2, const uint8_t in[8], uint8_t out[8]) {
    uint8_t t[8];
    k1.decryptBlock(in, t);
    k2.encryptBlock(t, t);
    k1.decryptBlock(t, out);
}

const uint16_t kDesMagic = Crypto::kMagicDes;

} /* anonymous namespace */

/* ------------------------------------------------------------- DES 原语 */
CDes::CDes(const uint8_t key[kKeySize]) {
    std::vector<uint8_t> k56 = permute(kPC1, 56, bytesToBits(key, kKeySize));
    std::vector<uint8_t> L(k56.begin(), k56.begin() + 28);
    std::vector<uint8_t> R(k56.begin() + 28, k56.end());
    for (int r = 0; r < 16; ++r) {
        for (int s = 0; s < kSHIFT[r]; ++s) {              /* 循环左移 */
            const uint8_t lh = L[0], rh = R[0];
            L.erase(L.begin()); L.push_back(lh);
            R.erase(R.begin()); R.push_back(rh);
        }
        std::vector<uint8_t> cd;
        cd.insert(cd.end(), L.begin(), L.end());
        cd.insert(cd.end(), R.begin(), R.end());
        m_subkeys[r] = permute(kPC2, 48, cd);
    }
}

void CDes::encryptBlock(const uint8_t in[8], uint8_t out[8]) const {
    const std::vector<uint8_t> b = desBlock(m_subkeys, bytesToBits(in, 8), false);
    bitsToBytes(b, out);
}
void CDes::decryptBlock(const uint8_t in[8], uint8_t out[8]) const {
    const std::vector<uint8_t> b = desBlock(m_subkeys, bytesToBits(in, 8), true);
    bitsToBytes(b, out);
}

/* ------------------------------------------------------- DES-EDE-CBC 模式 */
ErrCode DesEdeCbcEncrypt(const uint8_t key[32], const uint8_t macKey[32],
                         const std::vector<uint8_t>& plain, std::vector<uint8_t>& cipher) {
    const CDes k1(key);            /* K1 = key[0..7] */
    const CDes k2(key + 8);        /* K2 = key[8..15]，K3 = K1 */
    cipher.clear();
    Crypto::putCipherHeader(cipher, kDesMagic, static_cast<uint64_t>(plain.size()));

    uint8_t iv[8];
    fillRandom(iv, 8);
    cipher.insert(cipher.end(), iv, iv + 8);

    /* PKCS#7：总是补 1..8 字节 */
    const std::size_t pad = 8 - (plain.size() % 8);
    std::vector<uint8_t> buf(plain.size() + pad, static_cast<uint8_t>(pad));
    if (!plain.empty()) std::memcpy(buf.data(), plain.data(), plain.size());

    const std::size_t blocks = buf.size() / 8;
    const std::size_t head = cipher.size();
    cipher.resize(head + buf.size());
    uint8_t chain[8];
    std::memcpy(chain, iv, 8);
    for (std::size_t b = 0; b < blocks; ++b) {
        uint8_t in[8], out[8];
        for (int i = 0; i < 8; ++i) in[i] = static_cast<uint8_t>(buf[b * 8 + i] ^ chain[i]);
        edeEncrypt(k1, k2, in, out);
        std::memcpy(cipher.data() + head + b * 8, out, 8);
        std::memcpy(chain, out, 8);
    }
    /* Encrypt-then-MAC：tag = HMAC-SHA256(macKey, 全部密文)[0..15] */
    uint8_t tag[32];
    CSha256::hmac(macKey, 32, cipher.data(), cipher.size(), tag);
    cipher.insert(cipher.end(), tag, tag + Crypto::kTagSize);
    std::memset(chain, 0, sizeof(chain));
    return E_OK;
}

ErrCode DesEdeCbcDecrypt(const uint8_t key[32], const uint8_t macKey[32],
                         const std::vector<uint8_t>& cipher, std::vector<uint8_t>& plain) {
    uint64_t rawLen = 0;
    std::size_t start = 0;
    if (!Crypto::readCipherHeader(cipher, kDesMagic, rawLen, start)) return E_CRYPTO_FAIL;
    /* 12 + IV8 + 密文(>=8) + tag16 */
    if (cipher.size() < start + 8 + 8 + 16) return E_TRUNCATED_ARCHIVE;
    const std::size_t ctStart = start + 8;
    const std::size_t ctLen = cipher.size() - ctStart - Crypto::kTagSize;
    if (ctLen % 8) return E_CRYPTO_FAIL;

    uint8_t tag[32];
    CSha256::hmac(macKey, 32, cipher.data(), ctStart + ctLen, tag);
    if (std::memcmp(tag, cipher.data() + cipher.size() - Crypto::kTagSize, Crypto::kTagSize) != 0) {
        return E_WRONG_PASSWORD;                     /* 口令错或数据被篡改 */
    }

    const CDes k1(key);
    const CDes k2(key + 8);
    uint8_t chain[8];
    std::memcpy(chain, cipher.data() + start, 8);
    std::vector<uint8_t> buf(ctLen);
    for (std::size_t b = 0; b < ctLen / 8; ++b) {
        uint8_t out[8];
        edeDecrypt(k1, k2, cipher.data() + ctStart + b * 8, out);
        for (int i = 0; i < 8; ++i) buf[b * 8 + i] = static_cast<uint8_t>(out[i] ^ chain[i]);
        std::memcpy(chain, cipher.data() + ctStart + b * 8, 8);
    }
    const uint8_t pad = buf.empty() ? 0 : buf[buf.size() - 1];
    if (pad == 0 || pad > 8 || buf.size() < rawLen + pad) return E_CRYPTO_FAIL;
    for (std::size_t i = buf.size() - pad; i < buf.size(); ++i) {
        if (buf[i] != pad) return E_CRYPTO_FAIL;
    }
    buf.resize(buf.size() - pad);
    if (buf.size() != rawLen) return E_CRYPTO_FAIL;
    plain.swap(buf);
    return E_OK;
}

} /* namespace DBKP */
