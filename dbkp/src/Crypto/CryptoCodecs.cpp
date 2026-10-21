/* ============================================================================
 *  CryptoCodecs.cpp  -- 把 AES / ChaCha20 / XOR 封装成统一的 IDataCodec
 * ==========================================================================*/
#include "Codec/DataCodec.h"
#include "Crypto/Algorithms.h"
#include "Crypto/Blob.h"
#include "Crypto/Sha256.h"

#include <cstring>

namespace DBKP {

namespace {

class CCryptoCodec : public IDataCodec {
public:
    CCryptoCodec(CryptoId id, const std::string& password,
                 const uint8_t salt[16], int rounds)
        : m_id(id), m_rounds(rounds > 0 ? rounds : 4096) {
        std::memcpy(m_salt, salt, 16);
        deriveCipherKeys(password, m_salt, m_rounds, m_enc, m_mac);
    }
    ~CCryptoCodec() override { std::memset(m_enc, 0, 32); std::memset(m_mac, 0, 32); }

    std::string name() const override { return cryptoName(m_id); }

    ErrCode encode(const std::vector<uint8_t>& in, std::vector<uint8_t>& out) override {
        return m_id == CRY_AES256_CBC ? AesCbcEncrypt(m_enc, m_mac, in, out)
                                      : ChaChaEncrypt(m_enc, m_mac, in, out);
    }
    ErrCode decode(const std::vector<uint8_t>& in, std::vector<uint8_t>& out) override {
        return m_id == CRY_AES256_CBC ? AesCbcDecrypt(m_enc, m_mac, in, out)
                                      : ChaChaDecrypt(m_enc, m_mac, in, out);
    }
    bool needsPaddedInput() const override { return m_id == CRY_AES256_CBC; }

private:
    CryptoId m_id;
    int m_rounds;
    uint8_t m_salt[16];
    uint8_t m_enc[32];
    uint8_t m_mac[32];
};

/* 仅用于单元测试的弱密码：SHA-256 计数器模式密钥流 + HMAC 标签 */
class CXorCodec : public IDataCodec {
public:
    explicit CXorCodec(const std::string& password) : m_pw(password) {}
    std::string name() const override { return "xor-test"; }

    ErrCode encode(const std::vector<uint8_t>& in, std::vector<uint8_t>& out) override {
        uint8_t nonce[8];
        fillRandom(nonce, 8);
        out.clear();
        Crypto::putCipherHeader(out, Crypto::kMagicXor, static_cast<uint64_t>(in.size()));
        out.insert(out.end(), nonce, nonce + 8);
        const std::size_t head = out.size();
        out.resize(head + in.size());
        applyKeystream(nonce, in.data(), out.data() + head, in.size());
        uint8_t tag[32];
        CSha256::hmac(nonce, 8, out.data(), head + in.size(), tag);
        out.insert(out.end(), tag, tag + Crypto::kTagSize);
        return E_OK;
    }

    ErrCode decode(const std::vector<uint8_t>& in, std::vector<uint8_t>& out) override {
        uint64_t rawLen = 0;
        std::size_t start = 0;
        if (!Crypto::readCipherHeader(in, Crypto::kMagicXor, rawLen, start)) return E_CRYPTO_FAIL;
        const std::size_t ctStart = start + 8;
        if (in.size() < ctStart + Crypto::kTagSize) return E_TRUNCATED_ARCHIVE;
        if (in.size() - ctStart - Crypto::kTagSize != rawLen) return E_CRYPTO_FAIL;
        uint8_t tag[32];
        CSha256::hmac(in.data() + start, 8, in.data(), ctStart + rawLen, tag);
        if (std::memcmp(tag, in.data() + in.size() - Crypto::kTagSize, Crypto::kTagSize) != 0) {
            return E_WRONG_PASSWORD;
        }
        out.resize(static_cast<size_t>(rawLen));
        if (rawLen) applyKeystream(in.data() + start, in.data() + ctStart, out.data(), out.size());
        return E_OK;
    }

private:
    void applyKeystream(const uint8_t nonce[8], const uint8_t* in, uint8_t* out, std::size_t len) {
        std::size_t off = 0;
        uint32_t counter = 0;
        while (off < len) {
            uint8_t material[8 + 4];
            std::memcpy(material, nonce, 8);
            for (int i = 0; i < 4; ++i) material[8 + i] = static_cast<uint8_t>(counter >> (8 * i));
            uint8_t block[32];
            CSha256::hmac(m_pw.data(), m_pw.size(), material, sizeof(material), block);
            const std::size_t take = (len - off) < 32 ? (len - off) : 32;
            for (std::size_t i = 0; i < take; ++i) out[off + i] = static_cast<uint8_t>(in[off + i] ^ block[i]);
            off += take;
            ++counter;
        }
    }

    std::string m_pw;
};

} /* anonymous namespace */

IDataCodec* NewAesCbcCodec(const std::string& password, const uint8_t salt[16], int rounds) {
    if (password.empty()) return nullptr;
    return new CCryptoCodec(CRY_AES256_CBC, password, salt, rounds);
}

IDataCodec* NewChaCha20Codec(const std::string& password, const uint8_t salt[16], int rounds) {
    if (password.empty()) return nullptr;
    return new CCryptoCodec(CRY_CHACHA20, password, salt, rounds);
}

IDataCodec* newXorTestCodec(const std::string& password) {
    if (password.empty()) return nullptr;
    return new CXorCodec(password);
}

} /* namespace DBKP */
