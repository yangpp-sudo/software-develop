/* ============================================================================
 *  CodecFactory.cpp  -- 算法注册与工厂（AlgorithmFactory / CryptoFactory）
 * ==========================================================================*/
#include "Codec/Codecs.h"
#include "Codec/DataCodec.h"

#include "Crypto/Algorithms.h"

namespace DBKP {

IDataCodec* CompressionFactory::create(AlgorithmId id) {
    switch (id) {
    case ALG_NONE:    return nullptr;
    case ALG_HUFFMAN: return new CHuffman();
    case ALG_LZ77:    return new CLZ77();
    case ALG_RLE:     return new CRle();
    case ALG_LZHUFF:  return new CComboCodec();
    default:          return nullptr;
    }
}

const char* CompressionFactory::description(AlgorithmId id) {
    switch (id) {
    case ALG_NONE:    return "no compression";
    case ALG_HUFFMAN: return "canonical Huffman, byte frequency table, <=24-bit codes";
    case ALG_LZ77:    return "LZ77, 4096B window, 3..18 byte matches, hash-accelerated";
    case ALG_RLE:     return "run-length coding with escape tokens";
    case ALG_LZHUFF:  return "LZ77 followed by Huffman (two-stage pipeline)";
    default:          return "unknown";
    }
}

IDataCodec* CryptoFactory::create(CryptoId id, const std::string& password,
                                  const uint8_t salt[16], int kdfRounds) {
    switch (id) {
    case CRY_NONE:       return nullptr;
    case CRY_AES256_CBC: return NewAesCbcCodec(password, salt, kdfRounds);
    case CRY_CHACHA20:   return NewChaCha20Codec(password, salt, kdfRounds);
    case CRY_XOR_TEST:   return newXorTestCodec(password);
    default:             return nullptr;
    }
}

const char* CryptoFactory::description(CryptoId id) {
    switch (id) {
    case CRY_NONE:       return "no encryption";
    case CRY_AES256_CBC: return "self-implemented AES-256-CBC, PKCS#7 padding, SHA-256 KDF";
    case CRY_CHACHA20:   return "self-implemented ChaCha20 stream cipher, SHA-256 KDF";
    case CRY_XOR_TEST:   return "test-only keystream cipher (NOT secure)";
    default:             return "unknown";
    }
}

} /* namespace DBKP */
