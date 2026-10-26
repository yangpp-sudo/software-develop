/* ============================================================================
 *  Defs.cpp  -- 名称/描述转换与错误码字符串
 * ==========================================================================*/
#include "Common/Defs.h"

namespace DBKP {

const char* errCodeToString(ErrCode code) {
    switch (code) {
    case E_OK:                      return "success";
    case E_INVALID_PARAMETER:       return "invalid parameter";
    case E_DESTINATION_NOT_EMPTY:   return "destination is not an empty directory";
    case E_DESTINATION_CREATE_FAIL: return "failed to create destination";
    case E_SOURCE_NOT_FOUND:        return "source path not found";
    case E_FILE_OPEN_FAIL:          return "failed to open file";
    case E_FILE_READ_FAIL:          return "failed to read file";
    case E_FILE_WRITE_FAIL:         return "failed to write file";
    case E_INVALID_HEADER_RECORD:   return "invalid header record";
    case E_INVALID_DATA_RECORD:     return "invalid data record";
    case E_CHECKSUM_MISMATCH:       return "checksum mismatch (archive corrupted)";
    case E_PATH_TOO_LONG:           return "path too long";
    case E_NOT_ENOUGH_SPACE:        return "not enough space on device";
    case E_PERMISSION_DENIED:       return "permission denied";
    case E_UNSUPPORTED_FEATURE:     return "unsupported feature on this platform";
    case E_TRUNCATED_ARCHIVE:       return "truncated archive";
    case E_WRONG_PASSWORD:          return "wrong password or damaged archive";
    case E_CRYPTO_FAIL:             return "crypto failed";
    case E_COMPRESS_FAIL:           return "compression failed";
    case E_ALREADY_EXISTS:          return "already exists";
    case E_NOT_FOUND:               return "not found";
    case E_INTERNAL:                return "internal error";
    case E_CANCELED:                return "operation canceled";
    default:                        return "unknown error";
    }
}

const char* fileTypeToDesc(char type) {
    switch (type) {
    case FT_REGULAR:  return "regular file";
    case FT_DIR:      return "directory";
    case FT_SYMLINK:  return "symbolic link";
    case FT_BLOCK:    return "block device";
    case FT_CHAR:     return "character device";
    case FT_FIFO:     return "named pipe (FIFO)";
    case FT_SOCKET:   return "unix socket";
    case FT_HARDLINK: return "hard link";
    case FT_EXTEND:   return "extended header";
    default:          return "unknown";
    }
}

const char* algorithmName(AlgorithmId id) {
    switch (id) {
    case ALG_NONE:    return "none";
    case ALG_HUFFMAN: return "huffman";
    case ALG_LZ77:    return "lz77";
    case ALG_LZHUFF:  return "lzhuff";
    case ALG_RLE:     return "rle";
    default:          return "none";
    }
}

AlgorithmId algorithmFromName(const std::string& name) {
    if (name == "huffman" || name == "huff") return ALG_HUFFMAN;
    if (name == "lz77"     || name == "lz")   return ALG_LZ77;
    if (name == "lzhuff"   || name == "lz+huffman") return ALG_LZHUFF;
    if (name == "rle")     return ALG_RLE;
    if (name == "none"     || name.empty())   return ALG_NONE;
    return ALG_NONE;
}

const char* cryptoName(CryptoId id) {
    switch (id) {
    case CRY_NONE:       return "none";
    case CRY_AES256_CBC: return "aes256-cbc";
    case CRY_CHACHA20:   return "chacha20";
    case CRY_XOR_TEST:   return "xor-test";
    default:             return "none";
    }
}

CryptoId cryptoFromName(const std::string& name) {
    if (name == "aes" || name == "aes256" || name == "aes256-cbc") return CRY_AES256_CBC;
    if (name == "chacha" || name == "chacha20")                    return CRY_CHACHA20;
    if (name == "xor")                                             return CRY_XOR_TEST;
    if (name == "none" || name.empty())                            return CRY_NONE;
    return CRY_NONE;
}

} /* namespace DBKP */
