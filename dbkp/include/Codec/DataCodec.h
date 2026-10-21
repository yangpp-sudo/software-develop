/* ============================================================================
 *  DataCodec.h  -- 压缩/加密算法的统一插件接口
 *
 *  对应第 12 讲"如何设计压缩算法的接口"：
 *    ICompressionAlgorithm 抽象基类 + AlgorithmFactory 工厂方法。
 *  这里把压缩与加密统一成 IDataCodec（字节缓冲 → 字节缓冲），
 *  使 CMyPack 可以按"先压缩、后加密"的顺序串接任意算法组合。
 * ==========================================================================*/
#ifndef DBKP_CODEC_DATACODEC_H
#define DBKP_CODEC_DATACODEC_H

#include <string>
#include <vector>

#include "Common/Defs.h"

namespace DBKP {

class IDataCodec {
public:
    virtual ~IDataCodec() {}
    virtual std::string name() const = 0;
    /** 原始字节 -> 编码字节 */
    virtual ErrCode encode(const std::vector<uint8_t>& in, std::vector<uint8_t>& out) = 0;
    /** 编码字节 -> 原始字节（失败必须返回明确错误码，不能崩） */
    virtual ErrCode decode(const std::vector<uint8_t>& in, std::vector<uint8_t>& out) = 0;
    /** 该算法是否要求输入长度对齐（如分组密码 CBC） */
    virtual bool needsPaddedInput() const { return false; }
};

/** 压缩算法工厂（AlgorithmFactory） */
class CompressionFactory {
public:
    /** 返回 nullptr 表示未知算法；调用方负责销毁 */
    static IDataCodec* create(AlgorithmId id);
    static const char* description(AlgorithmId id);
};

/** 加密算法工厂（CryptoFactory） */
class CryptoFactory {
public:
    /** password 为空时返回 nullptr（表示不加密） */
    static IDataCodec* create(CryptoId id, const std::string& password,
                              const uint8_t salt[16], int kdfRounds);
    static const char* description(CryptoId id);
};

} /* namespace DBKP */

#endif /* DBKP_CODEC_DATACODEC_H */
