/* ============================================================================
 *  Codecs.h  -- 自实现的压缩算法（不使用 zlib/bzip2 等第三方库）
 *
 *  流格式统一为：magic(2) + version(1) + flags(1) + rawLen(8) + payload
 *  全部小端；解码失败一律返回错误码，绝不越界写。
 * ==========================================================================*/
#ifndef DBKP_CODEC_CODECS_H
#define DBKP_CODEC_CODECS_H

#include <string>
#include <vector>

#include "Codec/DataCodec.h"

namespace DBKP {

static const uint32_t CODEC_MAGIC_HUFF = 0x4846u;   /* 'H''F' */
static const uint32_t CODEC_MAGIC_LZ   = 0x4C5Au;   /* 'L''Z' */
static const uint32_t CODEC_MAGIC_RLE  = 0x5245u;   /* 'R''E' */
static const uint32_t CODEC_MAGIC_COMBO = 0x4C5Au;  /* LZHUFF 内层仍是 LZ */

/* --------------------------------------------------------------- Huffman */
class CHuffman : public IDataCodec {
public:
    /* 头：magic(2) ver(1) flags(1) rawLen(8) + 256 字节的码长表 */
    static const std::size_t kHeaderSize = 12 + 256;
    static const int kMaxCodeLen = 24;

    std::string name() const override { return "huffman"; }
    ErrCode encode(const std::vector<uint8_t>& in, std::vector<uint8_t>& out) override;
    ErrCode decode(const std::vector<uint8_t>& in, std::vector<uint8_t>& out) override;

    /** 供测试与文档使用：由频表构造 1..kMaxCodeLen 的规范码长 */
    static void buildCodeLengths(const uint32_t freq[256], uint8_t len[256]);
    /** 码长表 -> 规范码（symbol -> code/len） */
    static void buildCanonicalCodes(const uint8_t len[256], uint32_t code[256]);
};

/* ------------------------------------------------------------------ LZ77 */
class CLZ77 : public IDataCodec {
public:
    static const int kWindowBits   = 12;              /* 4096 字节滑动窗口 */
    static const int kWindowSize   = 1 << kWindowBits;
    static const int kMinMatch     = 3;
    static const int kMaxMatch     = 18;              /* 4 bit 长度字段 + 3 */
    static const int kNumLitPerCtrl = 8;              /* 每 8 个项一个控制字节 */

    std::string name() const override { return "lz77"; }
    ErrCode encode(const std::vector<uint8_t>& in, std::vector<uint8_t>& out) override;
    ErrCode decode(const std::vector<uint8_t>& in, std::vector<uint8_t>& out) override;
};

/* ------------------------------------------------------------------- RLE */
class CRle : public IDataCodec {
public:
    std::string name() const override { return "rle"; }
    ErrCode encode(const std::vector<uint8_t>& in, std::vector<uint8_t>& out) override;
    ErrCode decode(const std::vector<uint8_t>& in, std::vector<uint8_t>& out) override;
};

/* ---------------------------------------------------- LZ77 + Huffman 组合 */
class CComboCodec : public IDataCodec {
public:
    CComboCodec() : m_inner(new CLZ77), m_outer(new CHuffman) {}
    ~CComboCodec() override { delete m_inner; delete m_outer; }
    std::string name() const override { return "lzhuff"; }
    ErrCode encode(const std::vector<uint8_t>& in, std::vector<uint8_t>& out) override;
    ErrCode decode(const std::vector<uint8_t>& in, std::vector<uint8_t>& out) override;

private:
    IDataCodec* m_inner;
    IDataCodec* m_outer;
};

/* ------------------------------------------------------------- 公共小工具 */
namespace Codec {

void putHeader(std::vector<uint8_t>& out, uint16_t magic, uint8_t ver, uint8_t flags,
               uint64_t rawLen);
/** 校验并解析头，返回 payload 起始下标；失败返回 false */
bool readHeader(const std::vector<uint8_t>& in, uint16_t expectMagic,
                uint8_t& ver, uint8_t& flags, uint64_t& rawLen, std::size_t& payloadStart);

/** 位写入器（低位在前；规范码用 writeMsb 保证与解码端一致） */
class BitWriter {
public:
    explicit BitWriter(std::vector<uint8_t>& out) : m_out(out), m_acc(0), m_bits(0) {}
    void write(uint32_t value, int nbits);
    void writeMsb(uint32_t value, int nbits);
    void flush();
private:
    std::vector<uint8_t>& m_out;
    uint32_t m_acc;
    int m_bits;
};

/** 位读取器（低位在前），越界返回 false */
class BitReader {
public:
    BitReader(const uint8_t* data, std::size_t size) : m_data(data), m_size(size),
        m_pos(0), m_acc(0), m_bits(0) {}
    bool read(uint32_t& value, int nbits);
    bool readMsb(uint32_t& value, int nbits);
    bool eofBits() const { return m_pos >= m_size && m_bits == 0; }
    uint64_t bitsConsumed() const {
        return uint64_t(m_pos) * 8 - uint64_t(m_bits);
    }
private:
    const uint8_t* m_data;
    std::size_t m_size;
    std::size_t m_pos;
    uint32_t m_acc;
    int m_bits;
};

} /* namespace Codec */
} /* namespace DBKP */

#endif /* DBKP_CODEC_CODECS_H */
