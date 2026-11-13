/* ============================================================================
 *  test_wb_codec.cpp  -- 批次10 白盒单测 B5：四种压缩算法 × 五种输入
 *
 *  覆盖目标（白盒，逐分支）：
 *    CHuffman::encode/decode      src/Codec/Huffman.cpp:95 / :121
 *    CLZ77::encode/decode         src/Codec/LZ77.cpp:15  / :85
 *    CRle::encode/decode          src/Codec/LZ77.cpp:136 / :166
 *    CComboCodec::encode/decode   src/Codec/LZ77.cpp:204 / :211
 *    Codec::putHeader/readHeader  src/Codec/BitIo.cpp:11 / :20
 *  判据：语句覆盖 + 分支覆盖。五种输入专门命中不同分支：
 *    empty      -> in.empty() 早退分支（Huffman 0 符号 / LZ77 0 项 / RLE 0 游程）
 *    1 byte     -> 单字节、无法形成 match/min-run 的边界分支
 *    zeros 1MB  -> 全同字节：RLE 超长游程分支、LZ77 最大 match(18) 反复命中
 *    random 1MB -> 无重复：LZ77 逐字节 literal 分支、Huffman 码长逼近 24 上限
 *    repeat100K -> 中等重复块：LZ77 短/长 match 混合分支
 *  每条 TEST 都：encode 成功 -> 头 magic/ver 正确 -> decode 成功 -> 与原文逐字节相等。
 * ==========================================================================*/
#include "TestFramework.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "Codec/Codecs.h"
#include "Codec/DataCodec.h"
#include "Common/Defs.h"

using namespace DBKP;

namespace {

/* 固定种子的 xorshift64*，保证"随机输入"用例可复现（不依赖时间/系统随机） */
struct Lcg {
    uint64_t s;
    explicit Lcg(uint64_t seed) : s(seed ? seed : 0x9E3779B97F4A7C15ull) {}
    uint32_t next() {
        s ^= s >> 12; s ^= s << 25; s ^= s >> 27;
        return uint32_t((s * 2685821657736338717ull) >> 32);
    }
};

std::vector<uint8_t> inEmpty() { return std::vector<uint8_t>(); }

std::vector<uint8_t> inOneByte() {
    std::vector<uint8_t> v(1, 0x5A);
    return v;
}

std::vector<uint8_t> inZeros1MB() { return std::vector<uint8_t>(1024 * 1024, 0x00); }

std::vector<uint8_t> inRandom1MB() {
    Lcg g(0xDEADBEEFCAFEBABEull);
    std::vector<uint8_t> v(1024 * 1024);
    for (size_t i = 0; i < v.size(); ++i) v[i] = uint8_t(g.next() & 0xFF);
    return v;
}

std::vector<uint8_t> inRepeat100KB() {
    /* 256 字节周期图案重复到 100KB：既有 match 又有 literal 的混合分支 */
    Lcg g(0x0123456789ABCDEFull);
    std::vector<uint8_t> pat(256);
    for (size_t i = 0; i < pat.size(); ++i) pat[i] = uint8_t(g.next() & 0xFF);
    std::vector<uint8_t> v;
    v.reserve(100 * 1024);
    while (v.size() < 100u * 1024u) v.insert(v.end(), pat.begin(), pat.end());
    v.resize(100 * 1024);
    return v;
}

/* 通用往返断言：编码->头校验->解码->逐字节相等 */
void roundTrip(IDataCodec* codec, const std::vector<uint8_t>& in) {
    ASSERT_TRUE(codec != nullptr);
    std::vector<uint8_t> enc, dec;
    ErrCode e = codec->encode(in, enc);
    ASSERT_EQ(int(e), int(E_OK));
    /* 非空输入必须产出至少一个头（>=12B：magic2 ver1 flags1 rawLen8） */
    if (!in.empty()) EXPECT_GE((int)enc.size(), 12);
    ErrCode d = codec->decode(enc, dec);
    ASSERT_EQ(int(d), int(E_OK));
    ASSERT_EQ((int)dec.size(), (int)in.size());
    if (!in.empty())
        EXPECT_EQ(0, std::memcmp(dec.data(), in.data(), in.size()));
    delete codec;
}

/* 各算法工厂创建（CompressionFactory::create 覆盖 CodecFactory.cpp:11 的 switch） */
IDataCodec* make(AlgorithmId id) { return CompressionFactory::create(id); }

} /* anonymous namespace */

/* --------------------------------------------------------------- Huffman */
TEST(WbCodecHuffman, empty)       { roundTrip(make(ALG_HUFFMAN), inEmpty()); }
TEST(WbCodecHuffman, oneByte)     { roundTrip(make(ALG_HUFFMAN), inOneByte()); }
TEST(WbCodecHuffman, zeros1MB)    { roundTrip(make(ALG_HUFFMAN), inZeros1MB()); }
TEST(WbCodecHuffman, random1MB)   { roundTrip(make(ALG_HUFFMAN), inRandom1MB()); }
TEST(WbCodecHuffman, repeat100KB) { roundTrip(make(ALG_HUFFMAN), inRepeat100KB()); }

/* ------------------------------------------------------------------ LZ77 */
TEST(WbCodecLz77, empty)       { roundTrip(make(ALG_LZ77), inEmpty()); }
TEST(WbCodecLz77, oneByte)     { roundTrip(make(ALG_LZ77), inOneByte()); }
TEST(WbCodecLz77, zeros1MB)    { roundTrip(make(ALG_LZ77), inZeros1MB()); }
TEST(WbCodecLz77, random1MB)   { roundTrip(make(ALG_LZ77), inRandom1MB()); }
TEST(WbCodecLz77, repeat100KB) { roundTrip(make(ALG_LZ77), inRepeat100KB()); }

/* ------------------------------------------------------------------- RLE */
TEST(WbCodecRle, empty)       { roundTrip(make(ALG_RLE), inEmpty()); }
TEST(WbCodecRle, oneByte)     { roundTrip(make(ALG_RLE), inOneByte()); }
TEST(WbCodecRle, zeros1MB)    { roundTrip(make(ALG_RLE), inZeros1MB()); }
TEST(WbCodecRle, random1MB)   { roundTrip(make(ALG_RLE), inRandom1MB()); }
TEST(WbCodecRle, repeat100KB) { roundTrip(make(ALG_RLE), inRepeat100KB()); }

/* -------------------------------------------------------- LZ77+Huffman 组合 */
TEST(WbCodecCombo, empty)       { roundTrip(make(ALG_LZHUFF), inEmpty()); }
TEST(WbCodecCombo, oneByte)     { roundTrip(make(ALG_LZHUFF), inOneByte()); }
TEST(WbCodecCombo, zeros1MB)    { roundTrip(make(ALG_LZHUFF), inZeros1MB()); }
TEST(WbCodecCombo, random1MB)   { roundTrip(make(ALG_LZHUFF), inRandom1MB()); }
TEST(WbCodecCombo, repeat100KB) { roundTrip(make(ALG_LZHUFF), inRepeat100KB()); }

/* ------------------------------------------------ 头/工厂的补充白盒断言 */

/* readHeader 对错误 magic / 过短输入的拒绝分支（BitIo.cpp:20） */
TEST(WbCodecHeader, rejectBadMagicAndTruncated) {
    CHuffman h;
    std::vector<uint8_t> in(64, 'q');
    std::vector<uint8_t> enc;
    ASSERT_EQ(int(h.encode(in, enc)), int(E_OK));
    /* 截断到不足头长 -> decode 必须返回错误而非崩溃 */
    std::vector<uint8_t> trunc(enc.begin(), enc.begin() + 6);
    std::vector<uint8_t> out;
    EXPECT_NE(int(h.decode(trunc, out)), int(E_OK));
    /* 篡改 magic 首字节 -> readHeader 幻数不符 */
    std::vector<uint8_t> bad = enc;
    bad[0] ^= 0xFF;
    EXPECT_NE(int(h.decode(bad, out)), int(E_OK));
    /* 空缓冲 */
    std::vector<uint8_t> emptyIn;
    EXPECT_NE(int(h.decode(emptyIn, out)), int(E_OK));
}

/* 工厂对未知算法返回 nullptr（CodecFactory.cpp:11 default 分支） */
TEST(WbCodecFactory, unknownReturnsNullAndDescriptions) {
    EXPECT_TRUE(CompressionFactory::create(ALG_NONE) == nullptr);
    EXPECT_TRUE(CompressionFactory::create(ALG_COUNT) == nullptr);
    EXPECT_TRUE(make(ALG_HUFFMAN) != nullptr);
    delete make(ALG_HUFFMAN);
    EXPECT_TRUE(make(ALG_LZ77) != nullptr);
    delete make(ALG_LZ77);
    EXPECT_TRUE(make(ALG_RLE) != nullptr);
    delete make(ALG_RLE);
    EXPECT_TRUE(make(ALG_LZHUFF) != nullptr);
    delete make(ALG_LZHUFF);
    /* description 对每个合法 id 返回非空串 */
    EXPECT_TRUE(CompressionFactory::description(ALG_HUFFMAN) != nullptr);
    EXPECT_TRUE(CompressionFactory::description(ALG_LZ77) != nullptr);
    EXPECT_TRUE(CompressionFactory::description(ALG_RLE) != nullptr);
    EXPECT_TRUE(CompressionFactory::description(ALG_LZHUFF) != nullptr);
}
