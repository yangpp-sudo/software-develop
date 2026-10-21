/* ============================================================================
 *  test_codecs.cpp  -- Huffman / LZ77 / RLE / LZ+Huffman 往返与鲁棒性
 * ==========================================================================*/
#include "TestFramework.h"

#include <cstring>
#include <string>
#include <vector>

#include "Codec/Codecs.h"

using namespace DBKP;

static std::vector<uint8_t> bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

static std::vector<uint8_t> pseudoRandom(size_t n, uint32_t seed) {
    std::vector<uint8_t> v;
    v.reserve(n);
    uint32_t x = seed ? seed : 1;
    for (size_t i = 0; i < n; ++i) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        v.push_back(static_cast<uint8_t>(x));
    }
    return v;
}

/** 对每种输入做往返；同时要求"压缩结果不能膨胀超过 1 个块" */
static void RoundTrip(IDataCodec& codec, const std::vector<uint8_t>& in, const char* tag) {
    std::vector<uint8_t> enc, dec;
    ErrCode e = codec.encode(in, enc);
    ASSERT_EQ(e, E_OK);
    e = codec.decode(enc, dec);
    ASSERT_EQ(e, E_OK);
    EXPECT_TRUE(dec == in);
    EXPECT_LE(enc.size(), in.size() + BLOCK_SIZE);
}

TEST(Huffman, RoundTrip) {
    CHuffman h;
    RoundTrip(h, std::vector<uint8_t>(), "empty");
    RoundTrip(h, bytes("a"), "one byte");
    RoundTrip(h, bytes("aa"), "two bytes");
    RoundTrip(h, bytes("hello dbkp hello dbkp hello dbkp"), "repeated");
    RoundTrip(h, std::vector<uint8_t>(5000, 0x7f), "single symbol");
    RoundTrip(h, pseudoRandom(20000, 7), "random");
    std::vector<uint8_t> all;
    for (int i = 0; i < 256; ++i) for (int k = 0; k < 100; ++k) all.push_back(static_cast<uint8_t>(i));
    RoundTrip(h, all, "uniform 256 alphabet");
}

TEST(Huffman, CompressesText) {
    CHuffman h;
    std::string s;
    for (int i = 0; i < 2000; ++i) s += "the quick brown fox 12345\n";
    std::vector<uint8_t> in = bytes(s), enc;
    ASSERT_EQ(h.encode(in, enc), E_OK);
    EXPECT_LT(enc.size(), in.size() / 4);       /* 266 字节头 + 短码表 */
}

TEST(Huffman, RejectsGarbageStream) {
    CHuffman h;
    std::vector<uint8_t> enc;
    std::string s(2000, 'x');
    ASSERT_EQ(h.encode(bytes(s), enc), E_OK);
    /* 码长表被破坏 -> 必须返回错误而不是崩溃 */
    enc[20] = 0xFF;
    std::vector<uint8_t> out;
    EXPECT_NE(h.decode(enc, out), E_OK);
    /* 截断 */
    std::vector<uint8_t> trunc = enc;
    trunc.resize(trunc.size() / 2);
    EXPECT_NE(h.decode(trunc, out), E_OK);
    /* 空输入 */
    std::vector<uint8_t> empty;
    EXPECT_NE(h.decode(empty, out), E_OK);
}

TEST(LZ77, RoundTrip) {
    CLZ77 lz;
    RoundTrip(lz, std::vector<uint8_t>(), "empty");
    RoundTrip(lz, bytes("abc"), "short");
    RoundTrip(lz, std::vector<uint8_t>(300, 'a'), "long run");
    RoundTrip(lz, bytes(std::string(500, 'h') + std::string(500, 'i')), "two runs");
    RoundTrip(lz, pseudoRandom(9000, 11), "random -> store mode");
    std::string rep;
    for (int i = 0; i < 1000; ++i) rep += "dbkp-lz77-";
    RoundTrip(lz, bytes(rep), "highly repetitive");
}

TEST(LZ77, CompressesAndStoresWhenUnprofitable) {
    CLZ77 lz;
    std::string rep;
    for (int i = 0; i < 3000; ++i) rep += "abcdefgh";
    std::vector<uint8_t> enc;
    ASSERT_EQ(lz.encode(bytes(rep), enc), E_OK);
    EXPECT_LT(enc.size(), bytes(rep).size() / 8);

    const std::vector<uint8_t> rnd = pseudoRandom(8000, 5);
    std::vector<uint8_t> enc2;
    ASSERT_EQ(lz.encode(rnd, enc2), E_OK);
    EXPECT_TRUE(enc2[3] & 1);                   /* flags bit0 = 存储模式 */
    EXPECT_LE(enc2.size(), rnd.size() + 32);
}

TEST(LZ77, MaxMatchAndWindow) {
    CLZ77 lz;
    /* 构造一个 4095 字节偏移的匹配：先放 4095 字节 A，再放一份前缀，再放 4200 字节 B */
    std::vector<uint8_t> in(4095, 0x41);
    in.insert(in.end(), in.begin(), in.begin() + 100);      /* 偏移 4095 的重复 */
    for (int i = 0; i < 4200; ++i) in.push_back(static_cast<uint8_t>(0x42 + (i & 1)));
    std::vector<uint8_t> enc, dec;
    ASSERT_EQ(lz.encode(in, enc), E_OK);
    ASSERT_EQ(lz.decode(enc, dec), E_OK);
    EXPECT_TRUE(dec == in);
}

TEST(LZ77, RejectsCorruptOffsets) {
    CLZ77 lz;
    std::string s;
    for (int i = 0; i < 1000; ++i) s += "pattern pattern ";
    std::vector<uint8_t> enc;
    ASSERT_EQ(lz.encode(bytes(s), enc), E_OK);
    for (size_t i = 12; i < enc.size(); i += 5) {
        std::vector<uint8_t> bad = enc;
        bad[i] = static_cast<uint8_t>(bad[i] ^ 0xA5);
        std::vector<uint8_t> out;
        ErrCode e = lz.decode(bad, out);
        /* 要么报错，要么解出不同内容（令牌流本身没有内建校验），但绝不能越界崩溃 */
        EXPECT_TRUE(e != E_OK || out.size() <= s.size() + 64);
    }
}

TEST(Rle, RoundTrip) {
    CRle r;
    RoundTrip(r, std::vector<uint8_t>(), "empty");
    RoundTrip(r, bytes("abababab"), "no runs");
    RoundTrip(r, std::vector<uint8_t>(1000, 0x00), "long zero run");
    RoundTrip(r, bytes(std::string(300, 'a') + std::string(2, 'b') + std::string(400, 'c')), "mixed");
    RoundTrip(r, pseudoRandom(5000, 3), "random");
}

TEST(Combo, LzThenHuffmanRoundTrip) {
    CComboCodec c;
    std::string s;
    for (int i = 0; i < 1200; ++i) s += "LZ77+Huffman pipeline " + std::to_string(i % 10);
    RoundTrip(c, bytes(s), "pipeline");
    RoundTrip(c, pseudoRandom(6000, 21), "random pipeline");
    RoundTrip(c, std::vector<uint8_t>(700, 0x5a), "run pipeline");
}

TEST(Factory, CreatesEveryAlgorithm) {
    const AlgorithmId ids[] = {ALG_HUFFMAN, ALG_LZ77, ALG_RLE, ALG_LZHUFF};
    for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); ++i) {
        IDataCodec* c = CompressionFactory::create(ids[i]);
        ASSERT_TRUE(c != nullptr);
        const std::vector<uint8_t> in = bytes(std::string(300, static_cast<char>('a' + i)));
        std::vector<uint8_t> enc, dec;
        EXPECT_EQ(c->encode(in, enc), E_OK);
        EXPECT_EQ(c->decode(enc, dec), E_OK);
        EXPECT_TRUE(dec == in);
        delete c;
    }
    EXPECT_EQ(CompressionFactory::create(ALG_NONE), nullptr);
}
