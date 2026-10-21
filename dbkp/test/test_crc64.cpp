/* ============================================================================
 *  test_crc64.cpp  -- CRC-64/ECMA-182 实现的性质与回归测试
 * ==========================================================================*/
#include "TestFramework.h"

#include <cstring>
#include <string>
#include <vector>

#include "Utils/CRC64.h"

using DBKP::CRC64;

TEST(Crc64, EmptyInputIsZero) {
    EXPECT_EQ(CRC64::compute(nullptr, 0), 0ull);
}

TEST(Crc64, IncrementalEqualsOneShot) {
    const std::string text = "the quick brown fox jumps over the lazy dog";
    const uint8_t* p = reinterpret_cast<const uint8_t*>(text.data());
    uint64_t one = CRC64::compute(p, text.size());

    CRC64 acc;
    for (size_t i = 0; i < text.size(); ++i) acc.update(p + i, 1);
    EXPECT_EQ(acc.value(), one);

    CRC64 acc2;
    size_t off = 0;
    while (off < text.size()) {
        size_t take = (text.size() - off) < 7 ? text.size() - off : 7;
        acc2.update(p + off, take);
        off += take;
    }
    EXPECT_EQ(acc2.value(), one);
}

TEST(Crc64, DetectsSingleBitFlip) {
    std::vector<uint8_t> data;
    for (int i = 0; i < 4096; ++i) data.push_back(static_cast<uint8_t>(i * 7 + 3));
    const uint64_t base = CRC64::compute(data.data(), data.size());
    int detected = 0;
    for (size_t byte = 0; byte < 64; ++byte) {
        for (int bit = 0; bit < 8; ++bit) {
            std::vector<uint8_t> copy = data;
            copy[byte] = static_cast<uint8_t>(copy[byte] ^ (1 << bit));
            if (CRC64::compute(copy.data(), copy.size()) != base) ++detected;
        }
    }
    EXPECT_EQ(detected, 512);   /* 任何一个单比特翻转都必须被 64 位 CRC 发现 */
}

TEST(Crc64, RegressionValues) {
    /* 参考值由独立实现（Python 按 CRC-64/ECMA-182 定义逐位计算）得到并固化，
       作用是：一旦有人改动表格/多项式导致归档格式不兼容，测试立刻失败。 */
    const char* a = "123456789";
    EXPECT_EQ(CRC64::compute(a, 9), 0x6c40df5f0b497347ull);
    const char* b = "abc";
    EXPECT_EQ(CRC64::compute(b, 3), 0x66501a349a0e0855ull);
    EXPECT_EQ(CRC64::toString(CRC64::compute(b, 3)), std::string("66501a349a0e0855"));
}

TEST(Crc64, OrderSensitive) {
    const char* ab = "AB";
    const char* ba = "BA";
    EXPECT_NE(CRC64::compute(ab, 2), CRC64::compute(ba, 2));
}
