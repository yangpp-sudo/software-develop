/* ============================================================================
 *  test_regress_f3.cpp  -- F3 弱随机源修复的命名回归测试
 *
 *  背景（整改清单 F3）：原 fillRandom()/fillSalt() 用 time()+栈地址播种的
 *  xorshift 生成 IV/nonce/salt。fillSalt 的 seed 取的是"当前调用栈上局部变量
 *  的地址"，同一次进程运行、同一秒内连续两次 pack() 时，time() 相同、栈地址
 *  也相同 → 两箱 salt 完全一致（可预测）。
 *
 *  修法：Windows 改 BCryptGenRandom(BCRYPT_USE_SYSTEM_PREFERRED_RNG)，
 *        POSIX 改 getrandom()/urandom。接口签名不变。
 *
 *  本测试能在旧实现上稳定失败、在新实现上稳定通过：
 *    1) 同一进程同一秒内连打两箱，头部 salt（offset 68, 16B）必须不同；
 *    2) fillRandom 两次调用结果不同；
 *    3) 大样本字节覆盖全部 256 个取值（退化/低熵源会被抓出）。
 * ==========================================================================*/
#include "TestFramework.h"

#include <cstring>
#include <string>
#include <vector>

#include "Crypto/Algorithms.h"
#include "Pack/MyPack.h"
#include "Platform/FS.h"
#include "Utils/PathUtil.h"
#include "Utils/SimpleFile.h"

using namespace DBKP;

namespace {

const char* const kSrc   = "treg_f3_src";
const char* const kArcA  = "treg_f3_a.dbkp";
const char* const kArcB  = "treg_f3_b.dbkp";

void writeText(const std::string& abs, const std::string& text) {
    const std::string parent = Path::parentDir(abs);
    if (!parent.empty()) Platform::makeDirTree(parent);
    CSimpleFile::writeWhole(abs, std::vector<uint8_t>(text.begin(), text.end()));
}
void removeTree(const std::string& p) {
    std::vector<Platform::DirEntry> items;
    if (DBKP_IS_ERR(Platform::listDir(p, items))) return;
    for (size_t i = 0; i < items.size(); ++i) {
        const std::string c = Path::join(p, items[i].name);
        if (items[i].type == FT_DIR) removeTree(c);
        else Platform::removeFile(c);
    }
    Platform::removeDir(p);
}

/* 读归档头部第 68 字节起的 16 字节 salt（布局见 Common/Serialize.cpp）。 */
bool readSalt(const std::string& arc, uint8_t out[16]) {
    std::vector<uint8_t> bytes;
    if (DBKP_IS_ERR(CSimpleFile::readWhole(arc, bytes))) return false;
    if (bytes.size() < 68 + 16) return false;
    std::memcpy(out, bytes.data() + 68, 16);
    return true;
}

} /* anonymous namespace */

/* 主回归：同进程、同一秒内连打两箱，salt 必须无相关性（不同）。 */
TEST(RegressF3, random_source) {
    removeTree(kSrc);
    Platform::removeFile(kArcA);
    Platform::removeFile(kArcB);
    Platform::makeDirTree(kSrc);
    /* 固定明文：若 salt/IV 可预测，两箱会逐字节相同 */
    writeText(Path::join(kSrc, "one.txt"), std::string(2048, 'x'));

    CMyPack packer;
    PackOptions po;
    po.crypto   = CRY_AES256_CBC;
    po.password = "S3cret!";

    ASSERT_EQ(packer.pack(kSrc, kArcA, po), E_OK);
    ASSERT_EQ(packer.pack(kSrc, kArcB, po), E_OK);

    uint8_t saltA[16], saltB[16];
    ASSERT_TRUE(readSalt(kArcA, saltA));
    ASSERT_TRUE(readSalt(kArcB, saltB));

    /* 核心断言：旧实现（time+栈地址播种）在此处两 salt 相等 → 失败 */
    EXPECT_NE(std::memcmp(saltA, saltB, 16), 0);

    /* 附带：两箱整体字节也应不同（IV 同样来自强随机源） */
    std::vector<uint8_t> a, b;
    ASSERT_EQ(CSimpleFile::readWhole(kArcA, a), E_OK);
    ASSERT_EQ(CSimpleFile::readWhole(kArcB, b), E_OK);
    EXPECT_TRUE(a != b);

    removeTree(kSrc);
    Platform::removeFile(kArcA);
    Platform::removeFile(kArcB);
}

/* fillRandom 本身：两次调用不同 + 大样本覆盖全部 256 字节值。 */
TEST(RegressF3, fillRandomIsStrong) {
    uint8_t x[32], y[32];
    std::memset(x, 0, sizeof(x));
    std::memset(y, 0, sizeof(y));
    fillRandom(x, sizeof(x));
    fillRandom(y, sizeof(y));
    EXPECT_NE(std::memcmp(x, y, sizeof(x)), 0);

    /* 全 0 / 退化源会被这条抓出 */
    bool allZero = true;
    for (size_t i = 0; i < sizeof(x); ++i) {
        if (x[i] != 0) { allZero = false; break; }
    }
    EXPECT_FALSE(allZero);

    /* 16KB 样本应覆盖全部 256 个字节值（弱/短周期源难以稳定覆盖） */
    const size_t N = 16384;
    std::vector<uint8_t> big(N, 0);
    fillRandom(big.data(), N);
    std::vector<int> seen(256, 0);
    for (size_t i = 0; i < N; ++i) seen[big[i]] = 1;
    int distinct = 0;
    for (int v : seen) distinct += v;
    EXPECT_EQ(distinct, 256);
}
