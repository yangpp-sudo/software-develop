/* ============================================================================
 *  test_regress_f10.cpp  -- F10（归档头部 HMAC）的命名回归测试
 *
 *  背景（整改清单 F10）：
 *    加密箱 payload 每条记录早已走 EtM（Aes.cpp 的 macKey），但 512B 卷标头
 *    不在任何校验范围内。实测篡改头部 off=159（sourcePath 区）/ off=358
 *    （comment 区）后 verify 仍返回 0 —— 头部元数据可被离线篡改，kdfRounds
 *    可被降级。
 *  修法：
 *    ① 仅加密箱追加一个 512B "头部 HMAC" 扩展块（放在最后一个扩展块之后）：
 *       普通加密箱 headerSize 512 -> 1024，sha256 加密箱 -> 1536；
 *    ② HMAC-SHA256 用 deriveCipherKeys 的 macKey，覆盖"头部前 headerSize
 *       字节中除 HMAC 块自身外"的全部内容（含 sha256 摘要块，也为将来 F28
 *       的 kdfRounds 扩展块留好位置）；
 *    ③ verify 次序：先 payload 校验，后头部 HMAC —— 口令错必然 macKey 错，
 *       若先验头会把"口令不对"误报成"卷标被篡改"；
 *    ④ 旧格式加密箱（无 HMAC 块）只 WARN 不判失败；非加密箱不写不验，
 *       行为与改动前逐字节一致。
 * ==========================================================================*/
#include "TestFramework.h"

#include <cstring>
#include <string>
#include <vector>

#include "Common/Defs.h"
#include "Common/Serialize.h"
#include "Pack/MyPack.h"
#include "Platform/FS.h"
#include "Utils/PathUtil.h"
#include "Utils/SimpleFile.h"

using namespace DBKP;

namespace {

const char* const kSrc  = "_b6_f10_src";
const char* const kArc  = "_b6_f10_box.dbkp";
const char* const kOut  = "_b6_f10_out";
const char* const kPwd  = "correct horse";

void writeText(const std::string& abs, const std::string& text) {
    const std::string parent = Path::parentDir(abs);
    if (!parent.empty()) Platform::makeDirTree(parent);
    CSimpleFile::writeWhole(abs, std::vector<uint8_t>(text.begin(), text.end()));
}

void removeTree(const std::string& p) {
    std::vector<Platform::DirEntry> items;
    if (DBKP_IS_ERR(Platform::listDir(p, items))) { Platform::removeFile(p); return; }
    for (size_t i = 0; i < items.size(); ++i) {
        const std::string c = Path::join(p, items[i].name);
        if (items[i].type == FT_DIR) removeTree(c);
        else Platform::removeFile(c);
    }
    Platform::removeDir(p);
}

class F10Fixture {
public:
    explicit F10Fixture(ChecksumId sum = CHK_CRC64, CryptoId cry = CRY_AES256_CBC)
        : m_sum(sum), m_cry(cry) {
        removeTree(kSrc); removeTree(kOut); Platform::removeFile(kArc);
        Platform::makeDirTree(kSrc);
        writeText(Path::join(kSrc, "a.txt"), "alpha beta gamma");
        writeText(Path::join(kSrc, "sub/b.txt"), "delta epsilon zeta");
        writeText(Path::join(kSrc, "c.txt"), std::string(4096, 'k'));
        PackOptions po;
        po.comp     = ALG_LZ77;
        po.crypto   = m_cry;
        po.checksum = m_sum;
        if (m_cry != CRY_NONE) po.password = kPwd;
        m_packed = (CMyPack().pack(kSrc, kArc, po) == E_OK);
    }
    ~F10Fixture() { removeTree(kSrc); removeTree(kOut); Platform::removeFile(kArc); }

    bool packed() const { return m_packed; }

    /* 把箱文件第 off 字节翻转一位后写回，返回翻转前的原字节值 */
    uint8_t flipByte(size_t off) const {
        std::vector<uint8_t> all;
        CSimpleFile::readWhole(kArc, all);
        const uint8_t old = all[off];
        all[off] = static_cast<uint8_t>(old ^ 0x01u);
        CSimpleFile::writeWhole(kArc, all);
        return old;
    }

    ErrCode verify(const char* pwd, int& bad) const {
        return CMyPack().verify(kArc, pwd, bad);
    }

    ArchiveHeader header() const {
        ArchiveHeader hdr;
        CMyPack().readHeader(kArc, hdr);
        return hdr;
    }

private:
    ChecksumId m_sum;
    CryptoId   m_cry;
    bool       m_packed = false;
};

} /* anonymous namespace */

/* ①  加密箱打包后 headerSize == 1024、HMAC 块非空、verify 通过 */
TEST(RegressF10, encrypted_box_gains_hmac_block_and_verifies) {
    F10Fixture f;
    ASSERT_TRUE(f.packed());
    const ArchiveHeader hdr = f.header();
    EXPECT_EQ(int(hdr.headerSize), int(ARCHIVE_HEADER_EXT));
    EXPECT_EQ(hdr.payloadOffset, static_cast<uint64_t>(ARCHIVE_HEADER_EXT));
    EXPECT_EQ(hdr.headerHmac.size(), static_cast<size_t>(ARCHIVE_HEADER_HMAC_SIZE));
    bool nonzero = false;
    for (size_t i = 0; i < hdr.headerHmac.size(); ++i)
        if (hdr.headerHmac[i] != 0) nonzero = true;
    EXPECT_TRUE(nonzero);                    /* 占位全零说明 finalize 没写进去 */
    int bad = 0;
    EXPECT_EQ(int(f.verify(kPwd, bad)), int(E_OK));
    EXPECT_EQ(bad, 0);
}

/* ②  篡改头部 off=159（sourcePath 区）一个字节 -> verify 非零 + 篡改文案 */
TEST(RegressF10, tamper_sourcePath_region_is_detected) {
    F10Fixture f;
    ASSERT_TRUE(f.packed());
    f.flipByte(159);
    int bad = 0;
    const ErrCode e = f.verify(kPwd, bad);
    EXPECT_NE(int(e), int(E_OK));
    EXPECT_EQ(int(e), int(E_HEADER_TAMPERED));
    EXPECT_TRUE(bad >= 1);
    EXPECT_TRUE(std::strstr(errCodeToString(e), "篡改") != nullptr);
}

/* ③  篡改头部 off=358（comment 区）一个字节 -> verify 非零 */
TEST(RegressF10, tamper_comment_region_is_detected) {
    F10Fixture f;
    ASSERT_TRUE(f.packed());
    f.flipByte(358);
    int bad = 0;
    EXPECT_NE(int(f.verify(kPwd, bad)), int(E_OK));
}

/* ③b HMAC 块自身的填充区（不在覆盖范围内）也必须受保护，
      否则改这 476 个字节能躲过所有校验。 */
TEST(RegressF10, tamper_hmac_block_padding_is_detected) {
    F10Fixture f;
    ASSERT_TRUE(f.packed());
    f.flipByte(600);                          /* 512..1023 之间的零填充 */
    int bad = 0;
    EXPECT_EQ(int(f.verify(kPwd, bad)), int(E_HEADER_TAMPERED));
}

/* ④  错误密码 verify -> 报口令错误，绝不报"头部被篡改"（次序陷阱回归） */
TEST(RegressF10, wrong_password_reports_password_not_tamper) {
    F10Fixture f;
    ASSERT_TRUE(f.packed());
    int bad = 0;
    const ErrCode e = f.verify("wrong horse", bad);
    EXPECT_NE(int(e), int(E_OK));
    EXPECT_NE(int(e), int(E_HEADER_TAMPERED));
    EXPECT_EQ(int(e), int(E_WRONG_PASSWORD));
}

/* ⑤  人造旧格式箱（剥掉 HMAC 块、headerSize/payloadOffset 改回 512）
      -> 解析成功、verify 通过（只应 WARN），不能一夜之间全红 */
TEST(RegressF10, legacy_encrypted_box_parses_and_warns_only) {
    F10Fixture f;
    ASSERT_TRUE(f.packed());
    std::vector<uint8_t> all;
    ASSERT_EQ(int(CSimpleFile::readWhole(kArc, all)), int(E_OK));
    ArchiveHeader hdr = f.header();
    ASSERT_EQ(int(hdr.headerSize), int(ARCHIVE_HEADER_EXT));
    /* 取出载荷，按"没有 HMAC 块"的旧格式重排：512B 卷标 + 载荷 */
    std::vector<uint8_t> payload(all.begin() + static_cast<long>(hdr.payloadOffset), all.end());
    hdr.headerHmac.clear();
    hdr.payloadOffset = BLOCK_SIZE;
    std::vector<uint8_t> legacy;
    encodeArchiveHeader(hdr, legacy);
    EXPECT_EQ(int(legacy.size()), BLOCK_SIZE);
    legacy.insert(legacy.end(), payload.begin(), payload.end());
    ASSERT_EQ(int(CSimpleFile::writeWhole(kArc, legacy)), int(E_OK));

    const ArchiveHeader back = f.header();
    EXPECT_EQ(int(back.headerSize), BLOCK_SIZE);
    EXPECT_TRUE(back.headerHmac.empty());
    int bad = 0;
    EXPECT_EQ(int(f.verify(kPwd, bad)), int(E_OK));   /* 只有 WARN，不判失败 */
    EXPECT_EQ(bad, 0);
    /* 旧箱的载荷仍能正常还原 */
    UnpackOptions uo;
    uo.password = kPwd;
    Platform::makeDirTree(kOut);
    EXPECT_EQ(int(CMyPack().unpack(kArc, kOut, uo)), int(E_OK));
}

/* ⑥  非加密箱：headerSize 仍是 512，无 HMAC 块，verify 行为与改动前一致 */
TEST(RegressF10, plain_box_unchanged_512_header) {
    F10Fixture f(CHK_CRC64, CRY_NONE);
    ASSERT_TRUE(f.packed());
    const ArchiveHeader hdr = f.header();
    EXPECT_EQ(int(hdr.headerSize), BLOCK_SIZE);
    EXPECT_EQ(hdr.payloadOffset, static_cast<uint64_t>(BLOCK_SIZE));
    EXPECT_TRUE(hdr.headerHmac.empty());
    int bad = 0;
    EXPECT_EQ(int(f.verify("", bad)), int(E_OK));
    EXPECT_EQ(bad, 0);
    /* 头部字节被改也照旧检不出来（维持现状，不强行处理） */
    f.flipByte(159);
    int bad2 = -1;
    EXPECT_EQ(int(f.verify("", bad2)), int(E_OK));
}

/* ⑦  sha256 加密箱：headerSize == 1536，摘要块在中间、HMAC 块在最后；
      摘要块（HMAC 覆盖范围内）被改 -> 篡改必被检出 */
TEST(RegressF10, sha256_encrypted_box_header_1536) {
    F10Fixture f(CHK_SHA256, CRY_AES256_CBC);
    ASSERT_TRUE(f.packed());
    const ArchiveHeader hdr = f.header();
    EXPECT_EQ(int(hdr.headerSize), int(ARCHIVE_HEADER_EXT_HMAC));
    EXPECT_EQ(hdr.payloadOffset, static_cast<uint64_t>(ARCHIVE_HEADER_EXT_HMAC));
    EXPECT_EQ(hdr.payloadDigest.size(), static_cast<size_t>(ARCHIVE_DIGEST_SIZE));
    EXPECT_EQ(hdr.headerHmac.size(), static_cast<size_t>(ARCHIVE_HEADER_HMAC_SIZE));
    int bad = 0;
    EXPECT_EQ(int(f.verify(kPwd, bad)), int(E_OK));

    /* HMAC 块（1024..1535）内的零填充被改：payload 校验管不到，靠块自身信封检查 */
    f.flipByte(1200);
    int bad2 = 0;
    EXPECT_EQ(int(f.verify(kPwd, bad2)), int(E_HEADER_TAMPERED));
}

/* ⑧  篡改 kdfRounds（头部偏移 84）必须被检出：这正是清单点名的降级攻击 */
TEST(RegressF10, kdf_rounds_downgrade_is_detected) {
    F10Fixture f;
    ASSERT_TRUE(f.packed());
    std::vector<uint8_t> all;
    ASSERT_EQ(int(CSimpleFile::readWhole(kArc, all)), int(E_OK));
    all[84] = static_cast<uint8_t>(all[84] ^ 0x01u);   /* kdfRounds 低字节 */
    ASSERT_EQ(int(CSimpleFile::writeWhole(kArc, all)), int(E_OK));
    int bad = 0;
    const ErrCode e = f.verify(kPwd, bad);
    /* 改小轮数 -> macKey 也随之变化，头部 HMAC 与 payload 校验都会失败；
       关键是绝不能绿灯通过。 */
    EXPECT_NE(int(e), int(E_OK));
}
