/* ============================================================================
 *  test_wb_coverage_gap.cpp -- 批次10 任务B7：覆盖率缺口定向白盒单测
 *
 *  本文件不是"随便再补几个用例"，而是按 gcov 报告逐行定位后，专门打三类
 *  从未被执行过的代码：
 *
 *  (1) src/Codec/BitIo.cpp:31-39  BitWriter::write（LSB 优先）
 *      src/Codec/BitIo.cpp:65-80  BitReader::read （LSB 优先）
 *      —— Huffman/LZ77 实际只调用 writeMsb/readMsb，LSB 一整套分支在原有
 *         318 个用例跑完后仍是 69%。唯一办法是直接对类本身做单元测试。
 *  (2) src/Crypto/CryptoCodecs.cpp:52-102,126  CXorCodec::encode/decode/
 *      applyKeystream 与 newXorTestCodec 的空密码分支 —— 原 42%。
 *  (3) src/Pack/MyPack.cpp:1065-1134 compareWithSource（整函数原为 0 覆盖），
 *      以及 stat/unpack 的特殊文件计数、硬链接去重、进度回调、取消、
 *      checkHeaderHmac 的四种篡改路径、旧格式兼容路径、pack/unpack 前置校验。
 *
 *  覆盖标准：语句覆盖 + 判定覆盖（compareWithSource 每个 ++diffCount 分支
 *  各自命中一次）+ 条件组合（记录 crc 字段 × RF_CRC_VALID 标志 四组合）。
 *
 *  诚实原则：所有期望值都来自 _probe/pn 的实测输出，不是"我以为应该是这样"。
 *  因此下面 t-cmp-05 会断言"同长度内容改动 -> diff=0"，这是 compareWithSource
 *  的真实盲区（它只重算归档内数据，从不读源文件内容），用例把它固化下来并
 *  写明原因，而不是改成"期望 1"让测试假绿。
 * ==========================================================================*/
#include "TestFramework.h"

#include <cstdint>
#include <string>
#include <vector>

#include "Codec/Codecs.h"
#include "Codec/DataCodec.h"
#include "Common/Defs.h"
#include "Common/Progress.h"
#include "Common/Serialize.h"
#include "Crypto/Algorithms.h"
#include "Pack/MyPack.h"
#include "Platform/FS.h"
#include "Utils/CRC64.h"
#include "Utils/PathUtil.h"
#include "Utils/SimpleFile.h"

namespace {

using namespace DBKP;

int g_seq = 0;

/* 递归删除（Platform 没有 removeTree，这里自己写，仅测试用） */
void cgRemoveTree(const std::string& p) {
    std::vector<Platform::DirEntry> items;
    if (DBKP_IS_ERR(Platform::listDir(p, items))) {
        Platform::removeFile(p);
        return;
    }
    for (size_t i = 0; i < items.size(); ++i) {
        const std::string c = Path::join(p, items[i].name);
        if (items[i].type == FT_DIR) cgRemoveTree(c);
        else Platform::removeFile(c);
    }
    Platform::removeDir(p);
}

/* 一个用例的目录骨架：root 独立，跑完自删，不留测试垃圾 */
struct CgSandbox {
    std::string root;
    std::string arc;
    std::string dest;
    explicit CgSandbox(const char* tag) {
        root = std::string("twb_cg_") + tag + "_" + std::to_string(g_seq++);
        arc  = Path::join(root, "box.dbkp");
        dest = Path::join(root, "out");
        cgRemoveTree(root);
        Platform::makeDirTree(root);
    }
    ~CgSandbox() { cgRemoveTree(root); }
};

void cgWrite(const std::string& p, const std::string& s) {
    std::vector<uint8_t> b(s.begin(), s.end());
    ASSERT_EQ(int(CSimpleFile::writeWhole(p, b)), int(E_OK));
}

std::string cgRead(const std::string& p) {
    std::vector<uint8_t> b;
    if (DBKP_IS_ERR(CSimpleFile::readWhole(p, b))) return std::string("<none>");
    return std::string(b.begin(), b.end());
}

uint64_t cgCrc(const std::string& s) {
    return CRC64::compute(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

int cgCountEntries(const std::string& dir) {
    std::vector<Platform::DirEntry> items;
    if (DBKP_IS_ERR(Platform::listDir(dir, items))) return -1;
    return int(items.size());
}

bool cgHasEntry(const std::string& dir, const std::string& name) {
    std::vector<Platform::DirEntry> items;
    if (DBKP_IS_ERR(Platform::listDir(dir, items))) return false;
    for (size_t i = 0; i < items.size(); ++i)
        if (items[i].name == name) return true;
    return false;
}

/* ---------------- 手工归档拼装（与 B1 同一手法，各自保留副本） ---------- */
struct Part {
    FileRecord rec;
    std::vector<uint8_t> payload;
};

uint64_t cgBlocksFor(int64_t n) { return uint64_t((n + BLOCK_SIZE - 1) / BLOCK_SIZE); }

/* 一条自洽的普通文件记录；crcValid/useOverride 用来凑条件组合 */
Part cgRegular(const std::string& rel, const std::string& body,
               bool crcValid = true, uint64_t crcOverride = 0, bool useOverride = false) {
    Part p;
    p.rec.path = rel;
    p.rec.type = FT_REGULAR;
    p.rec.compAlg   = ALG_NONE;
    p.rec.cryptoAlg = CRY_NONE;
    p.rec.flags     = crcValid ? RF_CRC_VALID : RF_NONE;
    p.payload.assign(body.begin(), body.end());
    p.rec.size       = int64_t(body.size());
    p.rec.storedSize = int64_t(body.size());
    p.rec.crc = useOverride ? crcOverride : cgCrc(body);
    return p;
}

Part cgTyped(const std::string& rel, char type, const std::string& link = std::string()) {
    Part p;
    p.rec.path = rel;
    p.rec.type = type;
    p.rec.link = link;
    p.rec.flags = RF_NONE;
    return p;
}

std::vector<uint8_t> cgBuildArchive(const std::vector<Part>& parts) {
    std::vector<uint8_t> region;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (DBKP_IS_ERR(encodeRecord(parts[i].rec, region))) return std::vector<uint8_t>();
        const int64_t bytes = parts[i].rec.storedSize;
        if (bytes > 0) {
            const size_t before = region.size();
            region.resize(before + size_t(cgBlocksFor(bytes) * BLOCK_SIZE), 0);
            for (size_t b = 0; b < size_t(bytes); ++b) region[before + b] = parts[i].payload[b];
        }
    }
    ArchiveHeader hdr;
    hdr.compAlg       = ALG_NONE;
    hdr.cryptoAlg     = CRY_NONE;
    hdr.checksum      = CHK_CRC64;
    hdr.payloadOffset = BLOCK_SIZE;
    hdr.payloadSize   = region.size();
    hdr.recordCount   = parts.size();
    hdr.fileCount     = parts.size();
    uint64_t raw = 0;
    for (size_t i = 0; i < parts.size(); ++i) raw += uint64_t(parts[i].rec.size);
    hdr.rawSize    = raw;
    hdr.payloadCrc = CRC64::compute(region.data(), region.size());

    std::vector<uint8_t> out;
    if (DBKP_IS_ERR(encodeArchiveHeader(hdr, out))) return std::vector<uint8_t>();
    out.insert(out.end(), region.begin(), region.end());
    return out;
}

void cgWriteArchive(const std::string& path, const std::vector<uint8_t>& bytes) {
    ASSERT_TRUE(!bytes.empty());
    ASSERT_EQ(int(CSimpleFile::writeWhole(path, bytes)), int(E_OK));
}

/* 只含一条记录的手工归档，配套一个源目录，供 compareWithSource 使用 */
struct CgCmpCase {
    CgSandbox sb;
    std::string src;
    explicit CgCmpCase(const char* tag) : sb(tag) {
        src = Path::join(sb.root, "src");
        Platform::makeDirTree(src);
    }
};

/* ---------------- 进度探针（IProgressSink 不可拷贝，自带 reset） -------- */
struct CgSink : public IProgressSink {
    int starts;
    int64_t startEntries;
    uint64_t startBytes;
    int ticks;
    int64_t lastEntries;
    uint64_t lastBytes;
    int cancelAfter;
    explicit CgSink(int cancelAt = 0)
        : starts(0), startEntries(0), startBytes(0), ticks(0),
          lastEntries(0), lastBytes(0), cancelAfter(cancelAt) {}
    void reset(int cancelAt = 0) {
        starts = 0; startEntries = 0; startBytes = 0;
        ticks = 0; lastEntries = 0; lastBytes = 0; cancelAfter = cancelAt;
    }
    void onStart(int64_t entries, uint64_t bytes) override {
        ++starts; startEntries = entries; startBytes = bytes;
    }
    void onProgress(int64_t entries, uint64_t bytes) override {
        ++ticks; lastEntries = entries; lastBytes = bytes;
    }
    bool canceled() const override { return cancelAfter > 0 && ticks >= cancelAfter; }
};

} /* namespace */

/* ==========================================================================
 * 一、BitIo LSB 直测（BitIo.cpp:31-39 / 65-80，原 69%）
 *  实测来源 _probe/pl、_probe/pn 第 6 节，逐字节写死，不做"大概是这样"推断。
 * ======================================================================== */

/* t-bit-01 半字节写入不落地：1bit、2bit 之后 buffer 仍为空 -> 覆盖 write 的
 * "攒够 8 位才 push_back" 判定假侧 */
TEST(WbCoverageGap, bitWriterLsbAccumulatesWithoutEmitting) {
    std::vector<uint8_t> bs;
    {
        Codec::BitWriter w(bs);
        w.write(1u, 1);
        EXPECT_EQ(bs.size(), size_t(0));
        w.write(2u, 2);
        EXPECT_EQ(bs.size(), size_t(0));
        w.write(8u, 8);
        EXPECT_EQ(bs.size(), size_t(1));   /* 第 11 位触发落盘 */
        w.write(3u, 3);
        EXPECT_EQ(bs.size(), size_t(1));
        w.flush();
    }
    /* 14 位 -> 2 字节，末字节高 2 位补零。实测 45 18 */
    ASSERT_EQ(bs.size(), size_t(2));
    EXPECT_EQ(int(bs[0]), 0x45);
    EXPECT_EQ(int(bs[1]), 0x18);
}

/* t-bit-02 逐段读回：0 位读成功且值为 0（read 的 bitLen==0 早退分支） */
TEST(WbCoverageGap, bitReaderLsbZeroBitReadSucceeds) {
    static const uint8_t kStream[2] = { 0x45, 0x18 };
    Codec::BitReader r(kStream, sizeof(kStream));
    uint32_t v = 0xA5A5u;
    EXPECT_TRUE(r.read(v, 0));
    EXPECT_EQ(int(v), 0);
    EXPECT_EQ((unsigned long long)r.bitsConsumed(), 0ull);
}

/* t-bit-03 与写入完全对称的读回序列 1/2/8/3，并核对游标与 eof */
TEST(WbCoverageGap, bitReaderLsbRoundTripsWrittenValues) {
    static const uint8_t kStream[2] = { 0x45, 0x18 };
    Codec::BitReader r(kStream, sizeof(kStream));
    uint32_t v = 0;
    EXPECT_TRUE(r.read(v, 1)); EXPECT_EQ(int(v), 1);
    EXPECT_TRUE(r.read(v, 2)); EXPECT_EQ(int(v), 2);
    EXPECT_TRUE(r.read(v, 8)); EXPECT_EQ(int(v), 8);
    EXPECT_TRUE(r.read(v, 3)); EXPECT_EQ(int(v), 3);
    EXPECT_EQ((unsigned long long)r.bitsConsumed(), 14ull);
    EXPECT_FALSE(r.eofBits());
}

/* t-bit-04 剩余 2 位不足 1 次读取时不报错、返回 0，且 eofBits 仍为假；
 * 覆盖 read 的 "缓存够" / "缓存不够但能补位" 两侧判定 */
TEST(WbCoverageGap, bitReaderLsbTailBitsDoNotSignalEof) {
    static const uint8_t kStream[2] = { 0x45, 0x18 };
    Codec::BitReader r(kStream, sizeof(kStream));
    uint32_t v = 0;
    for (int i = 0; i < 14; ++i) EXPECT_TRUE(r.read(v, 1));
    EXPECT_EQ((unsigned long long)r.bitsConsumed(), 14ull);
    v = 0xEE;
    EXPECT_TRUE(r.read(v, 1));
    EXPECT_EQ(int(v), 0);
    EXPECT_FALSE(r.eofBits());
}

/* t-bit-05 空缓冲读取：read 失败、出参清零、eofBits 为真；0 位读仍成功 */
TEST(WbCoverageGap, bitReaderLsbOnEmptyBufferFails) {
    std::vector<uint8_t> empty;
    Codec::BitReader r(empty.data(), empty.size());
    uint32_t v = 0xA5A5u;
    EXPECT_FALSE(r.read(v, 1));
    EXPECT_EQ(int(v), 0);
    EXPECT_TRUE(r.eofBits());
    EXPECT_EQ((unsigned long long)r.bitsConsumed(), 0ull);
    EXPECT_TRUE(r.read(v, 0));
}

/* t-bit-06 MSB 路径与 LSB 路径产出不同字节序（回归护栏，非新增覆盖） */
TEST(WbCoverageGap, bitWriterMsbAndLsbDifferForSameBits) {
    std::vector<uint8_t> msb, lsb;
    {
        Codec::BitWriter wm(msb);
        wm.writeMsb(1u, 1); wm.writeMsb(2u, 2); wm.writeMsb(8u, 8); wm.flush();
    }
    {
        Codec::BitWriter wl(lsb);
        wl.write(1u, 1); wl.write(2u, 2); wl.write(8u, 8); wl.flush();
    }
    ASSERT_EQ(msb.size(), size_t(2));
    ASSERT_EQ(lsb.size(), size_t(2));
    EXPECT_EQ(int(msb[0]), 0x83);
    EXPECT_EQ(int(msb[1]), 0x00);
    EXPECT_NE(int(msb[0]), int(lsb[0]));

    uint32_t v = 0;
    Codec::BitReader rm(msb.data(), msb.size());
    EXPECT_TRUE(rm.readMsb(v, 1)); EXPECT_EQ(int(v), 1);
    EXPECT_TRUE(rm.readMsb(v, 2)); EXPECT_EQ(int(v), 2);
    EXPECT_TRUE(rm.readMsb(v, 8)); EXPECT_EQ(int(v), 8);
}

/* ==========================================================================
 * 二、CXorCodec 直测（CryptoCodecs.cpp:52-102,126，原 42%）
 * ======================================================================== */

/* t-xor-01 工厂属性：算法名与 needsPaddedInput（XOR 是分节流的，不需要填充） */
TEST(WbCoverageGap, xorCodecFactoryAttributes) {
    IDataCodec* c = newXorTestCodec("pw");
    ASSERT_TRUE(c != nullptr);
    EXPECT_STREQ(std::string(c->name()).c_str(), "xor-test");
    EXPECT_FALSE(c->needsPaddedInput());
    delete c;
}

/* t-xor-02 空口令必须拒绝构造（applyKeystream 前置校验的调用点） */
TEST(WbCoverageGap, xorCodecRejectsEmptyPassword) {
    IDataCodec* c = newXorTestCodec("");
    EXPECT_TRUE(c == nullptr);
    delete c;   /* nullptr 时 delete 合法，写在这里是为了以后工厂行为变化不泄漏 */
}

/* t-xor-03 100 字节往返：密文 = 12 头 + 8 nonce + 100 明文 + 16 tag = 136 */
TEST(WbCoverageGap, xorCodecRoundTripsHundredBytes) {
    IDataCodec* c = newXorTestCodec("pw");
    ASSERT_TRUE(c != nullptr);
    std::vector<uint8_t> in;
    for (int i = 0; i < 100; ++i) in.push_back(static_cast<uint8_t>(i * 7));
    std::vector<uint8_t> enc, dec;
    EXPECT_EQ(int(c->encode(in, enc)), int(E_OK));
    EXPECT_EQ(enc.size(), size_t(136));
    EXPECT_EQ(int(c->decode(enc, dec)), int(E_OK));
    EXPECT_EQ(dec.size(), size_t(100));
    EXPECT_TRUE(dec == in);
    delete c;
}

/* t-xor-04 空明文：encode 只出 36 字节头+tag，decode 回 0 字节
 * 覆盖 encode/decode 的 "输入为空" 边界与 applyKeystream 的零长度循环 */
TEST(WbCoverageGap, xorCodecHandlesEmptyPlaintext) {
    IDataCodec* c = newXorTestCodec("pw");
    ASSERT_TRUE(c != nullptr);
    std::vector<uint8_t> enc, dec;
    EXPECT_EQ(int(c->encode(std::vector<uint8_t>(), enc)), int(E_OK));
    EXPECT_EQ(enc.size(), size_t(36));
    EXPECT_EQ(int(c->decode(enc, dec)), int(E_OK));
    EXPECT_EQ(dec.size(), size_t(0));
    delete c;
}

/* t-xor-05 垃圾输入（长度够但认证不过）-> E_CRYPTO_FAIL */
TEST(WbCoverageGap, xorCodecRejectsGarbageInput) {
    IDataCodec* c = newXorTestCodec("pw");
    ASSERT_TRUE(c != nullptr);
    std::vector<uint8_t> junk(64, 0x07), dec;
    EXPECT_EQ(int(c->decode(junk, dec)), int(E_CRYPTO_FAIL));
    delete c;
}

/* t-xor-06 篡改 tag / 篡改正文 -> E_WRONG_PASSWORD（GCM 认证失败的统一口径） */
TEST(WbCoverageGap, xorCodecReportsWrongPasswordOnTamper) {
    IDataCodec* c = newXorTestCodec("pw");
    ASSERT_TRUE(c != nullptr);
    std::vector<uint8_t> in(64, 0x5A), enc;
    ASSERT_EQ(int(c->encode(in, enc)), int(E_OK));

    std::vector<uint8_t> bad = enc;
    bad[bad.size() - 1] ^= 0xFF;
    std::vector<uint8_t> dec;
    EXPECT_EQ(int(c->decode(bad, dec)), int(E_WRONG_PASSWORD));

    bad = enc;
    bad[20] ^= 0x01;
    dec.clear();
    EXPECT_EQ(int(c->decode(bad, dec)), int(E_WRONG_PASSWORD));
    delete c;
}

/* t-xor-07 截断到不足头部 / 多出 1 字节 -> E_CRYPTO_FAIL（长度校验先于认证） */
TEST(WbCoverageGap, xorCodecReportsCryptoFailOnBadLength) {
    IDataCodec* c = newXorTestCodec("pw");
    ASSERT_TRUE(c != nullptr);
    std::vector<uint8_t> in(64, 0x5A), enc;
    ASSERT_EQ(int(c->encode(in, enc)), int(E_OK));

    std::vector<uint8_t> bad = enc;
    bad.resize(8);
    std::vector<uint8_t> dec;
    EXPECT_EQ(int(c->decode(bad, dec)), int(E_CRYPTO_FAIL));

    bad = enc;
    bad.push_back(0x00);
    dec.clear();
    EXPECT_EQ(int(c->decode(bad, dec)), int(E_CRYPTO_FAIL));
    delete c;
}

/* ==========================================================================
 * 三、XOR 全链路归档（CryptoCodecs 的 makeCrypto 路径 + MyPack 加密分支）
 * ======================================================================== */

/* t-xar-01 打包后头部如实标记 cryptoAlg=3、checksum=1、headerSize=1024、带 32 字节 HMAC */
TEST(WbCoverageGap, xorArchiveHeaderRecordsAlgorithmAndHmac) {
    CgSandbox sb("xarhdr");
    std::string src = Path::join(sb.root, "src");
    Platform::makeDirTree(Path::join(src, "sub"));
    cgWrite(Path::join(src, "x.txt"), "HELLO-XOR-PAYLOAD-0123456789");
    cgWrite(Path::join(Path::join(src, "sub"), "y.bin"), std::string(300, 'Z'));

    CMyPack mp;
    PackOptions po;
    po.crypto   = CRY_XOR_TEST;
    po.password = "pw";
    po.force    = true;
    ASSERT_EQ(int(mp.pack(src, sb.arc, po)), int(E_OK));

    ArchiveHeader h;
    ASSERT_EQ(int(mp.readHeader(sb.arc, h)), int(E_OK));
    EXPECT_EQ(int(h.cryptoAlg), int(CRY_XOR_TEST));
    EXPECT_EQ(int(h.checksum), int(CHK_CRC64));
    EXPECT_EQ(int(h.headerSize), int(1024));
    EXPECT_EQ(h.headerHmac.size(), size_t(32));
}

/* t-xar-02 正确口令：verify 干净、unpack 内容一致、compare 无差异 */
TEST(WbCoverageGap, xorArchiveVerifyUnpackCompareWithRightPassword) {
    CgSandbox sb("xarok");
    std::string src = Path::join(sb.root, "src");
    Platform::makeDirTree(Path::join(src, "sub"));
    cgWrite(Path::join(src, "x.txt"), "HELLO-XOR-PAYLOAD-0123456789");
    cgWrite(Path::join(Path::join(src, "sub"), "y.bin"), std::string(300, 'Z'));

    CMyPack mp;
    PackOptions po;
    po.crypto = CRY_XOR_TEST; po.password = "pw"; po.force = true;
    ASSERT_EQ(int(mp.pack(src, sb.arc, po)), int(E_OK));

    int bad = -1;
    EXPECT_EQ(int(mp.verify(sb.arc, "pw", bad)), int(E_OK));
    EXPECT_EQ(bad, 0);

    UnpackOptions uo; uo.password = "pw";
    EXPECT_EQ(int(mp.unpack(sb.arc, sb.dest, uo)), int(E_OK));
    EXPECT_EQ(uo.warnings, 0);
    EXPECT_STREQ(cgRead(Path::join(sb.dest, "x.txt")).c_str(), "HELLO-XOR-PAYLOAD-0123456789");
    EXPECT_EQ(cgRead(Path::join(Path::join(sb.dest, "sub"), "y.bin")).size(), size_t(300));

    int diff = -1;
    EXPECT_EQ(int(mp.compareWithSource(sb.arc, src, "pw", diff)), int(E_OK));
    EXPECT_EQ(diff, 0);
}

/* t-xar-03 错误口令在归档层是 E_CHECKSUM_MISMATCH（不是 E_WRONG_PASSWORD）。
 * 诚实记录：XOR 编解码器单独调用时报 E_WRONG_PASSWORD，但走整箱校验时，
 * 解密得到的垃圾先被 CRC 拦下，错误码在 MyPack 层被"降级"了。 */
TEST(WbCoverageGap, xorArchiveWrongPasswordSurfacesAsChecksumMismatch) {
    CgSandbox sb("xarbad");
    std::string src = Path::join(sb.root, "src");
    Platform::makeDirTree(src);
    cgWrite(Path::join(src, "x.txt"), "PAYLOAD-FOR-XOR-ARCHIVE");
    CMyPack mp;
    PackOptions po;
    po.crypto = CRY_XOR_TEST; po.password = "pw"; po.force = true;
    ASSERT_EQ(int(mp.pack(src, sb.arc, po)), int(E_OK));

    int bad = -1;
    EXPECT_EQ(int(mp.verify(sb.arc, "nope", bad)), int(E_CHECKSUM_MISMATCH));
    EXPECT_EQ(bad, 1);

    UnpackOptions uo; uo.password = "bad";
    EXPECT_EQ(int(mp.unpack(sb.arc, sb.dest, uo)), int(E_CHECKSUM_MISMATCH));
    EXPECT_EQ(uo.warnings, 1);
}

/* t-xar-04 加密归档 + 空口令：unpack/verify 都在入口就拒绝，并给出可操作提示 */
TEST(WbCoverageGap, xorArchiveWithoutPasswordIsRejected) {
    CgSandbox sb("xarnopw");
    std::string src = Path::join(sb.root, "src");
    Platform::makeDirTree(src);
    cgWrite(Path::join(src, "x.txt"), "PAYLOAD-FOR-XOR-ARCHIVE");
    CMyPack mp;
    PackOptions po;
    po.crypto = CRY_XOR_TEST; po.password = "pw"; po.force = true;
    ASSERT_EQ(int(mp.pack(src, sb.arc, po)), int(E_OK));

    UnpackOptions uo;
    EXPECT_EQ(int(mp.unpack(sb.arc, sb.dest, uo)), int(E_WRONG_PASSWORD));
    EXPECT_STREQ(mp.lastErrorText().c_str(), "archive is encrypted, --password is required");

    int bad = -1;
    EXPECT_EQ(int(mp.verify(sb.arc, "", bad)), int(E_WRONG_PASSWORD));
    EXPECT_EQ(bad, 1);
}

/* t-xar-05 compareWithSource 对加密归档不传口令 -> E_INVALID_PARAMETER（makeCrypto 返回空的分支） */
TEST(WbCoverageGap, compareOnEncryptedArchiveWithoutPasswordFails) {
    CgSandbox sb("cmpnopw");
    std::string src = Path::join(sb.root, "src");
    Platform::makeDirTree(src);
    cgWrite(Path::join(src, "x.txt"), "PAYLOAD-FOR-XOR-ARCHIVE");
    CMyPack mp;
    PackOptions po;
    po.crypto = CRY_XOR_TEST; po.password = "pw"; po.force = true;
    ASSERT_EQ(int(mp.pack(src, sb.arc, po)), int(E_OK));

    int diff = -1;
    EXPECT_EQ(int(mp.compareWithSource(sb.arc, src, "", diff)), int(E_INVALID_PARAMETER));
    EXPECT_EQ(diff, 0);
}

/* ==========================================================================
 * 四、compareWithSource 判定矩阵（MyPack.cpp:1065-1134，原 0 覆盖）
 *  全部用手工归档，源目录可控，逐个 ++diffCount 分支单独命中。
 * ======================================================================== */

static const char* kBody = "ABCDEFGH";   /* 8 字节 */

/* t-cmp-01 归档与源完全一致 -> E_OK, diff=0（所有判定走假侧） */
TEST(WbCoverageGap, compareIdenticalReportsNoDifference) {
    CgCmpCase c("cmpsame");
    std::vector<Part> ps; ps.push_back(cgRegular("a.txt", kBody));
    cgWriteArchive(c.sb.arc, cgBuildArchive(ps));
    cgWrite(Path::join(c.src, "a.txt"), kBody);

    CMyPack mp; int diff = -1;
    EXPECT_EQ(int(mp.compareWithSource(c.sb.arc, c.src, "", diff)), int(E_OK));
    EXPECT_EQ(diff, 0);
}

/* t-cmp-02 源文件缺失 -> getInfo 失败分支，diff=1 */
TEST(WbCoverageGap, compareMissingSourceFileCountsOne) {
    CgCmpCase c("cmpdel");
    std::vector<Part> ps; ps.push_back(cgRegular("a.txt", kBody));
    cgWriteArchive(c.sb.arc, cgBuildArchive(ps));

    CMyPack mp; int diff = -1;
    EXPECT_EQ(int(mp.compareWithSource(c.sb.arc, c.src, "", diff)), int(E_OK));
    EXPECT_EQ(diff, 1);
}

/* t-cmp-03 源文件变长 -> size differs 分支，diff=1 */
TEST(WbCoverageGap, compareGrownSourceCountsOne) {
    CgCmpCase c("cmpgrow");
    std::vector<Part> ps; ps.push_back(cgRegular("a.txt", kBody));
    cgWriteArchive(c.sb.arc, cgBuildArchive(ps));
    cgWrite(Path::join(c.src, "a.txt"), std::string(kBody) + "EXTRA");

    CMyPack mp; int diff = -1;
    EXPECT_EQ(int(mp.compareWithSource(c.sb.arc, c.src, "", diff)), int(E_OK));
    EXPECT_EQ(diff, 1);
}

/* t-cmp-04 同名源变成目录 -> type differs 与 size differs 同时命中，diff=2 */
TEST(WbCoverageGap, compareFileBecameDirectoryCountsTwo) {
    CgCmpCase c("cmpdir");
    std::vector<Part> ps; ps.push_back(cgRegular("a.txt", kBody));
    cgWriteArchive(c.sb.arc, cgBuildArchive(ps));
    Platform::makeDirTree(Path::join(c.src, "a.txt"));

    CMyPack mp; int diff = -1;
    EXPECT_EQ(int(mp.compareWithSource(c.sb.arc, c.src, "", diff)), int(E_OK));
    EXPECT_EQ(diff, 2);
}

/* t-cmp-05【已知盲区，按实测固化】同长度内容改动 -> diff=0。
 * compareWithSource 只把归档里的数据重新算 CRC 与记录字段比对，
 * 从不读取源文件内容，所以"长度相同、内容被换掉"它检不出来。
 * 若将来实现补上源文件哈希，本用例会失败并提醒更新文档。 */
TEST(WbCoverageGap, compareSameLengthEditIsKnownBlindSpot) {
    CgCmpCase c("cmpsame2");
    std::vector<Part> ps; ps.push_back(cgRegular("a.txt", kBody));
    cgWriteArchive(c.sb.arc, cgBuildArchive(ps));
    cgWrite(Path::join(c.src, "a.txt"), "BBBB1111");

    CMyPack mp; int diff = -1;
    EXPECT_EQ(int(mp.compareWithSource(c.sb.arc, c.src, "", diff)), int(E_OK));
    EXPECT_EQ(diff, 0);
}

/* t-cmp-06 记录 crc 字段被改成 CRC^1（长度不变）-> content differs 分支，diff=1 */
TEST(WbCoverageGap, compareCorruptedCrcFieldCountsOne) {
    CgCmpCase c("cmpcrc");
    std::vector<Part> ps;
    ps.push_back(cgRegular("a.txt", kBody, true, cgCrc(kBody) ^ 1u, true));
    cgWriteArchive(c.sb.arc, cgBuildArchive(ps));
    cgWrite(Path::join(c.src, "a.txt"), kBody);

    CMyPack mp; int diff = -1;
    EXPECT_EQ(int(mp.compareWithSource(c.sb.arc, c.src, "", diff)), int(E_OK));
    EXPECT_EQ(diff, 1);
}

/* t-cmp-07/08/09 条件组合：RF_CRC_VALID 标志 × crc 字段值。
 * 实测说明 compare 只看 rec.crc，不看 RF_CRC_VALID：
 *   有标志 + 正确 crc -> 0；无标志 + 正确 crc -> 0；无标志 + crc=0 -> 1 */
TEST(WbCoverageGap, compareIgnoresCrcValidFlagWhenCrcCorrect) {
    CgCmpCase c("cmpflag");
    cgWrite(Path::join(c.src, "a.txt"), kBody);

    std::vector<Part> withFlag;    withFlag.push_back(cgRegular("a.txt", kBody, true));
    cgWriteArchive(Path::join(c.sb.root, "f1.dbkp"), cgBuildArchive(withFlag));
    std::vector<Part> noFlag;      noFlag.push_back(cgRegular("a.txt", kBody, false));
    cgWriteArchive(Path::join(c.sb.root, "f2.dbkp"), cgBuildArchive(noFlag));
    std::vector<Part> noFlagZero;  noFlagZero.push_back(cgRegular("a.txt", kBody, false, 0, true));
    cgWriteArchive(Path::join(c.sb.root, "f3.dbkp"), cgBuildArchive(noFlagZero));

    CMyPack mp; int diff = -1;
    EXPECT_EQ(int(mp.compareWithSource(Path::join(c.sb.root, "f1.dbkp"), c.src, "", diff)), int(E_OK));
    EXPECT_EQ(diff, 0);
    EXPECT_EQ(int(mp.compareWithSource(Path::join(c.sb.root, "f2.dbkp"), c.src, "", diff)), int(E_OK));
    EXPECT_EQ(diff, 0);
    EXPECT_EQ(int(mp.compareWithSource(Path::join(c.sb.root, "f3.dbkp"), c.src, "", diff)), int(E_OK));
    EXPECT_EQ(diff, 1);
}

/* t-cmp-10 符号链接记录 vs 普通源文件 -> type differs + target differs，diff=2 */
TEST(WbCoverageGap, compareSymlinkRecordAgainstRegularSourceCountsTwo) {
    CgCmpCase c("cmpsym");
    std::vector<Part> ps; ps.push_back(cgTyped("a.txt", FT_SYMLINK, "target-x"));
    cgWriteArchive(c.sb.arc, cgBuildArchive(ps));
    cgWrite(Path::join(c.src, "a.txt"), kBody);

    CMyPack mp; int diff = -1;
    EXPECT_EQ(int(mp.compareWithSource(c.sb.arc, c.src, "", diff)), int(E_OK));
    EXPECT_EQ(diff, 2);
}

/* t-cmp-11 空文件记录 vs 空源文件 -> diff=0（storedSize==0 跳过读数据分支） */
TEST(WbCoverageGap, compareEmptyFileAgainstEmptySourceIsClean) {
    CgCmpCase c("cmpempty");
    std::vector<Part> ps; ps.push_back(cgRegular("e.txt", ""));
    cgWriteArchive(c.sb.arc, cgBuildArchive(ps));
    cgWrite(Path::join(c.src, "e.txt"), "");

    CMyPack mp; int diff = -1;
    EXPECT_EQ(int(mp.compareWithSource(c.sb.arc, c.src, "", diff)), int(E_OK));
    EXPECT_EQ(diff, 0);
}

/* t-cmp-12 多条记录（一条在、一条缺）-> diff=1，验证循环不会漏计/重计 */
TEST(WbCoverageGap, compareCountsOnlyTheMissingRecord) {
    CgCmpCase c("cmptwo");
    std::vector<Part> ps;
    ps.push_back(cgRegular("a.txt", kBody));
    ps.push_back(cgRegular("b.txt", "ZZ"));
    cgWriteArchive(c.sb.arc, cgBuildArchive(ps));
    cgWrite(Path::join(c.src, "a.txt"), kBody);

    CMyPack mp; int diff = -1;
    EXPECT_EQ(int(mp.compareWithSource(c.sb.arc, c.src, "", diff)), int(E_OK));
    EXPECT_EQ(diff, 1);
}

/* t-cmp-13 归档不存在 -> 直接返回 E_SOURCE_NOT_FOUND，diff 保持 0 */
TEST(WbCoverageGap, compareWithMissingArchiveReturnsSourceNotFound) {
    CgCmpCase c("cmpnoarc");
    CMyPack mp; int diff = -1;
    EXPECT_EQ(int(mp.compareWithSource(Path::join(c.sb.root, "nope.dbkp"), c.src, "", diff)),
              int(E_SOURCE_NOT_FOUND));
    EXPECT_EQ(diff, 0);
}

/* t-cmp-14 payloadOffset 越界 -> 读块失败走 break，函数仍返回 E_OK diff=0。
 * 诚实记录：这条路径下 compare 静默"通过"，属于实现现状。 */
TEST(WbCoverageGap, compareWithBogusPayloadOffsetSilentlyPasses) {
    CgCmpCase c("cmpoob");
    std::vector<Part> ps; ps.push_back(cgRegular("a.txt", kBody));
    std::vector<uint8_t> bytes = cgBuildArchive(ps);
    cgWriteArchive(c.sb.arc, bytes);
    cgWrite(Path::join(c.src, "a.txt"), kBody);

    ArchiveHeader h;
    ASSERT_EQ(int(decodeArchiveHeader(bytes.data(), h)), int(E_OK));
    h.payloadOffset = 100000;
    std::vector<uint8_t> moved;
    ASSERT_EQ(int(encodeArchiveHeader(h, moved)), int(E_OK));
    moved.insert(moved.end(), bytes.begin() + BLOCK_SIZE, bytes.end());
    cgWriteArchive(Path::join(c.sb.root, "oob.dbkp"), moved);

    CMyPack mp; int diff = -1;
    EXPECT_EQ(int(mp.compareWithSource(Path::join(c.sb.root, "oob.dbkp"), c.src, "", diff)), int(E_OK));
    EXPECT_EQ(diff, 0);
}

/* ==========================================================================
 * 五、stat / unpack 的特殊文件计数（MyPack stat 分类分支 + unpack 降级路径）
 * ======================================================================== */

/* t-spc-01 手工归档塞满 8 种类型，stat 计数逐个核对 */
TEST(WbCoverageGap, statCountsEveryRecordType) {
    CgSandbox sb("spcstat");
    std::vector<Part> ps;
    ps.push_back(cgTyped(".", FT_DIR));
    ps.push_back(cgRegular("f.txt", "HELLO"));
    ps.push_back(cgTyped("sym.txt", FT_SYMLINK, "f.txt"));
    ps.push_back(cgTyped("hl.txt", FT_HARDLINK, "f.txt"));
    ps.push_back(cgTyped("fifo", FT_FIFO));
    ps.push_back(cgTyped("blk", FT_BLOCK));
    ps.push_back(cgTyped("chr", FT_CHAR));
    ps.push_back(cgTyped("sock", FT_SOCKET));
    cgWriteArchive(sb.arc, cgBuildArchive(ps));

    CMyPack mp;
    ArchiveHeader h; ArchiveStat st;
    ASSERT_EQ(int(mp.stat(sb.arc, h, st)), int(E_OK));
    EXPECT_EQ((long long)st.fileCount, 1ll);
    EXPECT_EQ((long long)st.dirCount, 1ll);
    EXPECT_EQ((long long)st.linkCount, 2ll);
    EXPECT_EQ((long long)st.specialCount, 4ll);
    EXPECT_EQ((long long)st.rawBytes, 5ll);
    EXPECT_EQ((long long)st.storedBytes, 5ll);
}

/* t-spc-02 还原这个"平台不支持"的归档：整体 E_OK 但记 1 条警告，
 * 且 Windows 上只有普通文件、硬链接（降级成副本）、socket 占位文件落地 */
TEST(WbCoverageGap, unpackUnsupportedTypesWarnsAndDegrades) {
    CgSandbox sb("spcunp");
    std::vector<Part> ps;
    ps.push_back(cgTyped(".", FT_DIR));
    ps.push_back(cgRegular("f.txt", "HELLO"));
    ps.push_back(cgTyped("sym.txt", FT_SYMLINK, "f.txt"));
    ps.push_back(cgTyped("hl.txt", FT_HARDLINK, "f.txt"));
    ps.push_back(cgTyped("fifo", FT_FIFO));
    ps.push_back(cgTyped("blk", FT_BLOCK));
    ps.push_back(cgTyped("chr", FT_CHAR));
    ps.push_back(cgTyped("sock", FT_SOCKET));
    cgWriteArchive(sb.arc, cgBuildArchive(ps));

    CMyPack mp;
    UnpackOptions uo;
    ASSERT_EQ(int(mp.unpack(sb.arc, sb.dest, uo)), int(E_OK));
    EXPECT_EQ(uo.warnings, 1);   /* 非特权进程建不出符号链接，计入警告 */
    EXPECT_STREQ(cgRead(Path::join(sb.dest, "f.txt")).c_str(), "HELLO");
    EXPECT_STREQ(cgRead(Path::join(sb.dest, "hl.txt")).c_str(), "HELLO");
    EXPECT_TRUE(cgHasEntry(sb.dest, "sock"));
    EXPECT_EQ(cgRead(Path::join(sb.dest, "sock")).size(), size_t(0));
    EXPECT_FALSE(cgHasEntry(sb.dest, "fifo"));
    EXPECT_FALSE(cgHasEntry(sb.dest, "blk"));
    EXPECT_FALSE(cgHasEntry(sb.dest, "chr"));
    EXPECT_EQ(cgCountEntries(sb.dest), 3);
}

/* ==========================================================================
 * 六、硬链接去重（pack 的 ino 缓存 + restoreEntry 的硬链接重建）
 * ======================================================================== */

TEST(WbCoverageGap, hardlinkDedupeRoundTripsToSingleInode) {
    CgSandbox sb("hl");
    std::string src = Path::join(sb.root, "src");
    Platform::makeDirTree(src);
    cgWrite(Path::join(src, "one.txt"), "SHARED-CONTENT");
    ErrCode he = Platform::makeHardLink(Path::join(src, "one.txt"), Path::join(src, "two.txt"));
    if (DBKP_IS_ERR(he)) return;   /* 卷/权限不支持硬链接时跳过，不算失败 */

    Platform::FileInfo f1, f2;
    ASSERT_EQ(int(Platform::getInfo(Path::join(src, "one.txt"), f1, false)), int(E_OK));
    ASSERT_EQ(int(Platform::getInfo(Path::join(src, "two.txt"), f2, false)), int(E_OK));
    ASSERT_EQ((unsigned long long)f1.ino, (unsigned long long)f2.ino);

    CMyPack mp;
    PackOptions po; po.hardlinkDedupe = true; po.force = true;
    ASSERT_EQ(int(mp.pack(src, sb.arc, po)), int(E_OK));

    std::vector<FileRecord> recs;
    ASSERT_EQ(int(mp.list(sb.arc, recs)), int(E_OK));
    ASSERT_EQ(recs.size(), size_t(3));
    EXPECT_EQ(recs[1].type, FT_REGULAR);
    EXPECT_EQ((long long)recs[1].size, 14ll);
    EXPECT_EQ((long long)recs[1].storedSize, 14ll);
    EXPECT_EQ(int(recs[2].type), int(FT_HARDLINK));
    EXPECT_STREQ(recs[2].link.c_str(), "one.txt");
    EXPECT_EQ((long long)recs[2].storedSize, 0ll);

    UnpackOptions uo;
    ASSERT_EQ(int(mp.unpack(sb.arc, sb.dest, uo)), int(E_OK));
    EXPECT_EQ(uo.warnings, 0);
    Platform::FileInfo d1, d2;
    ASSERT_EQ(int(Platform::getInfo(Path::join(sb.dest, "one.txt"), d1, false)), int(E_OK));
    ASSERT_EQ(int(Platform::getInfo(Path::join(sb.dest, "two.txt"), d2, false)), int(E_OK));
    EXPECT_EQ((unsigned long long)d1.ino, (unsigned long long)d2.ino);
    EXPECT_STREQ(cgRead(Path::join(sb.dest, "one.txt")).c_str(), "SHARED-CONTENT");
    EXPECT_STREQ(cgRead(Path::join(sb.dest, "two.txt")).c_str(), "SHARED-CONTENT");
}

/* ==========================================================================
 * 七、进度回调与取消（MyPack 的 onStart/onProgress/canceled 三处调用点）
 * ======================================================================== */

/* t-prg-01 打包与还原都恰好 onStart 一次，并如实上报条目数与字节数 */
TEST(WbCoverageGap, progressSinkReportsStartAndCompletion) {
    CgSandbox sb("prg");
    std::string src = Path::join(sb.root, "src");
    Platform::makeDirTree(Path::join(src, "sub"));
    cgWrite(Path::join(src, "f0.txt"), "0123456789");
    cgWrite(Path::join(src, "f1.txt"), "0123456789");
    cgWrite(Path::join(Path::join(src, "sub"), "f2.txt"), "0123456789");

    CMyPack mp;
    CgSink sp;
    PackOptions po; po.progress = &sp; po.force = true;
    ASSERT_EQ(int(mp.pack(src, sb.arc, po)), int(E_OK));
    EXPECT_EQ(sp.starts, 1);
    EXPECT_EQ((long long)sp.startEntries, 5ll);   /* . + sub + 3 个文件 */
    EXPECT_EQ((unsigned long long)sp.startBytes, 30ull);
    EXPECT_EQ((long long)sp.lastEntries, 5ll);
    EXPECT_EQ((unsigned long long)sp.lastBytes, 30ull);

    CgSink su;
    UnpackOptions uo; uo.progress = &su;
    ASSERT_EQ(int(mp.unpack(sb.arc, sb.dest, uo)), int(E_OK));
    EXPECT_EQ(su.starts, 1);
    EXPECT_EQ((long long)su.startEntries, 5ll);
    EXPECT_EQ((unsigned long long)su.startBytes, 30ull);
    EXPECT_TRUE(su.ticks >= 1);
}

/* t-prg-02 还原中途取消：E_CANCELED + 明确文案，且已还原的条目不回滚（现状） */
TEST(WbCoverageGap, unpackCancelReportsCanceledAndKeepsPartialOutput) {
    CgSandbox sb("unpcancel");
    std::string src = Path::join(sb.root, "src");
    Platform::makeDirTree(src);
    cgWrite(Path::join(src, "f0.txt"), "0123456789");
    cgWrite(Path::join(src, "f1.txt"), "0123456789");

    CMyPack mp;
    PackOptions po; po.force = true;
    ASSERT_EQ(int(mp.pack(src, sb.arc, po)), int(E_OK));

    CgSink sink(2);
    UnpackOptions uo; uo.progress = &sink;
    EXPECT_EQ(int(mp.unpack(sb.arc, sb.dest, uo)), int(E_CANCELED));
    EXPECT_STREQ(mp.lastErrorText().c_str(), "restore canceled by user");
    EXPECT_EQ(sink.ticks, 2);
    /* 取消不回滚：部分产物留在原地，由用户自己决定（实测 1 个条目） */
    EXPECT_EQ(cgCountEntries(sb.dest), 1);
}

/* t-prg-03 打包中途取消：E_CANCELED + 明确文案，且不留归档、也不留 .tmp */
TEST(WbCoverageGap, packCancelLeavesNoArchiveAndNoTempFile) {
    CgSandbox sb("pkcancel");
    std::string src = Path::join(sb.root, "src");
    Platform::makeDirTree(Path::join(src, "sub"));
    cgWrite(Path::join(src, "f0.txt"), "0123456789");
    cgWrite(Path::join(src, "f1.txt"), "0123456789");
    cgWrite(Path::join(Path::join(src, "sub"), "f2.txt"), "0123456789");

    CMyPack mp;
    CgSink sink(2);
    PackOptions po; po.progress = &sink;
    EXPECT_EQ(int(mp.pack(src, sb.arc, po)), int(E_CANCELED));
    EXPECT_STREQ(mp.lastErrorText().c_str(), "backup canceled by user");
    EXPECT_NE(int(Platform::exists(sb.arc)), int(E_OK));
    EXPECT_NE(int(Platform::exists(sb.arc + ".tmp")), int(E_OK));
}

/* ==========================================================================
 * 八、checkHeaderHmac 篡改路径 + 旧格式兼容（MyPack.cpp:768-830）
 * ======================================================================== */

/* t-hmac-01 四种破坏头部的方式，错误码各不相同，逐个固化 */
TEST(WbCoverageGap, headerHmacTamperingHasDistinctErrorCodes) {
    CgSandbox sb("hmac");
    std::string src = Path::join(sb.root, "src");
    Platform::makeDirTree(src);
    cgWrite(Path::join(src, "e.txt"), "ENCRYPT-ME");

    CMyPack mp;
    PackOptions po; po.crypto = CRY_AES256_CBC; po.password = "pw"; po.force = true;
    ASSERT_EQ(int(mp.pack(src, sb.arc, po)), int(E_OK));

    ArchiveHeader h;
    ASSERT_EQ(int(mp.readHeader(sb.arc, h)), int(E_OK));
    ASSERT_EQ((int)h.headerSize, 1024);
    ASSERT_EQ(h.headerHmac.size(), size_t(32));

    std::vector<uint8_t> orig;
    ASSERT_EQ(int(CSimpleFile::readWhole(sb.arc, orig)), int(E_OK));
    /* CRC64 校验头 -> HMAC 块紧随 512 字节主头 */
    const size_t hmacOff = BLOCK_SIZE;

    struct Mode { size_t off; uint8_t xorv; bool truncate; ErrCode want; int wantBad; };
    const Mode modes[4] = {
        { hmacOff + 4 + ARCHIVE_HEADER_HMAC_SIZE + 10, 0xAB, false, E_HEADER_TAMPERED, 1 },
        { hmacOff,                                      0xFF, false, E_INVALID_HEADER_RECORD, 0 },
        { 60,                                           0xFF, false, E_HEADER_TAMPERED, 1 },
        { 0,                                            0,    true,  E_TRUNCATED_ARCHIVE, 1 }
    };
    for (int i = 0; i < 4; ++i) {
        std::vector<uint8_t> bytes = orig;
        if (modes[i].truncate) bytes.resize(bytes.size() - 3);
        else bytes[modes[i].off] ^= modes[i].xorv;

        const std::string p = Path::join(sb.root, std::string("t") + char('0' + i) + ".dbkp");
        ASSERT_EQ(int(CSimpleFile::writeWhole(p, bytes)), int(E_OK));
        int bad = -1;
        ErrCode e = mp.verify(p, "pw", bad);
        EXPECT_EQ(int(e), int(modes[i].want));
        EXPECT_EQ(bad, modes[i].wantBad);
    }
}

/* t-hmac-02 旧格式（无 HMAC 块）加密归档必须仍然可校验通过 —— 兼容性护栏 */
TEST(WbCoverageGap, legacyEncryptedArchiveWithoutHeaderHmacStillVerifies) {
    CgSandbox sb("legacy");
    std::vector<uint8_t> region;
    FileRecord r;
    r.path = "."; r.type = FT_DIR;
    ASSERT_EQ(int(encodeRecord(r, region)), int(E_OK));

    ArchiveHeader hdr;
    hdr.cryptoAlg     = CRY_AES256_CBC;
    hdr.checksum      = CHK_CRC64;
    hdr.headerSize    = 512;         /* 旧格式：没有扩展块，也就没有 HMAC */
    hdr.payloadOffset = 512;
    hdr.payloadSize   = region.size();
    hdr.recordCount   = 1;
    hdr.fileCount     = 1;
    hdr.kdfRounds     = 4096;
    hdr.payloadCrc    = CRC64::compute(region.data(), region.size());

    std::vector<uint8_t> out;
    ASSERT_EQ(int(encodeArchiveHeader(hdr, out)), int(E_OK));
    out.insert(out.end(), region.begin(), region.end());
    cgWriteArchive(sb.arc, out);

    CMyPack mp;
    ArchiveHeader h;
    ASSERT_EQ(int(mp.readHeader(sb.arc, h)), int(E_OK));
    EXPECT_EQ(h.headerHmac.size(), size_t(0));

    int bad = -1;
    EXPECT_EQ(int(mp.verify(sb.arc, "pw", bad)), int(E_OK));
    EXPECT_EQ(bad, 0);
}

/* t-hmac-03 SHA256 校验 + headerSize=1024 的手工头部：HMAC 块位置随之右移，
 * 头部本身读得出 digest，但 verify 在载荷阶段就失败（诚实记录当前顺序） */
TEST(WbCoverageGap, sha256ArchiveWithShortHeaderReadsDigestButFailsVerify) {
    CgSandbox sb("shahdr");
    std::vector<uint8_t> region;
    FileRecord r;
    r.path = "."; r.type = FT_DIR;
    ASSERT_EQ(int(encodeRecord(r, region)), int(E_OK));

    ArchiveHeader hdr;
    hdr.cryptoAlg     = CRY_AES256_CBC;
    hdr.checksum      = CHK_SHA256;
    hdr.headerSize    = 1024;
    hdr.payloadOffset = 1024;
    hdr.payloadSize   = region.size();
    hdr.recordCount   = 1;
    hdr.fileCount     = 1;
    hdr.kdfRounds     = 4096;
    hdr.payloadCrc    = CRC64::compute(region.data(), region.size());

    std::vector<uint8_t> out;
    ASSERT_EQ(int(encodeArchiveHeader(hdr, out)), int(E_OK));
    out.insert(out.end(), region.begin(), region.end());
    cgWriteArchive(sb.arc, out);

    CMyPack mp;
    ArchiveHeader h;
    ASSERT_EQ(int(mp.readHeader(sb.arc, h)), int(E_OK));
    EXPECT_EQ(h.payloadDigest.size(), size_t(32));
    EXPECT_EQ(h.headerHmac.size(), size_t(0));

    int bad = -1;
    EXPECT_EQ(int(mp.verify(sb.arc, "pw", bad)), int(E_CHECKSUM_MISMATCH));
    EXPECT_EQ(bad, 1);
}

/* ==========================================================================
 * 九、pack / unpack 前置校验（参数与头部合法性，全部实测错误码）
 * ======================================================================== */

/* t-pre-01 只给算法不给口令 / 只给口令不给算法：都拒，但文案策略不同 */
TEST(WbCoverageGap, packRefusesMismatchedCryptoAndPasswordOptions) {
    CgSandbox sb("premism");
    std::string src = Path::join(sb.root, "src");
    Platform::makeDirTree(src);
    cgWrite(Path::join(src, "a.txt"), "AAAABBBB");

    CMyPack mp;
    PackOptions noPw; noPw.crypto = CRY_AES256_CBC;
    EXPECT_EQ(int(mp.pack(src, sb.arc, noPw)), int(E_INVALID_PARAMETER));

    PackOptions noAlg; noAlg.password = "pw";
    EXPECT_EQ(int(mp.pack(src, sb.arc, noAlg)), int(E_INVALID_PARAMETER));
    EXPECT_STREQ(mp.lastErrorText().c_str(),
                 "password given but no crypto algorithm (-c): refusing to write an "
                 "unencrypted archive. Use -c aes256|chacha20|3des, or drop the password.");
}

/* t-pre-02 空参数：源路径空 / 归档路径空 / 还原参数空，一律 E_INVALID_PARAMETER */
TEST(WbCoverageGap, emptyArgumentsAreRejectedUpFront) {
    CgSandbox sb("preempty");
    std::string src = Path::join(sb.root, "src");
    Platform::makeDirTree(src);
    cgWrite(Path::join(src, "a.txt"), "AAAABBBB");

    CMyPack mp;
    PackOptions po;
    EXPECT_EQ(int(mp.pack("", sb.arc, po)), int(E_INVALID_PARAMETER));
    EXPECT_EQ(int(mp.pack(src, "", po)), int(E_INVALID_PARAMETER));

    UnpackOptions uo;
    EXPECT_EQ(int(mp.unpack("", sb.dest, uo)), int(E_INVALID_PARAMETER));
}

/* t-pre-03 源不存在 -> E_SOURCE_NOT_FOUND（无文案）；归档已存在且未 --force -> E_ALREADY_EXISTS（有文案） */
TEST(WbCoverageGap, packGuardsMissingSourceAndExistingArchive) {
    CgSandbox sb("prepack");
    std::string src = Path::join(sb.root, "src");
    Platform::makeDirTree(src);
    cgWrite(Path::join(src, "a.txt"), "AAAABBBB");

    CMyPack mp;
    PackOptions po;
    EXPECT_EQ(int(mp.pack(Path::join(sb.root, "nope"), sb.arc, po)), int(E_SOURCE_NOT_FOUND));

    po.force = false;
    ASSERT_EQ(int(mp.pack(src, sb.arc, po)), int(E_OK));
    EXPECT_EQ(int(mp.pack(src, sb.arc, po)), int(E_ALREADY_EXISTS));
    EXPECT_STREQ(mp.lastErrorText().c_str(),
                 ("archive already exists: " + sb.arc + " (use --force to overwrite)").c_str());
}

/* t-pre-04 归档打不开 -> E_SOURCE_NOT_FOUND 且文案指出是归档；头部字段非法 -> E_INVALID_HEADER_RECORD */
TEST(WbCoverageGap, unpackRejectsMissingArchiveAndIllegalHeaderFields) {
    CgSandbox sb("preunp");
    std::string src = Path::join(sb.root, "src");
    Platform::makeDirTree(src);
    cgWrite(Path::join(src, "a.txt"), kBody);

    CMyPack mp;
    UnpackOptions u0;
    const std::string missing = Path::join(sb.root, "nope.dbkp");
    EXPECT_EQ(int(mp.unpack(missing, sb.dest, u0)), int(E_SOURCE_NOT_FOUND));
    EXPECT_STREQ(mp.lastErrorText().c_str(), ("cannot open archive: " + missing).c_str());

    std::vector<Part> ps; ps.push_back(cgRegular("a.txt", kBody));
    std::vector<uint8_t> bytes = cgBuildArchive(ps);
    cgWriteArchive(sb.arc, bytes);

    ArchiveHeader h;
    ASSERT_EQ(int(decodeArchiveHeader(bytes.data(), h)), int(E_OK));

    h.version = 99;
    std::vector<uint8_t> badVer;
    ASSERT_EQ(int(encodeArchiveHeader(h, badVer)), int(E_OK));
    badVer.insert(badVer.end(), bytes.begin() + BLOCK_SIZE, bytes.end());
    const std::string verPath = Path::join(sb.root, "ver.dbkp");
    cgWriteArchive(verPath, badVer);
    UnpackOptions u1;
    EXPECT_EQ(int(mp.unpack(verPath, sb.dest, u1)), int(E_INVALID_HEADER_RECORD));

    h.version = 1; h.compAlg = ALG_COUNT;
    std::vector<uint8_t> badAlg;
    ASSERT_EQ(int(encodeArchiveHeader(h, badAlg)), int(E_OK));
    badAlg.insert(badAlg.end(), bytes.begin() + BLOCK_SIZE, bytes.end());
    const std::string algPath = Path::join(sb.root, "alg.dbkp");
    cgWriteArchive(algPath, badAlg);
    UnpackOptions u2;
    EXPECT_EQ(int(mp.unpack(algPath, sb.dest, u2)), int(E_INVALID_HEADER_RECORD));

    h.compAlg = ALG_NONE; h.cryptoAlg = CRY_COUNT;
    std::vector<uint8_t> badCry;
    ASSERT_EQ(int(encodeArchiveHeader(h, badCry)), int(E_OK));
    badCry.insert(badCry.end(), bytes.begin() + BLOCK_SIZE, bytes.end());
    const std::string cryPath = Path::join(sb.root, "cry.dbkp");
    cgWriteArchive(cryPath, badCry);
    UnpackOptions u3;
    EXPECT_EQ(int(mp.unpack(cryPath, sb.dest, u3)), int(E_INVALID_HEADER_RECORD));
}
