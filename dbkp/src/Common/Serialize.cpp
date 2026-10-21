/* ============================================================================
 *  Serialize.cpp  -- 归档结构编解码（固定 512B 块 + 强制小端）
 * ==========================================================================*/
#include "Common/Serialize.h"

#include <algorithm>
#include <cstring>

namespace DBKP {

/* ------------------------------------------------------ 记录内字段偏移 */
enum RecOffset {
    RO_MAGIC = 0,   RO_TYPE = 4,    RO_FLAGS = 5,   RO_PATHLEN = 6,  RO_LINKLEN = 8,
    RO_MODE = 10,   RO_UID = 14,    RO_GID = 18,
    RO_MTIME = 22,  RO_MTIMENS = 30, RO_ATIME = 38,  RO_ATIMENS = 46, RO_CTIME = 54,
    RO_INO = 62,    RO_NLINK = 70,  RO_DEV = 74,    RO_MAJOR = 78,   RO_MINOR = 82,
    RO_SIZE = 86,   RO_STORED = 94, RO_CRC = 102,
    RO_COMP = 110,  RO_CRYPTO = 111, RO_RSVD16 = 112,
    RO_PATH = 114,  RO_LINK = 274,  RO_FREE = 370,
};

void appendLE16(std::string& buf, uint16_t v) {
    buf.push_back(char(v & 0xFF)); buf.push_back(char((v >> 8) & 0xFF));
}
void appendLE32(std::string& buf, uint32_t v) {
    for (int i = 0; i < 4; ++i) buf.push_back(char((v >> (8 * i)) & 0xFF));
}
void appendLE64(std::string& buf, uint64_t v) {
    for (int i = 0; i < 8; ++i) buf.push_back(char((v >> (8 * i)) & 0xFF));
}
uint16_t readLE16(const uint8_t* p) {
    return uint16_t(p[0]) | (uint16_t(p[1]) << 8);
}
uint32_t readLE32(const uint8_t* p) {
    uint32_t v = 0;
    for (int i = 0; i < 4; ++i) v |= uint32_t(p[i]) << (8 * i);
    return v;
}
uint64_t readLE64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= uint64_t(p[i]) << (8 * i);
    return v;
}

/* ------------------------------------------------------ 通用块写入助手 */
namespace {

struct BlockWriter {
    uint8_t* p;
    void u8 (size_t off, uint8_t  v) { p[off] = v; }
    void u16(size_t off, uint16_t v) { appendLE16Into(off, v); }
    void u32(size_t off, uint32_t v) { for (int i = 0; i < 4; ++i) p[off + i] = uint8_t((v >> (8 * i)) & 0xFF); }
    void u64(size_t off, uint64_t v) { for (int i = 0; i < 8; ++i) p[off + i] = uint8_t((v >> (8 * i)) & 0xFF); }
    void raw(size_t off, const std::string& s, size_t cap) {
        size_t n = s.size() < cap ? s.size() : cap;
        if (n) std::memcpy(p + off, s.data(), n);
    }
private:
    void appendLE16Into(size_t off, uint16_t v) {
        p[off] = uint8_t(v & 0xFF); p[off + 1] = uint8_t((v >> 8) & 0xFF);
    }
};

void zeroBlock(uint8_t* block) { std::memset(block, 0, BLOCK_SIZE); }

} /* anonymous namespace */

/* ------------------------------------------------------ 归档卷标 */
ErrCode encodeArchiveHeader(const ArchiveHeader& hdr, std::vector<uint8_t>& out512) {
    out512.assign(BLOCK_SIZE, 0);
    uint8_t* p = out512.data();
    BlockWriter w{p};
    w.u32(0,  hdr.magic);
    w.u16(4,  hdr.version);
    w.u16(6,  hdr.headerSize);
    w.u8 (8,  hdr.compAlg);
    w.u8 (9,  hdr.cryptoAlg);
    w.u8 (10, hdr.checksum);
    w.u8 (11, hdr.flags);
    w.u64(12, hdr.payloadCrc);
    w.u64(20, hdr.payloadOffset);
    w.u64(28, hdr.payloadSize);
    w.u64(36, hdr.rawSize);
    w.u64(44, hdr.recordCount);
    w.u64(52, hdr.fileCount);
    w.u64(60, hdr.createTime);
    for (int i = 0; i < 16; ++i) p[68 + i] = hdr.salt[i];
    w.u16(84, hdr.kdfRounds);
    w.u16(86, uint16_t(hdr.sourcePath.size() > 256 ? 256 : hdr.sourcePath.size()));
    w.u16(88, uint16_t(hdr.comment.size() > 160 ? 160 : hdr.comment.size()));
    w.raw(90, hdr.sourcePath, 256);   /* 90..345  */
    w.raw(346, hdr.comment, 166);     /* 346..511 */
    return E_OK;
}

ErrCode decodeArchiveHeader(const uint8_t* in512, ArchiveHeader& hdr) {
    if (readLE32(in512) != ARCHIVE_MAGIC) return E_INVALID_HEADER_RECORD;
    hdr.magic         = readLE32(in512 + 0);
    hdr.version       = readLE16(in512 + 4);
    hdr.headerSize    = readLE16(in512 + 6);
    hdr.compAlg       = in512[8];
    hdr.cryptoAlg     = in512[9];
    hdr.checksum      = in512[10];
    hdr.flags         = in512[11];
    hdr.payloadCrc    = readLE64(in512 + 12);
    hdr.payloadOffset = readLE64(in512 + 20);
    hdr.payloadSize   = readLE64(in512 + 28);
    hdr.rawSize       = readLE64(in512 + 36);
    hdr.recordCount   = readLE64(in512 + 44);
    hdr.fileCount     = readLE64(in512 + 52);
    hdr.createTime    = readLE64(in512 + 60);
    for (int i = 0; i < 16; ++i) hdr.salt[i] = in512[68 + i];
    hdr.kdfRounds     = readLE16(in512 + 84);
    uint16_t srcLen   = readLE16(in512 + 86);
    uint16_t comLen   = readLE16(in512 + 88);
    if (srcLen > 256 || comLen > 166) return E_INVALID_HEADER_RECORD;
    hdr.sourcePath.assign(reinterpret_cast<const char*>(in512 + 90), srcLen);
    hdr.comment.assign(reinterpret_cast<const char*>(in512 + 346), comLen);
    return E_OK;
}

/* ------------------------------------------------------ 文件记录写入 */
namespace {

/** 写一条主记录（path/link 的内联槽位由调用方裁好） */
void writeMainRecord(uint8_t* block, const FileRecord& rec,
                     const std::string& inlinePath, const std::string& inlineLink,
                     bool hasExtend) {
    zeroBlock(block);
    BlockWriter w{block};
    w.u32(RO_MAGIC, RECORD_MAGIC);
    w.u8 (RO_TYPE, uint8_t(rec.type));
    uint8_t flags = rec.flags;
    if (hasExtend) flags |= RF_HAS_EXTEND;
    w.u8 (RO_FLAGS, flags);
    w.u16(RO_PATHLEN, uint16_t(rec.path.size()));
    w.u16(RO_LINKLEN, uint16_t(rec.link.size()));
    w.u32(RO_MODE, rec.mode);
    w.u32(RO_UID, rec.uid);
    w.u32(RO_GID, rec.gid);
    w.u64(RO_MTIME, uint64_t(rec.mtimeSec));
    w.u64(RO_MTIMENS, uint64_t(rec.mtimeNSec));
    w.u64(RO_ATIME, uint64_t(rec.atimeSec));
    w.u64(RO_ATIMENS, uint64_t(rec.atimeNSec));
    w.u64(RO_CTIME, uint64_t(rec.ctimeSec));
    w.u64(RO_INO, rec.ino);
    w.u32(RO_NLINK, rec.nlink);
    w.u32(RO_DEV, rec.dev);
    w.u32(RO_MAJOR, rec.majorNum);
    w.u32(RO_MINOR, rec.minorNum);
    w.u64(RO_SIZE, uint64_t(rec.size));
    w.u64(RO_STORED, uint64_t(rec.storedSize));
    w.u64(RO_CRC, rec.crc);
    w.u8 (RO_COMP, rec.compAlg);
    w.u8 (RO_CRYPTO, rec.cryptoAlg);
    w.raw(RO_PATH, inlinePath, REC_INLINE_PATH);
    w.raw(RO_LINK, inlineLink, REC_INLINE_LINK);
}

/** 写一条扩展记录：把 chunk 依次铺进 path/link/free 三段（共 398B） */
void writeExtendRecord(uint8_t* block, const std::string& chunk) {
    zeroBlock(block);
    BlockWriter w{block};
    w.u32(RO_MAGIC, RECORD_MAGIC);
    w.u8 (RO_TYPE, uint8_t(FT_EXTEND));
    w.u8 (RO_FLAGS, RF_NONE);
    w.u64(RO_SIZE, uint64_t(chunk.size()));
    const size_t slots[3] = { RO_PATH, RO_LINK, RO_FREE };
    const size_t caps[3]  = { REC_INLINE_PATH, REC_INLINE_LINK, REC_INLINE_FREE };
    size_t off = 0;
    for (int s = 0; s < 3 && off < chunk.size(); ++s) {
        size_t n = chunk.size() - off;
        if (n > caps[s]) n = caps[s];
        std::memcpy(block + slots[s], chunk.data() + off, n);
        off += n;
    }
}

} /* anonymous namespace */

ErrCode encodeRecord(const FileRecord& rec, std::vector<uint8_t>& out) {
    if (rec.path.size() > 0xFFFF || rec.link.size() > 0xFFFF) return E_PATH_TOO_LONG;

    /* 超出内联槽位的部分：先 path 尾巴，再 link 尾巴，顺序拼接成一条尾巴流 */
    std::string tail;
    std::string inlinePath = rec.path.substr(0, REC_INLINE_PATH);
    std::string inlineLink = rec.link.substr(0, REC_INLINE_LINK);
    if (rec.path.size() > REC_INLINE_PATH) tail += rec.path.substr(REC_INLINE_PATH);
    if (rec.link.size() > REC_INLINE_LINK) tail += rec.link.substr(REC_INLINE_LINK);

    for (size_t off = 0; off < tail.size(); off += REC_EXTEND_PAYLOAD) {
        size_t before = out.size();
        out.resize(before + BLOCK_SIZE);
        writeExtendRecord(out.data() + before, tail.substr(off, REC_EXTEND_PAYLOAD));
    }

    size_t before = out.size();
    out.resize(before + BLOCK_SIZE);
    writeMainRecord(out.data() + before, rec, inlinePath, inlineLink, !tail.empty());
    return E_OK;
}

ErrCode CRecordReader::pushBlock(const uint8_t* block512) {
    if (readLE32(block512) != RECORD_MAGIC) return E_INVALID_HEADER_RECORD;
    const uint8_t type = block512[RO_TYPE];

    if (type == uint8_t(FT_EXTEND)) {
        uint64_t n = readLE64(block512 + RO_SIZE);
        if (n > REC_EXTEND_PAYLOAD) return E_INVALID_HEADER_RECORD;
        size_t remain = size_t(n);
        const size_t slots[3] = { RO_PATH, RO_LINK, RO_FREE };
        const size_t caps[3]  = { REC_INLINE_PATH, REC_INLINE_LINK, REC_INLINE_FREE };
        for (int s = 0; s < 3 && remain; ++s) {
            size_t take = remain < caps[s] ? remain : caps[s];
            m_extraPath.append(reinterpret_cast<const char*>(block512 + slots[s]), take);
            remain -= take;
        }
        return E_OK;
    }

    FileRecord rec;
    rec.type       = char(type);
    rec.flags      = block512[RO_FLAGS];
    const uint16_t pathLen = readLE16(block512 + RO_PATHLEN);
    const uint16_t linkLen = readLE16(block512 + RO_LINKLEN);
    rec.mode       = readLE32(block512 + RO_MODE);
    rec.uid        = readLE32(block512 + RO_UID);
    rec.gid        = readLE32(block512 + RO_GID);
    rec.mtimeSec   = int64_t(readLE64(block512 + RO_MTIME));
    rec.mtimeNSec  = int64_t(readLE64(block512 + RO_MTIMENS));
    rec.atimeSec   = int64_t(readLE64(block512 + RO_ATIME));
    rec.atimeNSec  = int64_t(readLE64(block512 + RO_ATIMENS));
    rec.ctimeSec   = int64_t(readLE64(block512 + RO_CTIME));
    rec.ino        = readLE64(block512 + RO_INO);
    rec.nlink      = readLE32(block512 + RO_NLINK);
    rec.dev        = readLE32(block512 + RO_DEV);
    rec.majorNum   = readLE32(block512 + RO_MAJOR);
    rec.minorNum   = readLE32(block512 + RO_MINOR);
    rec.size       = int64_t(readLE64(block512 + RO_SIZE));
    rec.storedSize = int64_t(readLE64(block512 + RO_STORED));
    rec.crc        = readLE64(block512 + RO_CRC);
    rec.compAlg    = block512[RO_COMP];
    rec.cryptoAlg  = block512[RO_CRYPTO];

    const size_t inlinePath = pathLen < REC_INLINE_PATH ? pathLen : REC_INLINE_PATH;
    rec.path.assign(reinterpret_cast<const char*>(block512 + RO_PATH), inlinePath);
    const size_t inlineLink = linkLen < REC_INLINE_LINK ? linkLen : REC_INLINE_LINK;
    rec.link.assign(reinterpret_cast<const char*>(block512 + RO_LINK), inlineLink);

    if (rec.flags & RF_HAS_EXTEND) {
        /* 尾巴流 = path 超出部分 + link 超出部分 */
        const size_t needPath = pathLen > REC_INLINE_PATH ? pathLen - REC_INLINE_PATH : 0;
        const size_t needLink = linkLen > REC_INLINE_LINK ? linkLen - REC_INLINE_LINK : 0;
        if (m_extraPath.size() < needPath + needLink) return E_TRUNCATED_ARCHIVE;
        rec.path.append(m_extraPath, 0, needPath);
        rec.link.append(m_extraPath, needPath, needLink);
        m_extraPath.clear();
    } else if (!m_extraPath.empty()) {
        m_extraPath.clear();
        return E_INVALID_HEADER_RECORD;   /* 扩展记录后面缺少主记录 */
    }

    m_rec   = rec;
    m_ready = true;
    return E_OK;
}

FileRecord CRecordReader::take() {
    m_ready = false;
    return std::move(m_rec);
}

ErrCode decodeRecordBlocks(const std::vector<uint8_t>& bytes, FileRecord& rec) {
    if (bytes.empty() || bytes.size() % BLOCK_SIZE) return E_INVALID_DATA_RECORD;
    CRecordReader reader;
    for (size_t off = 0; off < bytes.size(); off += BLOCK_SIZE) {
        ErrCode e = reader.pushBlock(bytes.data() + off);
        if (DBKP_IS_ERR(e)) return e;
        if (reader.hasRecord()) { rec = reader.take(); return E_OK; }
    }
    return E_TRUNCATED_ARCHIVE;
}

} /* namespace DBKP */



