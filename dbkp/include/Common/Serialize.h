/* ============================================================================
 *  Serialize.h  -- 归档结构的"内存对象 <-> 磁盘字节"编解码（强制小端）
 *  对应《系统设计文档》4.2 归档格式模块
 * ==========================================================================*/
#ifndef DBKP_COMMON_SERIALIZE_H
#define DBKP_COMMON_SERIALIZE_H

#include <cstdint>
#include <string>
#include <vector>

#include "Common/Defs.h"

namespace DBKP {

/* ------------------------------------------------------- 小端读写原语 */
void appendLE16(std::string& buf, uint16_t v);
void appendLE32(std::string& buf, uint32_t v);
void appendLE64(std::string& buf, uint64_t v);
uint16_t readLE16(const uint8_t* p);
uint32_t readLE32(const uint8_t* p);
uint64_t readLE64(const uint8_t* p);

/* ------------------------------------------------------- 归档卷标 */
ErrCode encodeArchiveHeader(const ArchiveHeader& hdr, std::vector<uint8_t>& out512);
ErrCode decodeArchiveHeader(const uint8_t* in512, ArchiveHeader& hdr);

/* ------------------------------------------------------- 文件记录 */
/**
 * @brief 把一条 FileRecord 编码成 1+ 个 512B 磁盘块（扩展记录在前，主记录在后）
 * @param rec   内存态记录（path/link 为 UTF-8）
 * @param out   追加输出的字节（长度为 512 的整数倍）
 */
ErrCode encodeRecord(const FileRecord& rec, std::vector<uint8_t>& out);

/**
 * @brief 记录流式解码器
 *
 * 归档中一条逻辑记录可能由若干条 'X' 扩展记录 + 1 条主记录组成，
 * 因此需要按块喂入、内部聚合，得到完整记录后再交付上层。
 */
class CRecordReader {
public:
    CRecordReader() = default;

    /** 喂入一个 512B 块；返回 E_OK=尚需更多块, E_OK+完整记录用 hasRecord() 查询 */
    ErrCode pushBlock(const uint8_t* block512);

    bool hasRecord() const { return m_ready; }
    FileRecord take();                          /* 取走完整记录并复位 */

    /** 供 verify 使用：把解码结果重新编码并与原块比较 */
    bool strictVerify = true;

private:
    FileRecord    m_rec;
    std::string   m_extraPath;
    std::string   m_extraLink;
    bool          m_ready = false;
};

/** 便捷函数：一次性解析一条（可能带扩展记录的）逻辑记录所需的所有块 */
ErrCode decodeRecordBlocks(const std::vector<uint8_t>& bytes, FileRecord& rec);

} /* namespace DBKP */

#endif /* DBKP_COMMON_SERIALIZE_H */
