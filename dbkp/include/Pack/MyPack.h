/* ============================================================================
 *  MyPack.h  -- 单文件归档器（.dbkp）：头记录 + 数据块 + CRC64 + 压缩 + 加密
 *
 *  归档物理布局：
 *    [ArchiveHeader 512B]
 *    [ (ExtendRecord*)? HeaderRecord 512B  DataBlock*N ] * fileCount
 *    （无独立尾记录；卷标里的 payloadSize/payloadCrc 足以定长校验）
 *
 *  一条逻辑记录的读写顺序：
 *    写：先算原始 CRC64 → 压缩 → 加密 → 写头记录（含 storedSize）→ 写数据块
 *    读：读头记录 → 按 storedSize 读数据块 → 解密 → 解压 → 校验 CRC64 → 落盘
 * ==========================================================================*/
#ifndef DBKP_PACK_MYPACK_H
#define DBKP_PACK_MYPACK_H

#include <map>
#include <string>
#include <vector>

#include "Codec/DataCodec.h"
#include "Common/Defs.h"
#include "Common/Progress.h"
#include "Enumerator/FileEnumerator.h"
#include "Utils/SimpleFile.h"

namespace DBKP {

struct PackOptions {
    FilterOptions filter;                 /* 自定义备份：6 个过滤维度 */
    AlgorithmId   comp        = ALG_NONE; /* 压缩算法 */
    CryptoId      crypto      = CRY_NONE; /* 加密算法 */
    std::string   password;
    ChecksumId    checksum    = CHK_CRC64;
    bool          hardlinkDedupe = true;  /* 硬链接去重（inode 表） */
    bool          preserveMeta   = true;  /* 元数据备份与恢复 */
    int64_t       codecThreshold = 256ll * 1024 * 1024; /* 超过则直存，避免爆内存 */
    std::string   comment;
    IProgressSink* progress = nullptr;   /* Web/守护进程用；CLI 保持 nullptr */
};

struct UnpackOptions {
    bool        overwrite  = false;       /* 目标非空时是否继续 */
    bool        verifyOnly = false;       /* 只校验不落盘 */
    bool        restoreMeta = true;
    std::string password;
    /* 解包过程中的软失败计数（特殊文件在无权限时降级为告警） */
    int         warnings = 0;
    IProgressSink* progress = nullptr;    /* 还原进度与取消 */
};

class CMyPack {
public:
    CMyPack() = default;

    /* ---------------- 打包 ---------------- */
    ErrCode pack(const std::string& sourceDir, const std::string& archivePath,
                 const PackOptions& opt);

    /* ---------------- 解包 ---------------- */
    ErrCode unpack(const std::string& archivePath, const std::string& targetDir,
                   UnpackOptions& opt);

    /* ---------------- 只读辅助 ---------------- */
    ErrCode readHeader(const std::string& archivePath, ArchiveHeader& hdr);
    ErrCode list(const std::string& archivePath, std::vector<FileRecord>& recs);
    ErrCode stat(const std::string& archivePath, ArchiveHeader& hdr, ArchiveStat& st);
    /** 完整性校验：CRC + 解码，逐条记录，不落盘 */
    ErrCode verify(const std::string& archivePath, const std::string& password,
                   int& badCount);
    /** 与原始目录对比，报告差异（用于"备份可靠性"测试） */
    ErrCode compareWithSource(const std::string& archivePath, const std::string& sourceDir,
                             const std::string& password, int& diffCount);

    const std::string& lastErrorText() const { return m_errorText; }

private:
    struct InodeKey {
        uint32_t dev; uint64_t ino;
        bool operator<(const InodeKey& o) const {
            return dev != o.dev ? dev < o.dev : ino < o.ino;
        }
    };

    ErrCode writeRecord(CSimpleFile& out, const FileRecord& rec);
    ErrCode writeFileData(CSimpleFile& out, const std::string& absPath, FileRecord& rec,
                          IDataCodec* comp, IDataCodec* crypto, const PackOptions& opt);
    ErrCode readDataBlocks(CSimpleFile& in, const FileRecord& rec,
                            std::vector<uint8_t>& rawOut,
                            IDataCodec* comp, IDataCodec* crypto,
                            const std::string& password, UnpackOptions& opt);
    ErrCode restoreEntry(const std::string& targetDir, const FileRecord& rec,
                         const std::vector<uint8_t>* data, UnpackOptions& opt,
                         std::vector<FileRecord>& pendingDirs);
    ErrCode applyMetadata(const std::string& absPath, const FileRecord& rec,
                          UnpackOptions& opt, bool followSymlink);
    IDataCodec* makeComp(AlgorithmId id, std::string& errText) const;
    IDataCodec* makeCrypto(CryptoId id, const std::string& password,
                           const uint8_t salt[16], int rounds, std::string& errText) const;

    std::map<InodeKey, std::string> m_inodeMap;   /* 打包期硬链接去重 */
    std::map<std::string, std::string> m_hardLinks; /* 解包期：link 记录名 -> 首次落盘名 */
    std::string m_errorText;
};

} /* namespace DBKP */

#endif /* DBKP_PACK_MYPACK_H */
