/* ============================================================================
 *  BackupEngine.h  -- 备份编排层
 *
 *  两种备份形态（对应课程"基本要求"）：
 *    1) 归档模式 archive：源目录 -> 单个 .dbkp 文件（CMyPack 负责）
 *    2) 复制模式 copy   ：源目录 -> 目标目录（逐文件复制，保留元数据）
 *  另外提供：
 *    - 备份后自动校验（verifyAfter）：逐条 CRC 对比源与目标，量化"健壮性"
 *    - 定时备份 + 保留策略（CScheduler）
 * ==========================================================================*/
#ifndef DBKP_BACKUP_BACKUPENGINE_H
#define DBKP_BACKUP_BACKUPENGINE_H

#include <string>
#include <vector>

#include "Common/Defs.h"
#include "Enumerator/FilterOptions.h"
#include "Pack/MyPack.h"

namespace DBKP {

struct BackupOptions {
    std::string  source;                 /* 源目录 */
    std::string  destination;            /* .dbkp 文件 或 目标目录 */
    BackupMode   mode = MODE_AUTO;       /* AUTO 时按扩展名判断 */
    PackOptions  pack;                   /* 归档模式参数 */
    FilterOptions filter;                /* 复制模式参数 */
    bool         preserveMeta = true;    /* 复制模式是否还原元数据 */
    bool         verifyAfter  = true;    /* 备份完成后自动校验 */
    std::string  password;               /* 加密口令 */
    int          warnings = 0;
};

enum class CopyReport {                    /* 便于测试断言 */
    Ok, Failed
};

class CBackupEngine {
public:
    CBackupEngine() = default;

    /** 统一入口：根据 mode 分派 archive / copy */
    ErrCode run(BackupOptions& opt);

    /** 逐文件复制备份（课程"基本要求"的直接备份形态） */
    ErrCode copyBackup(const std::string& source, const std::string& dest,
                       const FilterOptions& filter, bool preserveMeta, int& warnings);

    /** 从复制目录还原到新的目标目录（反向复制） */
    ErrCode copyRestore(const std::string& backupDir, const std::string& dest,
                        bool preserveMeta, int& warnings);

    /** 校验复制结果：条目数 + 每个普通文件的 CRC64 */
    ErrCode verifyCopy(const std::string& source, const std::string& dest,
                       const FilterOptions& filter, int& diffCount);

    /** 校验归档：等价于 CMyPack::verify，但会给出摘要 */
    ErrCode verifyArchive(const std::string& archive, const std::string& password,
                          ArchiveStat& stat, uint64_t& crc);

    const std::string& lastError() const { return m_error; }
    static BackupMode resolveMode(const std::string& destination, BackupMode requested);

private:
    ErrCode copyOneFile(const std::string& srcAbs, const std::string& dstAbs,
                        const FileRecord& rec, bool preserveMeta, int& warnings);
    std::string m_error;
};

} /* namespace DBKP */

#endif /* DBKP_BACKUP_BACKUPENGINE_H */
