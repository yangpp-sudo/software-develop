/* ============================================================================
 *  Scheduler.h  -- 定时备份 + 备份保留策略（扩展项：定时备份 / 自动淘汰）
 * ==========================================================================*/
#ifndef DBKP_BACKUP_SCHEDULER_H
#define DBKP_BACKUP_SCHEDULER_H

#include <string>
#include <vector>

#include "Backup/BackupEngine.h"

namespace DBKP {

struct ScheduleOptions {
    int          intervalSeconds = 300;   /* --every 5m|2h|90s */
    int          times = 1;               /* --times N，<=0 表示一直跑 */
    std::string  archiveDir;              /* 输出目录，默认取 backup.destination 的父目录 */
    std::string  prefix;                  /* 归档文件名前缀，默认 backup 源目录名 */
    int          keep = 0;                /* 保留最近 N 份，0 = 不删除 */
    BackupOptions backup;                 /* 每次备份的参数 */
};

class CScheduler {
public:
    /** 阻塞式定时备份；返回最后一次备份的错误码（全部成功则 E_OK） */
    ErrCode run(const ScheduleOptions& opt);

    /** "5m"/"2h"/"90s"/"300" -> 秒；非法返回 -1 */
    static int parseInterval(const std::string& text, bool* okOut = nullptr);

    /** 生成 <prefix>-YYYYmmdd-HHMMSS.dbkp 形式的路径 */
    static std::string makeArchiveName(const std::string& dir, const std::string& prefix);

    /** 按名称时间序删除最旧的归档，只保留最近 keep 份，返回删除数量 */
    static int applyRetention(const std::string& dir, const std::string& prefix, int keep);
};

} /* namespace DBKP */

#endif /* DBKP_BACKUP_SCHEDULER_H */
