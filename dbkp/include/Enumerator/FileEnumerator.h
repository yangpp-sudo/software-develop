/* ============================================================================
 *  FileEnumerator.h  -- 递归目录遍历（先序）
 *
 *  对应讲义第 4 讲《文件目录遍历》的 CFileEnumerator 设计，并做了 3 处加固：
 *    1. 不依赖 chdir()（线程安全，且避免相对路径在异常路径下失效）；
 *    2. 符号链接跟随带 realpath 环检测；
 *    3. --no-cross-dev 用 st_dev 判定，防止误备份挂载点下的整块磁盘。
 * ==========================================================================*/
#ifndef DBKP_ENUMERATOR_FILEENUMERATOR_H
#define DBKP_ENUMERATOR_FILEENUMERATOR_H

#include <set>
#include <string>
#include <vector>

#include "Common/Defs.h"
#include "Enumerator/FilterOptions.h"
#include "Platform/FS.h"

namespace DBKP {

/** 遍历得到的一个条目 */
struct EnumeratedEntry {
    std::string          relPath;   /* 相对备份根，'/' 分隔；根目录为 "." */
    Platform::FileInfo   info;
};

class CFileEnumerator {
public:
    CFileEnumerator() = default;

    /**
     * @brief 递归枚举 rootPath 下所有条目（先序：目录先于其内容）
     * @return E_OK 成功；E_SOURCE_NOT_FOUND 根不存在；E_INVALID_PARAMETER 根不是目录
     */
    ErrCode enumerateFiles(const std::string& rootPath,
                           const FilterOptions& filter,
                           std::vector<EnumeratedEntry>& out);

    /** 单层递归（可被上层复用，做增量/进度显示） */
    ErrCode traverseDir(const std::string& absDir,
                        const std::string& relDir,
                        const FilterOptions& filter,
                        std::vector<EnumeratedEntry>& out,
                        int depth);

    /* 统计信息，供 CLI 输出"扫描 N 项 / 过滤 M 项 / 跳过 K 项" */
    int scanned()  const { return m_scanned; }
    int filtered() const { return m_filtered; }
    int skipped()  const { return m_skipped; }
    int errors()   const { return m_errors; }
    void resetCounters() { m_scanned = m_filtered = m_skipped = m_errors = 0; }

    /** 单项 stat 失败（权限/竞态）时的策略：true=中止，false=记为错误并继续 */
    void setStrict(bool strict) { m_strict = strict; }

private:
    bool shouldDescend(const std::string& relDir, int depth,
                       const FilterOptions& filter, const Platform::FileInfo& fi) const;

    std::set<std::string> m_visitedDirs;   /* 跟随符号链接时的环检测 */
    uint32_t m_rootDev = 0;
    bool     m_rootDevValid = false;
    bool     m_strict = false;
    int m_scanned = 0, m_filtered = 0, m_skipped = 0, m_errors = 0;
};

} /* namespace DBKP */

#endif /* DBKP_ENUMERATOR_FILEENUMERATOR_H */
