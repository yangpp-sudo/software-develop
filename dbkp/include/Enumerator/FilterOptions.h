/* ============================================================================
 *  FilterOptions.h  -- 自定义备份过滤器（对应扩展项"自定义备份"的 6 个维度）
 *
 *  维度        命令行开关                     字段
 *  ----------  -----------------------------  ----------------------------
 *  1 路径      --exclude/--include            excludePaths / includePaths
 *  2 文件名称  --name / --name-exclude        nameGlobs / nameRejects
 *  3 文件类型  --type / --type-exclude        typeAllow / typeDeny
 *  4 修改时间  --newer-than / --older-than    mtimeAfter / mtimeBefore
 *  5 尺寸      --min-size / --max-size        minSize / maxSize
 *  6 拥有者    --uid / --owner                uids / ownerNames
 *  其他        --follow-symlinks --no-cross-dev --max-depth --skip-special
 * ==========================================================================*/
#ifndef DBKP_ENUMERATOR_FILTEROPTIONS_H
#define DBKP_ENUMERATOR_FILTEROPTIONS_H

#include <cstdint>
#include <string>
#include <vector>

#include "Platform/FS.h"

namespace DBKP {

struct FilterOptions {
    /* 1. 路径：支持 glob，匹配相对路径（相对备份根，'/' 分隔） */
    std::vector<std::string> includePaths;
    std::vector<std::string> excludePaths;
    /* 2. 文件名称：匹配 basename */
    std::vector<std::string> nameGlobs;
    std::vector<std::string> nameRejects;
    /* 3. 文件类型：FileTypeTag 字符集合 */
    std::vector<char> typeAllow;
    std::vector<char> typeDeny;
    /* 4. 修改时间区间（Unix 秒，0 表示不限） */
    int64_t mtimeAfter  = 0;
    int64_t mtimeBefore = 0;
    /* 5. 尺寸区间（字节，<0 表示不限） */
    int64_t minSize = -1;
    int64_t maxSize = -1;
    /* 6. 拥有者 */
    std::vector<uint32_t>      uids;
    std::vector<std::string>   ownerNames;

    /* 遍历策略 */
    bool  followSymlinks = false;   /* 跟随符号链接（有环检测） */
    bool  noCrossDevice  = false;   /* 不跨越文件系统边界 */
    int   maxDepth       = -1;      /* -1 = 不限 */
    bool  skipSpecials   = false;   /* 跳过管道/设备/套接字 */
    bool  includeDirs    = true;    /* 目录条目是否入档（还原结构需要） */

    FilterOptions() = default;

    /** 判断一条相对路径的记录是否通过全部过滤维度 */
    bool pass(const std::string& relPath, const Platform::FileInfo& fi) const;
    /**
     * @brief 目录是否允许继续下探
     *
     * 名称/尺寸/时间/属主这四个维度只描述"文件本身"，不应该阻断对子目录的遍历
     * （与 find/tar 的语义一致）；路径与类型维度则会阻断遍历。
     */
    bool passForTraversal(const std::string& relDir, const Platform::FileInfo& fi) const;
    /** 是否允许进入该子目录继续遍历（只看路径/深度维度） */
    bool passTraversal(const std::string& relDir) const;

    /** 解析 --type/-t 之类逗号分隔串，如 "-DL" 或 "regular,dir" */
    bool setTypeSpec(const std::string& spec);
    /** 解析人类可读大小："10MB" "1.5G" "4096" */
    static int64_t parseSize(const std::string& text, bool* okOut = nullptr);
    /** 解析时间："2024-01-01" "2024-01-01T12:00:00" "7d"(最近 7 天) */
    static int64_t parseTime(const std::string& text, bool* okOut = nullptr);

    std::string describe() const;
    bool isEmpty() const;
};

} /* namespace DBKP */

#endif /* DBKP_ENUMERATOR_FILTEROPTIONS_H */
