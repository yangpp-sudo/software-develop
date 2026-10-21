/* ============================================================================
 *  FileEnumerator.cpp  -- 先序递归遍历 + 自定义过滤 + 环检测
 * ==========================================================================*/
#include "Enumerator/FileEnumerator.h"

#include <algorithm>

#include "Utils/Logger.h"
#include "Utils/PathUtil.h"

namespace DBKP {

ErrCode CFileEnumerator::enumerateFiles(const std::string& rootPath,
                                       const FilterOptions& filter,
                                       std::vector<EnumeratedEntry>& out) {
    resetCounters();
    m_visitedDirs.clear();
    m_rootDevValid = false;

    Platform::FileInfo rootInfo;
    ErrCode e = Platform::getInfo(rootPath, rootInfo, true);
    if (DBKP_IS_ERR(e)) {
        LOG_ERR("cannot access source: " + rootPath + " (" + errCodeToString(e) + ")");
        return E_SOURCE_NOT_FOUND;
    }
    if (rootInfo.type != FT_DIR) {
        LOG_ERR("source is not a directory: " + rootPath);
        return E_INVALID_PARAMETER;
    }

    std::string absRoot;
    if (DBKP_IS_ERR(Platform::canonicalPath(rootPath, absRoot))) absRoot = Path::normalize(rootPath);
    m_visitedDirs.insert(absRoot);
    m_rootDev = rootInfo.dev;
    m_rootDevValid = true;

    /* 根目录本身作为 "." 入档（与讲义一致），还原时对应用户指定的目标目录；
       但根目录同样要接受过滤条件（例如 --type -D 时不应留下任何目录条目）。 */
    if (filter.includeDirs && filter.pass(".", rootInfo)) {
        EnumeratedEntry root;
        root.relPath = ".";
        root.info    = rootInfo;
        out.push_back(root);
    }
    return traverseDir(absRoot, ".", filter, out, 0);
}

ErrCode CFileEnumerator::traverseDir(const std::string& absDir,
                                     const std::string& relDir,
                                     const FilterOptions& filter,
                                     std::vector<EnumeratedEntry>& out,
                                     int depth) {
    std::vector<Platform::DirEntry> items;
    ErrCode e = Platform::listDir(absDir, items);
    if (DBKP_IS_ERR(e)) {
        LOG_WARN("cannot list directory: " + absDir + " (" + errCodeToString(e) + ")");
        ++m_errors;
        return m_strict ? e : E_OK;
    }

    for (size_t i = 0; i < items.size(); ++i) {
        const Platform::DirEntry& de = items[i];
        const std::string absChild = absDir + "/" + de.name;
        const std::string relChild = (relDir == "." || relDir.empty())
                                   ? de.name : relDir + "/" + de.name;

        Platform::FileInfo fi;
        ErrCode ge = Platform::getInfo(absChild, fi, false);   /* 关键：不跟随链接 */
        if (DBKP_IS_ERR(ge)) {
            LOG_WARN("cannot stat: " + absChild + " (" + errCodeToString(ge) + ")");
            ++m_errors;
            if (m_strict) return ge;
            continue;
        }
        ++m_scanned;

        const bool isDir = (fi.type == FT_DIR);
        const bool crossDeviceOk = !(filter.noCrossDevice && m_rootDevValid &&
                                     fi.dev != m_rootDev);
        const bool depthOk = !(filter.maxDepth >= 0 && depth + 1 > filter.maxDepth);
        /* --max-depth 采用与 `find -maxdepth` 相同的口径：根目录下的条目是第 1 层。
         * 深度既要能拦住"下探"，也要拦住条目本身，否则第 2 层的文件会被入档，
         * 而它所在的目录又不会被继续下探，产生一个"看着空却没备全"的结构。 */
        const bool included = crossDeviceOk && depthOk && filter.pass(relChild, fi);
        /* 目录即使自身不入档，也可能需要下探：名称/尺寸/时间不应剪枝 */
        const bool canDescend = isDir && crossDeviceOk && depthOk &&
                                filter.passForTraversal(relChild, fi) &&
                                filter.passTraversal(relChild);

        if (!included) {
            ++m_filtered;
            LOG_DEBUG("filtered: " + relChild);
            if (!canDescend) continue;
        } else if (isDir && !filter.includeDirs) {
            /* 目录条目本身不入档，但仍需下探 */
        } else {
            EnumeratedEntry ent;
            ent.relPath = relChild;
            ent.info    = fi;
            out.push_back(ent);
        }

        bool descend = canDescend;
        if (!isDir && fi.type == FT_SYMLINK && filter.followSymlinks && !fi.linkTarget.empty()) {
            std::string real;
            if (DBKP_IS_ERR(Platform::canonicalPath(absChild, real))) {
                LOG_DEBUG("dangling symlink: " + relChild);
            } else if (m_visitedDirs.count(real)) {
                LOG_WARN("symlink loop skipped: " + relChild + " -> " + real);
                ++m_skipped;
            } else {
                Platform::FileInfo tfi;
                if (DBKP_IS_ERR(Platform::getInfo(absChild, tfi, true)) || tfi.type != FT_DIR) {
                    /* 指向文件的链接无需下探 */
                } else {
                    m_visitedDirs.insert(real);
                    descend = depthOk;
                }
            }
        }

        if (descend) {
            ErrCode sub = traverseDir(absChild, relChild, filter, out, depth + 1);
            if (m_strict && DBKP_IS_ERR(sub)) return sub;
        }
    }
    return E_OK;
}

} /* namespace DBKP */
