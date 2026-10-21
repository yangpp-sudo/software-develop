/* ============================================================================
 *  PathUtil.h  -- 路径处理（归档内统一使用 '/'，对外做平台分隔符转换）
 * ==========================================================================*/
#ifndef DBKP_UTILS_PATHUTIL_H
#define DBKP_UTILS_PATHUTIL_H

#include <string>
#include <vector>

#include "Platform/Compat.h"

namespace DBKP {
namespace Path {

/* 归档内部规范分隔符 */
static const char kArchiveSep = '/';
#if defined(DBKP_OS_WINDOWS)
static const char kOsSep = '\\';
#else
static const char kOsSep = '/';
#endif

std::string join(const std::string& a, const std::string& b);
/** 归一化：折叠 '//'、去掉 './'、解析 '../'、统一分隔符为 '/'，去掉尾部 '/' */
std::string normalize(const std::string& p);
/** 把任意分隔符转成当前操作系统分隔符 */
std::string toOs(const std::string& archivePath);
/** 转成归档内的 '/' 分隔 */
std::string toArchive(const std::string& osPath);
bool   isAbsolute(const std::string& p);
std::string fileName(const std::string& p);
std::string parentDir(const std::string& p);
std::string extension(const std::string& p);
/** child 相对 parent 的相对路径；parent 不是前缀时返回空串 */
std::string relative(const std::string& parent, const std::string& child);
bool   isPathTraversalSafe(const std::string& archivePath);
/** 简易 glob：支持 * ? []，用于 -name 过滤 */
bool   matchGlob(const std::string& pattern, const std::string& text);
/** 大小写无关比较（Windows 路径判重用） */
bool   iequals(const std::string& a, const std::string& b);
std::string baseNameWithoutExt(const std::string& p);
std::string withSuffix(const std::string& stem, const std::string& suffix);

#if defined(DBKP_OS_WINDOWS)
/* UTF-8 <-> UTF-16（Win32 W 系 API 需要） */
std::wstring utf8ToWide(const std::string& utf8);
std::string  wideToUtf8(const std::wstring& wide);
#endif

} /* namespace Path */
} /* namespace DBKP */

#endif /* DBKP_UTILS_PATHUTIL_H */
