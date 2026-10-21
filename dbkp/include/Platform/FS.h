/* ============================================================================
 *  FS.h  -- 文件系统抽象层（POSIX / Win32 两套实现）
 *
 *  上层只看见 FileTypeTag + FileInfo + 一组动作函数，看不到 struct stat /
 *  WIN32_FIND_DATAW，从而把"特殊文件支持(扩展项)"与"元数据支持(扩展项)"
 *  的差异集中在这里实现一次。
 *  对应《系统设计文档》4.1 平台抽象层
 * ==========================================================================*/
#ifndef DBKP_PLATFORM_FS_H
#define DBKP_PLATFORM_FS_H

#include <cstdint>
#include <string>
#include <vector>

#include "Common/Defs.h"

namespace DBKP {
namespace Platform {

/** 一次 lstat 拿到的全部信息 */
struct FileInfo {
    char        type = FT_REGULAR;   /* FileTypeTag */
    uint32_t    mode = 0;            /* POSIX 权限位（Windows 映射为 0444/0666） */
    uint32_t    uid  = 0;
    uint32_t    gid  = 0;
    int64_t     size = 0;
    int64_t     mtimeSec = 0, mtimeNSec = 0;
    int64_t     atimeSec = 0, atimeNSec = 0;
    int64_t     ctimeSec = 0;
    uint64_t    ino  = 0;
    uint32_t    nlink = 1;
    uint32_t    dev  = 0;
    uint32_t    majorNum = 0;
    uint32_t    minorNum = 0;
    std::string linkTarget;          /* 仅 FT_SYMLINK 有效 */
    bool        valid = false;
};

struct DirEntry {
    std::string name;   /* 不含路径前缀 */
    char        type = FT_REGULAR;
};

/* ----------------------------------------------------------- 信息查询 */
ErrCode getInfo(const std::string& path, FileInfo& out, bool followSymlink = false);
ErrCode readLink(const std::string& path, std::string& target);
ErrCode currentDir(std::string& out);
ErrCode canonicalPath(const std::string& path, std::string& out);
uint64_t freeSpaceAt(const std::string& path);

/* ----------------------------------------------------------- 目录操作 */
ErrCode listDir(const std::string& path, std::vector<DirEntry>& out);
ErrCode makeDir(const std::string& path);
ErrCode makeDirTree(const std::string& path);
ErrCode removeDir(const std::string& path);
ErrCode removeFile(const std::string& path);
ErrCode renameFile(const std::string& from, const std::string& to);
ErrCode exists(const std::string& path);           /* E_OK 表示存在 */
bool    isDirectory(const std::string& path);
ErrCode assertDirEmpty(const std::string& path);

/* ----------------------------------------------------- 特殊文件创建 */
ErrCode makeSymlink(const std::string& target, const std::string& linkPath);
ErrCode makeHardLink(const std::string& existing, const std::string& newPath);
ErrCode makeFifo(const std::string& path, uint32_t mode);
ErrCode makeDeviceNode(const std::string& path, char type,
                       uint32_t majorNum, uint32_t minorNum, uint32_t mode);
ErrCode makeSocketPlaceholder(const std::string& path); /* 套接字不可重建，落占位 */

/* --------------------------------------------------------- 元数据恢复 */
ErrCode setMode(const std::string& path, uint32_t mode);
ErrCode setOwner(const std::string& path, uint32_t uid, uint32_t gid);
ErrCode setTimes(const std::string& path,
                 int64_t mtimeSec, int64_t mtimeNSec,
                 int64_t atimeSec, int64_t atimeNSec,
                 bool followSymlink = true);

/* ------------------------------------------------- 原生文件描述符（UTF-8 路径安全） */
/**
 * @brief 以 UTF-8 路径打开文件；Windows 侧内部转 UTF-16 调 _wopen，
 *        从而支持"中文目录名"的备份（第 6 讲跨平台移植要点）。
 * @return >=0 文件描述符；-1 失败（errno 有效）
 */
int  openNative(const std::string& path, int flags, int mode);
int64_t readNative(int fd, void* buf, int64_t bytes);
int64_t writeNative(int fd, const void* buf, int64_t bytes);
int64_t seekNative(int fd, int64_t offset, int whence);
int   closeNative(int fd);
int   fsyncNative(int fd);
int64_t fileSizeOf(int fd);

/* ------------------------------------------------------------- 属主解析 */
ErrCode uidToName(uint32_t uid, std::string& name);
ErrCode nameToUid(const std::string& name, uint32_t& uid);

/* ------------------------------------------------------------ 能力查询 */
bool supportsSymlink();
bool supportsHardlink();
bool supportsFifo();
bool supportsDeviceNode();
bool supportsOwner();
bool supportsNanoTime();
std::string osName();

} /* namespace Platform */
} /* namespace DBKP */

#endif /* DBKP_PLATFORM_FS_H */
