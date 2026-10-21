/* ============================================================================
 *  FS_posix.cpp  -- Linux/POSIX 平台实现（lstat / 特殊文件 / 纳秒时间 / 属主）
 *  本课程的主目标平台：7 类文件与完整元数据都能真正备份、还原。
 * ==========================================================================*/
#define _GNU_SOURCE 1

#include "Platform/Compat.h"

#if defined(DBKP_OS_POSIX)

#include "Platform/FS.h"
#include "Utils/PathUtil.h"
#include "Utils/SimpleFile.h"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <unistd.h>
#include <utime.h>

#if defined(__linux__)
#  include <sys/sysmacros.h>          /* major() / minor() / makedev() */
#endif

/* 纳秒时间字段在不同 libc 下名字不同 */
#if defined(__APPLE__)
#  define DBKP_ST_MTIM(x) ((x).st_mtimespec)
#  define DBKP_ST_ATIM(x) ((x).st_atimespec)
#else
#  define DBKP_ST_MTIM(x) ((x).st_mtim)
#  define DBKP_ST_ATIM(x) ((x).st_atim)
#endif

namespace DBKP {
namespace Platform {

namespace {

char typeFromMode(mode_t m) {
    if (S_ISREG(m))  return FT_REGULAR;
    if (S_ISDIR(m))  return FT_DIR;
    if (S_ISLNK(m))  return FT_SYMLINK;
    if (S_ISBLK(m))  return FT_BLOCK;
    if (S_ISCHR(m))  return FT_CHAR;
    if (S_ISFIFO(m)) return FT_FIFO;
    if (S_ISSOCK(m)) return FT_SOCKET;
    return FT_REGULAR;
}

ErrCode errFromErrno() {
    switch (errno) {
    case ENOENT:        return E_SOURCE_NOT_FOUND;
    case EACCES:        return E_PERMISSION_DENIED;
    case EPERM:         return E_PERMISSION_DENIED;
    case ENOSPC:        return E_NOT_ENOUGH_SPACE;
    case EEXIST:        return E_ALREADY_EXISTS;
    case ENOTDIR:       return E_INVALID_PARAMETER;
    case ELOOP:         return E_INVALID_PARAMETER;
    case ENAMETOOLONG:  return E_PATH_TOO_LONG;
    default:            return E_INTERNAL;
    }
}

} /* anonymous namespace */

ErrCode getInfo(const std::string& path, FileInfo& out, bool followSymlink) {
    out = FileInfo();
    struct stat st;
    const int rc = followSymlink ? ::stat(path.c_str(), &st) : ::lstat(path.c_str(), &st);
    if (rc != 0) return errFromErrno();

    out.valid = true;
    out.type  = typeFromMode(st.st_mode);
    out.mode  = static_cast<uint32_t>(st.st_mode & 07777);
    out.uid   = static_cast<uint32_t>(st.st_uid);
    out.gid   = static_cast<uint32_t>(st.st_gid);
    out.size  = static_cast<int64_t>(st.st_size);
    out.ino   = static_cast<uint64_t>(st.st_ino);
    out.nlink = static_cast<uint32_t>(st.st_nlink);
    out.dev   = static_cast<uint32_t>(st.st_dev);
    if (out.type == FT_BLOCK || out.type == FT_CHAR) {
        out.majorNum = static_cast<uint32_t>(major(st.st_rdev));
        out.minorNum = static_cast<uint32_t>(minor(st.st_rdev));
    }
    out.mtimeSec = static_cast<int64_t>(st.st_mtime);
    out.atimeSec = static_cast<int64_t>(st.st_atime);
    out.ctimeSec = static_cast<int64_t>(st.st_ctime);
    out.mtimeNSec = DBKP_ST_MTIM(st).tv_nsec;
    out.atimeNSec = DBKP_ST_ATIM(st).tv_nsec;

    if (out.type == FT_SYMLINK) {
        std::string target;
        if (DBKP_IS_ERR(readLink(path, target))) target.clear();
        out.linkTarget = target;
    }
    return E_OK;
}

ErrCode readLink(const std::string& path, std::string& target) {
    target.clear();
    std::vector<char> buf(1024);
    for (;;) {
        const ssize_t n = ::readlink(path.c_str(), buf.data(), buf.size());
        if (n < 0) return errFromErrno();
        if (static_cast<size_t>(n) < buf.size()) {
            target.assign(buf.data(), static_cast<size_t>(n));
            return E_OK;
        }
        if (buf.size() >= 65536) return E_PATH_TOO_LONG;
        buf.resize(buf.size() * 2);
    }
}

ErrCode listDir(const std::string& path, std::vector<DirEntry>& out) {
    out.clear();
    DIR* d = ::opendir(path.c_str());
    if (!d) return errFromErrno();
    struct dirent* ent = nullptr;
    while ((ent = ::readdir(d)) != nullptr) {
        const std::string name = ent->d_name;
        if (name == "." || name == "..") continue;
        DirEntry e;
        e.name = name;
        FileInfo fi;
        /* 用 lstat 判类型：不依赖 d_type（NFS/旧文件系统上不可靠） */
        if (DBKP_IS_ERR(getInfo(Path::join(path, name), fi, false))) e.type = FT_REGULAR;
        else e.type = fi.type;
        out.push_back(e);
    }
    ::closedir(d);
    std::sort(out.begin(), out.end(),
              [](const DirEntry& a, const DirEntry& b) { return a.name < b.name; });
    return E_OK;
}

/* ------------------------------------------------------------- 目录操作 */
ErrCode makeDir(const std::string& path) {
    if (::mkdir(path.c_str(), 0777) == 0) return E_OK;
    return errno == EEXIST ? E_ALREADY_EXISTS : errFromErrno();
}

ErrCode makeDirTree(const std::string& path) {
    const std::string p = Path::normalize(path);
    if (p.empty()) return E_INVALID_PARAMETER;
    size_t i = 0;
    if (p[0] == '/') i = 1;
    for (;; ++i) {
        i = p.find('/', i);
        if (i == std::string::npos) i = p.size();
        ErrCode e = makeDir(p.substr(0, i));
        if (e == E_ALREADY_EXISTS) e = E_OK;
        if (DBKP_IS_ERR(e)) return e;
        if (i == p.size()) return E_OK;
    }
}

ErrCode removeDir(const std::string& path) {
    return ::rmdir(path.c_str()) == 0 ? E_OK : errFromErrno();
}

ErrCode removeFile(const std::string& path) {
    return ::unlink(path.c_str()) == 0 ? E_OK : errFromErrno();
}

ErrCode renameFile(const std::string& from, const std::string& to) {
    return ::rename(from.c_str(), to.c_str()) == 0 ? E_OK : errFromErrno();
}

ErrCode exists(const std::string& path) {
    if (::access(path.c_str(), F_OK) == 0) return E_OK;
    return (errno == ENOENT || errno == ENOTDIR) ? E_NOT_FOUND : E_PERMISSION_DENIED;
}

bool isDirectory(const std::string& path) {
    FileInfo fi;
    if (DBKP_IS_ERR(getInfo(path, fi, true))) return false;
    return fi.type == FT_DIR;
}

ErrCode assertDirEmpty(const std::string& path) {
    std::vector<DirEntry> es;
    ErrCode e = listDir(path, es);
    if (DBKP_IS_ERR(e)) return e;
    return es.empty() ? E_OK : E_DESTINATION_NOT_EMPTY;
}

ErrCode currentDir(std::string& out) {
    std::vector<char> buf(4096);
    if (!::getcwd(buf.data(), buf.size())) return errFromErrno();
    out.assign(buf.data());
    return E_OK;
}

ErrCode canonicalPath(const std::string& path, std::string& out) {
    std::vector<char> buf(4096);
    char* r = ::realpath(path.c_str(), buf.data());
    if (!r) {
        /* 悬空符号链接会让 realpath 失败：退化为词法规范化 */
        out = Path::normalize(path);
        return E_OK;
    }
    out.assign(r);
    return E_OK;
}

uint64_t freeSpaceAt(const std::string& path) {
    struct statvfs vfs;
    if (::statvfs(path.empty() ? "." : path.c_str(), &vfs) != 0) return 0;
    return static_cast<uint64_t>(vfs.f_bavail) * static_cast<uint64_t>(vfs.f_frsize);
}

/* ------------------------------------------------------------- 特殊文件 */
ErrCode makeSymlink(const std::string& target, const std::string& linkPath) {
    return ::symlink(target.c_str(), linkPath.c_str()) == 0 ? E_OK : errFromErrno();
}

ErrCode makeHardLink(const std::string& existing, const std::string& newPath) {
    return ::link(existing.c_str(), newPath.c_str()) == 0 ? E_OK : errFromErrno();
}

ErrCode makeFifo(const std::string& path, uint32_t mode) {
    return ::mkfifo(path.c_str(), static_cast<mode_t>(mode)) == 0 ? E_OK : errFromErrno();
}

ErrCode makeDeviceNode(const std::string& path, char type,
                       uint32_t majorNum, uint32_t minorNum, uint32_t mode) {
#if defined(__linux__)
    const mode_t kind = (type == FT_BLOCK) ? S_IFBLK : S_IFCHR;
    const dev_t dev = makedev(majorNum, minorNum);
    if (::mknod(path.c_str(), kind | static_cast<mode_t>(mode), dev) == 0) return E_OK;
    if (errno == EPERM) return E_PERMISSION_DENIED;
    return errFromErrno();
#else
    DBKP_UNUSED(path); DBKP_UNUSED(type);
    DBKP_UNUSED(majorNum); DBKP_UNUSED(minorNum); DBKP_UNUSED(mode);
    return E_UNSUPPORTED_FEATURE;
#endif
}

ErrCode makeSocketPlaceholder(const std::string& path) {
    /* UNIX 套接字是通信端点而非数据，无法"复活"，落占位文件保留目录项 */
    return CSimpleFile::writeWhole(path, std::vector<uint8_t>());
}

/* --------------------------------------------------------------- 元数据 */
ErrCode setMode(const std::string& path, uint32_t mode) {
    return ::chmod(path.c_str(), static_cast<mode_t>(mode)) == 0 ? E_OK : errFromErrno();
}

ErrCode setOwner(const std::string& path, uint32_t uid, uint32_t gid) {
    if (::lchown(path.c_str(), static_cast<uid_t>(uid), static_cast<gid_t>(gid)) == 0) return E_OK;
    if (errno == EPERM || errno == EINVAL) return E_PERMISSION_DENIED;
    return errFromErrno();
}

ErrCode setTimes(const std::string& path, int64_t mtimeSec, int64_t mtimeNSec,
                 int64_t atimeSec, int64_t atimeNSec, bool followSymlink) {
#if defined(AT_FDCWD) && defined(AT_SYMLINK_NOFOLLOW)
    struct timespec ts[2];
    ts[0].tv_sec  = static_cast<time_t>(atimeSec);
    ts[0].tv_nsec = static_cast<long>(atimeNSec);
    ts[1].tv_sec  = static_cast<time_t>(mtimeSec);
    ts[1].tv_nsec = static_cast<long>(mtimeNSec);
    if (::utimensat(AT_FDCWD, path.c_str(), ts,
                    followSymlink ? 0 : AT_SYMLINK_NOFOLLOW) == 0) return E_OK;
    if (errno != ENOSYS) return errFromErrno();
    /* 老内核退回 utimes（精度损失到秒） */
#endif
    struct utimbuf ub;
    ub.actime  = static_cast<time_t>(atimeSec);
    ub.modtime = static_cast<time_t>(mtimeSec);
    if (!followSymlink) return E_UNSUPPORTED_FEATURE;   /* utime 会跟随链接 */
    return ::utime(path.c_str(), &ub) == 0 ? E_OK : errFromErrno();
}

/* ------------------------------------------------------------- 属主解析 */
ErrCode uidToName(uint32_t uid, std::string& name) {
    struct passwd* pw = ::getpwuid(static_cast<uid_t>(uid));
    if (!pw || !pw->pw_name) return E_NOT_FOUND;
    name = pw->pw_name;
    return E_OK;
}

ErrCode nameToUid(const std::string& name, uint32_t& uid) {
    struct passwd* pw = ::getpwnam(name.c_str());
    if (!pw) return E_NOT_FOUND;
    uid = static_cast<uint32_t>(pw->pw_uid);
    return E_OK;
}

/* ------------------------------------------------------- 原生文件描述符 */
int openNative(const std::string& path, int flags, int mode) {
    return static_cast<int>(::open(path.c_str(), flags, static_cast<mode_t>(mode)));
}

int64_t readNative(int fd, void* buf, int64_t bytes) {
    const size_t want = static_cast<size_t>(bytes);
    for (;;) {
        const ssize_t n = ::read(fd, buf, want);
        if (n < 0 && errno == EINTR) continue;
        return n < 0 ? -1 : static_cast<int64_t>(n);
    }
}

int64_t writeNative(int fd, const void* buf, int64_t bytes) {
    const size_t want = static_cast<size_t>(bytes);
    for (;;) {
        const ssize_t n = ::write(fd, buf, want);
        if (n < 0 && errno == EINTR) continue;
        return n < 0 ? -1 : static_cast<int64_t>(n);
    }
}

int64_t seekNative(int fd, int64_t offset, int whence) {
    const off_t p = ::lseek(fd, static_cast<off_t>(offset), whence);
    return p < 0 ? -1 : static_cast<int64_t>(p);
}

int closeNative(int fd) { return ::close(fd); }
int fsyncNative(int fd) { for (;;) { if (::fsync(fd) == 0) return 0; if (errno != EINTR) return -1; } }

int64_t fileSizeOf(int fd) {
    struct stat st;
    if (::fstat(fd, &st) != 0) return -1;
    return static_cast<int64_t>(st.st_size);
}

/* ------------------------------------------------------------- 能力查询 */
bool supportsSymlink()    { return true; }
bool supportsHardlink()   { return true; }
bool supportsFifo()       { return true; }
bool supportsDeviceNode() { return true; }
bool supportsOwner()      { return true; }
bool supportsNanoTime()   { return true; }

std::string osName() {
#if defined(__linux__)
    return "Linux";
#elif defined(__APPLE__)
    return "macOS";
#else
    return "POSIX";
#endif
}

} /* namespace Platform */
} /* namespace DBKP */

#endif /* DBKP_OS_POSIX */


