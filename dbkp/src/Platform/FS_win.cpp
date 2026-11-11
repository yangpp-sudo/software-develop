/* ============================================================================
 *  FS_win.cpp  -- Windows 平台实现（Win32/UTF-16；特殊文件与属主按能力降级）
 *  对应讲义《打包解包及其关键技术》第 8 章 跨平台移植指南
 * ==========================================================================*/
#if defined(_WIN32) || defined(_WIN64)
#  ifndef _WIN32_WINNT
#    define _WIN32_WINNT 0x0600      /* CreateSymbolicLinkW 需要 Vista+ 接口 */
#  endif
#  ifndef WINVER
#    define WINVER 0x0600
#  endif
#endif

#include "Platform/Compat.h"      /* 必须先引入：DBKP_OS_WINDOWS 由它定义 */

#if defined(DBKP_OS_WINDOWS)

#include "Platform/FS.h"
#include "Utils/PathUtil.h"
#include "Utils/SimpleFile.h"

#include <cstring>
#include <cerrno>
#include <algorithm>
#include <windows.h>
#include <winioctl.h>
#include <sys/stat.h>
#include <direct.h>

namespace DBKP {
namespace Platform {

/* FILETIME(1601-01-01 起的 100ns) 与 Unix 秒/纳秒互转 */
static const int64_t kEpochDiff100ns = 116444736000000000ll;

static void fileTimeToUnix(const FILETIME& ft, int64_t& sec, int64_t& nsec) {
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime; u.HighPart = ft.dwHighDateTime;
    int64_t t100 = int64_t(u.QuadPart) - kEpochDiff100ns;
    sec  = t100 / 10000000ll;
    nsec = (t100 % 10000000ll) * 100ll;
    if (nsec < 0) { nsec += 1000000000ll; sec -= 1; }
}

static FILETIME unixToFileTime(int64_t sec, int64_t nsec) {
    int64_t t100 = sec * 10000000ll + nsec / 100ll + kEpochDiff100ns;
    ULARGE_INTEGER u; u.QuadPart = uint64_t(t100);
    FILETIME ft; ft.dwLowDateTime = u.LowPart; ft.dwHighDateTime = u.HighPart;
    return ft;
}

static FileTypeTag typeFromAttrs(DWORD attr, const std::wstring& wpath) {
    if (attr & FILE_ATTRIBUTE_REPARSE_POINT) {
        HANDLE h = CreateFileW(wpath.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_EXISTING,
                               FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                               nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            BYTE buf[1024];
            DWORD ret = 0;
            BOOL ok = DeviceIoControl(h, FSCTL_GET_REPARSE_POINT, nullptr, 0,
                                      buf, sizeof(buf), &ret, nullptr);
            CloseHandle(h);
            if (ok && ret >= 4) {
                DWORD tag = *reinterpret_cast<DWORD*>(buf);
                /* F1：junction（IO_REPARSE_TAG_MOUNT_POINT）与符号链接同类，
                   都必须判成 FT_SYMLINK——以前落到下面被按 FILE_ATTRIBUTE_DIRECTORY
                   误判成 FT_DIR，枚举器直接下探，围栏与环检测全部形同虚设。 */
                if (tag == IO_REPARSE_TAG_SYMLINK ||
                    tag == IO_REPARSE_TAG_MOUNT_POINT) return FT_SYMLINK;
            }
        }
        return (attr & FILE_ATTRIBUTE_DIRECTORY) ? FT_DIR : FT_SYMLINK;
    }
    if (attr & FILE_ATTRIBUTE_DIRECTORY) return FT_DIR;
    return FT_REGULAR;
}

/* ------------------------------------------------------------- getInfo */
ErrCode getInfo(const std::string& path, FileInfo& out, bool followSymlink) {
    out = FileInfo();
    std::wstring wp = Path::apiWide(path);
    if (wp.empty()) return E_INVALID_PARAMETER;

    DWORD attr = GetFileAttributesW(wp.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) {
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) return E_NOT_FOUND;
        if (err == ERROR_ACCESS_DENIED) return E_PERMISSION_DENIED;
        return E_SOURCE_NOT_FOUND;
    }

    out.type = followSymlink ? ((attr & FILE_ATTRIBUTE_DIRECTORY) ? FT_DIR : FT_REGULAR)
                             : typeFromAttrs(attr, wp);
    out.mode = (attr & FILE_ATTRIBUTE_READONLY) ? 0444u
             : (out.type == FT_DIR ? 0755u : 0644u);
    out.uid = 0; out.gid = 0;

    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (GetFileAttributesExW(wp.c_str(), GetFileExInfoStandard, &fad)) {
        out.size = (int64_t(fad.nFileSizeHigh) << 32) | fad.nFileSizeLow;
        fileTimeToUnix(fad.ftLastWriteTime, out.mtimeSec, out.mtimeNSec);
        fileTimeToUnix(fad.ftLastAccessTime, out.atimeSec, out.atimeNSec);
        int64_t cs = 0, cn = 0;
        fileTimeToUnix(fad.ftCreationTime, cs, cn);
        out.ctimeSec = cs;
    }

    HANDLE h = CreateFileW(wp.c_str(), FILE_READ_ATTRIBUTES,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING,
                           FILE_FLAG_BACKUP_SEMANTICS |
                           (out.type == FT_SYMLINK ? FILE_FLAG_OPEN_REPARSE_POINT : 0),
                           nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        BY_HANDLE_FILE_INFORMATION bi;
        if (GetFileInformationByHandle(h, &bi)) {
            out.ino   = (uint64_t(bi.nFileIndexHigh) << 32) | bi.nFileIndexLow;
            out.nlink = bi.nNumberOfLinks;
            out.dev   = bi.dwVolumeSerialNumber;
        }
        CloseHandle(h);
    }

    if (out.type == FT_SYMLINK) {
        std::string target;
        if (DBKP_IS_ERR(readLink(path, target))) out.type = FT_REGULAR;
        else out.linkTarget = target;
    }
    out.valid = true;
    return E_OK;
}

ErrCode readLink(const std::string& path, std::string& target) {
    target.clear();
    std::wstring wp = Path::apiWide(path);
    HANDLE h = CreateFileW(wp.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING,
                           FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                           nullptr);
    if (h == INVALID_HANDLE_VALUE) return E_NOT_FOUND;
    BYTE buf[4096];
    DWORD ret = 0;
    BOOL ok = DeviceIoControl(h, FSCTL_GET_REPARSE_POINT, nullptr, 0,
                              buf, sizeof(buf), &ret, nullptr);
    CloseHandle(h);
    if (!ok || ret < 8) return E_UNSUPPORTED_FEATURE;

    /* 手工解析 REPARSE_DATA_BUFFER，避免依赖不同 SDK 版本的结构体定义。
       统一尾部布局（symlink 与 mount point/junction 完全一致）：
         p+0  ReparseTag(4)  p+4 ReparseDataLength(2)  p+6 Reserved(2)
         data=p+8：SubstituteNameOffset(2) SubstituteNameLength(2)
                    PrintNameOffset(2)    PrintNameLength(2)
         pathBuf=data+8：实际宽字符名（偏移相对 pathBuf 起算）
       F1 之前 junction 被误判成 FT_DIR，本函数从不在 junction 上被调用，
       旧实现把字段基址错写成 data+ReparseDataLength，解析恒为空。现按规范
       修正，link 目标得以还原——环检测（修法②）与 restore link 校验（修法④）
       都依赖它。 */
    const uint8_t* p = buf;
    DWORD tag = *reinterpret_cast<const DWORD*>(p);
    if (tag != IO_REPARSE_TAG_SYMLINK && tag != IO_REPARSE_TAG_MOUNT_POINT)
        return E_UNSUPPORTED_FEATURE;
    if (ret < 16) return E_UNSUPPORTED_FEATURE;
    const uint8_t* data = p + 8;
    const size_t pathBufAvail = ret - 16;   /* pathBuf 起（p+16）到缓冲区末尾的字节数 */
    const uint8_t* pathBuf = data + 8;
    uint16_t subOff = *reinterpret_cast<const uint16_t*>(data + 0);
    uint16_t subLen = *reinterpret_cast<const uint16_t*>(data + 2);
    uint16_t priOff = *reinterpret_cast<const uint16_t*>(data + 4);
    uint16_t priLen = *reinterpret_cast<const uint16_t*>(data + 6);
    std::wstring wname;
    /* 优先 SubstituteName（真实目标）；为空时退回 PrintName（展示名）。 */
    if (subLen > 0 && size_t(subOff) + subLen <= pathBufAvail) {
        wname.assign(reinterpret_cast<const wchar_t*>(pathBuf + subOff), subLen / 2);
    } else if (priLen > 0 && size_t(priOff) + priLen <= pathBufAvail) {
        wname.assign(reinterpret_cast<const wchar_t*>(pathBuf + priOff), priLen / 2);
    }
    /* junction 的 SubstituteName 常带 \??\ 设备前缀，去掉它得到可读路径 */
    if (wname.size() >= 4 && wname.compare(0, 4, L"\\??\\") == 0) wname = wname.substr(4);
    std::string raw = Path::wideToUtf8(wname);
    for (size_t i = 0; i < raw.size(); ++i) if (raw[i] == '\\') raw[i] = '/';
    target = raw;
    if (target.empty()) return E_UNSUPPORTED_FEATURE;
    return E_OK;
}

/* ------------------------------------------------------------- 目录操作 */
ErrCode listDir(const std::string& path, std::vector<DirEntry>& out) {
    out.clear();
    std::wstring wp = Path::apiWide(path);
    if (wp.empty()) return E_INVALID_PARAMETER;
    WIN32_FIND_DATAW fd;
    std::wstring pat = wp + L"\\*";
    HANDLE h = FindFirstFileW(pat.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return E_SOURCE_NOT_FOUND;
    do {
        std::wstring name(fd.cFileName);
        if (name == L"." || name == L"..") continue;
        DirEntry e;
        e.name = Path::wideToUtf8(name);
        e.type = typeFromAttrs(fd.dwFileAttributes, wp + L"\\" + name);
        out.push_back(e);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    std::sort(out.begin(), out.end(),
              [](const DirEntry& a, const DirEntry& b) { return a.name < b.name; });
    return E_OK;
}

ErrCode makeDir(const std::string& path) {
    std::wstring wp = Path::apiWide(path);
    if (_wmkdir(wp.c_str()) == 0) return E_OK;
    if (errno == EEXIST) return E_ALREADY_EXISTS;
    return E_DESTINATION_CREATE_FAIL;
}

ErrCode makeDirTree(const std::string& path) {
    std::string p = Path::normalize(path);
    if (p.empty()) return E_INVALID_PARAMETER;
    size_t i = 0;
    if (p.size() >= 2 && p[1] == ':') i = 2;         /* 盘符 C: */
    if (i < p.size() && (p[i] == '/' || p[i] == '\\')) ++i;
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
    std::wstring wp = Path::apiWide(path);
    return RemoveDirectoryW(wp.c_str()) ? E_OK : E_FILE_WRITE_FAIL;
}

ErrCode removeFile(const std::string& path) {
    std::wstring wp = Path::apiWide(path);
    return DeleteFileW(wp.c_str()) ? E_OK : E_FILE_WRITE_FAIL;
}

ErrCode renameFile(const std::string& from, const std::string& to) {
    std::wstring wf = Path::apiWide(from);
    std::wstring wt = Path::apiWide(to);
    return MoveFileExW(wf.c_str(), wt.c_str(), MOVEFILE_REPLACE_EXISTING) ? E_OK : E_FILE_WRITE_FAIL;
}

ErrCode exists(const std::string& path) {
    std::wstring wp = Path::apiWide(path);
    return GetFileAttributesW(wp.c_str()) == INVALID_FILE_ATTRIBUTES ? E_NOT_FOUND : E_OK;
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
    wchar_t buf[4096];
    if (!_wgetcwd(buf, 4096)) return E_INTERNAL;
    out = Path::wideToUtf8(buf);
    for (size_t i = 0; i < out.size(); ++i) if (out[i] == '\\') out[i] = '/';
    return E_OK;
}

ErrCode canonicalPath(const std::string& path, std::string& out) {
    std::wstring wp = Path::apiWide(path);
    std::vector<wchar_t> buf(8192);
    /* F1：存在的路径优先做"真实解析"——GetFinalPathNameByHandleW 会把
       junction/symlink 链一直展开到最终位置；纯词法绝对化（GetFullPathNameW）
       看不见链接，正是 data-root 围栏被绕过的根源。打不开（不存在/无权限）
       时退回词法结果，保持"不存在的路径也能规范化"的原有能力。 */
    HANDLE hLink = CreateFileW(wp.c_str(), FILE_READ_ATTRIBUTES,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS,
                               nullptr);
    if (hLink != INVALID_HANDLE_VALUE) {
        DWORD fn = GetFinalPathNameByHandleW(hLink, buf.data(), DWORD(buf.size()),
                                             VOLUME_NAME_DOS | FILE_NAME_NORMALIZED);
        CloseHandle(hLink);
        if (fn > 0 && fn < buf.size()) {
            std::wstring s(buf.data(), fn);
            if (s.size() >= 8 && s.compare(0, 8, L"\\\\?\\UNC\\") == 0) s = L"\\\\" + s.substr(8);
            else if (s.size() >= 4 && s.compare(0, 4, L"\\\\?\\") == 0) s = s.substr(4);
            std::string u8 = Path::wideToUtf8(s);
            for (size_t i = 0; i < u8.size(); ++i) if (u8[i] == '\\') u8[i] = '/';
            out = u8;
            return E_OK;
        }
    }
    DWORD n = GetFullPathNameW(wp.c_str(), DWORD(buf.size()), buf.data(), nullptr);
    if (n == 0 || n >= buf.size()) return E_INVALID_PARAMETER;
    std::wstring s(buf.data(), n);
    /* \\?\ 形式的绝对化结果里带着前缀，内部规范路径不该有它：
     * 否则后续拼接 '/' 会破坏前缀语义（apiWide 只认反斜杠前缀） */
    if (s.size() >= 4 && s.compare(0, 4, L"\\\\?\\") == 0) s = s.substr(4);
    else if (s.size() >= 8 && s.compare(0, 8, L"\\\\?\\UNC\\") == 0) s = L"\\\\" + s.substr(8);
    std::string u8 = Path::wideToUtf8(s);
    for (size_t i = 0; i < u8.size(); ++i) if (u8[i] == '\\') u8[i] = '/';
    out = u8;
    return E_OK;
}

uint64_t freeSpaceAt(const std::string& path) {
    std::string root = path;
    size_t pos = root.find_first_of("/\\");
    if (root.size() >= 2 && root[1] == ':') root = root.substr(0, 2) + "\\";
    else if (pos != std::string::npos) root = root.substr(0, pos + 1);
    else root = ".";
    ULARGE_INTEGER freeBytes;
    std::wstring wp = Path::utf8ToWide(root);
    if (!GetDiskFreeSpaceExW(wp.c_str(), &freeBytes, nullptr, nullptr)) return 0;
    return freeBytes.QuadPart;
}

/* ------------------------------------------------------------- 特殊文件 */
ErrCode makeSymlink(const std::string& target, const std::string& linkPath) {
    std::wstring wt = Path::utf8ToWide(Path::normalize(target));
    std::wstring wl = Path::apiWide(linkPath);
    FileInfo fi;
    DWORD flag = (!DBKP_IS_ERR(getInfo(Path::normalize(target), fi, true)) &&
                  fi.type == FT_DIR) ? SYMBOLIC_LINK_FLAG_DIRECTORY : 0;
    /* 非特权/未开启开发者模式时返回不支持，由上层降级为警告 */
    if (!CreateSymbolicLinkW(wl.c_str(), wt.c_str(), flag)) {
        return GetLastError() == ERROR_PRIVILEGE_NOT_HELD ? E_PERMISSION_DENIED
                                                          : E_UNSUPPORTED_FEATURE;
    }
    return E_OK;
}

ErrCode makeHardLink(const std::string& existing, const std::string& newPath) {
    std::wstring we = Path::apiWide(existing);
    std::wstring wn = Path::apiWide(newPath);
    return CreateHardLinkW(wn.c_str(), we.c_str(), nullptr) ? E_OK : E_FILE_WRITE_FAIL;
}

ErrCode makeFifo(const std::string&, uint32_t) { return E_UNSUPPORTED_FEATURE; }

ErrCode makeDeviceNode(const std::string&, char, uint32_t, uint32_t, uint32_t) {
    return E_UNSUPPORTED_FEATURE;
}

ErrCode makeSocketPlaceholder(const std::string& path) {
    /* Windows 无 AF_UNIX 节点语义，落一个带说明的空文件保留目录项 */
    return CSimpleFile::writeWhole(path, std::vector<uint8_t>());
}

/* ------------------------------------------------------------- 元数据 */
ErrCode setMode(const std::string& path, uint32_t mode) {
    std::wstring wp = Path::apiWide(path);
    if (mode & 0200) {
        SetFileAttributesW(wp.c_str(), FILE_ATTRIBUTE_NORMAL);
        return E_OK;
    }
    return SetFileAttributesW(wp.c_str(), FILE_ATTRIBUTE_READONLY) ? E_OK : E_FILE_WRITE_FAIL;
}

ErrCode setOwner(const std::string&, uint32_t, uint32_t) { return E_UNSUPPORTED_FEATURE; }

ErrCode setTimes(const std::string& path, int64_t mtSec, int64_t mtNs,
                 int64_t atSec, int64_t atNs, bool follow) {
    std::wstring wp = Path::apiWide(path);
    HANDLE h = CreateFileW(wp.c_str(), FILE_WRITE_ATTRIBUTES,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING,
                           FILE_FLAG_BACKUP_SEMANTICS |
                           (follow ? 0 : FILE_FLAG_OPEN_REPARSE_POINT),
                           nullptr);
    if (h == INVALID_HANDLE_VALUE) return E_PERMISSION_DENIED;
    FILETIME at = unixToFileTime(atSec, atNs);
    FILETIME wt = unixToFileTime(mtSec, mtNs);
    BOOL ok = SetFileTime(h, nullptr, &at, &wt);
    CloseHandle(h);
    return ok ? E_OK : E_FILE_WRITE_FAIL;
}

/* --------------------------------------------------- 原生文件描述符 */
int openNative(const std::string& path, int flags, int mode) {
    std::wstring wp = Path::apiWide(path);
    if (wp.empty()) return -1;
    return _wopen(wp.c_str(), flags, mode);
}

int64_t readNative(int fd, void* buf, int64_t bytes) {
    unsigned int want = bytes > 0x40000000 ? 0x40000000u : unsigned(bytes);
    int rc = _read(fd, buf, want);
    return rc < 0 ? -1 : int64_t(rc);
}

int64_t writeNative(int fd, const void* buf, int64_t bytes) {
    unsigned int want = bytes > 0x40000000 ? 0x40000000u : unsigned(bytes);
    int rc = _write(fd, buf, want);
    return rc < 0 ? -1 : int64_t(rc);
}

int64_t seekNative(int fd, int64_t offset, int whence) {
    __int64 p = _lseeki64(fd, offset, whence);
    return p < 0 ? -1 : int64_t(p);
}

int closeNative(int fd) { return _close(fd); }

int fsyncNative(int fd) { return _commit(fd) == 0 ? 0 : -1; }

int64_t fileSizeOf(int fd) {
    __int64 cur = _lseeki64(fd, 0, SEEK_CUR);
    __int64 end = _lseeki64(fd, 0, SEEK_END);
    _lseeki64(fd, cur, SEEK_SET);
    return end;
}

/* ------------------------------------------------- 跨进程文件锁（F4） */
ErrCode tryLockFile(int fd) {
    /* LockFileEx 锁的是"文件句柄"而非进程：同进程两个句柄、跨进程句柄
       都会互相冲突，正好同时满足清单要求的"进程内 + 跨进程"两层锁。
       FAIL_IMMEDIATELY：拿不到立刻返回，绝不阻塞 UI/守护线程。 */
    HANDLE h = reinterpret_cast<HANDLE>(_get_osfhandle(fd));
    if (h == INVALID_HANDLE_VALUE) return E_FILE_OPEN_FAIL;
    OVERLAPPED ov;
    std::memset(&ov, 0, sizeof(ov));
    /* 锁 1 字节偏移 0：整文件独占。解锁/关闭句柄时系统自动释放。 */
    if (LockFileEx(h, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                   0, 1, 0, &ov))
        return E_OK;
    return E_BUSY;
}

void unlockFile(int fd) {
    HANDLE h = reinterpret_cast<HANDLE>(_get_osfhandle(fd));
    if (h == INVALID_HANDLE_VALUE) return;
    OVERLAPPED ov;
    std::memset(&ov, 0, sizeof(ov));
    UnlockFileEx(h, 0, 1, 0, &ov);
}

ErrCode truncateFile(int fd, int64_t size) {
    return _chsize_s(fd, size) == 0 ? E_OK : E_FILE_WRITE_FAIL;
}

/* ------------------------------------------------------------- 能力查询 */
bool supportsSymlink()    { return true;   /* 需开发者模式或管理员权限 */ }
bool supportsHardlink()   { return true; }
bool supportsFifo()       { return false; }
bool supportsDeviceNode() { return false; }
bool supportsOwner()      { return false; }
bool supportsNanoTime()   { return true; }

/* Windows 侧没有 POSIX 属主概念：统一返回不支持，过滤器会自动降级为"不按名字过滤" */
ErrCode uidToName(uint32_t, std::string& name) { name.clear(); return E_UNSUPPORTED_FEATURE; }
ErrCode nameToUid(const std::string&, uint32_t& uid) { uid = 0; return E_UNSUPPORTED_FEATURE; }

std::string osName() { return "Windows"; }

} /* namespace Platform */
} /* namespace DBKP */

#endif /* DBKP_OS_WINDOWS */



