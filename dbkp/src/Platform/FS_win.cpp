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

static char typeFromAttrs(DWORD attr, const std::wstring& wpath) {
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
                if (tag == IO_REPARSE_TAG_SYMLINK) return FT_SYMLINK;
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
    std::wstring wp = Path::utf8ToWide(path);
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
    std::wstring wp = Path::utf8ToWide(path);
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

    /* 手工解析 REPARSE_DATA_BUFFER，避免依赖不同 SDK 版本的结构体定义 */
    const uint8_t* p = buf;
    DWORD tag = *reinterpret_cast<const DWORD*>(p);
    uint16_t sub = *reinterpret_cast<const uint16_t*>(p + 4);
    const uint8_t* data = p + 8;
    std::wstring wname;
    if (tag == IO_REPARSE_TAG_SYMLINK) {
        uint16_t printOff = *reinterpret_cast<const uint16_t*>(data + sub);
        uint16_t printLen = *reinterpret_cast<const uint16_t*>(data + sub + 2);
        wname.assign(reinterpret_cast<const wchar_t*>(data + sub + 4 + printOff),
                     printLen / 2);
    } else if (tag == IO_REPARSE_TAG_MOUNT_POINT) {
        uint16_t tOff = *reinterpret_cast<const uint16_t*>(data + sub);
        uint16_t tLen = *reinterpret_cast<const uint16_t*>(data + sub + 2);
        wname.assign(reinterpret_cast<const wchar_t*>(data + sub + 4 + tOff), tLen / 2);
        if (wname.size() >= 4 && wname.compare(0, 4, L"\\??\\") == 0) wname = wname.substr(4);
    } else {
        return E_UNSUPPORTED_FEATURE;
    }
    std::string raw = Path::wideToUtf8(wname);
    for (size_t i = 0; i < raw.size(); ++i) if (raw[i] == '\\') raw[i] = '/';
    target = raw;
    return E_OK;
}

/* ------------------------------------------------------------- 目录操作 */
ErrCode listDir(const std::string& path, std::vector<DirEntry>& out) {
    out.clear();
    std::wstring wp = Path::utf8ToWide(path);
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
    std::wstring wp = Path::utf8ToWide(path);
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
    std::wstring wp = Path::utf8ToWide(path);
    return RemoveDirectoryW(wp.c_str()) ? E_OK : E_FILE_WRITE_FAIL;
}

ErrCode removeFile(const std::string& path) {
    std::wstring wp = Path::utf8ToWide(path);
    return DeleteFileW(wp.c_str()) ? E_OK : E_FILE_WRITE_FAIL;
}

ErrCode renameFile(const std::string& from, const std::string& to) {
    std::wstring wf = Path::utf8ToWide(from);
    std::wstring wt = Path::utf8ToWide(to);
    return MoveFileExW(wf.c_str(), wt.c_str(), MOVEFILE_REPLACE_EXISTING) ? E_OK : E_FILE_WRITE_FAIL;
}

ErrCode exists(const std::string& path) {
    std::wstring wp = Path::utf8ToWide(path);
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
    std::wstring wp = Path::utf8ToWide(path);
    wchar_t buf[4096];
    DWORD n = GetFullPathNameW(wp.c_str(), 4096, buf, nullptr);
    if (n == 0 || n >= 4096) return E_INVALID_PARAMETER;
    std::string s = Path::wideToUtf8(std::wstring(buf, n));
    for (size_t i = 0; i < s.size(); ++i) if (s[i] == '\\') s[i] = '/';
    out = s;
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
    std::wstring wl = Path::utf8ToWide(linkPath);
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
    std::wstring we = Path::utf8ToWide(existing);
    std::wstring wn = Path::utf8ToWide(newPath);
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
    std::wstring wp = Path::utf8ToWide(path);
    if (mode & 0200) {
        SetFileAttributesW(wp.c_str(), FILE_ATTRIBUTE_NORMAL);
        return E_OK;
    }
    return SetFileAttributesW(wp.c_str(), FILE_ATTRIBUTE_READONLY) ? E_OK : E_FILE_WRITE_FAIL;
}

ErrCode setOwner(const std::string&, uint32_t, uint32_t) { return E_UNSUPPORTED_FEATURE; }

ErrCode setTimes(const std::string& path, int64_t mtSec, int64_t mtNs,
                 int64_t atSec, int64_t atNs, bool follow) {
    std::wstring wp = Path::utf8ToWide(path);
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
    std::wstring wp = Path::utf8ToWide(path);
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



