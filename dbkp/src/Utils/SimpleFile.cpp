/* ============================================================================
 *  SimpleFile.cpp  -- CSimpleFile 实现（路径统一按 UTF-8 交给平台层打开）
 * ==========================================================================*/
#include "Utils/SimpleFile.h"

#include <cerrno>
#include <cstring>
#include <vector>

#include "Platform/FS.h"

namespace DBKP {

static int toNativeFlags(CSimpleFile::OpenMode mode) {
    int flags = 0;
    switch (mode) {
    case CSimpleFile::MODE_READ:         flags = O_RDONLY; break;
    case CSimpleFile::MODE_WRITE_NEW:    flags = O_WRONLY | O_CREAT | O_TRUNC; break;
    case CSimpleFile::MODE_WRITE_APPEND: flags = O_WRONLY | O_CREAT | O_APPEND; break;
    case CSimpleFile::MODE_READ_WRITE:   flags = O_RDWR | O_CREAT | O_TRUNC; break;
    }
#if defined(DBKP_OS_WINDOWS)
    flags |= O_BINARY;
#endif
    return flags;
}

CSimpleFile::~CSimpleFile() {
    if (m_fd >= 0) Platform::closeNative(m_fd);
}

ErrCode CSimpleFile::open(const std::string& path, OpenMode mode) {
    if (m_fd >= 0) close();
    int fd = Platform::openNative(path, toNativeFlags(mode), 0644);
    if (fd < 0) {
        if (errno == EACCES || errno == EPERM) return E_PERMISSION_DENIED;
        if (errno == ENOENT && mode == MODE_READ) return E_SOURCE_NOT_FOUND;
        if (errno == ENOSPC) return E_NOT_ENOUGH_SPACE;
        return E_FILE_OPEN_FAIL;
    }
    m_path = path;
    m_fd   = fd;
    m_eof  = false;
    m_pos  = (mode == CSimpleFile::MODE_WRITE_APPEND)
           ? Platform::seekNative(fd, 0, SEEK_END) : 0;
    return E_OK;
}

ErrCode CSimpleFile::close() {
    if (m_fd < 0) return E_OK;
    int rc = Platform::closeNative(m_fd);
    m_fd = -1;
    return rc == 0 ? E_OK : E_FILE_WRITE_FAIL;
}

ErrCode CSimpleFile::readN(void* buffer, int64_t bytes) {
    if (m_fd < 0) return E_FILE_OPEN_FAIL;
    m_eof = false;
    uint8_t* p = static_cast<uint8_t*>(buffer);
    int64_t got = 0;
    while (got < bytes) {
        int64_t n = Platform::readNative(m_fd, p + got, bytes - got);
        if (n < 0) {
            if (errno == EINTR) continue;
            return E_FILE_READ_FAIL;
        }
        if (n == 0) { m_eof = true; return E_FILE_READ_FAIL; }  /* 提前 EOF */
        got += n;
    }
    m_pos += got;
    return E_OK;
}

ErrCode CSimpleFile::writeN(const void* buffer, int64_t bytes) {
    if (m_fd < 0) return E_FILE_OPEN_FAIL;
    const uint8_t* p = static_cast<const uint8_t*>(buffer);
    int64_t put = 0;
    while (put < bytes) {
        int64_t n = Platform::writeNative(m_fd, p + put, bytes - put);
        if (n < 0) {
            if (errno == EINTR) continue;
            return errno == ENOSPC ? E_NOT_ENOUGH_SPACE : E_FILE_WRITE_FAIL;
        }
        if (n == 0) return E_FILE_WRITE_FAIL;
        put += n;
    }
    m_pos += put;
    return E_OK;
}

ErrCode CSimpleFile::readAll(std::vector<uint8_t>& out, int64_t limitBytes) {
    out.clear();
    if (m_fd < 0) return E_FILE_OPEN_FAIL;
    m_eof = false;
    const int64_t CHUNK = 64 * 1024;
    std::vector<uint8_t> buf;
    buf.resize(std::vector<uint8_t>::size_type(CHUNK));
    for (;;) {
        int64_t want = CHUNK;
        if (limitBytes >= 0) {
            int64_t remain = limitBytes - int64_t(out.size());
            if (remain <= 0) return E_NOT_ENOUGH_SPACE;
            if (want > remain) want = remain;
        }
        int64_t n = Platform::readNative(m_fd, buf.data(), want);
        if (n < 0) {
            if (errno == EINTR) continue;
            return E_FILE_READ_FAIL;
        }
        if (n == 0) { m_eof = true; break; }      /* 正常读到文件末尾 */
        out.insert(out.end(), buf.begin(), buf.begin() + n);
        m_pos += n;
        if (limitBytes >= 0 && int64_t(out.size()) >= limitBytes) break;
    }
    return E_OK;
}

ErrCode CSimpleFile::writeAll(const std::vector<uint8_t>& data) {
    return writeN(data.data(), int64_t(data.size()));
}

ErrCode CSimpleFile::seekFile(int64_t offset, int whence) {
    if (m_fd < 0) return E_FILE_OPEN_FAIL;
    int64_t pos = Platform::seekNative(m_fd, offset, whence);
    if (pos < 0) return E_FILE_READ_FAIL;
    m_pos = pos;
    m_eof = false;
    return E_OK;
}

ErrCode CSimpleFile::size(int64_t& outSize) const {
    if (m_fd < 0) return E_FILE_OPEN_FAIL;
    outSize = Platform::fileSizeOf(m_fd);
    return outSize < 0 ? E_FILE_READ_FAIL : E_OK;
}

ErrCode CSimpleFile::flush() {
    if (m_fd < 0) return E_OK;
    return Platform::fsyncNative(m_fd) == 0 ? E_OK : E_FILE_WRITE_FAIL;
}

ErrCode CSimpleFile::readWhole(const std::string& path, std::vector<uint8_t>& out) {
    CSimpleFile f;
    ErrCode e = f.open(path, MODE_READ);
    if (DBKP_IS_ERR(e)) return e;
    return f.readAll(out);
}

ErrCode CSimpleFile::writeWhole(const std::string& path, const std::vector<uint8_t>& data) {
    CSimpleFile f;
    ErrCode e = f.open(path, MODE_WRITE_NEW);
    if (DBKP_IS_ERR(e)) return e;
    e = f.writeAll(data);
    DBKP_FAIL(e, f.flush());
    return f.close();
}

} /* namespace DBKP */
