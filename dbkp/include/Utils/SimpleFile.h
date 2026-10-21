/* ============================================================================
 *  SimpleFile.h  -- 最小二进制文件封装（沿用讲义 CSimpleFile 接口并扩展）
 *
 *  readN/writeN 保证"要么读满/写满，要么返回明确错误"，
 *  避免讲义实现里 short read/short write 被忽略的隐患。
 * ==========================================================================*/
#ifndef DBKP_UTILS_SIMPLEFILE_H
#define DBKP_UTILS_SIMPLEFILE_H

#include <cstdint>
#include <string>
#include <vector>

#include "Common/Defs.h"

namespace DBKP {

class CSimpleFile {
public:
    CSimpleFile() : m_fd(-1) {}
    explicit CSimpleFile(const std::string& path) { open(path, MODE_READ); }
    ~CSimpleFile();

    enum OpenMode { MODE_READ, MODE_WRITE_NEW, MODE_WRITE_APPEND, MODE_READ_WRITE };

    ErrCode open(const std::string& path, OpenMode mode);
    ErrCode close();

    bool isOpen() const { return m_fd >= 0; }
    int  fd() const { return m_fd; }
    const std::string& path() const { return m_path; }

    /* 读满 bytes 才算成功；到达文件末尾返回 E_FILE_READ_FAIL 并置 eof() */
    ErrCode readN(void* buffer, int64_t bytes);
    ErrCode writeN(const void* buffer, int64_t bytes);
    /** 读取直到 EOF（用于小文件；大文件请用 readN 分块） */
    ErrCode readAll(std::vector<uint8_t>& out, int64_t limitBytes = -1);
    ErrCode writeAll(const std::vector<uint8_t>& data);

    ErrCode seekFile(int64_t offset, int whence);
    ErrCode seekTo(int64_t offset) { return seekFile(offset, SEEK_SET); }
    int64_t tell() const { return m_pos; }
    ErrCode size(int64_t& outSize) const;

    ErrCode flush();
    bool  eof() const { return m_eof; }

    /* 便捷：整文件读写（UTF-8 路径安全） */
    static ErrCode readWhole(const std::string& path, std::vector<uint8_t>& out);
    static ErrCode writeWhole(const std::string& path, const std::vector<uint8_t>& data);

private:
    CSimpleFile(const CSimpleFile&) = delete;
    CSimpleFile& operator=(const CSimpleFile&) = delete;

    std::string m_path;
    int         m_fd  = -1;
    int64_t     m_pos = 0;
    bool        m_eof = false;
};

} /* namespace DBKP */

#endif /* DBKP_UTILS_SIMPLEFILE_H */
