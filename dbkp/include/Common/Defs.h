/* ============================================================================
 *  Defs.h  -- 全局数据类型、归档文件格式定义
 *
 *  【为什么不用 struct 直接 fwrite】
 *  讲义《打包解包》中 `fwrite(&record, sizeof(record), 1, fp)` 依赖
 *  sizeof/padding/字节序，跨平台移植时会出错（讲义"已知缺陷"第 5 条）。
 *  本实现把"内存对象"与"磁盘布局"分离：
 *      FileRecord  —— 内存态，path 用 std::string，无长度浪费、无对齐空洞
 *      磁盘态      —— 固定 512 字节、强制小端、逐字段序列化（Serialize.cpp）
 *  磁盘布局（头记录 512B）：
 *     0   4 recMagic |  4 1 type |  5 1 flags |  6 2 pathLen |  8 2 linkLen
 *    10   4 mode     | 14 4 uid  | 18 4 gid
 *    22   8 mtimeSec | 30 8 mtimeNSec | 38 8 atimeSec | 46 8 atimeNSec | 54 8 ctimeSec
 *    62   8 ino      | 70 4 nlink | 74 4 dev | 78 4 major | 82 4 minor
 *    86   8 size(原始) | 94 8 storedSize(编码后) | 102 8 crc64
 *   110   1 compAlg  | 111 1 cryptoAlg | 112 2 reserved
 *   114 160 path     | 274  96 link    | 370 142 reserved   => 合计 512B
 *  路径/链接超出内联槽位时，使用类型 'X' 的扩展记录（紧随其前，按序拼接）。
 * ==========================================================================*/
#ifndef DBKP_COMMON_DEFS_H
#define DBKP_COMMON_DEFS_H

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

#include "Platform/Compat.h"

namespace DBKP {

/* ------------------------------------------------------------ 常量 */
static const uint32_t ARCHIVE_MAGIC      = 0x44424B50u; /* "DBKP" */
static const uint32_t RECORD_MAGIC       = 0x52484431u; /* "1DHR" 小端 */
static const uint16_t ARCHIVE_VERSION    = 1;
static const std::size_t BLOCK_SIZE      = 512;  /* 与 POSIX tar 对齐 */
static const std::size_t REC_INLINE_PATH = 160;
static const std::size_t REC_INLINE_LINK = 96;
static const std::size_t REC_INLINE_FREE = 142;
static const std::size_t REC_EXTEND_PAYLOAD =
        REC_INLINE_PATH + REC_INLINE_LINK + REC_INLINE_FREE;   /* 398 */
static const char* const DEFAULT_ARCHIVE_SUFFIX = ".dbkp";

/* ------------------------------------------------------------ 文件类型 */
enum FileTypeTag : char {
    FT_REGULAR   = '-',
    FT_DIR       = 'D',
    FT_SYMLINK   = 'L',
    FT_BLOCK     = 'B',
    FT_CHAR      = 'C',
    FT_FIFO      = 'F',
    FT_SOCKET    = 'S',
    FT_HARDLINK  = 'H',  /* 同一 inode 的后续链接，仅记录首次出现的相对路径 */
    FT_EXTEND    = 'X',  /* 扩展记录：承载超长 path/link */
};

/** 头记录标志位 */
enum RecordFlag : uint8_t {
    RF_NONE         = 0x00,
    RF_HAS_EXTEND   = 0x01,  /* 前方存在 'X' 扩展记录 */
    RF_HARDLINK_SRC = 0x02,  /* 本记录是某 inode 的首次完整备份 */
    RF_META_UID     = 0x04,  /* uid/gid 有效（还原时尝试 chown） */
    RF_META_MODE    = 0x08,  /* mode 有效（还原时 chmod） */
    RF_META_TIME    = 0x10,  /* mtime/atime 有效 */
    RF_CRC_VALID    = 0x20,  /* crc64 字段有效 */
    RF_DIR_LAST     = 0x40,  /* 目录延迟恢复标记（两遍恢复第 2 遍） */
};

/* ------------------------------------------------------------ 编码算法 */
enum AlgorithmId : uint8_t {
    ALG_NONE     = 0,
    ALG_HUFFMAN  = 1,
    ALG_LZ77     = 2,
    ALG_LZHUFF   = 3,   /* LZ77 之后再 Huffman（组合算法，额外加分项） */
    ALG_RLE      = 4,
    ALG_COUNT    = 5,
};

enum CryptoId : uint8_t {
    CRY_NONE       = 0,
    CRY_AES256_CBC = 1,
    CRY_CHACHA20   = 2,
    CRY_XOR_TEST   = 3,   /* 仅用于单元测试的极弱算法，勿用于生产 */
};

enum ChecksumId : uint8_t {
    CHK_NONE   = 0,
    CHK_CRC64  = 1,
    CHK_SHA256 = 2,
};

/* 备份形态：自动按目标扩展名判断（.dbkp -> 归档，否则 -> 逐文件复制） */
enum BackupMode { MODE_AUTO = 0, MODE_ARCHIVE = 1, MODE_COPY = 2 };

inline const char* backupModeName(BackupMode m) {
    switch (m) {
    case MODE_ARCHIVE: return "archive";
    case MODE_COPY:    return "copy";
    default:           return "auto";
    }
}

/* ------------------------------------------------------------ 错误码 */
enum ErrCode : int {
    E_OK                    = 0,
    E_INVALID_PARAMETER     = 1,
    E_DESTINATION_NOT_EMPTY = 2,
    E_DESTINATION_CREATE_FAIL = 3,
    E_SOURCE_NOT_FOUND      = 4,
    E_FILE_OPEN_FAIL        = 5,
    E_FILE_READ_FAIL        = 6,
    E_FILE_WRITE_FAIL       = 7,
    E_INVALID_HEADER_RECORD = 8,
    E_INVALID_DATA_RECORD   = 9,
    E_CHECKSUM_MISMATCH     = 10,
    E_PATH_TOO_LONG         = 11,
    E_NOT_ENOUGH_SPACE      = 12,
    E_PERMISSION_DENIED     = 13,
    E_UNSUPPORTED_FEATURE   = 14,
    E_TRUNCATED_ARCHIVE     = 15,
    E_WRONG_PASSWORD        = 16,
    E_CRYPTO_FAIL           = 17,
    E_COMPRESS_FAIL         = 18,
    E_ALREADY_EXISTS        = 19,
    E_NOT_FOUND             = 20,
    E_INTERNAL              = 21,
    E_CANCELED              = 22,  /* 用户/服务端主动取消（Web 任务取消） */
    E_UNKNOWN               = 127,
};

#define DBKP_IS_ERR(x)   ((x) != DBKP::E_OK)
#define DBKP_FAIL(x, y)  (((x) != DBKP::E_OK) ? (x) : (y))

const char* errCodeToString(ErrCode code);
const char* fileTypeToDesc(char type);
const char* algorithmName(AlgorithmId id);
AlgorithmId algorithmFromName(const std::string& name);
const char* cryptoName(CryptoId id);
CryptoId    cryptoFromName(const std::string& name);

/* ------------------------------------------------------------ 内存态记录 */
/**
 * @brief 归档中的一条文件/目录记录（内存态）
 *
 * path 为**相对路径**（相对备份根，统一 '/' 分隔，UTF-8 编码），
 * 使归档与平台无关，还原时可拼接到任意目标目录。
 */
struct FileRecord {
    std::string  path;              /* 相对路径，不含前导 '/' */
    std::string  link;              /* 符号链接目标 / 硬链接首次出现路径 */
    char         type      = FT_REGULAR;
    uint8_t      flags     = RF_NONE;
    uint8_t      compAlg   = ALG_NONE;
    uint8_t      cryptoAlg = CRY_NONE;

    uint32_t     mode      = 0;
    uint32_t     uid       = 0;
    uint32_t     gid       = 0;
    int64_t      mtimeSec  = 0, mtimeNSec = 0;
    int64_t      atimeSec  = 0, atimeNSec = 0;
    int64_t      ctimeSec  = 0;
    uint64_t     ino       = 0;
    uint32_t     nlink     = 1;
    uint32_t     dev       = 0;
    uint32_t     majorNum  = 0;
    uint32_t     minorNum  = 0;

    int64_t      size       = 0;    /* 原始字节数 */
    int64_t      storedSize = 0;    /* 编码后字节数 */
    uint64_t     crc        = 0;

    FileRecord() = default;

    bool isDirectory() const { return type == FT_DIR; }
    bool isRegular()   const { return type == FT_REGULAR; }
    bool isExtend()    const { return type == FT_EXTEND; }
    bool hasData()     const { return type == FT_REGULAR && storedSize > 0; }
};

/** 归档卷标（磁盘 512B，内存态） */
struct ArchiveHeader {
    uint32_t   magic         = ARCHIVE_MAGIC;
    uint16_t   version       = ARCHIVE_VERSION;
    uint16_t   headerSize    = BLOCK_SIZE;
    uint8_t    compAlg       = ALG_NONE;
    uint8_t    cryptoAlg     = CRY_NONE;
    uint8_t    checksum      = CHK_CRC64;
    uint8_t    flags         = 0;
    uint64_t   payloadCrc    = 0;
    uint64_t   payloadOffset = BLOCK_SIZE;
    uint64_t   payloadSize   = 0;   /* 编码后的载荷总字节 */
    uint64_t   rawSize       = 0;   /* 原始数据总字节 */
    uint64_t   recordCount   = 0;   /* 头记录数（含扩展记录） */
    uint64_t   fileCount     = 0;   /* 文件/目录条目数 */
    uint64_t   createTime    = 0;
    uint8_t    salt[16];
    uint16_t   kdfRounds     = 0;
    std::string sourcePath;         /* 备份源绝对路径（信息用） */
    std::string comment;            /* 用户备注 */

    ArchiveHeader() { for (int i = 0; i < 16; ++i) salt[i] = 0; }
};

/** 归档统计（供 info/verify 命令与演示使用） */
struct ArchiveStat {
    int64_t fileCount    = 0;
    int64_t dirCount     = 0;
    int64_t linkCount    = 0;
    int64_t specialCount = 0;
    int64_t rawBytes     = 0;
    int64_t storedBytes  = 0;
};

} /* namespace DBKP */

#endif /* DBKP_COMMON_DEFS_H */

