/* ============================================================================
 *  Compat.h  -- 操作系统能力探测与最小 POSIX 兼容层
 *
 *  设计目标（见《系统设计文档》3.1 跨平台层）：
 *    1. 上层模块（Enumerator / Pack / Backup）只使用本头文件暴露的能力宏，
 *       不直接书写 #ifdef __linux__，保证一次编写、Linux 全功能、Windows 可跑。
 *    2. 在 Windows(MinGW/MSVC) 上编译通过并可完成"目录树 + 普通文件 + 元数据(时间)"
 *       的备份还原；符号链接/硬链接/管道/设备节点在 Linux 上提供完整支持。
 * ==========================================================================*/
#ifndef DBKP_PLATFORM_COMPAT_H
#define DBKP_PLATFORM_COMPAT_H

/* ---------------------------------------------------------------- 平台识别 */
#if defined(_WIN32) || defined(_WIN64)
#  define DBKP_OS_WINDOWS 1
#  include <sys/types.h>
#  include <sys/stat.h>
#  include <fcntl.h>
#  include <direct.h>
#  include <io.h>
   /* Windows 侧统一走 Win32/UTF-16 接口（见 Platform/FS_win.cpp），
    * 因此这里只需要少数字节宽度别名。 */
   typedef int      dbkp_ssize_t;
#  ifndef S_ISREG
#    define S_ISREG(m)  (((m) & S_IFMT) == S_IFREG)
#  endif
#  ifndef S_ISDIR
#    define S_ISDIR(m)  (((m) & S_IFMT) == S_IFDIR)
#  endif
#else
#  define DBKP_OS_POSIX 1
#  include <sys/types.h>
#  include <sys/stat.h>
#  include <sys/statvfs.h>
#  include <unistd.h>
#  include <dirent.h>
#  include <utime.h>
#  include <fcntl.h>
#  include <limits.h>
   typedef ssize_t  dbkp_ssize_t;
#endif

/* ------------------------------------------------------ 文件系统能力矩阵 */
#if defined(DBKP_OS_POSIX)
#  define DBKP_HAS_LSTAT            1   /* lstat / S_ISLNK                */
#  define DBKP_HAS_SYMLINK          1   /* symlink / readlink / lchown    */
#  define DBKP_HAS_HARDLINK         1   /* st_nlink / link()              */
#  define DBKP_HAS_FIFO             1   /* mkfifo                         */
#  define DBKP_HAS_DEVICE_NODE      1   /* mknod(S_IFCHR|S_IFBLK)         */
#  define DBKP_HAS_OWNER            1   /* chown / fchown / getuid        */
#  define DBKP_HAS_PERMISSION       1   /* chmod                          */
#  define DBKP_HAS_NANOSECOND_TIME  1   /* st_mtim.tv_nsec / utimensat    */
#  define DBKP_HAS_INOTIFY          1   /* 实时备份监控（第 9 讲扩展）     */
#  define DBKP_HAS_XATTR            0   /* 扩展属性：按需开启，需 <sys/xattr.h> */
#else
#  define DBKP_HAS_LSTAT            0
#  define DBKP_HAS_SYMLINK          0   /* Windows 上仅识别、不复原        */
#  define DBKP_HAS_HARDLINK         1   /* CreateHardLinkW                */
#  define DBKP_HAS_FIFO             0
#  define DBKP_HAS_DEVICE_NODE      0
#  define DBKP_HAS_OWNER            0
#  define DBKP_HAS_PERMISSION       1   /* 仅读/写位（DOS 属性映射）       */
#  define DBKP_HAS_NANOSECOND_TIME  1   /* FILETIME 100ns 精度            */
#  define DBKP_HAS_INOTIFY          0
#  define DBKP_HAS_XATTR            0
#endif

/* Windows 的 st_mode 中没有 S_IFLNK，统一由 Platform/FS.h 的 FileType 表达 */
#ifndef S_IFLNK
#  define S_IFLNK 0
#endif

/* ------------------------------------------------------------ 通用小工具 */
#define DBKP_UNUSED(x) ((void)(x))

#define DBKP_DISALLOW_COPY_AND_ASSIGN(ClassName)        \
    ClassName(const ClassName&) = delete;               \
    ClassName& operator=(const ClassName&) = delete;

/** 取数组元素个数（编译期） */
#define DBKP_ARRAY_COUNT(a) (sizeof(a) / sizeof((a)[0]))

#endif /* DBKP_PLATFORM_COMPAT_H */
