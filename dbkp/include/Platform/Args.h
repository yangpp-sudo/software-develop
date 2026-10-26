/* ============================================================================
 *  Args.h  --  让"进程参数 / 控制台输出"和工程内部的 UTF-8 路径表示对齐
 *
 *  Windows 的 argv 是"当前 ANSI 码页"的字节串（中文系统 = GBK），而本工程内部
 *  一律用 UTF-8 表示路径。直接把 argv[i] 当 UTF-8 用，中文目录名就坏了：
 *  表现是 bkd 的 --data-root 与 HTTP 请求体里（UTF-8）的路径比不上，
 *  所有任务都被路径沙箱判成"超出允许访问的根目录"。
 *
 *  这里从 Unicode 命令行重取参数并转成 UTF-8；POSIX 下 argv 本来就是字节透传，
 *  不做任何转换。顺带把控制台输出码页设成 UTF-8，日志里的中文不再乱码。
 * ==========================================================================*/
#ifndef DBKP_PLATFORM_ARGS_H
#define DBKP_PLATFORM_ARGS_H

#include "Platform/Compat.h"
#include "Utils/PathUtil.h"

#include <cstddef>
#include <string>
#include <vector>

#if defined(DBKP_OS_WINDOWS)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>          /* GetCommandLineW / SetConsoleOutputCP */
#  include <shellapi.h>         /* CommandLineToArgvW（LEAN_AND_MEAN 会把它排除掉，必须单独引） */
#endif

namespace DBKP {
namespace Platform {

/**
 * 就地改写 argc/argv，使两者指向 UTF-8 参数；拿不到 Unicode 命令行时保持原样
 * （至少纯 ASCII 参数仍然可用）。storage 与内部指针表存活到进程结束，
 * 调用方只要在 main 的作用域里用完即可。
 */
inline void useUtf8Args(int& argc, char**& argv, std::vector<std::string>& storage) {
#if defined(DBKP_OS_WINDOWS)
    ::SetConsoleOutputCP(CP_UTF8);
    int wideCount = 0;
    LPWSTR* wideArgs = ::CommandLineToArgvW(::GetCommandLineW(), &wideCount);
    if (wideArgs == nullptr) return;
    storage.clear();
    storage.reserve(static_cast<std::size_t>(wideCount));
    for (int i = 0; i < wideCount; ++i)
        storage.push_back(Path::wideToUtf8(wideArgs[i]));
    ::LocalFree(wideArgs);
    /* 指针表必须是静态的：main 返回前 argv 一直要有效 */
    static std::vector<char*> ptrs;
    ptrs.clear();
    for (std::size_t i = 0; i < storage.size(); ++i) ptrs.push_back(&storage[i][0]);
    ptrs.push_back(nullptr);
    argc = wideCount;
    argv = ptrs.data();
#else
    (void)argc; (void)argv; (void)storage;   /* POSIX：argv 已是本机字节串，原样用 */
#endif
}

} /* namespace Platform */
} /* namespace DBKP */

#endif /* DBKP_PLATFORM_ARGS_H */
