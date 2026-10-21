/* ============================================================================
 *  test_main.cpp  -- 迷你框架入口（真实 gtest 下由 gtest_main 提供入口）
 * ==========================================================================*/
#include "TestFramework.h"

#if !defined(DBKP_USE_REAL_GTEST)

#include <cstdlib>
#include <cstdio>
#include <string>

#include "Utils/CRC64.h"

/* 单测会在当前目录建 ttest_* 测试树。为了不把源码树弄脏（也避免遗留文件影响
 * shell 通配展开），启动时把工作目录切到临时沙箱里。 */
#if defined(_WIN32)
#  include <direct.h>
#  define DBKP_CHDIR(p) _chdir(p)
#  define DBKP_MKDIR(p) _mkdir(p)
#else
#  include <sys/stat.h>
#  include <unistd.h>
#  define DBKP_CHDIR(p) chdir(p)
#  define DBKP_MKDIR(p) mkdir((p), 0755)
#endif

static std::string sandboxDir() {
    const char* tmp = std::getenv("TMP");
    if (tmp == NULL || *tmp == '\0') tmp = std::getenv("TEMP");
    if (tmp == NULL || *tmp == '\0') tmp = std::getenv("TMPDIR");
    std::string base = (tmp != NULL && *tmp != '\0') ? std::string(tmp) : std::string(".");
    if (base.empty()) base = ".";
    const char last = base[base.size() - 1];
    if (last != '/' && last != '\\') base += '/';
    return base + "dbkp_ut";
}

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;
    const std::string sb = sandboxDir();
    DBKP_MKDIR(sb.c_str());                       /* 已存在则失败，忽略 */
    if (DBKP_CHDIR(sb.c_str()) == 0) {
        std::printf("[ sandbox  ] %s\n", sb.c_str());
    } else {
        std::printf("[ sandbox  ] cannot enter %s, using current dir\n", sb.c_str());
    }
    DBKP::CRC64::initTable();
    return RUN_ALL_TESTS();
}

#endif /* !DBKP_USE_REAL_GTEST */
