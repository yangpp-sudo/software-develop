/* ============================================================================
 *  test_wb_main.cpp  -- 批次10：真实 GoogleTest 下的测试入口
 *
 *  为什么需要它：test_main.cpp 里的 main 被 #if !DBKP_USE_REAL_GTEST 屏蔽了，
 *  而 vendored gtest 我们只用 gtest-all.cc（不链 gtest_main），否则老用例的
 *  "把工作目录切到 %TMP%/dbkp_ut 沙箱" 这一步会丢 —— 那一步保证 ttest_* /
 *  wb_* 之类的相对路径不会把源码树弄脏。所以这里把同样的沙箱逻辑搬过来，
 *  再调 InitGoogleTest + RUN_ALL_TESTS。
 *
 *  迷你框架编译时（make test）本文件整体为空翻译单元，不影响旧行为。
 * ==========================================================================*/
#include "TestFramework.h"

#if defined(DBKP_USE_REAL_GTEST)

#include <cstdio>
#include <cstdlib>
#include <string>

#include "Utils/CRC64.h"

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
    return base + "dbkp_gt";
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
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

#endif /* DBKP_USE_REAL_GTEST */
