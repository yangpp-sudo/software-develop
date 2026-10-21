/* ============================================================================
 *  test_main.cpp  -- 迷你框架入口（真实 gtest 下由 gtest_main 提供入口）
 * ==========================================================================*/
#include "TestFramework.h"

#if !defined(DBKP_USE_REAL_GTEST)

#include "Utils/CRC64.h"

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;
    DBKP::CRC64::initTable();
    return RUN_ALL_TESTS();
}

#endif /* !DBKP_USE_REAL_GTEST */
