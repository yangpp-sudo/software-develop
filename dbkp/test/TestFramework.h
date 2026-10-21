/* ============================================================================
 *  TestFramework.h  -- 与 GoogleTest 接口兼容的最小测试框架
 *
 *  为什么自带：课程机器不一定装了 libgtest，但"单元测试覆盖率"是完成度分。
 *  用法：
 *    Linux 有 gtest  ->  make gtest   （-DDBKP_USE_REAL_GTEST=1 -lgtest）
 *    任何平台        ->  make test    （本文件的迷你实现）
 *  只实现我们用到的宏子集：TEST / EXPECT_TRUE/FALSE / EQ / NE / LT / GE / GT /
 *  STREQ / NEAR / ASSERT_* / RUN_ALL_TESTS。
 * ==========================================================================*/
#ifndef DBKP_TEST_FRAMEWORK_H
#define DBKP_TEST_FRAMEWORK_H

#if defined(DBKP_USE_REAL_GTEST)

#include <gtest/gtest.h>

#else /* 迷你实现 */

#include <cmath>
#include <cstdio>
#include <cstring>
#include <functional>
#include <sstream>
#include <string>
#include <vector>

namespace dbkp_test {

struct Case {
    std::string suite;
    std::string name;
    std::function<void()> body;
};

class Registry {
public:
    static Registry& instance() {
        static Registry r;
        return r;
    }
    void add(const Case& c) { m_cases.push_back(c); }
    int runAll() {
        int failed = 0, run = 0;
        for (size_t i = 0; i < m_cases.size(); ++i) {
            const Case& c = m_cases[i];
            m_currentFail = 0;
            std::printf("[ RUN      ] %s.%s\n", c.suite.c_str(), c.name.c_str());
            try {
                c.body();
            } catch (const std::exception& ex) {
                std::printf("    exception: %s\n", ex.what());
                ++m_currentFail;
            } catch (...) {
                std::printf("    unknown exception\n");
                ++m_currentFail;
            }
            ++run;
            if (m_currentFail == 0) {
                std::printf("[       OK ] %s.%s\n", c.suite.c_str(), c.name.c_str());
            } else {
                std::printf("[  FAILED  ] %s.%s (%d check(s))\n",
                            c.suite.c_str(), c.name.c_str(), m_currentFail);
                ++failed;
            }
        }
        std::printf("[========== ] %d tests ran, %d failed\n", run, failed);
        return failed == 0 ? 0 : 1;
    }
    void fail(const char* file, int line, const std::string& what) {
        ++m_currentFail;
        std::printf("    %s:%d: failure: %s\n", file, line, what.c_str());
    }
    bool fatal() const { return m_fatal; }
    void setFatal(bool v) { m_fatal = v; }

private:
    Registry() : m_currentFail(0), m_fatal(false) {}
    std::vector<Case> m_cases;
    int m_currentFail;
    bool m_fatal;
};

struct Registrar {
    Registrar(const char* suite, const char* name, std::function<void()> fn) {
        Registry::instance().add(Case{suite, name, fn});
    }
};

template <typename T>
std::string toStr(const T& v) {
    std::ostringstream os;
    os << v;
    return os.str();
}
inline std::string toStr(bool v) { return v ? "true" : "false"; }
inline std::string toStr(const char* v) { return v ? std::string(v) : std::string("(null)"); }
inline std::string toStr(const std::string& v) { return v; }

} /* namespace dbkp_test */

#define TEST(suite, name)                                                    \
    static void suite##_##name##_Body();                                     \
    static ::dbkp_test::Registrar suite##_##name##_Registrar(                \
        #suite, #name, suite##_##name##_Body);                               \
    static void suite##_##name##_Body()

#define DBKP_CHECK_(cond, text)                                              \
    do {                                                                     \
        if (!(cond)) {                                                       \
            ::dbkp_test::Registry::instance().fail(__FILE__, __LINE__, text);\
            if (dbkpFatal) { dbkpFatal = false; return; }                    \
        }                                                                    \
    } while (0)

#define EXPECT_TRUE(x)  DBKP_CHECK_((x), "expected true: " #x)
#define EXPECT_FALSE(x) DBKP_CHECK_(!(x), "expected false: " #x)
#define EXPECT_EQ(a, b) DBKP_CHECK_((a) == (b), std::string(#a " == " #b))
#define EXPECT_NE(a, b) DBKP_CHECK_((a) != (b), std::string(#a " != " #b))
#define EXPECT_LT(a, b) DBKP_CHECK_((a) < (b),  std::string(#a " < " #b))
#define EXPECT_LE(a, b) DBKP_CHECK_((a) <= (b), std::string(#a " <= " #b))
#define EXPECT_GT(a, b) DBKP_CHECK_((a) > (b),  std::string(#a " > " #b))
#define EXPECT_GE(a, b) DBKP_CHECK_((a) >= (b), std::string(#a " >= " #b))
#define EXPECT_STREQ(a, b) DBKP_CHECK_(std::strcmp((a), (b)) == 0, std::string(#a " == " #b))
#define EXPECT_NEAR(a, b, c) DBKP_CHECK_(std::fabs((a) - (b)) <= (c), std::string(#a " ~ " #b))

#define ASSERT_TRUE(x)  do { dbkpFatal = true; DBKP_CHECK_((x), "fatal: " #x); } while (0)
#define ASSERT_FALSE(x) do { dbkpFatal = true; DBKP_CHECK_(!(x), "fatal: " #x); } while (0)
#define ASSERT_EQ(a, b) do { dbkpFatal = true; DBKP_CHECK_((a) == (b), "fatal: " #a " == " #b); } while (0)
#define ASSERT_NE(a, b) do { dbkpFatal = true; DBKP_CHECK_((a) != (b), "fatal: " #a " != " #b); } while (0)
#define ASSERT_LT(a, b) do { dbkpFatal = true; DBKP_CHECK_((a) < (b), "fatal: " #a " < " #b); } while (0)
#define ASSERT_LE(a, b) do { dbkpFatal = true; DBKP_CHECK_((a) <= (b), "fatal: " #a " <= " #b); } while (0)
#define ASSERT_GT(a, b) do { dbkpFatal = true; DBKP_CHECK_((a) > (b), "fatal: " #a " > " #b); } while (0)
#define ASSERT_GE(a, b) do { dbkpFatal = true; DBKP_CHECK_((a) >= (b), "fatal: " #a " >= " #b); } while (0)
#define ASSERT_STREQ(a, b) do { dbkpFatal = true; DBKP_CHECK_(std::strcmp((a), (b)) == 0, "fatal: " #a " == " #b); } while (0)

inline bool dbkpFatal = false;

#define RUN_ALL_TESTS() ::dbkp_test::Registry::instance().runAll()

#endif /* DBKP_USE_REAL_GTEST */

#endif /* DBKP_TEST_FRAMEWORK_H */
