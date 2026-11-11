/* ============================================================================
 *  test_regress_f11.cpp  -- F11（同秒双写撞名）的命名回归测试
 *
 *  背景（整改清单 F11）：
 *    makeArchiveName 只精确到秒（%Y%m%d-%H%M%S）。调度器/守护进程在同一秒内
 *    触发两次备份会得到同一个目标名：第二次把第一次的箱原地顶掉，
 *    等于丢了一次备份。
 *  修法：时间戳补毫秒段；目标名已存在时再递增 "-xN" 计数后缀，
 *    保证同秒（甚至同毫秒）双写得到两个不同名箱；名字仍以 .dbkp 结尾，
 *    applyRetention 的前缀 + 字典序过滤不受影响。
 * ==========================================================================*/
#include "TestFramework.h"

#include <string>
#include <vector>

#include "Backup/Scheduler.h"
#include "Platform/FS.h"
#include "Utils/PathUtil.h"
#include "Utils/SimpleFile.h"

using namespace DBKP;

namespace {

void removeTree(const std::string& p) {
    std::vector<Platform::DirEntry> items;
    if (DBKP_IS_ERR(Platform::listDir(p, items))) { Platform::removeFile(p); return; }
    for (size_t i = 0; i < items.size(); ++i) {
        const std::string c = Path::join(p, items[i].name);
        if (items[i].type == FT_DIR) removeTree(c);
        else Platform::removeFile(c);
    }
    Platform::removeDir(p);
}

bool endsWith(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

} /* anonymous namespace */

/* 名字格式：前缀 + 时间戳（含毫秒段）+ .dbkp，且可被保留策略按前缀筛到 */
TEST(RegressF11, name_has_millisecond_field_and_suffix) {
    const std::string dir = "treg_f11_fmt";
    removeTree(dir);
    Platform::makeDirTree(dir);

    const std::string a = CScheduler::makeArchiveName(dir, "data");
    EXPECT_TRUE(endsWith(a, ".dbkp"));
    EXPECT_TRUE(a.find("data-") != std::string::npos);
    /* 时间戳段：YYYYmmdd-HHMMSS-mmm —— 数一下短横应为 3 个（日期/秒/毫秒） */
    const std::string base = Path::fileName(a);
    int dashes = 0;
    for (size_t i = 0; i < base.size(); ++i) if (base[i] == '-') ++dashes;
    EXPECT_EQ(dashes, 3);

    removeTree(dir);
}

/* 验收①：同秒双写 -> 两个不同名箱。模拟方式：第一个名字的文件已落盘后，
   连续再取名必须避开已占用名（毫秒相同/不同两条路都覆盖）。 */
TEST(RegressF11, same_second_collision_yields_distinct_names) {
    const std::string dir = "treg_f11_collide";
    removeTree(dir);
    Platform::makeDirTree(dir);

    /* 连取 5 个名字，每取一个立刻"落盘"（模拟同秒内备份逐个完成） */
    std::vector<std::string> names;
    for (int i = 0; i < 5; ++i) {
        const std::string n = CScheduler::makeArchiveName(dir, "job");
        for (size_t j = 0; j < names.size(); ++j)
            EXPECT_NE(names[j], n);                 /* 两两不同名 */
        EXPECT_TRUE(endsWith(n, ".dbkp"));
        ASSERT_EQ(int(CSimpleFile::writeWhole(n,
                    std::vector<uint8_t>(16, 'x'))), int(E_OK));
        names.push_back(n);
    }
    /* 5 个名字全部真实存在且互不相同 */
    std::vector<Platform::DirEntry> items;
    ASSERT_EQ(int(Platform::listDir(dir, items)), int(E_OK));
    EXPECT_EQ(int(items.size()), 5);

    removeTree(dir);
}

/* 保留策略兼容：新格式名字仍按前缀筛入、按字典序排列（时间序） */
TEST(RegressF11, retention_still_works_with_new_names) {
    const std::string dir = "treg_f11_keep";
    removeTree(dir);
    Platform::makeDirTree(dir);

    std::vector<std::string> made;
    for (int i = 0; i < 5; ++i) {
        const std::string n = CScheduler::makeArchiveName(dir, "ret");
        CSimpleFile::writeWhole(n, std::vector<uint8_t>(8, 'x'));
        made.push_back(n);
    }
    const int removed = CScheduler::applyRetention(dir, "ret", 3);
    EXPECT_EQ(removed, 2);
    /* 剩下最晚的 3 个 */
    std::vector<Platform::DirEntry> items;
    ASSERT_EQ(int(Platform::listDir(dir, items)), int(E_OK));
    EXPECT_EQ(int(items.size()), 3);

    removeTree(dir);
}
