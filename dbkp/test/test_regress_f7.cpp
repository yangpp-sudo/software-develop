/* ============================================================================
 *  test_regress_f7.cpp  -- F7（schedule --times 0 死循环）的命名回归测试
 *
 *  背景（整改清单 F7）：
 *    CScheduler::run 的循环条件是 while (opt.times <= 0 || done < opt.times)，
 *    times<=0 被当成"无限常驻"，bk schedule --times 0 永不返回（CLI 里也没有
 *    信号退出路径），用户只能强杀进程。
 *  修法：times 语义收紧为"必须 >= 1"。CLI 在解析处用 strtol 严格校验（非整数
 *    或 <1 直接 exit 2），调度器入口再兜一层拒绝（<=0 返回 E_INVALID_PARAMETER），
 *    循环条件去掉无限分支。常驻请改用 watch / daemon。
 * ==========================================================================*/
#include "TestFramework.h"

#include <atomic>
#include <string>
#include <vector>

#include "Backup/Scheduler.h"
#include "Platform/FS.h"
#include "Utils/PathUtil.h"
#include "Utils/SimpleFile.h"

using namespace DBKP;

namespace {

void writeText(const std::string& abs, const std::string& text) {
    const std::string parent = Path::parentDir(abs);
    if (!parent.empty()) Platform::makeDirTree(parent);
    CSimpleFile::writeWhole(abs, std::vector<uint8_t>(text.begin(), text.end()));
}

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

ScheduleOptions makeOpt(const std::string& root, int times) {
    ScheduleOptions so;
    so.times           = times;
    so.intervalSeconds = 3600;          /* 就算漏判也不会卡在测试里等一轮 */
    so.backup.source   = Path::join(root, "src");
    so.backup.destination = Path::join(root, "out");
    so.backup.verifyAfter = false;
    so.archiveDir      = Path::join(root, "out");
    return so;
}

} /* anonymous namespace */

/* 核心回归：times==0 必须立刻返回错误，而不是无限循环 */
TEST(RegressF7, times_zero_rejected_immediately) {
    const std::string root = "treg_f7_zero";
    removeTree(root);
    writeText(Path::join(root, "src/a.txt"), "alpha");

    CScheduler sch;
    std::atomic<bool> stop(false);
    ErrCode e = sch.run(makeOpt(root, 0), &stop);
    EXPECT_EQ(int(e), int(E_INVALID_PARAMETER));

    removeTree(root);
}

/* times<0 同样拒绝 */
TEST(RegressF7, times_negative_rejected) {
    const std::string root = "treg_f7_neg";
    removeTree(root);
    writeText(Path::join(root, "src/a.txt"), "alpha");

    CScheduler sch;
    EXPECT_EQ(int(sch.run(makeOpt(root, -5))), int(E_INVALID_PARAMETER));
    EXPECT_EQ(int(sch.run(makeOpt(root, -1))), int(E_INVALID_PARAMETER));

    removeTree(root);
}

/* 反面对照：times==1 正常跑完一次并产出归档（收紧语义不能把正路打死） */
TEST(RegressF7, times_one_runs_once) {
    const std::string root = "treg_f7_one";
    removeTree(root);
    writeText(Path::join(root, "src/a.txt"), "alpha");
    Platform::makeDirTree(Path::join(root, "out"));

    CScheduler sch;
    ScheduleOptions so = makeOpt(root, 1);
    ASSERT_EQ(int(sch.run(so)), int(E_OK));

    std::vector<Platform::DirEntry> items;
    ASSERT_EQ(int(Platform::listDir(Path::join(root, "out"), items)), int(E_OK));
    int boxes = 0;
    for (size_t i = 0; i < items.size(); ++i)
        if (items[i].name.size() >= 5 &&
            items[i].name.compare(items[i].name.size() - 5, 5, ".dbkp") == 0) ++boxes;
    EXPECT_EQ(boxes, 1);

    removeTree(root);
}

/* times==2 跑满两轮：循环条件去掉无限分支后计数仍然正确 */
TEST(RegressF7, times_two_runs_twice) {
    const std::string root = "treg_f7_two";
    removeTree(root);
    writeText(Path::join(root, "src/a.txt"), "alpha");
    Platform::makeDirTree(Path::join(root, "out"));

    CScheduler sch;
    ScheduleOptions so = makeOpt(root, 2);
    so.intervalSeconds = 1;
    ASSERT_EQ(int(sch.run(so)), int(E_OK));

    std::vector<Platform::DirEntry> items;
    ASSERT_EQ(int(Platform::listDir(Path::join(root, "out"), items)), int(E_OK));
    int boxes = 0;
    for (size_t i = 0; i < items.size(); ++i)
        if (items[i].name.size() >= 5 &&
            items[i].name.compare(items[i].name.size() - 5, 5, ".dbkp") == 0) ++boxes;
    EXPECT_EQ(boxes, 2);

    removeTree(root);
}

/* 默认值仍是 1（头文件注释与结构体初值同步收紧后的自证） */
TEST(RegressF7, default_times_is_valid) {
    ScheduleOptions so;
    EXPECT_EQ(so.times, 1);
}
