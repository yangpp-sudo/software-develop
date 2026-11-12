/* ============================================================================
 *  test_regress_f8.cpp  -- F8（坏 glob 静默产出 0 条目"成功"空箱）的命名回归测试
 *
 *  背景（整改清单 F8）：
 *    --name '[' 这类语法残缺的 glob，matchCharClass 在未闭合时恒返回 false，
 *    matchGlob 又不做任何语法预校验，于是所有文件都被过滤掉，最后产出一只
 *    0 条目的空箱还 exit=0"成功" —— 用户以为备份好了，其实什么都没装。
 *  修法：新增 Path::validateGlob，规则严格对齐 matchCharClass/matchGlob 方言
 *    （'[' 必须闭合、字符类体非空、区间上界不得小于下界）。CLI 四个 glob 入口
 *    与 API applyFilterJson 在"入口"就拒绝非法模式；打包后若 0 条目且用户没给
 *    exclude 过滤，额外 LOG_WARN 兜底。
 * ==========================================================================*/
#include "TestFramework.h"

#include <string>
#include <vector>

#include "Enumerator/FilterOptions.h"
#include "Pack/MyPack.h"
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

bool validateFails(const std::string& pat) {
    std::string why;
    bool ok = Path::validateGlob(pat, why);
    return !ok;
}

} /* anonymous namespace */

/* 核心回归：未闭合的 '[' 必须被 validateGlob 判非法 */
TEST(RegressF8, unclosed_char_class_rejected) {
    EXPECT_TRUE(validateFails("["));
    EXPECT_TRUE(validateFails("*.txt["));
    EXPECT_TRUE(validateFails("report[0-9"));
    EXPECT_TRUE(validateFails("a[b"));
}

/* 空字符类 '[]' 恒不匹配，同样判非法（本方言里 ']' 不能作字面量打头） */
TEST(RegressF8, empty_char_class_rejected) {
    EXPECT_TRUE(validateFails("[]"));
    EXPECT_TRUE(validateFails("file[].txt"));
    EXPECT_TRUE(validateFails("![]"));
    EXPECT_TRUE(validateFails("[]abc]"));
}

/* 区间上下界颠倒（z-a）永不匹配，判非法 */
TEST(RegressF8, reversed_range_rejected) {
    EXPECT_TRUE(validateFails("[z-a]"));
    EXPECT_TRUE(validateFails("x[9-0]y"));
}

/* 空模式不可能匹配任何文件 */
TEST(RegressF8, empty_pattern_rejected) {
    EXPECT_TRUE(validateFails(""));
}

/* 反面对照：合法 glob 一律放行（含取反、区间、] 作首字符、- 在边缘等） */
TEST(RegressF8, valid_globs_accepted) {
    std::string why;
    EXPECT_TRUE(Path::validateGlob("*.txt", why));
    EXPECT_TRUE(Path::validateGlob("report_2024-??.csv", why));
    EXPECT_TRUE(Path::validateGlob("[a-z]*.log", why));
    EXPECT_TRUE(Path::validateGlob("[!abc]file", why));   /* 取反 */
    EXPECT_TRUE(Path::validateGlob("[^0-9]x", why));      /* 取反 */
    EXPECT_TRUE(Path::validateGlob("[a-]", why));         /* - 在边缘合法 */
    EXPECT_TRUE(Path::validateGlob("[-a]", why));
    EXPECT_TRUE(Path::validateGlob("[0-9][0-9][0-9].*", why));
    EXPECT_TRUE(Path::validateGlob("no-glob-here.txt", why));
}

/* 端到端：用非法 --name 模式打包，pack 层本身不报错（校验在 CLI 入口做），
   但 0 条目的空源会被打包 —— 这里验证的是"合法模式能正常过滤"这条正路，
   确保新增校验没有把 matchGlob 的行为改动。 */
TEST(RegressF8, valid_glob_filters_correctly) {
    const std::string root = "treg_f8_filter";
    const std::string arc  = Path::join(Path::join(root, "sub"), "out.dbkp");
    removeTree(root);
    Platform::makeDirTree(Path::join(root, "sub"));
    writeText(Path::join(root, "keep.txt"), "keep");
    writeText(Path::join(root, "drop.log"), "drop");

    CMyPack p;
    PackOptions o;
    std::string why;
    ASSERT_TRUE(Path::validateGlob("*.txt", why));
    o.filter.nameGlobs.push_back("*.txt");
    ASSERT_EQ(int(p.pack(root, arc, o)), int(E_OK));

    std::vector<FileRecord> recs;
    ASSERT_EQ(int(p.list(arc, recs)), int(E_OK));
    bool sawTxt = false, sawLog = false;
    for (size_t i = 0; i < recs.size(); ++i) {
        if (recs[i].path.find("keep.txt") != std::string::npos) sawTxt = true;
        if (recs[i].path.find("drop.log") != std::string::npos) sawLog = true;
    }
    EXPECT_TRUE(sawTxt);
    EXPECT_FALSE(sawLog);

    removeTree(root);
}
