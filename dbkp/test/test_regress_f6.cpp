/* ============================================================================
 *  test_regress_f6.cpp  -- F6（watch 自喂循环）
 *
 *  背景（整改清单 F6）：
 *    bk watch <source> <archiveDir> 里，只要 archiveDir 落在 source 子树内
 *    （或与 source 相等），每生成一个箱都会被监听器当成"源里来了新文件"，
 *    于是再备一次 —— 16 秒实测能炸出 15 个箱（edge14\loop2.ps1）。
 *  修法：把"parent 是否包含 child"下沉成 Path::isSubPath，CLI（cmdWatch）
 *    与 API（hWatchStart）都在启动时拒绝，根本不进监听循环。
 *    Web 层的 400 与 CLI 的非零 exit 属于 socket/main 路径，单测够不着，
 *    这里回归的是两处共用的那颗判定核心。
 *
 *  注意：DBKP_TEST_FILTER 是对 "Suite.Name" 做子串匹配，
 *    过滤 "RegressF6" 会连既有的 RegressF6b.* 一起跑，不是本文件的用例。
 * ==========================================================================*/
#include "TestFramework.h"

#include <string>
#include <vector>

#include "Platform/FS.h"
#include "Utils/PathUtil.h"
#include "Utils/SimpleFile.h"

using namespace DBKP;

namespace {

std::string fwd(const std::string& in) {
    std::string o = in;
    for (size_t i = 0; i < o.size(); ++i) if (o[i] == '\\') o[i] = '/';
    return o;
}

std::string absOf(const std::string& rel) {
    std::string cur;
    if (Platform::currentDir(cur) != E_OK) cur = ".";
    return fwd(Path::join(cur, rel));
}

void writeText(const std::string& abs, const std::string& text) {
    const std::string parent = Path::parentDir(abs);
    if (!parent.empty()) Platform::makeDirTree(parent);
    CSimpleFile::writeWhole(abs, std::vector<uint8_t>(text.begin(), text.end()));
}

/* 用 python 的 _winapi 创建 junction；返回是否成功（无 python 时上层跳过）。 */
bool makeJunction(const std::string& targetAbs, const std::string& linkAbs) {
    const std::string cmd =
        "python -c \"import _winapi; _winapi.CreateJunction(r'" + targetAbs +
        "', r'" + linkAbs + "')\" 2>NUL";
    return std::system(cmd.c_str()) == 0;
}

void removeJunction(const std::string& linkAbs) {
    const std::string cmd =
        "python -c \"import os; os.rmdir(r'" + linkAbs + "')\" 2>NUL";
    std::system(cmd.c_str());
}

/* 递归清理：FT_SYMLINK（junction）只摘链接，绝不顺着链接进目标删真实数据。 */
void removeTree(const std::string& p) {
    std::vector<Platform::DirEntry> items;
    if (DBKP_IS_ERR(Platform::listDir(p, items))) return;
    for (size_t i = 0; i < items.size(); ++i) {
        const std::string c = Path::join(p, items[i].name);
        if (items[i].type == FT_DIR) {
            removeTree(c);
        } else if (items[i].type == FT_SYMLINK) {
            removeJunction(absOf(c));
            Platform::removeDir(c);            /* 兜底：若已不是链接 */
        } else {
            Platform::removeFile(c);
        }
    }
    Platform::removeDir(p);
}

} /* anonymous namespace */

/* 极端情况：归档目录与源目录是同一个 —— 必须判为"包含"，两处入口据此拒绝 */
TEST(RegressF6, archive_equal_source_is_contained) {
    const std::string root = "treg_f6_eq";
    removeTree(root);
    Platform::makeDirTree(root);
    const std::string src = absOf(root);

    EXPECT_TRUE(Path::isSubPath(src, src));
    /* 同一目录换个写法（尾分隔符 / 反斜杠）也必须相等 */
    EXPECT_TRUE(Path::isSubPath(src, src + "/"));
    EXPECT_TRUE(Path::isSubPath(src + "/", src));

    removeTree(root);
}

/* 归档目录在源内一层：watch 每轮生成的箱都在 source 里，必然自喂 */
TEST(RegressF6, archive_one_level_inside_source_refused) {
    const std::string root = "treg_f6_in1";
    removeTree(root);
    Platform::makeDirTree(Path::join(root, "src"));
    Platform::makeDirTree(Path::join(root, "src/out"));
    const std::string src = absOf(Path::join(root, "src"));
    const std::string dst = absOf(Path::join(root, "src/out"));

    EXPECT_TRUE(Path::isSubPath(src, dst));
    /* 反向不成立：源不在归档里，别把正常的"父目录当归档"也误杀 */
    EXPECT_FALSE(Path::isSubPath(dst, src));

    removeTree(root);
}

/* 归档目录在源内多层：同样必须拒绝 */
TEST(RegressF6, archive_deep_inside_source_refused) {
    const std::string root = "treg_f6_in3";
    removeTree(root);
    Platform::makeDirTree(Path::join(root, "src"));
    Platform::makeDirTree(Path::join(root, "src/a/b/c/boxes"));
    const std::string src = absOf(Path::join(root, "src"));
    const std::string dst = absOf(Path::join(root, "src/a/b/c/boxes"));

    EXPECT_TRUE(Path::isSubPath(src, dst));

    removeTree(root);
}

/* 批次 4 踩过的坑：c:/a 与 c:/ab 共用前缀但不是子树。
   .../src 与 .../src_out 是兄弟目录，必须放行，否则正常用法全报废。 */
TEST(RegressF6, sibling_prefix_not_contained) {
    const std::string root = "treg_f6_sib";
    removeTree(root);
    Platform::makeDirTree(Path::join(root, "src"));
    Platform::makeDirTree(Path::join(root, "src_out"));
    const std::string src = absOf(Path::join(root, "src"));
    const std::string dst = absOf(Path::join(root, "src_out"));

    EXPECT_FALSE(Path::isSubPath(src, dst));
    EXPECT_FALSE(Path::isSubPath(dst, src));
    /* 兄弟之外：真正的旁支目录同样要放行 */
    Platform::makeDirTree(Path::join(root, "elsewhere"));
    EXPECT_FALSE(Path::isSubPath(src, absOf(Path::join(root, "elsewhere"))));

    removeTree(root);
}

/* Windows 大小写不敏感：SOURCE 与 source 是同一个目录，得判为包含 */
TEST(RegressF6, case_insensitive_on_windows) {
    const std::string root = "treg_f6_case";
    removeTree(root);
    Platform::makeDirTree(Path::join(root, "src/boxes"));
    const std::string src = absOf(Path::join(root, "src"));
    std::string upper;
    for (size_t i = 0; i < src.size(); ++i) {
        const char c = src[i];
        upper += (c >= 'a' && c <= 'z') ? static_cast<char>(c - 32) : c;
    }
    EXPECT_TRUE(Path::isSubPath(upper, src));
    EXPECT_TRUE(Path::isSubPath(src, upper));
    removeTree(root);
}

/* 分隔符归一：混合 \ 与 / 的同一对路径，结论必须一致 */
TEST(RegressF6, separator_mixed_forms_agree) {
    const std::string root = "treg_f6_sep";
    removeTree(root);
    Platform::makeDirTree(Path::join(root, "src/boxes"));
    const std::string src = absOf(Path::join(root, "src"));
    std::string back = src;
    for (size_t i = 0; i < back.size(); ++i) if (back[i] == '/') back[i] = '\\';
    const std::string dst = fwd(absOf(Path::join(root, "src/boxes")));
    EXPECT_TRUE(Path::isSubPath(back, dst));
    removeTree(root);
}

/* junction 绕过：归档目录写成 source 内部一个 junction，或写成指向 source 的
   junction —— 先解析真实路径再比，不能被链接名骗过去。无 python 时跳过。 */
TEST(RegressF6, junction_pointing_into_source_refused) {
    const std::string root = "treg_f6_jct";
    removeTree(root);
    Platform::makeDirTree(Path::join(root, "src"));
    Platform::makeDirTree(Path::join(root, "real_boxes"));
    writeText(absOf(Path::join(root, "real_boxes/marker.txt")), "M");

    /* 归档目录 = 源里的一个 junction，真实目标在源外：
       canonicalPath 解析后落在源外，按"真实路径"放行是合理的（写出去
       的箱不在监听范围内）；但链接本身在源内，watch 会看到链接节点变化。
       两处入口都比的是解析后的真实路径，因此这里断言解析结果。 */
    const std::string linkAbs = absOf(Path::join(root, "src/in"));
    if (!makeJunction(absOf(Path::join(root, "real_boxes")), linkAbs)) {
        removeTree(root);
        return;    /* 环境没有 python：跳过而不是判失败 */
    }
    EXPECT_FALSE(Path::isSubPath(absOf(Path::join(root, "src")), linkAbs));
    removeTree(root);

    /* 反向：归档目录写成指向 source 的 junction，必须判为包含 */
    removeTree(root);
    Platform::makeDirTree(Path::join(root, "src"));
    const std::string alias = absOf(Path::join(root, "alias"));
    if (!makeJunction(absOf(Path::join(root, "src")), alias)) {
        removeTree(root);
        return;
    }
    EXPECT_TRUE(Path::isSubPath(absOf(Path::join(root, "src")), alias));
    EXPECT_TRUE(Path::isSubPath(alias, absOf(Path::join(root, "src"))));
    removeTree(root);
}
