/* ============================================================================
 *  test_regress_f1.cpp  -- F1 junction 围栏逃逸修复的命名回归测试
 *
 *  背景（整改清单 F1，含连带 F21）：
 *    原 typeFromAttrs() 只识别 IO_REPARSE_TAG_SYMLINK，junction
 *    （IO_REPARSE_TAG_MOUNT_POINT）按 FILE_ATTRIBUTE_DIRECTORY 误判成 FT_DIR，
 *    于是：
 *      - 枚举器把它当普通目录递归下探 → 围栏外数据进箱、指向上级时指数环；
 *      - Web 层 pathWithinRoot() 只做字符串前缀比较，看得见 ".." 看不见链接，
 *        data-root 里放一个指向外部的 junction 就"名正言顺"地钻出去；
 *      - restore 对归档里的 link 目标（F21）任意值照建。
 *
 *  修法（清单四点）：
 *    ① typeFromAttrs 增加 MOUNT_POINT 识别，归入 FT_SYMLINK；
 *    ② 枚举器对 reparse 目录默认不下探，followSymlinks 时以 canonicalPath 查环；
 *    ③ pathWithinRoot 用真实路径（GetFinalPathNameByHandleW/realpath）解析后比较；
 *    ④ restoreEntry 校验 rec.link（拒绝绝对路径与含 ".."）。
 *
 *  这些用例能在旧实现上稳定失败、在新实现上稳定通过。junction 是 NTFS 特性，
 *  全部用例仅在 Windows 侧生效（POSIX 编译期剔除，符合硬约束 #4 的分层）。
 *  创建 junction 用 python _winapi.CreateJunction（硬约束 #8）；删除只删链接
 *  本身（RemoveDirectoryW），绝不递归删除链接目标。
 * ==========================================================================*/
#include "TestFramework.h"

#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "Enumerator/FileEnumerator.h"
#include "Pack/MyPack.h"
#include "Platform/Compat.h"
#include "Platform/FS.h"
#include "Utils/PathUtil.h"
#include "Utils/SimpleFile.h"
#include "Web/Api.h"

using namespace DBKP;

#if defined(DBKP_OS_WINDOWS)

namespace {

/* 把反斜杠换成斜杠：Windows API 接受斜杠，喂给 python 字符串字面量也免转义 */
std::string fwd(const std::string& p) {
    std::string o = p;
    for (size_t i = 0; i < o.size(); ++i) if (o[i] == '\\') o[i] = '/';
    return o;
}

/* python 命令行里喂原生反斜杠路径（raw string），与手工验证方式一致 */
std::string back(const std::string& p) {
    std::string o = p;
    for (size_t i = 0; i < o.size(); ++i) if (o[i] == '/') o[i] = '\\';
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
        "python -c \"import _winapi; _winapi.CreateJunction(r'" + back(targetAbs) +
        "', r'" + back(linkAbs) + "')\" 2>NUL";
    return std::system(cmd.c_str()) == 0;
}

/* 删除 junction 链接本身：os.rmdir 只摘掉重解析点，不碰目标（硬约束 #8）。 */
void removeJunction(const std::string& linkAbs) {
    const std::string cmd =
        "python -c \"import os; os.rmdir(r'" + back(linkAbs) + "')\" 2>NUL";
    std::system(cmd.c_str());
}

/* 递归清理测试树：FT_DIR 下探，FT_SYMLINK（junction）只删链接，普通项删文件。
   关键点：绝不顺着链接进目标删真实数据。 */
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

bool anyPathContains(const std::vector<FileRecord>& recs, const std::string& needle) {
    for (size_t i = 0; i < recs.size(); ++i)
        if (recs[i].path.find(needle) != std::string::npos) return true;
    return false;
}
bool anyPathPrefix(const std::vector<FileRecord>& recs, const std::string& prefix) {
    for (size_t i = 0; i < recs.size(); ++i)
        if (recs[i].path.compare(0, prefix.size(), prefix) == 0) return true;
    return false;
}

} /* anonymous namespace */

/* ① junction 必须被判成 FT_SYMLINK，而不是 FT_DIR —— 这是其余三层修复的地基 */
TEST(RegressF1, junction_classified_as_symlink) {
    const std::string root = "treg_f1_cls";
    removeTree(root);
    Platform::makeDirTree(Path::join(root, "out"));
    writeText(absOf(Path::join(root, "out/secret.txt")), "SENTINEL");
    const std::string linkAbs = absOf(Path::join(root, "j"));
    ASSERT_TRUE(makeJunction(absOf(Path::join(root, "out")), linkAbs));

    Platform::FileInfo fi;
    ASSERT_EQ(Platform::getInfo(Path::join(root, "j"), fi, false), E_OK);
    EXPECT_EQ(fi.type, FT_SYMLINK);          /* 旧实现这里是 FT_DIR */

    /* 跟随链接仍应看到目录本体，供 followSymlinks 分支判定 */
    Platform::FileInfo follow;
    ASSERT_EQ(Platform::getInfo(Path::join(root, "j"), follow, true), E_OK);
    EXPECT_EQ(follow.type, FT_DIR);

    removeTree(root);
}

/* ② 默认备份绝不穿过 junction 把围栏外文件装进箱 */
TEST(RegressF1, backup_does_not_pack_outside) {
    const std::string root = "treg_f1_bkp";
    removeTree(root);
    Platform::makeDirTree(Path::join(root, "src"));
    Platform::makeDirTree(Path::join(root, "out"));
    writeText(absOf(Path::join(root, "src/normal.txt")), "inside the fence");
    writeText(absOf(Path::join(root, "out/secret.txt")), "OUTSIDE-FENCE-9999");
    ASSERT_TRUE(makeJunction(absOf(Path::join(root, "out")),
                             absOf(Path::join(root, "src/j"))));

    CMyPack packer;
    PackOptions po;
    ASSERT_EQ(packer.pack(Path::join(root, "src"), "treg_f1_bkp.dbkp", po), E_OK);

    std::vector<FileRecord> recs;
    ASSERT_EQ(packer.list("treg_f1_bkp.dbkp", recs), E_OK);
    /* 箱内正常文件在，围栏外哨兵绝不在 */
    EXPECT_TRUE(anyPathContains(recs, "normal.txt"));
    EXPECT_FALSE(anyPathContains(recs, "secret.txt"));
    EXPECT_FALSE(anyPathPrefix(recs, "j/"));   /* 未把 junction 当目录递归进去 */

    Platform::removeFile("treg_f1_bkp.dbkp");
    removeTree(root);
}

/* ② junction 指向上级目录构成环时，枚举必须在有限条目内收敛，不再指数递归 */
TEST(RegressF1, junction_loop_terminates) {
    const std::string root = "treg_f1_loop";
    removeTree(root);
    Platform::makeDirTree(Path::join(root, "src"));
    writeText(absOf(Path::join(root, "src/a.txt")), "a");
    /* src/self -> src 自身，形成回环 */
    ASSERT_TRUE(makeJunction(absOf(Path::join(root, "src")),
                             absOf(Path::join(root, "src/self"))));

    CFileEnumerator en;
    FilterOptions f;
    f.followSymlinks = true;                  /* 即便主动跟随，也要被环检测拦下 */
    std::vector<EnumeratedEntry> out;
    ASSERT_EQ(en.enumerateFiles(Path::join(root, "src"), f, out), E_OK);

    /* 旧实现：判成 FT_DIR 无限下探到 32767 字符路径上限才侥幸停；
       新实现：canonicalPath 命中 visitedDirs → 跳过，条目数极小。 */
    EXPECT_TRUE(out.size() < 50u);
    EXPECT_TRUE(en.skipped() >= 1);

    removeTree(root);
}

/* ③ pathWithinRoot：data-root 内的 junction 指向外部时，真实路径解析必须拒绝 */
TEST(RegressF1, path_within_root_blocks_junction_escape) {
    const std::string root = "treg_f1_pwr";
    removeTree(root);
    Platform::makeDirTree(Path::join(root, "data"));
    Platform::makeDirTree(Path::join(root, "outside"));
    writeText(absOf(Path::join(root, "outside/secret.txt")), "SECRET");
    ASSERT_TRUE(makeJunction(absOf(Path::join(root, "outside")),
                             absOf(Path::join(root, "data/evil"))));

    const std::string dataRoot = absOf(Path::join(root, "data"));
    std::string out;

    /* 控制组：字符串越界（..）本就应被拒 */
    EXPECT_FALSE(pathWithinRoot(dataRoot, "../x", out));
    EXPECT_FALSE(pathWithinRoot(dataRoot, "../../Windows", out));
    /* 根内正常子目录仍放行 */
    EXPECT_TRUE(pathWithinRoot(dataRoot, ".", out));

    /* 关键：evil 字符串上在根内，真实位置在根外——必须 403 */
    EXPECT_FALSE(pathWithinRoot(dataRoot, "evil", out));
    EXPECT_FALSE(pathWithinRoot(dataRoot, "evil/secret.txt", out));

    removeTree(root);
}

/* ④（F21）restore 拒绝绝对路径 / 含 ".." 的 link 目标，绝不写出目标目录之外 */
TEST(RegressF1, restore_refuses_escaping_link) {
    const std::string root = "treg_f1_f21";
    removeTree(root);
    Platform::makeDirTree(Path::join(root, "src"));
    Platform::makeDirTree(Path::join(root, "out"));
    writeText(absOf(Path::join(root, "out/secret.txt")), "F21-SENTINEL");
    /* src/j 是指向 out 的 junction，打包后 rec.link 是绝对路径 */
    ASSERT_TRUE(makeJunction(absOf(Path::join(root, "out")),
                             absOf(Path::join(root, "src/j"))));

    CMyPack packer;
    PackOptions po;
    ASSERT_EQ(packer.pack(Path::join(root, "src"), "treg_f1_f21.dbkp", po), E_OK);

    UnpackOptions uo;
    const ErrCode rc = packer.unpack("treg_f1_f21.dbkp",
                                     Path::join(root, "rd"), uo);
    /* 绝对 link 被 F21 校验拒绝：整卷还原报错。同时兜底确认哨兵文件
       无论以何种路径（rd/secret.txt 或 rd/j/secret.txt）都没落到目标目录里。 */
    Platform::FileInfo probe;
    const bool leaked =
        (Platform::getInfo(Path::join(root, "rd/secret.txt"), probe, true) == E_OK) ||
        (Platform::getInfo(Path::join(root, "rd/j/secret.txt"), probe, true) == E_OK);
    EXPECT_TRUE(DBKP_IS_ERR(rc));
    EXPECT_FALSE(leaked);

    Platform::removeFile("treg_f1_f21.dbkp");
    removeTree(root);
}

#endif /* DBKP_OS_WINDOWS */
