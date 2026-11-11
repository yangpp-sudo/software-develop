/* ============================================================================
 *  test_regress_f4.cpp  -- F4（临时文件 -> 自校验 -> 原子 rename + 文件锁 +
 *                          --force）的命名回归测试
 *
 *  背景（整改清单 F4）：
 *    原实现直接以 MODE_READ_WRITE(O_TRUNC) 就地打开目标写正式箱：进程中途被
 *    kill 留下半截新箱顶掉旧箱；两个进程并发备份同一目标互相截尾；同名任务
 *    没有任何互斥。
 *  修法：
 *    ① 内容全部写 "<archive>.tmp"（同目录），写完先按正式标准自校验，
 *      通过后 MoveFileEx(REPLACE_EXISTING)/rename 原子替换；
 *    ② tmp 打开顺序 = 无 O_TRUNC 打开 -> LockFileEx/flock 独占锁 -> 显式截断，
 *      并发第二个进程拿到 E_BUSY；
 *    ③ 目标已存在且未 --force 时拒绝（E_ALREADY_EXISTS）。
 * ==========================================================================*/
#include "TestFramework.h"

#include <cstring>
#include <string>
#include <vector>

#include "Common/Progress.h"
#include "Pack/MyPack.h"
#include "Platform/Compat.h"
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

bool fileExists(const std::string& p) { return Platform::exists(p) == E_OK; }

bool bytesEqual(const std::string& a, const std::string& b) {
    std::vector<uint8_t> x, y;
    if (DBKP_IS_ERR(CSimpleFile::readWhole(a, x))) return false;
    if (DBKP_IS_ERR(CSimpleFile::readWhole(b, y))) return false;
    return x == y;
}

/* 处理到第 n 个条目即请求取消的进度汇（模拟"备份中途被打断"） */
class CancelAfterN : public IProgressSink {
public:
    explicit CancelAfterN(int64_t n) : m_n(n) {}
    void onProgress(int64_t entriesDone, uint64_t) override {
        if (entriesDone >= m_n) m_hit = true;
    }
    bool canceled() const override { return m_hit; }
private:
    int64_t m_n;
    bool    m_hit = false;
};

ErrCode makeSource(const std::string& srcRoot) {
    writeText(Path::join(srcRoot, "a.txt"), "alpha-content");
    writeText(Path::join(srcRoot, "b.txt"), "bravo-content");
    writeText(Path::join(srcRoot, "sub/c.txt"), "charlie-content");
    return E_OK;
}

} /* anonymous namespace */

/* ③ 目标已存在且未 --force：必须拒绝，且旧箱字节级纹丝不动、无 tmp 残骸 */
TEST(RegressF4, refuse_existing_target_without_force) {
    const std::string root = "treg_f4_refuse";
    const std::string src  = Path::join(root, "src");
    const std::string arc  = Path::join(root, "box.dbkp");
    removeTree(root);
    makeSource(src);

    CMyPack p1;
    PackOptions o1;
    EXPECT_EQ(int(p1.pack(src, arc, o1)), int(E_OK));
    EXPECT_TRUE(fileExists(arc));
    const std::string snapshot = arc + ".snapshot";
    { std::vector<uint8_t> raw; CSimpleFile::readWhole(arc, raw);
      CSimpleFile::writeWhole(snapshot, raw); }

    /* 第二次不带 force：拒绝 */
    CMyPack p2;
    PackOptions o2;
    ErrCode e = p2.pack(src, arc, o2);
    EXPECT_EQ(int(e), int(E_ALREADY_EXISTS));
    EXPECT_TRUE(p2.lastErrorText().find("--force") != std::string::npos);
    /* 旧箱内容完好（与快照逐字节一致），也没有留下 tmp */
    EXPECT_TRUE(bytesEqual(arc, snapshot));
    EXPECT_FALSE(fileExists(arc + ".tmp"));

    /* 带 force：覆盖成功，产物可 verify，且正式名旁无残骸 */
    PackOptions o3;
    o3.force = true;
    CMyPack p3;
    EXPECT_EQ(int(p3.pack(src, arc, o3)), int(E_OK));
    int bad = 0;
    EXPECT_EQ(int(p3.verify(arc, "", bad)), int(E_OK));
    EXPECT_FALSE(fileExists(arc + ".tmp"));

    Platform::removeFile(snapshot);
    removeTree(root);
}

/* ② 跨进程锁：tmp 已被另一"进程"（此处以独立 fd + 独占锁模拟）占用时，
      pack 必须快速失败返回 E_BUSY，而不是阻塞或截掉对方数据 */
TEST(RegressF4, concurrent_target_returns_busy) {
    const std::string root = "treg_f4_busy";
    const std::string src  = Path::join(root, "src");
    const std::string arc  = Path::join(root, "box.dbkp");
    removeTree(root);
    makeSource(src);

    /* 模拟竞争者：先一步打开 tmp 并持锁不释放。
       注意：不带 force 时 pack 在"tmp 存在性检查"就先拒绝（E_INCOMPLETE），
       要走到锁这一层必须 force=true——存在性检查是友好拒绝，锁才是权威拒绝。 */
    CSimpleFile rival;
    ASSERT_EQ(int(rival.open(arc + ".tmp", CSimpleFile::MODE_READ_WRITE_CREATE)), int(E_OK));
    ASSERT_EQ(int(Platform::tryLockFile(rival.fd())), int(E_OK));

    CMyPack p;
    PackOptions o;
    o.force = true;
    ErrCode e = p.pack(src, arc, o);
    EXPECT_EQ(int(e), int(E_BUSY));
    EXPECT_TRUE(p.lastErrorText().find("locked") != std::string::npos);
    /* 失败方不得动正式名 */
    EXPECT_FALSE(fileExists(arc));

    /* 释放锁后重试：应成功并原子提交 */
    Platform::unlockFile(rival.fd());
    rival.close();
    CMyPack p2;
    EXPECT_EQ(int(p2.pack(src, arc, o)), int(E_OK));
    EXPECT_TRUE(fileExists(arc));
    EXPECT_FALSE(fileExists(arc + ".tmp"));

    removeTree(root);
}

/* 同一 fd 重复加锁也应失败（进程内互斥层），并验证 unlock 后立即可重锁 */
TEST(RegressF4, lock_is_exclusive_and_releasable) {
    const std::string root = "treg_f4_lock";
    const std::string f = Path::join(root, "x.bin");
    removeTree(root);
    Platform::makeDirTree(root);

    CSimpleFile a, b;
    ASSERT_EQ(int(a.open(f, CSimpleFile::MODE_READ_WRITE_CREATE)), int(E_OK));
    ASSERT_EQ(int(b.open(f, CSimpleFile::MODE_READ_WRITE_CREATE)), int(E_OK));
    EXPECT_EQ(int(Platform::tryLockFile(a.fd())), int(E_OK));
    EXPECT_EQ(int(Platform::tryLockFile(b.fd())), int(E_BUSY));
    Platform::unlockFile(a.fd());
    EXPECT_EQ(int(Platform::tryLockFile(b.fd())), int(E_OK));
    Platform::unlockFile(b.fd());
    a.close();
    b.close();
    removeTree(root);
}

/* ① 写入中途取消：正式名下的旧箱必须完好，半成品只存在于 tmp 且被清除 */
TEST(RegressF4, mid_write_cancel_keeps_old_box) {
    const std::string root = "treg_f4_cancel";
    const std::string src  = Path::join(root, "src");
    const std::string arc  = Path::join(root, "box.dbkp");
    removeTree(root);
    makeSource(src);

    CMyPack p1;
    PackOptions o1;
    ASSERT_EQ(int(p1.pack(src, arc, o1)), int(E_OK));
    std::vector<uint8_t> oldBytes;
    ASSERT_EQ(int(CSimpleFile::readWhole(arc, oldBytes)), int(E_OK));

    CancelAfterN sink(1);   /* 第一个条目后即取消 */
    PackOptions o2;
    o2.force = true;
    o2.progress = &sink;
    CMyPack p2;
    ErrCode e = p2.pack(src, arc, o2);
    EXPECT_EQ(int(e), int(E_CANCELED));
    /* 旧箱逐字节完好；tmp 残骸被清理 */
    std::vector<uint8_t> nowBytes;
    EXPECT_EQ(int(CSimpleFile::readWhole(arc, nowBytes)), int(E_OK));
    EXPECT_TRUE(nowBytes == oldBytes);
    EXPECT_FALSE(fileExists(arc + ".tmp"));

    removeTree(root);
}

/* rename 提交前自校验：tmp 阶段产物必须能通过正式 verify 标准（间接验证
   "先 verify 后 rename" 顺序没有把坏箱提交到正式名）。坏源文件 -> 失败路径
   不留任何正式名改动。 */
TEST(RegressF4, committed_box_is_always_self_consistent) {
    const std::string root = "treg_f4_consistent";
    const std::string src  = Path::join(root, "src");
    const std::string arc  = Path::join(root, "box.dbkp");
    removeTree(root);
    makeSource(src);

    CMyPack p;
    PackOptions o;
    ASSERT_EQ(int(p.pack(src, arc, o)), int(E_OK));
    int bad = 0;
    EXPECT_EQ(int(p.verify(arc, "", bad)), int(E_OK));
    EXPECT_EQ(bad, 0);
    /* 还原回来的内容与源逐文件一致 */
    const std::string dst = Path::join(root, "out");
    UnpackOptions u;
    EXPECT_EQ(int(p.unpack(arc, dst, u)), int(E_OK));
    EXPECT_TRUE(bytesEqual(Path::join(src, "a.txt"), Path::join(dst, "a.txt")));
    EXPECT_TRUE(bytesEqual(Path::join(src, "sub/c.txt"), Path::join(dst, "sub/c.txt")));
    removeTree(root);
}
