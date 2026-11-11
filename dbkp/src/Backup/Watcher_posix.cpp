/* ============================================================================
 *  Watcher_posix.cpp  -- POSIX 降级实现（周期性签名扫描）
 *
 *  没有 inotify 的简化处理：每 intervalMs 递归遍历目录树，收集
 *  (path, size, mtime) 三元组作为"签名快照"；若两次快照不同则置脏。
 *  语义等价、跨平台可用；事件驱动时延退化为轮询周期。
 * ==========================================================================*/
#include "Backup/Watcher.h"

#if !defined(DBKP_OS_WINDOWS)

#include <algorithm>
#include <chrono>
#include <cstring>
#include <ctime>
#include <functional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

namespace DBKP {

/* 签名：path -> (size, mtime)；任何新/删/改/重命名都会导致差异 */
using Snapshot = std::unordered_map<std::string, std::pair<int64_t, int64_t>>;

static void scanTree(const std::string& root, Snapshot& out) {
    DIR* d = opendir(root.c_str());
    if (!d) return;
    struct dirent* ent;
    while ((ent = readdir(d)) != nullptr) {
        if (std::strcmp(ent->d_name, ".") == 0 || std::strcmp(ent->d_name, "..") == 0)
            continue;
        std::string full = root + "/" + ent->d_name;
        struct stat st;
        if (lstat(full.c_str(), &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            scanTree(full, out);
        } else {
            out[full] = { static_cast<int64_t>(st.st_size),
                          static_cast<int64_t>(st.st_mtime) };
        }
    }
    closedir(d);
}

struct CDirWatcher::Impl {
    std::thread worker;
    std::string watchDir;
    int         intervalMs = 1000;
};

static void pollLoop(CDirWatcher* self, CDirWatcher::Impl* impl) {
    Snapshot prev;
    scanTree(impl->watchDir, prev);

    while (!self->m_stop.load(std::memory_order_relaxed)) {
        /* 分段 sleep 以便快速响应停止 */
        int slept = 0;
        while (slept < impl->intervalMs && !self->m_stop.load(std::memory_order_relaxed)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            slept += 100;
        }
        if (self->m_stop.load(std::memory_order_relaxed)) break;

        Snapshot curr;
        scanTree(impl->watchDir, curr);
        if (curr != prev) {
            self->m_dirty.store(true, std::memory_order_relaxed);
            prev = std::move(curr);
        }
    }
}

ErrCode CDirWatcher::start(const std::string& dir) {
    if (!m_impl) m_impl = new Impl();
    /* 验证目录存在 */
    struct stat st;
    if (stat(dir.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
        m_error = "watch dir not found: " + dir;
        return E_SOURCE_NOT_FOUND;
    }
    m_impl->watchDir = dir;
    m_dirty.store(false);
    m_stop.store(false);
    m_native.store(false);  /* 轮询模式 */
    m_impl->worker = std::thread(pollLoop, this, m_impl);
    return E_OK;
}

void CDirWatcher::stop() {
    m_stop.store(true);
    if (m_impl && m_impl->worker.joinable()) {
        m_impl->worker.join();
    }
    m_native.store(false);
}

bool CDirWatcher::takeDirty() {
    bool expected = true;
    return m_dirty.compare_exchange_strong(expected, false, std::memory_order_acq_rel);
}

CDirWatcher::CDirWatcher() : m_impl(nullptr) {}

CDirWatcher::~CDirWatcher() {
    stop();
    delete m_impl;
    m_impl = nullptr;
}

} /* namespace DBKP */

#endif /* !DBKP_OS_WINDOWS */
