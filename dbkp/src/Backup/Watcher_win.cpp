/* ============================================================================
 *  Watcher_win.cpp  -- Windows 原生目录监听（ReadDirectoryChangesW）
 *
 *  仅在 _WIN32 下编译（Makefile 过滤），核心逻辑：
 *    1. 用 CreateFileW + FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OVERLAPPED 打开目录
 *       （路径经 Path::apiWide 做 UTF-8->UTF-16 转换，兼容中文/超长路径）
 *    2. 启动后台线程，循环调 ReadDirectoryChangesW（递归=TRUE）
 *    3. 每次完成回调置 m_dirty = true
 *    4. stop() 时 CancelIoEx + join，确保线程安全退出
 * ==========================================================================*/
#include "Backup/Watcher.h"

#if defined(DBKP_OS_WINDOWS)

#include <windows.h>

#include <cstring>
#include <thread>

#include "Utils/PathUtil.h"

namespace DBKP {

struct CDirWatcher::Impl {
    std::thread      worker;
    HANDLE           dirHandle   = INVALID_HANDLE_VALUE;
    HANDLE           ovEvent     = nullptr;
    /* ReadDirectoryChangesW 推荐 >= 4096 字节缓冲 */
    uint8_t          buffer[8192];
};

/* 后台线程主循环：阻塞在 ReadDirectoryChangesW，有变化就置脏 */
static void watchLoop(CDirWatcher* self, CDirWatcher::Impl* impl) {
    /* 通知过滤器：新增/删除/改名/写入/创建/大小变化 */
    const DWORD filter = FILE_NOTIFY_CHANGE_FILE_NAME
                       | FILE_NOTIFY_CHANGE_DIR_NAME
                       | FILE_NOTIFY_CHANGE_LAST_WRITE
                       | FILE_NOTIFY_CHANGE_CREATION
                       | FILE_NOTIFY_CHANGE_SIZE;

    OVERLAPPED ov;

    while (!self->m_stop.load(std::memory_order_relaxed)) {
        ResetEvent(impl->ovEvent);
        std::memset(&ov, 0, sizeof(ov));
        ov.hEvent = impl->ovEvent;

        DWORD bytesReturned = 0;
        BOOL ok = ReadDirectoryChangesW(
            impl->dirHandle,
            impl->buffer,
            static_cast<DWORD>(sizeof(impl->buffer)),
            TRUE,               /* 递归子目录 */
            filter,
            &bytesReturned,
            &ov,
            nullptr);

        if (!ok) {
            DWORD err = GetLastError();
            if (err == ERROR_OPERATION_ABORTED || self->m_stop.load()) break;
            break;  /* 其它错误（如目录被删除），停止 */
        }

        /* 内层等待：轮询事件或检查停止标志 */
        bool aborted = false;
        for (;;) {
            DWORD w = WaitForSingleObject(impl->ovEvent, 200 /* ms */);
            if (w == WAIT_OBJECT_0) break;   /* 操作完成 */
            if (self->m_stop.load(std::memory_order_relaxed)) {
                /* CancelIo 取消当前线程在该 handle 上的所有 pending I/O。
                   因为 ReadDirectoryChangesW 是由本线程发起的，所以 CancelIo 可用。 */
                CancelIo(impl->dirHandle);
                WaitForSingleObject(impl->ovEvent, 2000);
                aborted = true;
                break;
            }
            /* WAIT_TIMEOUT 且未停止：继续等待同一次操作 */
        }
        if (aborted) break;

        /* 获取结果 */
        DWORD transferred = 0;
        if (!GetOverlappedResult(impl->dirHandle, &ov, &transferred, FALSE)) {
            DWORD e2 = GetLastError();
            if (e2 == ERROR_OPERATION_ABORTED) break;
            continue;   /* 非致命错误，重试 */
        }
        if (transferred > 0) {
            self->m_dirty.store(true, std::memory_order_relaxed);
        }
    }
}

ErrCode CDirWatcher::start(const std::string& dir) {
    if (!m_impl) m_impl = new Impl();

    /* 目录必须以 FILE_ACCESS_READ|FILE_LIST_DIRECTORY 方式打开。
       路径统一走 UTF-16 W 系 API：dir 内部是 UTF-8，直接喂 CreateFileA 会被
       按系统 ANSI(GBK) 代码页解释，含中文时得到 ERROR_INVALID_NAME(123)。 */
    const std::wstring wdir = Path::apiWide(dir);
    HANDLE h = CreateFileW(
        wdir.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        nullptr);

    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        char buf[160];
        std::snprintf(buf, sizeof(buf), "CreateFileW(%s) failed, err=%lu", dir.c_str(), err);
        m_error = buf;
        return E_SOURCE_NOT_FOUND;
    }

    m_impl->dirHandle = h;
    m_impl->ovEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!m_impl->ovEvent) {
        CloseHandle(h);
        m_impl->dirHandle = INVALID_HANDLE_VALUE;
        m_error = "CreateEventA failed";
        return E_INTERNAL;
    }

    m_dirty.store(false);
    m_stop.store(false);
    m_native.store(true);

    m_impl->worker = std::thread(watchLoop, this, m_impl);
    return E_OK;
}

void CDirWatcher::stop() {
    m_stop.store(true);
    if (m_impl) {
        /* 等待后台线程自行检测 m_stop 并调用 CancelIo 退出 */
        if (m_impl->worker.joinable()) {
            m_impl->worker.join();
        }
        if (m_impl->ovEvent) { CloseHandle(m_impl->ovEvent); m_impl->ovEvent = nullptr; }
        if (m_impl->dirHandle != INVALID_HANDLE_VALUE) {
            CloseHandle(m_impl->dirHandle);
            m_impl->dirHandle = INVALID_HANDLE_VALUE;
        }
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

#endif /* DBKP_OS_WINDOWS */
