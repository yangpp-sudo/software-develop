/* ============================================================================
 *  Watcher.h  -- 目录变化监听（扩展项：实时备份 15 分，"自动感知用户文件变化"）
 *
 *  设计取向：只做一件事——告诉调用方"从上次检查到现在，被监听目录树里是否
 *  发生过新增/删除/改名/写入"。用「后台线程置脏标记 + 主线程 takeDirty 取走」
 *  的模型，把"感知"与"触发备份"解耦：
 *    - Windows 走原生 ReadDirectoryChangesW（递归子树，事件驱动、几乎零轮询开销）；
 *    - 其它平台降级为周期性递归签名扫描（size+mtime），语义等价、跨平台可用。
 *  去抖（debounce）留给上层：一次改动往往连着好几条通知，攒一会儿再备一次，
 *  避免编辑器保存、下载完成这类连续动作把备份刷爆。
 * ==========================================================================*/
#ifndef DBKP_BACKUP_WATCHER_H
#define DBKP_BACKUP_WATCHER_H

#include <atomic>
#include <string>

#include "Common/Defs.h"

namespace DBKP {

class CDirWatcher {
public:
    CDirWatcher();
    ~CDirWatcher();

    CDirWatcher(const CDirWatcher&) = delete;
    CDirWatcher& operator=(const CDirWatcher&) = delete;

    /** 开始监听 dir（递归）。失败返回明确错误码，不抛异常。 */
    ErrCode start(const std::string& dir);

    /** 停止后台线程并回收资源，可安全多次调用。 */
    void stop();

    /** 取走"是否变脏"：有变化返回 true 并清零；否则 false。主线程轮询用。 */
    bool takeDirty();

    /** 原生（事件驱动）监听是否生效。false 表示当前走的是轮询降级实现。 */
    bool nativeEventDriven() const { return m_native; }

    const std::string& lastError() const { return m_error; }

    /* 后台线程访问：置脏/检查停止标志 —— 设计上只供 Impl 内部线程使用，
       标 public 是为了避免友元声明散落在平台实现中，课程项目简化。 */
    std::atomic<bool> m_dirty;
    std::atomic<bool> m_stop;

    struct Impl;            /* 平台相关状态（线程/handle/缓冲），藏在 .cpp */
    Impl* m_impl;

private:
    std::atomic<bool> m_native;
    std::string m_error;
};

} /* namespace DBKP */

#endif /* DBKP_BACKUP_WATCHER_H */
