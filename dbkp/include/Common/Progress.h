/* ============================================================================
 *  Progress.h  -- 备份/还原过程的进度与取消回调
 *
 *  为什么需要它：内核（CMyPack/CBackupEngine）原本是同步阻塞的，CLI 直接打印
 *  日志就能表达进度；但 Web/守护进程场景必须：
 *    1) 把"已完成条目数 / 已处理字节数"实时推给前端（SSE 进度条）
 *    2) 允许用户中途取消（前端点"取消"-> 服务端置位 -> 内核在下一个个点退出）
 *  因此这里只定义一个**纯抽象接口**，内核不依赖任何网络代码，默认 nullptr
 *  时行为与原来完全一致（CLI 与 92 项单测不受影响）。
 * ==========================================================================*/
#ifndef DBKP_COMMON_PROGRESS_H
#define DBKP_COMMON_PROGRESS_H

#include <cstdint>

#include "Platform/Compat.h"

namespace DBKP {

class IProgressSink {
public:
    IProgressSink() = default;
    virtual ~IProgressSink() = default;

    /** 枚举完成、即将开始读写时调用一次（totalEntries/totalBytes 可能为 0） */
    virtual void onStart(int64_t totalEntries, uint64_t totalBytes) {
        DBKP_UNUSED(totalEntries); DBKP_UNUSED(totalBytes);
    }
    /** 每处理完一个条目调用一次；bytesDone 为**明文**累计字节 */
    virtual void onProgress(int64_t entriesDone, uint64_t bytesDone) {
        DBKP_UNUSED(entriesDone); DBKP_UNUSED(bytesDone);
    }
    /** 返回 true 时内核在当前条目边界安全退出并回滚（删除半成品归档） */
    virtual bool canceled() const { return false; }

private:
    DBKP_DISALLOW_COPY_AND_ASSIGN(IProgressSink);
};

} /* namespace DBKP */

#endif /* DBKP_COMMON_PROGRESS_H */
