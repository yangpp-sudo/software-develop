/* ============================================================================
 *  JobManager.h  -- 后台作业表：Web 层把"要跑几十秒的备份"交给它，立刻返回
 *
 *  为什么需要：内核（CMyPack/CBackupEngine）是同步阻塞的。HTTP 请求必须马上回，
 *  所以任务丢到工作线程，前端用 GET /api/jobs/:id 或 SSE 轮询状态。
 *  这正是内核加 IProgressSink 的用途：sink 由 CJob 自己实现，进度/取消都在这里。
 *
 *  与内核解耦：submit() 收的是一个 std::function<void(IProgressSink&)>，
 *  JobManager 不知道备份参数长什么样，因此能单独做单元测试（用假任务）。
 * ==========================================================================*/
#ifndef DBKP_WEB_JOBMANAGER_H
#define DBKP_WEB_JOBMANAGER_H

#include "Common/Defs.h"
#include "Common/Progress.h"
#include "Web/Json.h"

#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace DBKP {

class CJobManager {
public:
    enum State { ST_QUEUED = 0, ST_RUNNING = 1, ST_SUCCEEDED = 2, ST_FAILED = 3, ST_CANCELED = 4 };

    /** 作业任务体：sink 由 JobManager 提供，任务必须周期性检查 sink.canceled()；
     *  返回 ErrCode（E_OK 即成功），message 用来放"人类可读的失败原因"，
     *  handler 把内核对象的 lastError() 塞进来即可，不必再复制一套错误表。 */
    typedef std::function<ErrCode(IProgressSink& sink, std::string& message)> Task;

    /** 对外快照：可拷贝，供 handler 序列化，不暴露内部原子量 */
    struct Info {
        long long   id = 0;
        std::string type;              /* backup / restore / pack / unpack / verify */
        std::string label;             /* 用户起的名字，列表里显示 */
        std::string source, target;
        State       state = ST_QUEUED;
        int         code = 0;          /* ErrCode */
        std::string message;
        long long   totalEntries = 0, entriesDone = 0;
        unsigned long long totalBytes = 0, bytesDone = 0;
        long long   createdAt = 0, startedAt = 0, finishedAt = 0;
        std::vector<std::string> log;  /* 最近若干行，见 maxLogLines */
    };

    CJobManager();
    explicit CJobManager(std::size_t workerCount);
    ~CJobManager();

    /** 取消所有运行中的作业并等待线程退出；析构会自动调用。
     *  没有 start()：构造完即可 submit，少一个"忘了启动"的坑。 */
    void stop();

    long long submit(const std::string& type, const std::string& label,
                     const std::string& source, const std::string& target, Task task);

    /** 请求取消：排队中直接标记为 canceled，运行中由内核在下个条目边界退出 */
    bool cancel(long long id);

    bool get(long long id, Info& out) const;
    /** 新->旧排序；limit<=0 表示全部 */
    void list(std::vector<Info>& out, std::size_t limit = 0) const;

    std::size_t count() const;
    unsigned long long revision() const { return m_revision.load(); }

    void setKeepHistory(std::size_t n) { m_keepHistory = n; }
    void setMaxLogLines(std::size_t n) { m_maxLogLines = n; }

    static const char* stateName(State s);
    static CJsonValue toJson(const Info& info, bool withLog);

private:
    class Job : public IProgressSink {
    public:
        Job();
        void onStart(int64_t totalEntries, uint64_t totalBytes) override;
        void onProgress(int64_t entriesDone, uint64_t bytesDone) override;
        bool canceled() const override;

        void addLog(const std::string& line, std::size_t maxLines);
        void snapshot(Info& out) const;

        long long   m_id = 0;
        std::string m_type, m_label, m_source, m_target;
        std::atomic<int>       m_state;
        std::atomic<int>       m_code;
        std::atomic<long long> m_totalEntries, m_entriesDone;
        std::atomic<unsigned long long> m_totalBytes, m_bytesDone;
        std::atomic<long long> m_createdAt, m_startedAt, m_finishedAt;
        std::atomic<bool>      m_cancelReq;
        mutable std::mutex     m_mtx;
        std::deque<std::string> m_log;
        std::string            m_message;
        Task                   m_task;     /* 由 worker 执行；入队时填好 */
        bool                   m_busy = false;  /* 已被某 worker 取走 */
    };

    /* --- 执行体：固定数量 worker 线程从队列取任务 ---
       为什么不用"每作业一线程"：备份是 IO 密集型，几十个线程只会互相抢磁盘；
       限成少量 worker 既能"边备份边跑校验"，又让线程记账简单
       ——构造时创建、stop() 时 join，不会有游离线程。 */
    void workerLoop();
    void pruneLocked();

    mutable std::mutex        m_mtx;               /* const 的 get/list 也要加锁 */
    std::condition_variable m_cv;
    std::deque<std::shared_ptr<Job> > m_pending;   /* 等待执行 */
    std::deque<std::shared_ptr<Job> > m_history;   /* 全部作业（含执行中），旧->新 */
    std::vector<std::thread> m_threads;
    long long   m_nextId = 1;
    std::size_t m_keepHistory = 64;
    std::size_t m_maxLogLines = 200;
    bool        m_accepting = true;                /* stop() 后置 false */
    std::atomic<unsigned long long> m_revision;    /* 状态变化计数，SSE 靠它判新 */

    DBKP_DISALLOW_COPY_AND_ASSIGN(CJobManager);
};

} /* namespace DBKP */

#endif /* DBKP_WEB_JOBMANAGER_H */
