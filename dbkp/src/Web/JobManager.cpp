/* ============================================================================
 *  JobManager.cpp  -- 见 JobManager.h
 * ==========================================================================*/
#include "Web/JobManager.h"

#include "Common/Defs.h"
#include "Utils/Logger.h"

#include <chrono>

namespace DBKP {

namespace {

long long nowSec() {
    return static_cast<long long>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

std::string formatLogLine(LogLevel lv, const std::string& line) {
    const char* tag = "info";
    switch (lv) {
    case LL_ERROR: tag = "error"; break;
    case LL_WARN:  tag = "warn";  break;
    case LL_DEBUG: tag = "debug"; break;
    default: break;
    }
    return std::string(tag) + ": " + line;
}

} /* anonymous namespace */

/* ------------------------------------------------------------------ Job */
CJobManager::Job::Job()
    : m_state(ST_QUEUED), m_code(0), m_totalEntries(0), m_entriesDone(0),
      m_totalBytes(0), m_bytesDone(0), m_createdAt(0), m_startedAt(0),
      m_finishedAt(0), m_cancelReq(false) {}

void CJobManager::Job::onStart(int64_t totalEntries, uint64_t totalBytes) {
    m_totalEntries.store(static_cast<long long>(totalEntries));
    m_totalBytes.store(totalBytes);
}

void CJobManager::Job::onProgress(int64_t entriesDone, uint64_t bytesDone) {
    m_entriesDone.store(static_cast<long long>(entriesDone));
    m_bytesDone.store(bytesDone);
}

bool CJobManager::Job::canceled() const {
    return m_cancelReq.load();
}

void CJobManager::Job::addLog(const std::string& line, std::size_t maxLines) {
    std::lock_guard<std::mutex> lk(m_mtx);
    m_log.push_back(line);
    /* 环形缓冲：长任务打几上万行日志时，前端只需要最近这些，
       但内存必须是有界的（否则跑一整夜的定时备份会把进程吃爆）。 */
    while (m_log.size() > maxLines) m_log.pop_front();
}

void CJobManager::Job::snapshot(Info& out) const {
    out.id = m_id;
    out.type = m_type;
    out.label = m_label;
    out.source = m_source;
    out.target = m_target;
    out.state = static_cast<State>(m_state.load());
    out.code = m_code.load();
    out.totalEntries = m_totalEntries.load();
    out.entriesDone = m_entriesDone.load();
    out.totalBytes = m_totalBytes.load();
    out.bytesDone = m_bytesDone.load();
    out.createdAt = m_createdAt.load();
    out.startedAt = m_startedAt.load();
    out.finishedAt = m_finishedAt.load();
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        out.message = m_message;
        out.log.assign(m_log.begin(), m_log.end());
    }
}

/* -------------------------------------------------------------- 生命周期 */
CJobManager::CJobManager() : CJobManager(2) {}

CJobManager::CJobManager(std::size_t workerCount) {
    m_revision.store(0);
    if (workerCount < 1) workerCount = 1;
    if (workerCount > 8) workerCount = 8;      /* 再多也只是抢磁盘 */
    for (std::size_t i = 0; i < workerCount; ++i)
        m_threads.push_back(std::thread(&CJobManager::workerLoop, this));
}

CJobManager::~CJobManager() { stop(); }

void CJobManager::stop() {
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        if (!m_accepting) return;              /* 幂等：析构可能再次调用 */
        m_accepting = false;
        /* 排队中的直接标记取消，不必再执行；运行中的置 cancelReq 让内核收尾，
           这样半成品归档会被删除，不会留下一个"看起来成功"的坏包。 */
        for (std::size_t i = 0; i < m_pending.size(); ++i) {
            Job& j = *m_pending[i];
            if (j.m_state.load() == ST_QUEUED) {
                j.m_cancelReq.store(true);
                j.m_state.store(ST_CANCELED);
                j.m_code.store(E_CANCELED);
                j.m_finishedAt.store(nowSec());
                std::lock_guard<std::mutex> lk2(j.m_mtx);
                j.m_message = "服务停止，任务未执行";
            }
        }
    }
    m_cv.notify_all();
    for (std::size_t i = 0; i < m_threads.size(); ++i)
        if (m_threads[i].joinable()) m_threads[i].join();
    m_threads.clear();
}

/* ------------------------------------------------------------------ 提交 */
long long CJobManager::submit(const std::string& type, const std::string& label,
                              const std::string& source, const std::string& target,
                              Task task) {
    std::shared_ptr<Job> job(new Job());
    job->m_type = type;
    job->m_label = label;
    job->m_source = source;
    job->m_target = target;
    job->m_createdAt.store(nowSec());
    job->m_task = task;

    std::lock_guard<std::mutex> lk(m_mtx);
    if (!m_accepting) return -1;
    job->m_id = m_nextId++;
    m_pending.push_back(job);
    m_history.push_back(job);
    pruneLocked();
    m_revision.fetch_add(1);
    m_cv.notify_one();
    return job->m_id;
}

/* ------------------------------------------------------------ worker 循环 */
void CJobManager::workerLoop() {
    for (;;) {
        std::shared_ptr<Job> job;
        {
            std::unique_lock<std::mutex> lk(m_mtx);
            m_cv.wait(lk, [this] { return !m_pending.empty() || !m_accepting; });
            if (!m_accepting && m_pending.empty()) return;   /* 收尾退出 */
            job = m_pending.front();
            m_pending.pop_front();
        }
        if (!job) continue;
        if (job->m_state.load() == ST_CANCELED) { m_revision.fetch_add(1); continue; }

        job->m_startedAt.store(nowSec());
        job->m_state.store(ST_RUNNING);
        m_revision.fetch_add(1);

        /* 本线程产生的日志只进这个 job 的环形缓冲：并发任务互不串台，
           靠的是 Logger 里的 thread_local sink，而不是全局状态。 */
        const std::size_t maxLines = m_maxLogLines;
        Logger::setThreadSink([job, maxLines](LogLevel lv, const std::string& line) {
            job->addLog(formatLogLine(lv, line), maxLines);
        });

        ErrCode code = E_INTERNAL;
        std::string message;
        try {
            if (job->m_task) code = job->m_task(*job, message);
            else message = "内部错误：任务体为空";
        } catch (const std::exception& e) {
            code = E_INTERNAL;
            message = std::string("任务抛出异常：") + e.what();
        } catch (...) {
            code = E_INTERNAL;
            message = "任务抛出未知异常";
        }
        Logger::setThreadSink(Logger::ThreadSink());   /* 线程复用前必须清掉 */

        if (job->m_cancelReq.load() || code == E_CANCELED) {
            job->m_state.store(ST_CANCELED);
            job->m_code.store(E_CANCELED);
            if (message.empty()) message = "任务已取消";
        } else if (code == E_OK) {
            job->m_state.store(ST_SUCCEEDED);
            job->m_code.store(E_OK);
            if (message.empty()) message = "完成";
        } else {
            job->m_state.store(ST_FAILED);
            job->m_code.store(static_cast<int>(code));
            if (message.empty()) message = errCodeToString(code);
        }
        {
            std::lock_guard<std::mutex> lk(job->m_mtx);
            job->m_message = message;
        }
        job->m_finishedAt.store(nowSec());
        m_revision.fetch_add(1);

        {
            std::lock_guard<std::mutex> lk(m_mtx);
            pruneLocked();      /* 定时备份跑一整夜也不会把内存单调吃掉 */
        }
    }
}

void CJobManager::pruneLocked() {
    while (m_history.size() > m_keepHistory) {
        const int st = m_history.front()->m_state.load();
        if (st == ST_QUEUED || st == ST_RUNNING) {
            /* 队首还在执行时先删后面第一个已结束的，保持"旧的先出门" */
            bool erased = false;
            for (std::size_t i = 1; i < m_history.size(); ++i) {
                const int s2 = m_history[i]->m_state.load();
                if (s2 != ST_QUEUED && s2 != ST_RUNNING) {
                    m_history.erase(m_history.begin() + static_cast<std::ptrdiff_t>(i));
                    erased = true;
                    break;
                }
            }
            if (!erased) return;                /* 全都在跑：等下一轮 */
        } else {
            m_history.pop_front();
        }
    }
}

/* --------------------------------------------------------------- 查询/控制 */
bool CJobManager::cancel(long long id) {
    std::lock_guard<std::mutex> lk(m_mtx);
    for (std::size_t i = 0; i < m_history.size(); ++i) {
        if (m_history[i]->m_id != id) continue;
        Job& j = *m_history[i];
        const int st = j.m_state.load();
        if (st != ST_QUEUED && st != ST_RUNNING) return false;   /* 已结束的取消不了 */
        j.m_cancelReq.store(true);
        if (st == ST_QUEUED) {
            /* 还没开始，直接终态；worker 之后取到它会跳过 */
            j.m_state.store(ST_CANCELED);
            j.m_code.store(E_CANCELED);
            j.m_finishedAt.store(nowSec());
            std::lock_guard<std::mutex> lk2(j.m_mtx);
            j.m_message = "已在排队阶段取消";
        }
        m_revision.fetch_add(1);
        return true;
    }
    return false;
}

bool CJobManager::get(long long id, Info& out) const {
    std::shared_ptr<Job> found;
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        for (std::size_t i = 0; i < m_history.size(); ++i)
            if (m_history[i]->m_id == id) { found = m_history[i]; break; }
    }
    if (!found) return false;
    found->snapshot(out);
    return true;
}

void CJobManager::list(std::vector<Info>& out, std::size_t limit) const {
    std::vector<std::shared_ptr<Job> > snap;
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        snap.assign(m_history.begin(), m_history.end());
    }
    /* 新->旧：前端列表最想先看正在跑/刚跑完的那个 */
    for (std::size_t i = snap.size(); i > 0; --i) {
        if (limit && out.size() >= limit) break;
        Info info;
        snap[i - 1]->snapshot(info);
        out.push_back(info);
    }
}

std::size_t CJobManager::count() const {
    std::lock_guard<std::mutex> lk(m_mtx);
    return m_history.size();
}

const char* CJobManager::stateName(State s) {
    switch (s) {
    case ST_QUEUED:    return "queued";
    case ST_RUNNING:   return "running";
    case ST_SUCCEEDED: return "succeeded";
    case ST_FAILED:    return "failed";
    case ST_CANCELED:  return "canceled";
    }
    return "unknown";
}

CJsonValue CJobManager::toJson(const Info& info, bool withLog) {
    CJsonValue o = CJsonValue::makeObject();
    o["id"]     = CJsonValue::makeInt(info.id);
    o["type"]   = CJsonValue::makeString(info.type);
    o["label"]  = CJsonValue::makeString(info.label);
    o["source"] = CJsonValue::makeString(info.source);
    o["target"] = CJsonValue::makeString(info.target);
    o["state"]  = CJsonValue::makeString(stateName(info.state));
    o["code"]   = CJsonValue::makeInt(info.code);
    o["codeText"] = CJsonValue::makeString(errCodeToString(static_cast<ErrCode>(info.code)));
    o["message"] = CJsonValue::makeString(info.message);
    o["totalEntries"] = CJsonValue::makeInt(info.totalEntries);
    o["entriesDone"]  = CJsonValue::makeInt(info.entriesDone);
    o["totalBytes"]   = CJsonValue::makeInt(static_cast<int64_t>(info.totalBytes));
    o["bytesDone"]    = CJsonValue::makeInt(static_cast<int64_t>(info.bytesDone));
    o["createdAt"] = CJsonValue::makeInt(info.createdAt);
    o["startedAt"] = CJsonValue::makeInt(info.startedAt);
    o["finishedAt"] = CJsonValue::makeInt(info.finishedAt);

    double ratio = 0.0;
    if (info.totalEntries > 0) ratio = static_cast<double>(info.entriesDone) / static_cast<double>(info.totalEntries);
    else if (info.totalBytes > 0) ratio = static_cast<double>(info.bytesDone) / static_cast<double>(info.totalBytes);
    if (info.state == ST_SUCCEEDED) ratio = 1.0;         /* 内核可能少报最后一条 */
    if (ratio < 0) ratio = 0;
    if (ratio > 1) ratio = 1;
    o["ratio"] = CJsonValue::makeDouble(ratio);

    if (withLog) {
        CJsonValue arr = CJsonValue::makeArray();
        for (std::size_t i = 0; i < info.log.size(); ++i)
            arr.push_back(CJsonValue::makeString(info.log[i]));
        o["log"] = arr;
    }
    return o;
}

} /* namespace DBKP */
