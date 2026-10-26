/* ============================================================================
 *  Logger.h  -- 分级日志（-v/-q 控制），备份工具的"健壮性"证据来源
 * ==========================================================================*/
#ifndef DBKP_UTILS_LOGGER_H
#define DBKP_UTILS_LOGGER_H

#include <functional>
#include <string>

namespace DBKP {

enum LogLevel { LL_QUIET = 0, LL_ERROR = 1, LL_WARN = 2, LL_INFO = 3, LL_DEBUG = 4 };

class Logger {
public:
    static Logger& instance();

    /**
     * 线程级日志接收器：Web/守护进程在任务线程里安装它，把该线程产生的日志
     * 行单独收集到"任务日志环形缓冲"，再由 SSE 推给对应的前端页面。
     * 不安装（或传空）时行为与 CLI 完全一致：写 stdout/stderr。
     * 注意：用 thread_local 而非全局，保证并发任务之间日志不串台。
     */
    using ThreadSink = std::function<void(LogLevel level, const std::string& line)>;
    static void setThreadSink(ThreadSink sink);
    static bool hasThreadSink();

    void setLevel(LogLevel lv) { m_level = lv; }
    void setLevelFromText(const std::string& text);   /* quiet|error|warn|info|debug */
    LogLevel level() const { return m_level; }

    void error(const std::string& msg);
    void warn(const std::string& msg);
    void info(const std::string& msg);
    void debug(const std::string& msg);
    /** 成功/失败计数，供 CLI 汇总与测试断言 */
    void countWarning() { ++m_warnings; }
    void countError()   { ++m_errors; }
    int  warnings() const { return m_warnings; }
    int  errors()   const { return m_errors; }
    void resetCounters() { m_warnings = 0; m_errors = 0; }

private:
    Logger() = default;
    void write(LogLevel lv, const char* tag, const std::string& msg);

    LogLevel m_level = LL_INFO;
    int m_warnings = 0;
    int m_errors = 0;
};

/* 便于书写的宏：LOG_INFO("saved " + p) */
#define LOG_ERR(msg)  DBKP::Logger::instance().error(msg)
#define LOG_WARN(msg) DBKP::Logger::instance().warn(msg)
#define LOG_INFO(msg) DBKP::Logger::instance().info(msg)
#define LOG_DEBUG(msg) DBKP::Logger::instance().debug(msg)

} /* namespace DBKP */

#endif /* DBKP_UTILS_LOGGER_H */
