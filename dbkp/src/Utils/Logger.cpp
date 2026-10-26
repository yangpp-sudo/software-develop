/* ============================================================================
 *  Logger.cpp
 * ==========================================================================*/
#include "Utils/Logger.h"

#include <cstdio>
#include <cstring>
#include <ctime>
#include <utility>
#if defined(DBKP_OS_WINDOWS)
#define dbkp_strcasecmp _stricmp
#else
#include <strings.h>
#define dbkp_strcasecmp strcasecmp
#endif

namespace DBKP {

Logger& Logger::instance() {
    static Logger s_logger;
    return s_logger;
}

void Logger::setLevelFromText(const std::string& text) {
    if (!dbkp_strcasecmp(text.c_str(), "quiet"))      m_level = LL_QUIET;
    else if (!dbkp_strcasecmp(text.c_str(), "error")) m_level = LL_ERROR;
    else if (!dbkp_strcasecmp(text.c_str(), "warn"))  m_level = LL_WARN;
    else if (!dbkp_strcasecmp(text.c_str(), "info"))  m_level = LL_INFO;
    else if (!dbkp_strcasecmp(text.c_str(), "debug")) m_level = LL_DEBUG;
    else m_level = LL_INFO;
}

namespace {
/* 每个线程独立的日志接收器：并发备份任务之间不会串台 */
thread_local Logger::ThreadSink g_threadSink;
}

void Logger::setThreadSink(ThreadSink sink) { g_threadSink = std::move(sink); }
bool Logger::hasThreadSink() { return static_cast<bool>(g_threadSink); }

void Logger::write(LogLevel lv, const char* tag, const std::string& msg) {
    if (lv > m_level) return;

    std::string line;
    if (m_level >= LL_DEBUG && lv >= LL_INFO) {
        std::time_t now = std::time(nullptr);
        char stamp[32] = {0};
        std::strftime(stamp, sizeof(stamp), "%H:%M:%S", std::localtime(&now));
        line = std::string("[") + stamp + "][" + tag + "] " + msg;
    } else if (lv <= LL_WARN) {
        line = std::string("[") + tag + "] " + msg;
    } else {
        line = msg;
    }

    if (g_threadSink) {
        /* 服务端：日志交给任务缓冲；错误/告警同时进守护进程 stderr 便于排查 */
        g_threadSink(lv, line);
        if (lv <= LL_WARN) {
            std::fprintf(stderr, "%s\n", line.c_str());
            std::fflush(stderr);
        }
        return;
    }
    std::FILE* out = (lv <= LL_WARN) ? stderr : stdout;
    std::fprintf(out, "%s\n", line.c_str());
    std::fflush(out);
}

void Logger::error(const std::string& msg) { ++m_errors;  write(LL_ERROR, "ERROR", msg); }
void Logger::warn (const std::string& msg) { ++m_warnings; write(LL_WARN,  "WARN ", msg); }
void Logger::info (const std::string& msg) { write(LL_INFO,  "INFO ", msg); }
void Logger::debug(const std::string& msg) { write(LL_DEBUG, "DEBUG", msg); }

} /* namespace DBKP */
