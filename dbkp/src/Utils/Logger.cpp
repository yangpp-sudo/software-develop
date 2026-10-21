/* ============================================================================
 *  Logger.cpp
 * ==========================================================================*/
#include "Utils/Logger.h"

#include <cstdio>
#include <cstring>
#include <ctime>
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

void Logger::write(LogLevel lv, const char* tag, const std::string& msg) {
    if (lv > m_level) return;
    std::FILE* out = (lv <= LL_WARN) ? stderr : stdout;
    if (m_level >= LL_DEBUG && lv >= LL_INFO) {
        std::time_t now = std::time(nullptr);
        char stamp[32] = {0};
        std::strftime(stamp, sizeof(stamp), "%H:%M:%S", std::localtime(&now));
        std::fprintf(out, "[%s][%s] %s\n", stamp, tag, msg.c_str());
    } else if (lv <= LL_WARN) {
        std::fprintf(out, "[%s] %s\n", tag, msg.c_str());
    } else {
        std::fprintf(out, "%s\n", msg.c_str());
    }
    std::fflush(out);
}

void Logger::error(const std::string& msg) { ++m_errors;  write(LL_ERROR, "ERROR", msg); }
void Logger::warn (const std::string& msg) { ++m_warnings; write(LL_WARN,  "WARN ", msg); }
void Logger::info (const std::string& msg) { write(LL_INFO,  "INFO ", msg); }
void Logger::debug(const std::string& msg) { write(LL_DEBUG, "DEBUG", msg); }

} /* namespace DBKP */
