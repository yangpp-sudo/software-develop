/* ============================================================================
 *  Scheduler.cpp  -- 定时备份与保留策略
 * ==========================================================================*/
#include "Backup/Scheduler.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <thread>

#include "Platform/FS.h"
#include "Utils/Logger.h"
#include "Utils/PathUtil.h"

namespace DBKP {

int CScheduler::parseInterval(const std::string& text, bool* okOut) {
    if (okOut) *okOut = false;
    if (text.empty()) return -1;
    char* endp = nullptr;
    long v = std::strtol(text.c_str(), &endp, 10);
    if (endp == text.c_str() || v < 0) return -1;
    std::string unit = endp ? std::string(endp) : std::string();
    for (size_t i = 0; i < unit.size(); ++i) {
        unit[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(unit[i])));
    }
    int mul = 1;
    if (unit.empty() || unit == "s") mul = 1;
    else if (unit == "m" || unit == "min") mul = 60;
    else if (unit == "h") mul = 3600;
    else if (unit == "d") mul = 86400;
    else return -1;
    if (okOut) *okOut = true;
    return static_cast<int>(v * mul);
}

std::string CScheduler::makeArchiveName(const std::string& dir, const std::string& prefix) {
    std::time_t now = std::time(nullptr);
    struct tm tmv;
    std::memset(&tmv, 0, sizeof(tmv));
#if defined(DBKP_OS_WINDOWS)
    localtime_s(&tmv, &now);
#else
    localtime_r(&now, &tmv);
#endif
    char stamp[32];
    std::strftime(stamp, sizeof(stamp), "%Y%m%d-%H%M%S", &tmv);
    std::string name = prefix + "-" + stamp + DEFAULT_ARCHIVE_SUFFIX;
    return Path::join(dir, name);
}

int CScheduler::applyRetention(const std::string& dir, const std::string& prefix, int keep) {
    if (keep <= 0) return 0;
    std::vector<Platform::DirEntry> items;
    if (DBKP_IS_ERR(Platform::listDir(dir, items))) return 0;
    std::vector<std::string> archives;
    for (size_t i = 0; i < items.size(); ++i) {
        const std::string& n = items[i].name;
        if (n.compare(0, prefix.size(), prefix) != 0) continue;
        if (n.size() < 5 || n.compare(n.size() - 5, 5, ".dbkp") != 0) continue;
        archives.push_back(n);
    }
    if (static_cast<int>(archives.size()) <= keep) return 0;
    std::sort(archives.begin(), archives.end());          /* 时间戳字典序 == 时间序 */
    const int excess = static_cast<int>(archives.size()) - keep;
    int removed = 0;
    for (int i = 0; i < excess; ++i) {
        const std::string full = Path::join(dir, archives[i]);
        if (DBKP_IS_ERR(Platform::removeFile(full))) {
            LOG_WARN("retention: cannot delete " + full);
            continue;
        }
        LOG_INFO("retention: removed " + archives[i]);
        ++removed;
    }
    return removed;
}

ErrCode CScheduler::run(const ScheduleOptions& opt) {
    std::string dir = opt.archiveDir;
    std::string prefix = opt.prefix;
    if (dir.empty()) {
        dir = Path::parentDir(opt.backup.destination);
        if (dir.empty()) dir = ".";
    }
    if (prefix.empty()) prefix = Path::fileName(Path::normalize(opt.backup.source));
    if (prefix.empty() || prefix == ".") prefix = "backup";
    if (DBKP_IS_ERR(Platform::exists(dir))) Platform::makeDirTree(dir);

    ErrCode last = E_OK;
    int done = 0;
    LOG_INFO("scheduler start: every " + std::to_string(opt.intervalSeconds) + "s, times=" +
             std::to_string(opt.times) + ", keep=" + std::to_string(opt.keep) +
             ", prefix=" + prefix);
    while (opt.times <= 0 || done < opt.times) {
        const std::string archive = CScheduler::makeArchiveName(dir, prefix);
        BackupOptions each = opt.backup;
        each.destination = archive;
        each.mode = MODE_ARCHIVE;

        CBackupEngine engine;
        ErrCode e = engine.run(each);
        last = e;
        ++done;
        if (DBKP_IS_ERR(e)) {
            LOG_ERR("scheduled backup #" + std::to_string(done) + " failed: " + engine.lastError());
        } else {
            LOG_INFO("scheduled backup #" + std::to_string(done) + " -> " + archive);
            CScheduler::applyRetention(dir, prefix, opt.keep);
        }
        if (opt.times > 0 && done >= opt.times) break;
        for (int s = 0; s < opt.intervalSeconds; ++s) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
    return last;
}

} /* namespace DBKP */
