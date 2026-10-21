/* ============================================================================
 *  FilterOptions.cpp  -- 六个维度的自定义备份过滤
 * ==========================================================================*/
#include "Enumerator/FilterOptions.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <sstream>

#include "Utils/Logger.h"
#include "Utils/PathUtil.h"

namespace DBKP {

namespace {

std::vector<std::string> splitList(const std::string& text, char sep) {
    std::vector<std::string> out;
    std::string cur;
    for (size_t i = 0; i < text.size(); ++i) {
        if (text[i] == sep) { if (!cur.empty()) { out.push_back(cur); cur.clear(); } }
        else cur.push_back(text[i]);
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

bool anyGlob(const std::vector<std::string>& globs, const std::string& text) {
    for (size_t i = 0; i < globs.size(); ++i) {
        if (Path::matchGlob(globs[i], text)) return true;
    }
    return false;
}

/** relDir 是否可能是某条 include 模式的路径前缀（用于放行父目录） */
bool isPrefixOfAny(const std::string& relDir, const std::vector<std::string>& globs) {
    for (size_t i = 0; i < globs.size(); ++i) {
        const std::string& g = globs[i];
        size_t cut = g.find_first_of("*?[");
        if (cut == std::string::npos) cut = g.size();
        std::string prefix = g.substr(0, cut);
        size_t slash = prefix.find_last_of('/');
        if (slash != std::string::npos) prefix = prefix.substr(0, slash + 1);
        if (prefix.empty()) continue;
        if (relDir.size() < prefix.size()) {
            if (prefix.compare(0, relDir.size(), relDir) == 0) return true;
        }
    }
    return false;
}

} /* anonymous namespace */

bool FilterOptions::isEmpty() const {
    return includePaths.empty() && excludePaths.empty() &&
           nameGlobs.empty() && nameRejects.empty() &&
           typeAllow.empty() && typeDeny.empty() &&
           mtimeAfter == 0 && mtimeBefore == 0 &&
           minSize < 0 && maxSize < 0 &&
           uids.empty() && ownerNames.empty() &&
           !followSymlinks && !noCrossDevice && maxDepth < 0 && !skipSpecials;
}

bool FilterOptions::pass(const std::string& relPath, const Platform::FileInfo& fi) const {
    /* --- 3. 文件类型 --- */
    if (std::find(typeDeny.begin(), typeDeny.end(), fi.type) != typeDeny.end()) return false;
    if (!typeAllow.empty() &&
        std::find(typeAllow.begin(), typeAllow.end(), fi.type) == typeAllow.end()) return false;
    if (skipSpecials && (fi.type == FT_FIFO || fi.type == FT_BLOCK ||
                         fi.type == FT_CHAR  || fi.type == FT_SOCKET)) return false;

    /* --- 1. 路径 --- */
    if (!excludePaths.empty() && anyGlob(excludePaths, relPath)) return false;
    if (!includePaths.empty() && !anyGlob(includePaths, relPath)) {
        if (fi.type == FT_DIR && isPrefixOfAny(relPath, includePaths)) { /* 放行父目录 */ }
        else return false;
    }

    /* --- 2. 文件名称 --- */
    const std::string base = Path::fileName(relPath);
    if (!nameGlobs.empty() && !anyGlob(nameGlobs, base)) {
        std::ostringstream os;
        for (size_t i = 0; i < nameGlobs.size(); ++i) os << (i ? "," : "") << nameGlobs[i];
        LOG_DEBUG("name allow miss: base=[" + base + "] globs=[" + os.str() + "]");
        return false;
    }
    if (!nameRejects.empty() && anyGlob(nameRejects, base)) return false;

    /* --- 5. 尺寸（仅普通文件） --- */
    if (fi.type == FT_REGULAR) {
        if (minSize >= 0 && fi.size < minSize) return false;
        if (maxSize >= 0 && fi.size > maxSize) return false;
    }
    /* --- 4. 修改时间 --- */
    if (mtimeAfter > 0  && fi.mtimeSec < mtimeAfter)  return false;
    if (mtimeBefore > 0 && fi.mtimeSec > mtimeBefore) return false;

    /* --- 6. 拥有者 --- */
    if (!uids.empty() &&
        std::find(uids.begin(), uids.end(), fi.uid) == uids.end()) return false;
    if (!ownerNames.empty()) {
        std::string name;
        if (DBKP_IS_ERR(Platform::uidToName(fi.uid, name))) {
            /* 平台无法解析属主（如 Windows）：降级为不按名字过滤 */
        } else {
            bool matched = false;
            for (size_t i = 0; i < ownerNames.size(); ++i) {
                if (Path::iequals(ownerNames[i], name)) { matched = true; break; }
            }
            if (!matched) return false;
        }
    }
    return true;
}

bool FilterOptions::passTraversal(const std::string& relDir) const {
    if (relDir.empty()) return true;
    if (!excludePaths.empty() && anyGlob(excludePaths, relDir)) return false;
    return true;
}

bool FilterOptions::passForTraversal(const std::string& relDir,
                                     const Platform::FileInfo& fi) const {
    if (fi.type != FT_DIR) return false;
    if (relDir.empty()) return true;
    /* 只有"路径"维度能剪断遍历；类型/名称/尺寸维度仅决定条目本身是否入档，
       否则 --type -D（不要目录条目）会连子目录里的文件一起丢掉。 */
    if (!excludePaths.empty() && anyGlob(excludePaths, relDir)) return false;
    if (!includePaths.empty() && !anyGlob(includePaths, relDir) &&
        !isPrefixOfAny(relDir, includePaths)) return false;
    return true;
}

bool FilterOptions::setTypeSpec(const std::string& spec) {
    if (spec.empty()) return false;
    bool deny = false;
    size_t start = 0;
    if (spec[0] == '-') { deny = true; start = 1; }
    else if (spec[0] == '+') { start = 1; }
    const std::string body = spec.substr(start);
    if (body.empty()) return false;

    /* 类型 token 有两种写法：单字母集合 "-DL" 与逗号名单 "regular,dir" */
    struct TypeAlias { const char* text; char type; };
    static const TypeAlias kAliases[] = {
        { "r", FT_REGULAR }, { "regular", FT_REGULAR }, { "file", FT_REGULAR },
        { "plain", FT_REGULAR },
        { "d", FT_DIR }, { "dir", FT_DIR }, { "directory", FT_DIR },
        { "l", FT_SYMLINK }, { "link", FT_SYMLINK }, { "symlink", FT_SYMLINK },
        { "h", FT_HARDLINK }, { "hard", FT_HARDLINK }, { "hardlink", FT_HARDLINK },
        { "f", FT_FIFO }, { "pipe", FT_FIFO }, { "fifo", FT_FIFO },
        { "b", FT_BLOCK }, { "block", FT_BLOCK },
        { "c", FT_CHAR }, { "char", FT_CHAR }, { "character", FT_CHAR },
        { "s", FT_SOCKET }, { "sock", FT_SOCKET }, { "socket", FT_SOCKET },
    };

    /* 全字母且无逗号 -> 视为字母集合，逐字符拆开 */
    bool letterSet = body.size() > 1 && body.find(',') == std::string::npos;
    for (size_t i = 0; i < body.size() && letterSet; ++i) {
        std::string one = body.substr(i, 1);
        bool known = false;
        for (size_t k = 0; k < sizeof(kAliases) / sizeof(kAliases[0]); ++k) {
            if (std::strlen(kAliases[k].text) == 1 && kAliases[k].text[0] == std::tolower(static_cast<unsigned char>(body[i]))) {
                known = true; break;
            }
        }
        if (!known) letterSet = false;
    }
    std::vector<std::string> items;
    if (letterSet) {
        for (size_t i = 0; i < body.size(); ++i) items.push_back(body.substr(i, 1));
    } else {
        items = splitList(body, ',');
    }
    if (items.empty()) return false;

    std::vector<char>& bucket = deny ? typeDeny : typeAllow;
    for (size_t i = 0; i < items.size(); ++i) {
        std::string tok;
        for (size_t k = 0; k < items[i].size(); ++k) {
            tok.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(items[i][k]))));
        }
        char t = 0;
        for (size_t k = 0; k < sizeof(kAliases) / sizeof(kAliases[0]); ++k) {
            if (tok == kAliases[k].text) { t = kAliases[k].type; break; }
        }
        if (t == 0) { LOG_WARN("ignore unknown file type: " + items[i]); continue; }
        if (std::find(bucket.begin(), bucket.end(), t) == bucket.end()) bucket.push_back(t);
    }
    /* 语法正确即返回 true：非法类型名只告警并忽略（与 tar --exclude 的宽容一致） */
    return true;
}

int64_t FilterOptions::parseSize(const std::string& text, bool* okOut) {
    if (okOut) *okOut = false;
    if (text.empty()) return -1;
    char* endp = nullptr;
    double v = std::strtod(text.c_str(), &endp);
    if (endp == text.c_str()) return -1;
    std::string unit = endp ? std::string(endp) : std::string();
    for (size_t i = 0; i < unit.size(); ++i) {
        unit[i] = static_cast<char>(std::toupper(static_cast<unsigned char>(unit[i])));
    }
    if (unit.empty() || unit == "B") { if (okOut) *okOut = true; return static_cast<int64_t>(v); }
    int64_t mul = 0;
    if      (unit == "K" || unit == "KB") mul = 1024;
    else if (unit == "M" || unit == "MB") mul = 1024 * 1024;
    else if (unit == "G" || unit == "GB") mul = 1024 * 1024 * 1024;
    else if (unit == "T" || unit == "TB") mul = static_cast<int64_t>(1024) * 1024 * 1024 * 1024;
    if (mul == 0) return -1;
    if (okOut) *okOut = true;
    return static_cast<int64_t>(v * static_cast<double>(mul));
}

int64_t FilterOptions::parseTime(const std::string& text, bool* okOut) {
    if (okOut) *okOut = false;
    if (text.empty()) return 0;
    /* 相对时间："7d" "12h" "30m" "60s" —— 表示"距今多久之前" */
    if (text.size() >= 2 && std::isdigit(static_cast<unsigned char>(text[0]))) {
        char last = static_cast<char>(std::tolower(static_cast<unsigned char>(text[text.size() - 1])));
        if (last == 'd' || last == 'h' || last == 'm' || last == 's') {
            double n = std::atof(text.substr(0, text.size() - 1).c_str());
            int64_t per = last == 'd' ? 86400 : (last == 'h' ? 3600 : (last == 'm' ? 60 : 1));
            if (okOut) *okOut = true;
            return static_cast<int64_t>(std::time(nullptr)) - static_cast<int64_t>(n * per);
        }
    }
    std::tm tmv;
    std::memset(&tmv, 0, sizeof(tmv));
    int y = 0, mo = 0, d = 0, h = 12, mi = 0, s = 0;
    int matched = std::sscanf(text.c_str(), "%d-%d-%dT%d:%d:%d", &y, &mo, &d, &h, &mi, &s);
    if (matched < 3) {
        matched = std::sscanf(text.c_str(), "%d-%d-%d %d:%d:%d", &y, &mo, &d, &h, &mi, &s);
        if (matched < 3) return 0;
    }
    tmv.tm_year = y - 1900; tmv.tm_mon = mo - 1; tmv.tm_mday = d;
    tmv.tm_hour = h; tmv.tm_min = mi; tmv.tm_sec = s;
    tmv.tm_isdst = -1;
    if (okOut) *okOut = true;
    return static_cast<int64_t>(std::mktime(&tmv));
}

std::string FilterOptions::describe() const {
    std::ostringstream os;
    if (!includePaths.empty()) os << "include-path=" << includePaths.size() << " ";
    if (!excludePaths.empty()) os << "exclude-path=" << excludePaths.size() << " ";
    if (!nameGlobs.empty())    os << "name=" << nameGlobs.size() << " ";
    if (!nameRejects.empty())  os << "name-exclude=" << nameRejects.size() << " ";
    if (!typeAllow.empty())    os << "type=" << typeAllow.size() << " ";
    if (!typeDeny.empty())     os << "type-exclude=" << typeDeny.size() << " ";
    if (minSize >= 0 || maxSize >= 0) os << "size=[" << minSize << "," << maxSize << "] ";
    if (mtimeAfter > 0 || mtimeBefore > 0)
        os << "mtime=[" << mtimeAfter << "," << mtimeBefore << "] ";
    if (!uids.empty() || !ownerNames.empty())
        os << "owner=" << (uids.size() + ownerNames.size()) << " ";
    if (followSymlinks) os << "follow-symlink ";
    if (noCrossDevice)  os << "no-cross-device ";
    if (maxDepth >= 0)  os << "max-depth=" << maxDepth << " ";
    if (skipSpecials)   os << "skip-special ";
    std::string s = os.str();
    if (!s.empty() && s[s.size() - 1] == ' ') s.erase(s.size() - 1);
    return s.empty() ? "none" : s;
}

} /* namespace DBKP */

