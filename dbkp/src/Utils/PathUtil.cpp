/* ============================================================================
 *  PathUtil.cpp
 * ==========================================================================*/
#include "Utils/PathUtil.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <sstream>

#if defined(DBKP_OS_WINDOWS)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace DBKP {
namespace Path {

std::string join(const std::string& a, const std::string& b) {
    if (a.empty()) return b;
    if (b.empty()) return a;
    char last = a[a.size() - 1];
    if (last == '/' || last == '\\') return a + b;
    return a + kArchiveSep + b;
}

bool isAbsolute(const std::string& p) {
    if (p.empty()) return false;
    if (p[0] == '/' || p[0] == '\\') return true;
    return p.size() >= 2 && std::isalpha(static_cast<unsigned char>(p[0])) && p[1] == ':';
}

std::string normalize(const std::string& raw) {
    std::vector<std::string> parts;
    std::string cur;
    bool absolute = isAbsolute(raw);
    bool drivePrefix = absolute && raw.size() >= 2 && raw[1] == ':';
    if (drivePrefix) {
        parts.push_back(raw.substr(0, 2));
        cur.clear();
    }
    for (size_t i = drivePrefix ? 2 : 0; i < raw.size(); ++i) {
        char c = raw[i];
        if (c == '/' || c == '\\') {
            if (!cur.empty()) { parts.push_back(cur); cur.clear(); }
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) parts.push_back(cur);

    std::vector<std::string> out;
    for (size_t i = 0; i < parts.size(); ++i) {
        const std::string& seg = parts[i];
        if (seg == ".") continue;
        if (seg == "..") {
            if (!out.empty() && out.back() != ".." &&
                !(out.back().size() == 2 && out.back()[1] == ':')) {
                out.pop_back();
            } else if (!absolute) {
                out.push_back("..");
            }
            continue;
        }
        out.push_back(seg);
    }

    std::string res;
    for (size_t i = 0; i < out.size(); ++i) {
        if (i) res += kArchiveSep;
        res += out[i];
    }
    /* 绝对路径必须保留前导 '/'（此前被丢掉，导致 "/x//y/" -> "x/y"） */
    if (absolute && !drivePrefix) res = std::string(1, kArchiveSep) + res;
    if (res.empty()) res = absolute ? std::string(1, kArchiveSep) : std::string(".");
    return res;
}

std::string toOs(const std::string& archivePath) {
#if defined(DBKP_OS_WINDOWS)
    std::string r = archivePath;
    for (size_t i = 0; i < r.size(); ++i) if (r[i] == '/') r[i] = kOsSep;
    return r;
#else
    return archivePath;
#endif
}

std::string toArchive(const std::string& osPath) {
    std::string r = osPath;
    for (size_t i = 0; i < r.size(); ++i) if (r[i] == '\\') r[i] = '/';
    return r;
}

std::string fileName(const std::string& p) {
    size_t pos = p.find_last_of("/\\");
    return pos == std::string::npos ? p : p.substr(pos + 1);
}

std::string parentDir(const std::string& p) {
    size_t pos = p.find_last_of("/\\");
    if (pos == std::string::npos) return "";
    if (pos == 0) return "/";
    return p.substr(0, pos);
}

std::string extension(const std::string& p) {
    std::string name = fileName(p);
    size_t pos = name.find_last_of('.');
    if (pos == std::string::npos || pos == 0) return "";
    return name.substr(pos);   /* 含点号 */
}

std::string baseNameWithoutExt(const std::string& p) {
    std::string name = fileName(p);
    size_t pos = name.find_last_of('.');
    if (pos == std::string::npos || pos == 0) return name;
    return name.substr(0, pos);
}

std::string withSuffix(const std::string& stem, const std::string& suffix) {
    if (suffix.empty() || suffix[0] != '.') return stem + suffix;
    return stem + suffix;
}

std::string relative(const std::string& parent, const std::string& child) {
    std::string p = normalize(parent), c = normalize(child);
    if (p == "/" ) { return c.size() && c[0] == '/' ? c.substr(1) : c; }
    if (c.size() < p.size()) return "";
    if (c.compare(0, p.size(), p) != 0) return "";
    if (c.size() == p.size()) return "";
    if (c[p.size()] == '/' || c[p.size()] == '\\') {
        std::string r = c.substr(p.size() + 1);
        for (size_t i = 0; i < r.size(); ++i) if (r[i] == '\\') r[i] = '/';
        return r;
    }
    return "";
}

bool isPathTraversalSafe(const std::string& archivePath) {
    if (archivePath.empty()) return false;
    if (isAbsolute(archivePath)) return false;
    std::stringstream ss(archivePath);
    std::string seg;
    while (std::getline(ss, seg, '/')) {
        if (seg.empty()) continue;
        if (seg == "..") return false;
    }
    return true;
}

bool iequals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) return false;
    }
    return true;
}

/* ---------------------------------------------------------- glob 匹配 */
namespace {

/** 解析 [..] 字符类；返回是否匹配，pos 推进到 ']' 之后 */
bool matchCharClass(const std::string& pat, size_t& pos, char c) {
    size_t q = pos + 1;                           /* 跳过 '[' */
    bool negate = false;
    if (q < pat.size() && (pat[q] == '!' || pat[q] == '^')) { negate = true; ++q; }
    bool found = false;
    while (q < pat.size() && pat[q] != ']') {
        if (q + 2 < pat.size() && pat[q + 1] == '-' && pat[q + 2] != ']') {
            if (c >= pat[q] && c <= pat[q + 2]) found = true;
            q += 3;
        } else {
            if (c == pat[q]) found = true;
            ++q;
        }
    }
    if (q >= pat.size()) return false;            /* 方括号未闭合 */
    pos = q + 1;
    return found != negate;
}

} /* anonymous namespace */

bool matchGlob(const std::string& pattern, const std::string& text) {
    size_t p = 0, t = 0;
    size_t starPos = std::string::npos, starText = 0;
    while (t < text.size()) {
        if (p < pattern.size() && pattern[p] == '?') { ++p; ++t; }
        else if (p < pattern.size() && pattern[p] == '[') {
            size_t next = p;
            if (matchCharClass(pattern, next, text[t])) { p = next; ++t; }
            else if (starPos != std::string::npos) { p = starPos + 1; t = ++starText; }
            else return false;
        }
        else if (p < pattern.size() && pattern[p] == '*') { starPos = p++; starText = t; }
        else if (p < pattern.size() && pattern[p] == text[t]) { ++p; ++t; }
        else if (starPos != std::string::npos) { p = starPos + 1; t = ++starText; }
        else return false;
    }
    while (p < pattern.size() && pattern[p] == '*') ++p;
    return p == pattern.size();
}

#if defined(DBKP_OS_WINDOWS)
std::wstring utf8ToWide(const std::string& utf8) {
    if (utf8.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, utf8.data(), int(utf8.size()), nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring w(size_t(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.data(), int(utf8.size()), &w[0], n);
    return w;
}

std::string wideToUtf8(const std::wstring& wide) {
    if (wide.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, wide.data(), int(wide.size()),
                                nullptr, 0, nullptr, nullptr);
    if (n <= 0) return std::string();
    std::string s(size_t(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.data(), int(wide.size()),
                        &s[0], n, nullptr, nullptr);
    return s;
}
#endif /* DBKP_OS_WINDOWS */

} /* namespace Path */
} /* namespace DBKP */

