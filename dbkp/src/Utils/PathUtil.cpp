/* ============================================================================
 *  PathUtil.cpp
 * ==========================================================================*/
#include "Utils/PathUtil.h"

#include "Platform/FS.h"

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
    if (raw.empty()) return raw;      /* 空输入 -> 空输出（调用方另有约定） */
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

bool isSubPath(const std::string& parent, const std::string& child) {
    /* F6：三处（watch CLI、watch API、引擎重叠守卫）共用的"包含"判定。
       顺序很关键，都是批次 4 踩过的坑：
       1) 先解析真实路径 —— junction/symlink 指向内部时必须被看见；
          解析失败（不存在/无权限）退回词法绝对化，不因此放行风险路径。
       2) 再判相等。Path::relative 对"相等"返回空串，和"不是前缀"撞车，
          所以绝不能只靠 relative 判包含。
       3) 判子树时只认分隔符边界：c:/a 与 c:/ab 词法是前缀但不是父子。
       Windows 路径大小写不敏感，比较前统一转小写。 */
    std::string p, c;
    if (DBKP_IS_ERR(Platform::canonicalPath(parent, p)) || p.empty()) p = parent;
    if (DBKP_IS_ERR(Platform::canonicalPath(child, c)) || c.empty()) c = child;
    p = normalize(p);
    c = normalize(c);
    if (p.empty() || c.empty()) return false;
#if defined(DBKP_OS_WINDOWS)
    std::string pl = p, cl = c;
    for (size_t i = 0; i < pl.size(); ++i) pl[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(pl[i])));
    for (size_t i = 0; i < cl.size(); ++i) cl[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(cl[i])));
    if (pl == cl) return true;                     /* 相等也算包含：自喂的极端情况 */
    if (cl.size() <= pl.size()) return false;
    if (cl.compare(0, pl.size(), pl) != 0) return false;
    return pl[pl.size() - 1] == '/' ? true : cl[pl.size()] == '/';
#else
    if (p == c) return true;
    if (c.size() <= p.size()) return false;
    if (c.compare(0, p.size(), p) != 0) return false;
    return p[p.size() - 1] == '/' ? true : c[p.size()] == '/';
#endif
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

/* F8：语法预校验。规则严格对齐 matchCharClass/matchGlob 的方言：
   - 每个 '[' 必须在串内闭合（未闭合时 matchCharClass 恒 false，整条模式永不匹配）；
   - 字符类体非空（"[]" 同样恒 false）；
   - 类体支持 !/^ 取反、a-z 形式的区间，区间上界 < 下界时该段永不匹配，视为非法。
   目的：坏模式在"入口"就报出来，而不是匹配不到任何文件后产出 0 条目的空箱。 */
bool validateGlob(const std::string& pattern, std::string& why) {
    why.clear();
    if (pattern.empty()) {
        why = "glob 模式为空，不可能匹配任何文件";
        return false;
    }
    size_t i = 0;
    while (i < pattern.size()) {
        if (pattern[i] != '[') { ++i; continue; }
        size_t q = i + 1;
        if (q < pattern.size() && (pattern[q] == '!' || pattern[q] == '^')) ++q;
        const size_t bodyStart = q;
        bool closed = false;
        while (q < pattern.size()) {
            if (pattern[q] == ']') { closed = true; break; }
            /* 与 matchCharClass 完全相同的三元组判定：X-Y 且 Y 不是 ']' */
            if (q + 2 < pattern.size() && pattern[q + 1] == '-' && pattern[q + 2] != ']') {
                if (static_cast<unsigned char>(pattern[q + 2]) <
                    static_cast<unsigned char>(pattern[q])) {
                    why = "字符类区间上下界颠倒：[" + pattern.substr(q, 3) + "]";
                    return false;
                }
                q += 3;
            } else {
                ++q;
            }
        }
        if (!closed) { why = "字符类未闭合：'" + pattern.substr(i) + "' 缺少 ']'"; return false; }
        if (q == bodyStart) { why = "字符类为空：'[]' 永远匹配不到任何名字"; return false; }
        i = q + 1;
    }
    return true;
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

std::wstring apiWide(const std::string& path) {
    std::wstring w = utf8ToWide(path);
    if (w.empty()) return w;
    if (w.size() >= 4 && w.compare(0, 4, L"\\\\?\\") == 0) return w;   /* 已是扩展形式 */

    /* 1) 绝对化 + 折叠 ./..：GetFullPathNameW 不做存在性检查，纯字符串处理 */
    std::vector<wchar_t> buf(8192);
    DWORD n = GetFullPathNameW(w.c_str(), DWORD(buf.size()), buf.data(), nullptr);
    std::wstring abs = (n > 0 && n < buf.size()) ? std::wstring(buf.data(), n) : w;

    /* 2) \\?\ 只认反斜杠 */
    for (size_t i = 0; i < abs.size(); ++i) if (abs[i] == L'/') abs[i] = L'\\';

    /* 3) 只在可能踩到 260 限制时才加前缀：短路径保持原样，
     *    便于日志/比较里看到人类可读的路径，也避免前缀形式的语义差异 */
    if (abs.size() < 248) return abs;
    if (abs.size() >= 2 && abs[0] == L'\\' && abs[1] == L'\\') {
        const std::wstring rest = abs.substr(2);           /* UNC: \\srv\share\... */
        return std::wstring(L"\\\\?\\UNC\\") + rest;
    }
    return std::wstring(L"\\\\?\\") + abs;
}
#endif /* DBKP_OS_WINDOWS */

} /* namespace Path */
} /* namespace DBKP */

