/* ============================================================================
 *  PathUtil.cpp
 * ==========================================================================*/
#include "Utils/PathUtil.h"

#include "Platform/FS.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <vector>
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

/* C13：检测 Unicode 双向文本覆盖/零宽/格式字符（钓鱼文件名）。
   典型手法 "invoice<U+202E>txt.exe" 在资源管理器里显示成 "invoiceexe.txt"，
   用户以为是可信文档，双击却是可执行程序。这些码点在 UTF-8 里的字节序列：
     U+200B..U+200F  E2 80 8B..8F   (零宽空格 / LRM / RLM)
     U+202A..U+202E  E2 80 AA..AE   (LRE/RLE/PDF/LRO/RLO，RLO 即 U+202E)
     U+2066..U+2069  E2 81 A6..A9   (LRI/RLI/FSI/PDI)
     U+FEFF          EF BB BF       (BOM / 零宽不换行空格)
     U+061C          D8 9C          (阿拉伯字母标记)
     U+00AD          C2 AD          (软连字符，可隐形)
     C1 控制区 U+0080..U+009F  C2 80..9F
   这些字符在任何平台上都不属于"可信文件名"，与平台路径语义无关，故跨平台
   一律拒绝（老师第 4 页：路径全部按恶意输入处理）。 */
static bool hasVisualSpoof(const std::string& s) {
    const unsigned char* p = reinterpret_cast<const unsigned char*>(s.data());
    const size_t n = s.size();
    for (size_t i = 0; i < n; ++i) {
        const unsigned char c = p[i];
        if (c == 0xE2 && i + 2 < n) {
            const unsigned char b = p[i+1], d = p[i+2];
            if (b == 0x80 && ((d >= 0x8B && d <= 0x8F) || (d >= 0xAA && d <= 0xAE)))
                return true;
            if (b == 0x81 && d >= 0xA6 && d <= 0xA9) return true;
        }
        if (c == 0xEF && i + 2 < n && p[i+1] == 0xBB && p[i+2] == 0xBF) return true;
        if (c == 0xD8 && i + 1 < n && p[i+1] == 0x9C) return true;
        if (c == 0xC2 && i + 1 < n) {
            const unsigned char d = p[i+1];
            if (d == 0xAD || (d >= 0x80 && d <= 0x9F)) return true;
        }
    }
    return false;
}

/* A1：归档名前缀必须是"单个文件名组分"，绝不能含路径分隔符 / 盘符 / .. /
   控制字符 / 绝对形态。schedule --prefix、watch --prefix、Web 参数都走这里。
   否则 makeArchiveName 会把 "..\..\x" 拼进路径，把备份箱写到目标目录之外，
   同时 applyRetention 的前缀匹配失效导致旧箱永不清理。 */
bool isSafeNameComponent(const std::string& name) {
    if (name.empty() || name == "." || name == "..") return false;
    if (hasVisualSpoof(name)) return false;
    for (size_t i = 0; i < name.size(); ++i) {
        const unsigned char ch = static_cast<unsigned char>(name[i]);
        if (ch == '/' || ch == '\\' || ch == ':' || ch < 0x20 || ch == 0x7F)
            return false;
    }
    if (name.find("..") != std::string::npos) return false;  /* 含 .. 一律拒 */
    if (isAbsolute(name)) return false;
    return true;
}

bool isPathTraversalSafe(const std::string& archivePath) {
    /* 归档内路径是不可信输入（老师第 4 页：文件头/密码/路径全部按恶意处理）。
       规则按目标平台的真实语义定制，避免在 POSIX 上误杀合法文件名：
       Windows：
         1) 反斜杠归一成斜杠再检查 —— "..\..\x" 与 "../.." 等价，
            normalize/absOf 拼接层会词法消解 ".."，不归一就是 N1 穿透；
         2) 含 ':' 一律拒绝 —— 盘符、盘符相对路径("C:x")、NTFS ADS("a.txt:stream")；
         3) 拒绝绝对路径；
         4) 逐段检查：段尾的空格和点剥离后再比 —— Windows 会把 "a. " 静默当作
            "a."、".. " 当作 ".."，不剥就漏。
       POSIX：
         只拒 NUL。':' 和 '\\' 都是合法文件名字符（"report:2024.txt"、"a\b.txt"），
         所以不归一反斜杠、不剥离段尾点空格（POSIX 不会静默改写文件名）。
       全平台：拒绝 Unicode 双向覆盖/零宽字符（C13 钓鱼名，与平台语义无关）。
       syml 的 link 目标同样走本函数（F21）。 */
    if (archivePath.empty()) return false;
    if (hasVisualSpoof(archivePath)) return false;

#if defined(DBKP_OS_WINDOWS)
    std::string s = archivePath;
    for (size_t i = 0; i < s.size(); ++i) {
        unsigned char ch = static_cast<unsigned char>(s[i]);
        if (s[i] == '\\') { s[i] = '/'; continue; }
        if (ch == ':' || ch < 0x20 || ch == 0x7F) return false;   /* ADS/盘符/控制字符 */
    }
#else
    const std::string& s = archivePath;
    if (s.find('\0') != std::string::npos) return false;          /* POSIX 仅拒 NUL */
#endif
    if (isAbsolute(s)) return false;

    std::stringstream ss(s);
    std::string seg;
    while (std::getline(ss, seg, '/')) {
        if (seg.empty()) continue;
#if defined(DBKP_OS_WINDOWS)
        /* r = seg 去掉尾部空格和点（Windows 会把 "a. " 静默当 "a."）。
           注意 ".." 剥完会变成空串，所以不能只比较 r==".."：
           剥空但原段含 ".."（即 ".."/".. "/".. ." 这类）同样要拒绝。 */
        std::string r = seg;
        while (!r.empty() && (r[r.size() - 1] == ' ' || r[r.size() - 1] == '.'))
            r.erase(r.size() - 1);
        if (r == "..") return false;
        if (r.empty() && seg.find("..") != std::string::npos) return false;
#else
        if (seg == "..") return false;
#endif
    }
    return true;
}

/* F22：Windows 保留设备名。restore 走 \\?\ 前缀直写时，Win32 会跳过保留名
   解析，CON/COM1 等会被真实落盘且资源管理器无法常规删除。取最后一个
   分隔符之后的文件名、第一个 '.' 之前的主名比较（CON.txt 同样命中），
   主名不区分大小写。 */
bool isReservedDeviceName(const std::string& name) {
    std::string base = name;
    const size_t slash = base.find_last_of("/\\");
    if (slash != std::string::npos) base = base.substr(slash + 1);
    const size_t dot = base.find('.');
    if (dot != std::string::npos) base = base.substr(0, dot);
    for (size_t i = 0; i < base.size(); ++i)
        base[i] = static_cast<char>(std::toupper(static_cast<unsigned char>(base[i])));
    static const char* const kDev[] = {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    };
    for (size_t i = 0; i < sizeof(kDev) / sizeof(kDev[0]); ++i)
        if (base == kDev[i]) return true;
    return false;
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

/** 递归匹配核心（支持 ** 递归通配符）。
 *  方言约定（与旧实现完全兼容，不破坏既有 361 个单测口径）：
 *  - '*'     ：匹配任意字符（包括 '/'），贪心枚举 + 回溯；
 *  - '**'    ：连续两个以上 '*' 视为递归通配符；
 *      · 独立段或后随 '/' 时，「双星加斜线」作为一个单元匹配"零层或多层目录"
 *        （即匹配空串，或任意以 '/' 结尾的前缀）；
 *      · 结尾的 '**' 匹配任意剩余串（含空）；
 *      · 夹在段中间（如 a**b）退化为普通 '*'；
 *  - '?'     ：匹配单个任意字符；'[]' 字符类复用 matchCharClass。
 *  dead[] 记忆化 (pattern_pos, text_pos) 已失败组合，防止病态模式指数爆炸。 */
static bool mgRec(const std::string& pat, size_t p,
                  const std::string& txt, size_t t,
                  std::vector<uint8_t>& dead) {
    const size_t W = txt.size() + 1;
    while (p < pat.size()) {
        if (dead[p * W + t]) return false;
        const char c = pat[p];
        if (c == '*') {
            size_t q = p;
            while (q < pat.size() && pat[q] == '*') ++q;   /* 吞掉连续 '*' */
            const bool isDbl = (q - p) >= 2;
            if (isDbl && q < pat.size() && pat[q] == '/') {
                /* 「双星加斜线」单元：匹配 "" 或任意以 '/' 结尾的前缀 */
                const size_t next = q + 1;
                if (mgRec(pat, next, txt, t, dead)) return true;
                for (size_t k = t; k < txt.size(); ++k) {
                    if (txt[k] == '/' && mgRec(pat, next, txt, k + 1, dead)) return true;
                }
            } else {
                /* 单 '*' 或结尾 '**'：匹配任意剩余串 */
                for (size_t k = t; k <= txt.size(); ++k) {
                    if (mgRec(pat, q, txt, k, dead)) return true;
                }
            }
            dead[p * W + t] = 1;
            return false;
        } else if (c == '?') {
            if (t >= txt.size()) return false;
            ++p; ++t;
        } else if (c == '[') {
            if (t >= txt.size()) return false;
            size_t next = p;
            if (!matchCharClass(pat, next, txt[t])) { dead[p * W + t] = 1; return false; }
            p = next; ++t;
        } else {
            if (t >= txt.size() || txt[t] != c) { dead[p * W + t] = 1; return false; }
            ++p; ++t;
        }
    }
    return t == txt.size();
}

bool matchGlob(const std::string& pattern, const std::string& text) {
    /* 快路径：无 '*' 时退化为逐字符比较（保留旧实现的语义） */
    const size_t W = text.size() + 1;
    std::vector<uint8_t> dead((pattern.size() + 1) * W, 0);
    return mgRec(pattern, 0, text, 0, dead);
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

