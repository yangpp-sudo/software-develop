/* ============================================================================
 *  Json.cpp  -- 见 Json.h 的设计说明
 * ==========================================================================*/
#include "Web/Json.h"

#include <cmath>
#include <cstdio>
#include <cstdlib>

namespace DBKP {

namespace {

const int kMaxDepth = 64;

void indentTo(std::string& oss, int indent, int depth) {
    if (indent <= 0) return;
    oss.append(static_cast<std::size_t>(indent * depth), ' ');
}

bool isWs(char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; }
bool isDigit(char c) { return c >= '0' && c <= '9'; }

} /* anonymous namespace */

/* ------------------------------------------------------------ 构造函数 */
CJsonValue CJsonValue::makeObject() { return CJsonValue(KIND_OBJECT); }
CJsonValue CJsonValue::makeArray()  { return CJsonValue(KIND_ARRAY); }

CJsonValue CJsonValue::makeString(const std::string& s) {
    CJsonValue v(KIND_STRING);
    v.m_str = s;
    return v;
}
CJsonValue CJsonValue::makeInt(int64_t n) {
    CJsonValue v(KIND_INT);
    v.m_num = n;
    return v;
}
CJsonValue CJsonValue::makeDouble(double d) {
    CJsonValue v(KIND_DOUBLE);
    v.m_dnum = d;
    return v;
}
CJsonValue CJsonValue::makeBool(bool b) {
    CJsonValue v(KIND_BOOL);
    v.m_bool = b;
    return v;
}

/* -------------------------------------------------------------- 读取值 */
bool CJsonValue::asBool(bool def) const {
    if (m_kind == KIND_BOOL) return m_bool;
    if (m_kind == KIND_INT)  return m_num != 0;
    return def;
}

int64_t CJsonValue::asInt(int64_t def) const {
    if (m_kind == KIND_INT)    return m_num;
    if (m_kind == KIND_DOUBLE) return static_cast<int64_t>(m_dnum);
    if (m_kind == KIND_BOOL)   return m_bool ? 1 : 0;
    if (m_kind == KIND_STRING) {
        /* 浏览器表单里数字常是字符串：宽容一次 */
        char* end = nullptr;
        const long long v = std::strtoll(m_str.c_str(), &end, 10);
        if (end && end != m_str.c_str()) return static_cast<int64_t>(v);
    }
    return def;
}

double CJsonValue::asDouble(double def) const {
    if (m_kind == KIND_DOUBLE) return m_dnum;
    if (m_kind == KIND_INT)    return static_cast<double>(m_num);
    return def;
}

std::string CJsonValue::asString(const std::string& def) const {
    if (m_kind == KIND_STRING) return m_str;
    if (m_kind == KIND_INT)    return std::to_string(m_num);
    if (m_kind == KIND_BOOL)   return m_bool ? "true" : "false";
    return def;
}

/* ---------------------------------------------------------- 对象访问 */
CJsonValue& CJsonValue::operator[](const std::string& key) {
    if (m_kind != KIND_OBJECT) { m_kind = KIND_OBJECT; m_items.clear(); }
    for (std::size_t i = 0; i < m_members.size(); ++i)
        if (m_members[i].first == key) return m_members[i].second;
    m_members.push_back(std::make_pair(key, CJsonValue()));
    return m_members.back().second;
}

const CJsonValue* CJsonValue::find(const std::string& key) const {
    for (std::size_t i = 0; i < m_members.size(); ++i)
        if (m_members[i].first == key) return &m_members[i].second;
    return nullptr;
}

bool CJsonValue::getString(const std::string& key, std::string& out) const {
    const CJsonValue* v = find(key);
    if (!v || !v->isString()) return false;
    out = v->m_str;
    return true;
}

bool CJsonValue::getInt(const std::string& key, int64_t& out) const {
    const CJsonValue* v = find(key);
    if (!v || !v->isNumber()) return false;
    out = v->asInt(0);
    return true;
}

bool CJsonValue::getBool(const std::string& key, bool& out) const {
    const CJsonValue* v = find(key);
    if (!v || !(v->isBool() || v->isNumber())) return false;
    out = v->asBool(false);
    return true;
}

const CJsonValue& CJsonValue::member(const std::string& key, const CJsonValue& def) const {
    const CJsonValue* v = find(key);
    return v ? *v : def;
}

void CJsonValue::remove(const std::string& key) {
    for (std::size_t i = 0; i < m_members.size(); ++i) {
        if (m_members[i].first == key) { m_members.erase(m_members.begin() + i); return; }
    }
}

/* ---------------------------------------------------------- 数组访问 */
void CJsonValue::push_back(const CJsonValue& v) {
    if (m_kind != KIND_ARRAY) { m_kind = KIND_ARRAY; m_members.clear(); }
    m_items.push_back(v);
}

const CJsonValue& CJsonValue::at(std::size_t i) const {
    static const CJsonValue kNull;
    if (m_kind == KIND_ARRAY && i < m_items.size()) return m_items[i];
    return kNull;
}

const CJsonValue& CJsonValue::at(const std::string& key) const {
    static const CJsonValue kNull;
    const CJsonValue* v = find(key);
    return v ? *v : kNull;     /* handler 里 j.at("data").at("state") 这类链式取值不炸 */
}

void CJsonValue::removeNulls() {
    if (m_kind != KIND_OBJECT) return;
    for (std::size_t i = 0; i < m_members.size(); ) {
        if (m_members[i].second.isNull()) m_members.erase(m_members.begin() + i);
        else ++i;
    }
}

/* ------------------------------------------------------------ 序列化 */
std::string CJsonValue::escape(const std::string& text) {
    std::string out;
    out.reserve(text.size() + 8);
    for (std::size_t i = 0; i < text.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(text[i]);
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b";  break;
        case '\f': out += "\\f";  break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
            if (c < 0x20) {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                out += buf;
            } else {
                out += static_cast<char>(c);   /* UTF-8 字节原样输出 */
            }
        }
    }
    return out;
}

void CJsonValue::dumpTo(std::string& oss, int indent, int depth) const {
    const bool pretty = indent > 0;
    switch (m_kind) {
    case KIND_NULL: oss += "null"; break;
    case KIND_BOOL: oss += m_bool ? "true" : "false"; break;
    case KIND_INT:  oss += std::to_string(m_num); break;
    case KIND_DOUBLE: {
        char buf[40];
        std::snprintf(buf, sizeof(buf), "%.15g", m_dnum);
        oss += buf;
        break;
    }
    case KIND_STRING: oss += '"'; oss += escape(m_str); oss += '"'; break;
    case KIND_ARRAY:
        if (m_items.empty()) { oss += "[]"; break; }
        oss += '[';
        for (std::size_t i = 0; i < m_items.size(); ++i) {
            if (i) oss += ',';
            if (pretty) { oss += '\n'; indentTo(oss, indent, depth + 1); }
            m_items[i].dumpTo(oss, indent, depth + 1);
        }
        if (pretty) { oss += '\n'; indentTo(oss, indent, depth); }
        oss += ']';
        break;
    case KIND_OBJECT:
        if (m_members.empty()) { oss += "{}"; break; }
        oss += '{';
        for (std::size_t i = 0; i < m_members.size(); ++i) {
            if (i) oss += ',';
            if (pretty) { oss += '\n'; indentTo(oss, indent, depth + 1); }
            oss += '"'; oss += escape(m_members[i].first); oss += '"';
            oss += ':';
            if (pretty) oss += ' ';
            m_members[i].second.dumpTo(oss, indent, depth + 1);
        }
        if (pretty) { oss += '\n'; indentTo(oss, indent, depth); }
        oss += '}';
        break;
    }
}

std::string CJsonValue::dump(int indent) const {
    std::string oss;
    dumpTo(oss, indent, 0);
    return oss;
}

void CJsonValue::skipWs(const std::string& s, std::size_t& i) {
    while (i < s.size() && isWs(s[i])) ++i;
}

void CJsonValue::appendUtf8(std::string& out, unsigned cp) {
    if (cp < 0x80) {
        out += static_cast<char>(cp);
    } else if (cp < 0x800) {
        out += static_cast<char>(0xC0 | (cp >> 6));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
        out += static_cast<char>(0xE0 | (cp >> 12));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    } else {
        out += static_cast<char>(0xF0 | (cp >> 18));
        out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    }
}

bool CJsonValue::parseStringRaw(const std::string& s, std::size_t& i,
                                std::string& out, std::string& err) {
    if (i >= s.size() || s[i] != '"') { err = "expected string"; return false; }
    ++i;
    out.clear();
    while (i < s.size()) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (c == '"') { ++i; return true; }
        if (c < 0x20) { err = "raw control char in string"; return false; }
        if (c != '\\') { out += static_cast<char>(c); ++i; continue; }
        ++i;
        if (i >= s.size()) break;
        const char e = s[i++];
        switch (e) {
        case '"': out += '"'; break;
        case '\\': out += '\\'; break;
        case '/': out += '/'; break;
        case 'b': out += '\b'; break;
        case 'f': out += '\f'; break;
        case 'n': out += '\n'; break;
        case 'r': out += '\r'; break;
        case 't': out += '\t'; break;
        case 'u': {
            if (i + 4 > s.size()) { err = "truncated \\u"; return false; }
            unsigned cp = 0;
            bool bad = false;
            for (int k = 0; k < 4; ++k) {
                const char h = s[i++];
                unsigned d;
                if (h >= '0' && h <= '9') d = static_cast<unsigned>(h - '0');
                else if (h >= 'a' && h <= 'f') d = static_cast<unsigned>(h - 'a') + 10;
                else if (h >= 'A' && h <= 'F') d = static_cast<unsigned>(h - 'A') + 10;
                else { bad = true; break; }
                cp = cp * 16u + d;
            }
            if (bad) { err = "bad hex digit in \\u"; return false; }
            /* 代理对 \uD834\uDD1E -> U+1D11E：不让一个 emoji 拖垮整个请求 */
            if (cp >= 0xD800u && cp <= 0xDBFFu && i + 6 <= s.size() &&
                s[i] == '\\' && s[i + 1] == 'u') {
                unsigned lo = 0;
                std::size_t save = i;
                i += 2;
                bool ok = true;
                for (int k = 0; k < 4; ++k) {
                    const char h = s[i++];
                    unsigned d;
                    if (h >= '0' && h <= '9') d = static_cast<unsigned>(h - '0');
                    else if (h >= 'a' && h <= 'f') d = static_cast<unsigned>(h - 'a') + 10;
                    else if (h >= 'A' && h <= 'F') d = static_cast<unsigned>(h - 'A') + 10;
                    else { ok = false; break; }
                    lo = lo * 16u + d;
                }
                if (ok && lo >= 0xDC00u && lo <= 0xDFFFu)
                    cp = 0x10000u + ((cp - 0xD800u) << 10) + (lo - 0xDC00u);
                else { i = save; cp = 0xFFFDu; }
            } else if (cp >= 0xD800u && cp <= 0xDFFFu) {
                cp = 0xFFFDu;               /* 孤立代理项 -> 替换字符 */
            }
            appendUtf8(out, cp);
            break;
        }
        default: err = std::string("bad escape \\") + e; return false;
        }
    }
    err = "unterminated string";
    return false;
}

bool CJsonValue::parseNumberRaw(const std::string& s, std::size_t& i,
                                CJsonValue& out, std::string& err) {
    const std::size_t start = i;
    bool dbl = false;
    if (i < s.size() && (s[i] == '-' || s[i] == '+')) ++i;
    while (i < s.size()) {
        const char c = s[i];
        if (isDigit(c)) { ++i; continue; }
        if (c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') { dbl = true; ++i; continue; }
        break;
    }
    if (i == start) { err = "bad number"; return false; }
    const std::string text = s.substr(start, i - start);
    char* end = nullptr;
    if (!dbl) {
        const long long v = std::strtoll(text.c_str(), &end, 10);
        if (end && *end == '\0') { out = CJsonValue::makeInt(static_cast<int64_t>(v)); return true; }
    }
    end = nullptr;
    const double d = std::strtod(text.c_str(), &end);
    if (!end || end == text.c_str()) { err = "bad number"; return false; }
    out = CJsonValue::makeDouble(d);
    return true;
}

bool CJsonValue::parseValue(const std::string& s, std::size_t& i,
                            CJsonValue& out, std::string& err) {
    skipWs(s, i);
    if (i >= s.size()) { err = "unexpected end"; return false; }
    const char c = s[i];
    if (c == '{') {
        ++i;
        out = CJsonValue(KIND_OBJECT);
        skipWs(s, i);
        if (i < s.size() && s[i] == '}') { ++i; return true; }
        int count = 0;
        for (;;) {
            if (++count > kMaxDepth * 64) { err = "object too large"; return false; }
            std::string key;
            skipWs(s, i);
            if (!parseStringRaw(s, i, key, err)) return false;
            skipWs(s, i);
            if (i >= s.size() || s[i] != ':') { err = "expected ':'"; return false; }
            ++i;
            CJsonValue val;
            if (!parseValue(s, i, val, err)) return false;
            out[key] = val;
            skipWs(s, i);
            if (i >= s.size()) { err = "unterminated object"; return false; }
            if (s[i] == ',') { ++i; continue; }
            if (s[i] == '}') { ++i; return true; }
            err = "expected ',' or '}'";
            return false;
        }
    }
    if (c == '[') {
        ++i;
        out = CJsonValue(KIND_ARRAY);
        skipWs(s, i);
        if (i < s.size() && s[i] == ']') { ++i; return true; }
        int count = 0;
        for (;;) {
            if (++count > kMaxDepth * 64) { err = "array too large"; return false; }
            CJsonValue val;
            if (!parseValue(s, i, val, err)) return false;
            out.push_back(val);
            skipWs(s, i);
            if (i >= s.size()) { err = "unterminated array"; return false; }
            if (s[i] == ',') { ++i; continue; }
            if (s[i] == ']') { ++i; return true; }
            err = "expected ',' or ']'";
            return false;
        }
    }
    if (c == '"') {
        std::string str;
        if (!parseStringRaw(s, i, str, err)) return false;
        out = CJsonValue::makeString(str);
        return true;
    }
    if (s.compare(i, 4, "true") == 0)  { i += 4; out = CJsonValue::makeBool(true);  return true; }
    if (s.compare(i, 5, "false") == 0) { i += 5; out = CJsonValue::makeBool(false); return true; }
    if (s.compare(i, 4, "null") == 0)  { i += 4; out = CJsonValue();                return true; }
    return parseNumberRaw(s, i, out, err);
}

bool CJsonValue::parse(const std::string& text, CJsonValue& out, std::string& err) {
    std::size_t i = 0;
    /* 允许 BOM：记事本保存过的配置文件很常见 */
    if (text.size() >= 3 && static_cast<unsigned char>(text[0]) == 0xEF &&
        static_cast<unsigned char>(text[1]) == 0xBB &&
        static_cast<unsigned char>(text[2]) == 0xBF)
        i = 3;
    if (!out.parseValue(text, i, out, err)) {
        char buf[48];
        std::snprintf(buf, sizeof(buf), " at offset %llu",
                      static_cast<unsigned long long>(i));
        err = "json parse error: " + err + buf;
        return false;
    }
    skipWs(text, i);
    if (i != text.size()) { err = "json parse error: trailing content"; return false; }
    return true;
}

} /* namespace DBKP */
