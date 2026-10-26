/* ============================================================================
 *  Json.h  -- 极简 JSON 解析/序列化（自实现，不依赖任何第三方库）
 *
 *  为什么自己写：课程约束"算法与协议自实现"，而 Web 层只需要
 *  JSON 的读写，不需要 schema/反射等复杂能力，~400 行即可覆盖，
 *  并且可以像其它模块一样被单元测试直接驱动（无需起端口）。
 *
 *  设计取舍：
 *    - 对象成员用 vector<pair> 保存**插入顺序**，序列化后可读、可做快照 diff
 *    - 数字统一用 int64_t / double 两种 kind，避免"JSON 里全是 double"的精度坑
 *    - 解析严格：拒绝多余尾随内容、非法转义、控制字符；错误信息带字节偏移
 *    - 字符串一律按 UTF-8 处理；\uXXXX 会解码成 UTF-8（中文文件名不能坏）
 * ==========================================================================*/
#ifndef DBKP_WEB_JSON_H
#define DBKP_WEB_JSON_H

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace DBKP {

class CJsonValue {
public:
    enum Kind { KIND_NULL, KIND_BOOL, KIND_INT, KIND_DOUBLE, KIND_STRING,
                KIND_ARRAY, KIND_OBJECT };

    CJsonValue() : m_kind(KIND_NULL), m_bool(false), m_num(0) {}
    explicit CJsonValue(Kind k) : m_kind(k), m_bool(false), m_num(0) {}

    /* ------------------------------------------------------------ 构造 */
    static CJsonValue makeObject();
    static CJsonValue makeArray();
    static CJsonValue makeString(const std::string& s);
    static CJsonValue makeInt(int64_t v);
    static CJsonValue makeDouble(double v);
    static CJsonValue makeBool(bool v);

    /* ------------------------------------------------------------ 查询 */
    Kind kind() const { return m_kind; }
    bool isNull()   const { return m_kind == KIND_NULL; }
    bool isBool()   const { return m_kind == KIND_BOOL; }
    bool isInt()    const { return m_kind == KIND_INT; }
    bool isDouble() const { return m_kind == KIND_DOUBLE; }
    bool isNumber() const { return m_kind == KIND_INT || m_kind == KIND_DOUBLE; }
    bool isString() const { return m_kind == KIND_STRING; }
    bool isArray()  const { return m_kind == KIND_ARRAY; }
    bool isObject() const { return m_kind == KIND_OBJECT; }

    bool        asBool(bool def = false)     const;
    int64_t     asInt(int64_t def = 0)       const;
    double      asDouble(double def = 0.0)   const;
    std::string asString(const std::string& def = std::string()) const;

    /* ------------------------------------------------------ 对象访问 */
    /** 取成员；不存在则按 kind 自动创建（仅对 object 调用） */
    CJsonValue& operator[](const std::string& key);
    const CJsonValue* find(const std::string& key) const;
    bool has(const std::string& key) const { return find(key) != nullptr; }
    /** 便捷读取：类型不符/缺失返回 false，out 不写 */
    bool getString(const std::string& key, std::string& out) const;
    bool getInt(const std::string& key, int64_t& out) const;
    bool getBool(const std::string& key, bool& out) const;
    const CJsonValue& member(const std::string& key, const CJsonValue& def) const;
    std::size_t memberCount() const { return m_members.size(); }
    const std::vector<std::pair<std::string, CJsonValue> >& members() const { return m_members; }
    void remove(const std::string& key);
    void removeNulls();                            /* 构造响应时去掉未填字段 */

    /* ------------------------------------------------------ 数组访问 */
    void push_back(const CJsonValue& v);
    std::size_t size() const { return m_kind == KIND_ARRAY ? m_items.size() : m_members.size(); }
    const CJsonValue& at(std::size_t i) const;
    const CJsonValue& at(const std::string& key) const;  /* 缺字段返回 null 单例，不抛 */
    const std::vector<CJsonValue>& items() const { return m_items; }

    /* -------------------------------------------------------- 序列化 */
    /** indent>0 时美化输出（配置样例/调试用） */
    std::string dump(int indent = 0) const;
    static std::string escape(const std::string& text);

    /* ---------------------------------------------------------- 解析 */
    /** 解析整段文本；失败时 err 带偏移，out 保持默认值 */
    static bool parse(const std::string& text, CJsonValue& out, std::string& err);

private:
    void dumpTo(std::string& oss, int indent, int depth) const;
    bool parseValue(const std::string& s, std::size_t& i, CJsonValue& out, std::string& err);
    bool parseStringRaw(const std::string& s, std::size_t& i, std::string& out, std::string& err);
    bool parseNumberRaw(const std::string& s, std::size_t& i, CJsonValue& out, std::string& err);
    static void skipWs(const std::string& s, std::size_t& i);
    static void appendUtf8(std::string& out, unsigned cp);

    Kind        m_kind;
    bool        m_bool = false;
    double      m_dnum = 0.0;   /* 显式初始化：避免 -Wmaybe-uninitialized，
                                   也避免赋值拷贝时把脏值带进对象 */
    int64_t     m_num  = 0;
    std::string m_str;
    std::vector<CJsonValue> m_items;
    std::vector<std::pair<std::string, CJsonValue> > m_members;
};

} /* namespace DBKP */

#endif /* DBKP_WEB_JSON_H */
