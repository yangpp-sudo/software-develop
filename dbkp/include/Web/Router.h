/* ============================================================================
 *  Router.h  -- 极简路由表：把 "POST /api/jobs/:id/cancel" 分发到处理函数
 *
 *  设计：路径按 '/' 切成段，段的匹配规则三种——
 *      普通段   必须字面相等
 *      ":name"  匹配任意一段，并写进 req.params[name]
 *      "*"      通配剩余所有段（放在最后一段时生效，用于静态资源兜底）
 *  没做正则/前缀树：接口总共十来个，线性扫描足够，代码也更容易在答辩时讲清。
 * ==========================================================================*/
#ifndef DBKP_WEB_ROUTER_H
#define DBKP_WEB_ROUTER_H

#include "Web/Http.h"

#include <functional>
#include <map>
#include <string>
#include <vector>

namespace DBKP {

class CRouter {
public:
    typedef std::function<CHttpResponse(const CHttpRequest&)> Handler;

    void add(const std::string& method, const std::string& pattern, Handler handler);

    /* 便于书写的别名；del 而不是 remove，避免和 std 概念混淆 */
    void get(const std::string& pattern, Handler h)   { add("GET", pattern, h); }
    void post(const std::string& pattern, Handler h)  { add("POST", pattern, h); }
    void put(const std::string& pattern, Handler h)   { add("PUT", pattern, h); }
    void del(const std::string& pattern, Handler h)   { add("DELETE", pattern, h); }

    /** 命中则填充 params 并调用 handler，返回 true。
     *  req 必须是非常量引用：路由要把 ":id" 之类的捕获写进 req.params。
     *  未命中返回 false（调用方决定 404 还是走静态文件）。
     *  路径存在但方法不匹配时返回 405 —— 浏览器预检和误用 POST 时能给出有用提示。 */
    /* req 必须是非常量引用：命中时要把 ":id" 捕获写进 req.params */
    bool dispatch(CHttpRequest& req, CHttpResponse& res) const;

    /** 只判断"这个路径有没有注册过任何方法"，用于给出 405 而不是 404 */
    bool pathRegistered(const std::string& path) const;

    std::size_t routeCount() const { return m_total; }

private:
    struct Route {
        std::vector<std::string> segs;
        Handler                  handler;
    };
    /* method -> routes；用 map 而不是 vector 是为了 dispatch 时先按方法缩小范围 */
    std::map<std::string, std::vector<Route> > m_byMethod;
    std::size_t m_total = 0;

    static void splitPattern(const std::string& pattern, std::vector<std::string>& segs);
    static bool matchSegs(const std::vector<std::string>& segs,
                          const std::vector<std::string>& pathSegs,
                          CHttpRequest::TParams& params);
};

} /* namespace DBKP */

#endif /* DBKP_WEB_ROUTER_H */
