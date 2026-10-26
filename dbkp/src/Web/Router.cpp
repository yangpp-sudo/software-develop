/* ============================================================================
 *  Router.cpp  -- 见 Router.h
 * ==========================================================================*/
#include "Web/Router.h"

namespace DBKP {

void CRouter::splitPattern(const std::string& pattern, std::vector<std::string>& segs) {
    segs.clear();
    std::size_t pos = 0;
    if (pos < pattern.size() && pattern[pos] == '/') ++pos;
    while (pos <= pattern.size()) {
        std::size_t slash = pattern.find('/', pos);
        if (slash == std::string::npos) slash = pattern.size();
        const std::string seg = pattern.substr(pos, slash - pos);
        if (!seg.empty()) segs.push_back(seg);
        if (slash >= pattern.size()) break;
        pos = slash + 1;
    }
}

bool CRouter::matchSegs(const std::vector<std::string>& segs,
                        const std::vector<std::string>& pathSegs,
                        CHttpRequest::TParams& params) {
    for (std::size_t i = 0; i < segs.size(); ++i) {
        const std::string& p = segs[i];
        if (p == "*") return true;                       /* 尾部通配：剩下的都算命中 */
        if (i >= pathSegs.size()) return false;
        const std::string& v = pathSegs[i];
        if (p.size() > 1 && p[0] == ':') {
            if (v.empty()) return false;
            params[p.substr(1)] = v;
        } else if (p != v) {
            return false;
        }
    }
    /* 没有通配时，段数必须严格相等：/api/jobs 不该匹配 /api/jobs/9 */
    return segs.size() == pathSegs.size();
}

void CRouter::add(const std::string& method, const std::string& pattern, Handler handler) {
    Route r;
    splitPattern(pattern, r.segs);
    r.handler = handler;
    m_byMethod[CHttpRequest::methodUpper(method)].push_back(r);
    ++m_total;
}

bool CRouter::pathRegistered(const std::string& path) const {
    std::vector<std::string> pathSegs;
    splitPattern(path, pathSegs);
    for (std::map<std::string, std::vector<Route> >::const_iterator mi = m_byMethod.begin();
         mi != m_byMethod.end(); ++mi) {
        for (std::size_t i = 0; i < mi->second.size(); ++i) {
            CHttpRequest::TParams tmp;
            if (matchSegs(mi->second[i].segs, pathSegs, tmp)) return true;
        }
    }
    return false;
}

bool CRouter::dispatch(CHttpRequest& req, CHttpResponse& res) const {
    std::vector<std::string> pathSegs;
    splitPattern(req.path, pathSegs);

    std::map<std::string, std::vector<Route> >::const_iterator it = m_byMethod.find(req.method);
    if (it != m_byMethod.end()) {
        for (std::size_t i = 0; i < it->second.size(); ++i) {
            req.params.clear();                      /* 同一连接复用 req：必须清干净 */
            if (matchSegs(it->second[i].segs, pathSegs, req.params)) {
                res = it->second[i].handler(req);
                return true;
            }
        }
    }
    if (pathRegistered(req.path)) {                  /* 路径有、方法不对 -> 405 */
        res = CHttpResponse::jsonError(405, "method " + req.method + " not allowed for " + req.path, 405);
        res.setHeader("Allow", "GET, POST, PUT, DELETE, OPTIONS");
        return true;
    }
    return false;
}

} /* namespace DBKP */
