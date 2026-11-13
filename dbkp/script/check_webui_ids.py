# ============================================================================
#  check_webui_ids.py —— web/index.html 的静态自检（无 Node 环境的替代品）
#
#  仓库里原有的 script/check_webui.js 要 node 才能跑；本机没装 node，所以用这个
#  Python 版做同一件事中"够用"的子集，改前端后 30 秒就能过一遍：
#    1) JS 里 $('someId') 引用的 id 必须在 HTML 中真实存在（拼错、改名漏改直接暴露）
#    2) 顶层 const/let 是否重复声明（同名覆盖是运行时踩坑的高发点）
#    3) {} () [] 是否配平（大段编辑把函数体截断时的 sanity check）
#    4) 已废弃的旧控件 id 是否仍被引用（重构残留）
#  行为层面的验证仍由 script/smoke_web.ps1 与 script/web_full_test.ps1 负责。
#
#  用法（在 dbkp 目录下执行）：
#      python script/check_webui_ids.py web/index.html
#  退出码：0 干净；1 有悬空引用或旧 id 残留。
# ===========================================================================
import re
import sys

# 早期界面用过的控件名，重构后不应再出现在 JS 里
LEGACY_IDS = ('exclude', 'includePaths', 'nameGlobs', 'nameRejects',
              'typeAllow', 'typeDeny')


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else 'web/index.html'
    with open(path, encoding='utf-8') as f:
        html = f.read()
    m = re.search(r'<script>([\s\S]*?)</script>', html)
    if not m:
        print('no <script>')
        return 1
    src = m.group(1)

    ids = set(re.findall(r'id="([\w-]+)"', html))
    refs = sorted(set(re.findall(r"\$\('([\w-]+)'\)", src)))
    dangling = [r for r in refs if r not in ids]
    print('refs=%d htmlIds=%d dangling=%s' %
          (len(refs), len(ids), dangling or 'none'))

    names = {}
    for line in src.splitlines():
        mm = re.match(r'(?:const|let)\s+([A-Za-z_$][\w$]*)\s*=', line)
        if mm:
            names.setdefault(mm.group(1), 0)
            names[mm.group(1)] += 1
    dup = {k: v for k, v in names.items() if v > 1}
    print('dup top-level decl:', dup or 'none')

    for a, b in (('{', '}'), ('(', ')'), ('[', ']')):
        print('%s%s balance delta=%d' % (a, b, src.count(a) - src.count(b)))

    old = [x for x in LEGACY_IDS if "$('" + x + "'" in src]
    print('old ids still referenced:', old or 'none')

    return 1 if (dangling or old) else 0


if __name__ == '__main__':
    sys.exit(main())
