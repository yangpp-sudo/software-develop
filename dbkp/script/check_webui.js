/* ============================================================================
 *  check_webui.js —— 前端脚本静态自检（node script/check_webui.js）
 *
 *  不启动浏览器，也不改构建流程：把 web/index.html 里 <script> 那段取出来，
 *  喂一套最小 DOM/fetch 桩执行一遍，再断言路径 helper 的行为。它挡的是两类
 *  最容易溜过去的问题：整段 JS 有语法/引用错误，以及 browse 弹窗的路径拼接
 *  想当然（盘根、结尾斜杠、"." 这些边界）。真正的端到端仍由 smoke_web.ps1 负责。
 * ==========================================================================*/
const fs = require('fs');
const path = require('path');

const target = process.argv[2] || path.join(__dirname, '..', 'web', 'index.html');
const html = fs.readFileSync(target, 'utf8');
const m = html.match(/<script>([\s\S]*?)<\/script>/);
if (!m) { console.error('没找到 <script> 段'); process.exit(1); }
const src = m[1];

const mkEl = () => ({
  textContent: '', value: '', innerHTML: '', checked: false, dataset: {}, style: {},
  classList: { add() {}, remove() {}, contains: () => true },
  appendChild() {}, querySelectorAll: () => [], querySelector: () => null,
  addEventListener() {}, focus() {},
});
global.window = global;
global.document = {
  getElementById: () => mkEl(), addEventListener() {}, createElement: () => mkEl(),
  querySelectorAll: () => [], body: mkEl(),
};
global.sessionStorage = { getItem: () => '', setItem() {}, removeItem() {} };
global.location = { protocol: 'http:', href: 'http://127.0.0.1:8080/' };
global.fetch = async () => ({ ok: true, status: 200, text: async () => '{"code":0,"data":{}}' });
global.EventSource = function () { this.close = () => {}; this.addEventListener = () => {}; };

let api;
try {
  api = new Function(src +
    '\nreturn { normSep, trimSep, joinOf, parentOf, browseSeed, browseStart, isDirEntry, withinRoot, '
    + 'applyConfig, escapeHtml, fmtBytes };')();
} catch (e) {
  console.error('  [FAIL] 页面脚本执行出错：' + e.message);
  process.exit(1);
}

let fail = 0;
const eq = (name, got, want) => {
  const ok = got === want;
  if (!ok) fail++;
  console.log((ok ? '  [OK]   ' : '  [FAIL] ') + name + ' -> ' + JSON.stringify(got) +
              (ok ? '' : ' 期望 ' + JSON.stringify(want)));
};

console.log('== 前端脚本自检 ==');
eq("trimSep('D:/a/')", api.trimSep('D:/a/'), 'D:/a');
eq("trimSep('D:\\\\a\\\\b')", api.trimSep('D:\\a\\b'), 'D:/a/b');
eq("trimSep('/')", api.trimSep('/'), '/');
eq("joinOf('D:/a','b.txt')", api.joinOf('D:/a', 'b.txt'), 'D:/a/b.txt');
eq("joinOf('D:/','a')", api.joinOf('D:/', 'a'), 'D:/a');
eq("joinOf('.','src')", api.joinOf('.', 'src'), 'src');
eq("joinOf('/','etc')", api.joinOf('/', 'etc'), '/etc');
eq("parentOf('D:/a/b')", api.parentOf('D:/a/b'), 'D:/a');
eq("parentOf('D:/a')", api.parentOf('D:/a'), 'D:/');
eq("parentOf('D:/')", api.parentOf('D:/'), 'D:/');
eq("parentOf('/')", api.parentOf('/'), '/');
eq("parentOf('.')", api.parentOf('.'), '.');
eq("parentOf('src')", api.parentOf('src'), '.');
eq("browseSeed('')", api.browseSeed(''), '.');                 /* 没配 dataRoot 时用 \".\" */
eq("browseSeed('D:/a/b.dbkp')", api.browseSeed('D:/a/b.dbkp'), 'D:/a');
eq("browseSeed('D:/a/src')", api.browseSeed('D:/a/src'), 'D:/a/src');
eq("browseSeed('out/rel.dbkp')", api.browseSeed('out/rel.dbkp'), 'out');
eq('escapeHtml 转义尖括号', api.escapeHtml('<script>'), '&lt;script&gt;');

/* 页面上的 id 是字符串硬引用的，桩环境查不出来：把所有 $('xxx') 提到的 id
 * 跟 HTML 里真实存在的 id 对一遍，防止改按钮名字时漏改 JS。 */
const htmlIds = new Set();
for (const m of html.matchAll(/id="([\w-]+)"/g)) htmlIds.add(m[1]);
const refs = [...new Set([...src.matchAll(/\$\('([\w-]+)'\)/g)].map((m) => m[1]))];
const dangling = refs.filter((id) => !htmlIds.has(id));
console.log('  （对照了 ' + refs.length + ' 个不同 id 引用 / ' + htmlIds.size + ' 个页面 id）');
eq('每个 $(id) 都能在页面里找到', dangling.length ? '缺失: ' + dangling.join(',') : 'ok', 'ok');
eq('检查并非空跑（引用数 > 20）', refs.length > 20 ? 'ok' : '只有 ' + refs.length, 'ok');

/* 目录判定：这轮线上真 bug 就是服务端发 isDir、前端读 dir —— 字段名一失配，
   目录全被渲染成“文件”，点只会选中、永远进不去下一层，界面看着像卡死。 */
eq('isDirEntry 认 isDir', api.isDirEntry({ isDir: true }), true);
eq('isDirEntry 认 dir', api.isDirEntry({ dir: true }), true);
eq("isDirEntry 认 type='D'", api.isDirEntry({ type: 'D' }), true);
eq('isDirEntry 不认普通文件', api.isDirEntry({ isDir: false, dir: false, type: '-' }), false);

/* 数据根边界必须由前端挡住：游标一旦跑到根外，之后每次点击都是 403。 */
api.applyConfig({ algorithms: ['huffman'], defaultAlgorithm: 'huffman', dataRoot: 'D:/root' });
eq('有 dataRoot 时 browseStart 用它', api.browseStart(), 'D:/root');
eq("withinRoot('D:/root/sub')", api.withinRoot('D:/root/sub'), true);
eq("withinRoot('D:/root')", api.withinRoot('D:/root'), true);
eq("withinRoot('D:/other')", api.withinRoot('D:/other'), false);
eq("withinRoot('D:/rootx') 不做前缀糊弄", api.withinRoot('D:/rootx'), false);

/* 服务端 browse 实际发出的字段名要和前端读的对上，单方面改名直接红。 */
const cpp = fs.readFileSync(path.join(__dirname, '..', 'src', 'Web', 'Api.cpp'), 'utf8');
const bFrom = cpp.indexOf('CHttpResponse hBrowse(');
const bTo = cpp.indexOf('CHttpResponse hStat(', bFrom);
if (bFrom < 0 || bTo < 0) { console.log('  [FAIL] Api.cpp 里没定位到 hBrowse/hStat'); fail++; }
else {
  const seg = cpp.slice(bFrom, bTo);
  ['name', 'type', 'isDir', 'dir', 'size', 'mtime', 'path', 'parent', 'dataRoot', 'total',
   'truncated', 'entries'].forEach((k) =>
     eq('browse 服务端发字段 ' + k, seg.includes('"' + k + '"') ? 'ok' : '缺失', 'ok'));
}
/* CSS 声明顺序坑：`.hide { display:none }` 与 `.mask { display:flex }` 特异性
   相同（都是单个 class），后声明者赢——`class="mask hide"` 的浏览弹窗于是
   一加载就铺满屏幕，JS 加 hide 也关不掉。DOM 桩看不见样式，只能静态比顺序。 */
const style = (html.match(/<style>([\s\S]*?)<\/style>/i) || [, ''])[1]
  .replace(/\/\*[\s\S]*?\*\//g, '');
const hideAt = style.search(/(?:^|[;}>\s])\.hide\s*\{/);
eq('页面 <style> 里找得到 .hide 规则', hideAt >= 0 ? 'ok' : '没找到', 'ok');
const hideBody = hideAt >= 0 ? style.slice(hideAt, style.indexOf('}', hideAt) + 1) : '';
const winsByImportant = /display\s*:\s*none\s*!important/.test(hideBody);
/* 和 hide 并存的组件类：HTML 里写死的，以及 JS 动态 toggle('hide') 的那个元素 */
const co = new Set();
[...html.matchAll(/class="([^"]*\bhide\b[^"]*)"/g)].forEach((x) =>
  x[1].split(/\s+/).forEach((c) => { if (c && c !== 'hide') co.add(c); }));
[...src.matchAll(/\$\('([\w-]+)'\)\.classList\.(?:add|remove|toggle)\('hide'/g)].forEach((r) => {
  const t = html.match(new RegExp('id="' + r[1] + '"[^>]*class="([^"]*)"' +
                                  '|class="([^"]*)"[^>]*id="' + r[1] + '"'));
  if (t) (t[1] || t[2] || '').split(/\s+/).forEach((c) => { if (c && c !== 'hide') co.add(c); });
});
const beaten = [];
const ruleRe = /([^{}]+)\{([^{}]*)\}/g;
let rm;
while ((rm = ruleRe.exec(style)) !== null) {
  if (!/display\s*:\s*(?!none)/.test(rm[2])) continue;
  const hit = [...co].filter((c) => new RegExp('\\.' + c + '(?![-\\w])').test(rm[1]));
  if (hit.length && rm.index > hideAt) beaten.push(rm[1].trim() + '{' + hit.join('+') + '}');
}
eq('.hide 盖得住自带 display 的组件类（' + (co.size ? [...co].join('/') : '无') + '）',
   winsByImportant || !beaten.length ? 'ok' : '被声明顺序打败: ' + beaten.join(' ; '), 'ok');
eq('检查并非空跑（并存组件类 >= 1）', co.size >= 1 ? 'ok' : 'co=' + co.size, 'ok');

console.log(fail ? 'WEBUI CHECK FAILED: ' + fail + ' 项' : 'WEBUI CHECK OK');
process.exit(fail ? 1 : 0);
