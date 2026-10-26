/* ============================================================================
 *  check_webui_live.js —— 前端交互链路复现（需要 bkd 正在跑）
 *
 *      node script/check_webui_live.js [http://127.0.0.1:8080/]
 *
 *  无头复现：boot() 登录 -> 打开目录浏览弹窗 -> 真的触发目录行的 onclick ->
 *  连点“上一级” -> 回填输入框。DOM 是手搓的最小实现（元素带 children /
 *  classList / onclick），所以验的是“点一下到底有没有换目录”，而不只是接口通不通。
 *  本轮 browse 打不开下一层（服务端发 isDir、前端读 dir）就是它逮到的。
 *  静态那一半（不需要服务）在 script/check_webui.js。
 * ==========================================================================*/
const fs = require('fs');
const path = require('path');

const BASE = process.argv[2] || 'http://127.0.0.1:8080/';
const html = fs.readFileSync(path.join(__dirname, '..', 'web', 'index.html'), 'utf8');
const src = html.match(/<script>([\s\S]*?)<\/script>/)[1];
const htmlIds = new Set([...html.matchAll(/id="([\w-]+)"/g)].map((m) => m[1]));

class El {
  constructor(tag) {
    this.tagName = String(tag).toUpperCase(); this.children = []; this._cls = new Set();
    this._html = ''; this.onclick = null; this.value = ''; this.textContent = '';
    this.dataset = {}; this.style = {}; this.selected = false; this.scrollTop = 0;
  }
  get className() { return [...this._cls].join(' '); }
  set className(v) { this._cls = new Set(String(v).split(/\s+/).filter(Boolean)); }
  get innerHTML() { return this._html; }
  set innerHTML(v) { this._html = String(v); this.children = []; }   /* 真 DOM 就是赋值即清空子节点 */
  get firstChild() { return this.children[0] || null; }
  appendChild(c) { this.children.push(c); return c; }
  removeChild(c) { this.children = this.children.filter((x) => x !== c); }
  querySelectorAll(sel) {
    if (sel === '.it.sel') return this.children.filter((c) => c._cls.has('sel'));
    if (sel === 'button') return this.children.filter((c) => c._cls.has('ent'));
    return [];
  }
  querySelector() { return null; }
  addEventListener() {}
  focus() {}
  get classList() {
    const s = this._cls;
    return {
      add: (...a) => a.forEach((x) => s.add(x)),
      remove: (...a) => a.forEach((x) => s.delete(x)),
      contains: (x) => s.has(x),
      toggle: (x, force) => (force === undefined ? (s.has(x) ? s.delete(x) : s.add(x))
                          : (force ? s.add(x) : s.delete(x))),   /* 真 DOM 支持第二个强制参数 */
    };
  }
}

const byId = new Map();
const missing = [];
global.document = {
  getElementById(id) {
    if (!htmlIds.has(id)) missing.push(id);
    if (!byId.has(id)) byId.set(id, new El('div'));
    return byId.get(id);
  },
  createElement: (t) => new El(t),
  addEventListener() {},
  body: new El('body'),
};
global.window = global;
global.location = { href: BASE, protocol: BASE.indexOf('file:') === 0 ? 'file:' : 'http:' };
global.alert = (m) => console.log('ALERT: ' + m);
global.EventSource = class { addEventListener() {} close() {} };
for (const k of ['sessionStorage', 'localStorage']) {
  const m = new Map();
  global[k] = { getItem: (x) => (m.has(x) ? m.get(x) : null), setItem: (x, v) => m.set(x, String(v)),
                removeItem: (x) => m.delete(x), clear: () => m.clear() };
}
const reqs = [];
const log = [];
const nativeFetch = global.fetch;          /* 必须先存下来：包装里再调 fetch 就是调自己，会无限递归 */
global.fetch = async (u, o) => {
  const url = String(u).startsWith('http') ? String(u) : BASE + String(u).replace(/^\//, '');
  let r;
  try { r = await nativeFetch(url, o); }
  catch (e) { reqs.push(((o && o.method) || 'GET') + ' ' + String(u) + ' -> 抛错 ' + e.message); throw e; }
  reqs.push(((o && o.method) || 'GET') + ' ' + String(u) + ' -> ' + r.status);
  return r;
};
process.on('unhandledRejection', (e) => log.push('UNHANDLED REJECTION: ' + ((e && e.stack) || e)));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const api = new Function(src + '\n;return { openBrowse, closeBrowse, commitBrowse, loadBrowse, loadInto, '
  + 'BROWSE: () => BROWSE, CFG: () => window.CFG, TOKEN: () => TOKEN, showApp, applyConfig };')();

function dumpList(tag) {
  const box = byId.get('browseList') || new El('div');
  const dirs = box.children.filter((c) => c._html.indexOf('">目录<') >= 0);
  console.log(tag + ' cur=' + JSON.stringify(api.BROWSE().cur) +
    ' children=' + box.children.length + ' 目录项=' + dirs.length +
    ' mask=' + (byId.get('browseMask') ? [...byId.get('browseMask')._cls].join(',') : '无') +
    ' path显示=' + JSON.stringify((byId.get('browsePath') || {}).textContent) +
    ' hint=' + JSON.stringify((byId.get('browseHint') || {}).textContent) +
    ' bUp是否隐藏=' + (byId.get('bUp') ? byId.get('bUp').classList.contains('hide') : '无bUp'));
  if (process.env.DUMP_ROWS)
    box.children.slice(0, 5).forEach((c, i) =>
      console.log('      row[' + i + '] class=' + c.className + ' html=' + c._html.slice(0, 120)));
  return dirs;
}

(async () => {
  await sleep(1800);                                   /* boot() 是异步的，等它跑完 */
  console.log('boot: loginCard=' + [...(byId.get('loginCard') || { _cls: new Set() })._cls].join(',') +
    ' taskCard=' + [...(byId.get('taskCard') || { _cls: new Set() })._cls].join(',') +
    ' status=' + JSON.stringify((byId.get('status') || {}).textContent) +
    ' rootHint=' + JSON.stringify((byId.get('rootHint') || {}).textContent) +
    ' CFG.dataRoot=' + JSON.stringify(api.CFG() && api.CFG().dataRoot));
  console.log('boot 请求: ' + reqs.join(' | '));

  api.openBrowse('source');
  await sleep(1500);
  let dirs = dumpList('打开弹窗后:');
  for (let lvl = 0; lvl < 2; lvl++) {
    if (!dirs.length) { console.log('  -> 第 ' + (lvl + 1) + ' 层没有可点的目录行，链路断在这里'); break; }
    const before = api.BROWSE().cur;
    dirs[0].onclick(dirs[0]);                           /* 模拟真实点击 */
    await sleep(1500);
    dirs = dumpList('点第 ' + (lvl + 1) + ' 个目录后:');
    if (api.BROWSE().cur === before) console.log('  !! 点击后 cur 没变：' + before + '（跳转失效）');
  }
  console.log('连点 3 次“上一级”（老版本在这里会越界卡死）:');
  for (let i = 0; i < 3; i++) {
    if (byId.get('bUp')) byId.get('bUp').onclick();
    await sleep(1200);
    dumpList('  第 ' + (i + 1) + ' 次:');
  }
  api.commitBrowse();
  console.log('commitBrowse -> source.value=' + JSON.stringify(byId.get('source').value) +
    ' toast=' + JSON.stringify((byId.get('toast') || {}).textContent));
  console.log('未知 id 引用: ' + (missing.length ? [...new Set(missing)].join(',') : '无'));
  console.log('异常: ' + (log.length ? log.join('\n') : '无'));
  console.log('全部请求: ' + reqs.join(' | '));
})();
