/* fanout 控制台 —— 界面挂在随机前缀下，一切请求走相对路径 */
(() => {
'use strict';

const $ = s => document.querySelector(s);
const $$ = s => Array.from(document.querySelectorAll(s));

const ICON = {
  copy:'<svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>',
  stop:'<svg viewBox="0 0 24 24"><rect x="6" y="6" width="12" height="12" rx="1.6"/></svg>',
  redo:'<svg viewBox="0 0 24 24"><path d="M21 12a9 9 0 1 1-3-6.7L21 8"/><path d="M21 3v5h-5"/></svg>',
  ok:'<svg viewBox="0 0 24 24"><path d="M20 6 9 17l-5-5"/></svg>',
  bad:'<svg viewBox="0 0 24 24"><path d="M18 6 6 18M6 6l12 12"/></svg>',
  run:'<svg viewBox="0 0 24 24"><path d="M21 12a9 9 0 1 1-6.2-8.5"/></svg>',
  wait:'<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/></svg>',
  plus:'<svg viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg>',
  trash:'<svg viewBox="0 0 24 24"><path d="M3 6h18M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>',
  x:'<svg viewBox="0 0 24 24"><path d="M18 6 6 18M6 6l12 12"/></svg>',
  lock:'<svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
  clock:'<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3.2 2"/></svg>',
  bolt:'<svg viewBox="0 0 24 24"><path d="M13 2 4.5 13.5H11l-1 8.5 8.5-11.5H12z"/></svg>',
  server:'<svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/></svg>',
  swap:'<svg viewBox="0 0 24 24"><path d="M16 3 21 8l-5 5"/><path d="M21 8H9"/><path d="M8 21 3 16l5-5"/><path d="M3 16h12"/></svg>',
  eye:'<svg viewBox="0 0 24 24"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/></svg>',
  inbox:'<svg viewBox="0 0 24 24"><path d="M22 12h-6l-2 3h-4l-2-3H2"/><path d="M5.4 5.1 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.4-6.9A2 2 0 0 0 16.8 4H7.2a2 2 0 0 0-1.8 1.1z"/></svg>',
};

/* ───────────── 基础工具 ───────────── */

async function api(path, opts){
  const r = await fetch(path.replace(/^\//, ''), opts);
  const d = await r.json().catch(()=>({}));
  if(r.status === 401){
    // 会话 12 小时过期：读状态时整页重载走登录壳；提交请求则只报错，别把表单冲掉
    const method = ((opts && opts.method) || 'GET').toUpperCase();
    if(method === 'GET' && !document.querySelector('.dlg.open, .drw.open')) location.reload();
    throw new Error(d.error || '登录已过期');
  }
  if(!r.ok) throw new Error(d.error || ('HTTP '+r.status));
  return d;
}
function esc(s){
  return String(s == null ? '' : s).replace(/[&<>"']/g, c =>
    ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

let toastSeq = 0;
function toast(msg, kind){
  const box = $('#toasts');
  const el = document.createElement('div');
  const k = kind === true ? 'bad' : (kind || 'info');
  const ic = k === 'bad' ? ICON.bad : (k === 'ok' ? ICON.ok : ICON.bolt);
  el.className = 'toast ' + k;
  el.innerHTML = ic + '<div class="tx">' + esc(msg) + '</div><i class="bar"></i>';
  box.appendChild(el);
  const id = ++toastSeq;
  el.dataset.id = id;
  const kill = () => {
    if(!el.isConnected) return;
    el.classList.add('out');
    setTimeout(() => el.remove(), 220);
  };
  el.onclick = kill;
  setTimeout(kill, 3000);
  while(box.children.length > 4) box.firstChild.remove();
}

async function copy(text){
  // navigator.clipboard 只在 HTTPS/localhost 下存在，而面板通常是 http://IP 访问，
  // 所以必须留一条 execCommand 兜底路径，否则复制在正常使用场景里必然失败。
  if(navigator.clipboard && window.isSecureContext){
    try{ await navigator.clipboard.writeText(text); toast('已复制','ok'); return; }
    catch(e){}
  }
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.setAttribute('readonly','');
  // 放在视口内但不可见：置于视口外会让 iOS 在聚焦时滚动页面
  ta.style.cssText = 'position:fixed;top:0;left:0;width:1px;height:1px;opacity:0;padding:0;border:0';
  document.body.appendChild(ta);
  const prev = document.activeElement;
  ta.focus();
  ta.setSelectionRange(0, ta.value.length);
  let ok = false;
  try{ ok = document.execCommand('copy'); }catch(e){}
  ta.remove();
  if(prev && prev.focus) prev.focus();
  toast(ok ? '已复制' : '复制失败，请手动选中', ok ? 'ok' : 'bad');
}

function relTime(iso){
  const t = new Date(iso).getTime();
  if(!isFinite(t) || t < 0) return '';
  const s = Math.floor((Date.now() - t)/1000);
  if(s < 0) return '刚刚';
  if(s < 60) return s + ' 秒前';
  const m = Math.floor(s/60);
  if(m < 60) return m + ' 分钟前';
  const h = Math.floor(m/60);
  if(h < 24) return h + ' 小时 ' + (m%60) + ' 分前';
  return Math.floor(h/24) + ' 天前';
}
function upTime(iso){
  const t = new Date(iso).getTime();
  if(!isFinite(t)) return '';
  const s = Math.max(0, Math.floor((Date.now() - t)/1000));
  if(s < 60) return s + ' 秒';
  const m = Math.floor(s/60);
  if(m < 60) return m + ' 分钟';
  const h = Math.floor(m/60);
  if(h < 48) return h + ' 小时 ' + (m%60) + ' 分';
  return Math.floor(h/24) + ' 天';
}
function agoFrom(iso){
  const t = new Date(iso).getTime();
  if(!isFinite(t) || t < 3e5) return '';            // 0001-01-01 这类零值
  return relTime(iso);
}
function num(v){ const n = Number(v); return isFinite(n) ? n : 0; }
// 后端的 describeSteps 用 " && " 把几条命令串起来。界面只报最后那条真正装包的：
// 把 apt-get update -qq 也带上，320 宽上这一行要占十一行，而它不是有用的信息。
function lastStep(cmd){ const p = String(cmd || '').split(' && '); return p[p.length - 1] || ''; }

/* ───────────── 状态 ───────────── */

let view = {exits:[], direct:[], panel:'', backend:'', panel_info:'', public_ip:''};
let inbounds = [];
let jobs = [];
let regions = [];
let region = '';
let regionsLoaded = false;
let curDetail = null;
let curCred = null;
let curSettings = null;
let curBackend = null;
let filter = '';
let query = '';
let nodeQuery = '';
let lastOK = 0;
let pollTimer = null;
let booting = true;
let lastPanel = '';

const STATUS = {up:'已连通', starting:'连接中', failed:'失败', stopped:'已停止'};
const BACKEND_NAME = {'native':'自建 Xray', '3x-ui':'3x-ui', 'xray-cf-lite':'xray-cf-lite'};

// 自建模式下入站由 fanout 自己管，界面要提供新建入口；
// 接管 3x-ui 时入站归面板管，这里只读不写。
function isNative(){ return view.backend === 'native'; }
// xray-cf-lite 模式下节点归它管，fanout 只改路由，界面不给新建入口
function isXCL(){ return view.backend === 'xray-cf-lite'; }
function backendName(){ return BACKEND_NAME[view.backend] || '3x-ui'; }

const PROTO_TINT = {vless:'acc', vmess:'', trojan:'warn'};

/* ───────────── 主题 ───────────── */

const THEME_KEY = 'fanout.theme';
function applyTheme(t){
  document.documentElement.dataset.theme = t;
  const dark = t === 'dark';
  $('#themeLbl').textContent = dark ? '浅色' : '深色';
  $('#themeIcon').innerHTML = dark
    ? '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>'
    : '<circle cx="12" cy="12" r="4.2"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>';
  try{ localStorage.setItem(THEME_KEY, t); }catch(e){}
}
(function initTheme(){
  let t = null;
  try{ t = localStorage.getItem(THEME_KEY); }catch(e){}
  if(t !== 'dark' && t !== 'light'){
    t = (window.matchMedia && matchMedia('(prefers-color-scheme: dark)').matches) ? 'dark' : 'light';
  }
  applyTheme(t);
})();
$('#themeBtn').onclick = () =>
  applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');

// 退出要问一句：后台还在跑健康检查和自动补齐，点了就断掉正在做的事。
// 服务端 POST 那条分支只回 JSON，所以跳登录页由这里做。
$('#logoutBtn').onclick = async () => {
  if(!confirm('退出登录？出口和节点链接都在服务端继续跑，只是关掉这个管理页面。')) return;
  // 轮询先停：退出之后每个 tick 都会撞上 401，那会让 api() 把页面整页重载回登录壳，
  // 在跳转途中多闪一次不说，还可能把退出请求本身打断。负载那条小轮询也一样。
  clearTimeout(pollTimer);
  if(statTimer) clearInterval(statTimer);
  try{ await api('logout', { method: 'POST' }); }catch(e){ /* 会话本来就没了也算退出成功 */ }
  location.href = 'login';
};

/* ───────────── 顶栏主机负载 ───────────── */

// 独立于 poll() 的一条小轮询：负载数字要的是"现在"，
// 跟着出口状态一起刷会被拖到 4 秒一次，看着就像卡住了。
const STAT_MS = 2500;
let statTimer = null;
let statBusy = false;

function fmtGB(b){
  if(!b) return '0';
  const g = b / 1073741824;
  return (g >= 10 ? g.toFixed(0) : g.toFixed(1)) + 'G';
}

// 速率按 1024 进制缩写，跟内存/磁盘那几颗胶囊同一套口径，
// 免得页面上「1G 内存」和「1G 带宽」的 G 不是一个意思。
function fmtRate(bps){
  const k = (bps || 0) / 1024;
  if(k < 1024) return Math.round(k) + 'K/s';
  const m = k / 1024;
  return (m >= 10 ? m.toFixed(0) : m.toFixed(1)) + 'M/s';
}

// 胶囊上只放缩写，鼠标悬停给精确的 字节/秒 与 Mbps：
// 带宽是按 10 进制卖的，光看 M/s 判断不了是不是快到套餐上限了。
function fmtRateTip(bps){
  const mbps = (bps || 0) * 8 / 1e6;
  return Math.round(bps || 0) + ' 字节/秒 ≈ ' + (mbps >= 1 ? mbps.toFixed(1) : mbps.toFixed(3)) + ' Mbps';
}

function ratePill(k, bps, pct, ready, iface, link, dir){
  const head = k + ' ' + fmtRateTip(bps);
  const what = dir === 'up'
    ? '这台机器发出去的字节差分（含 openvpn 封装后的开销，所以它会比出口的实际代理流量大）'
    : '这台机器收到的字节差分（同上，是网卡上的量，不是解密后的代理流量）';
  const scale = link
    ? '绿条按 ' + iface + ' 报的链路速率 ' + link + ' Mbps 折算'
    : iface + ' 不报链路速率（虚拟网卡常见），绿条不画，只给数值';
  return {k, pct: ready ? pct : 0, v: ready ? fmtRate(bps) : '—',
    tip: ready ? head + '\n看的是 ' + iface + '，两次刷新之间' + what + '\n' + scale
               : '刚开始采样，还没有前一个计数可减\n' + scale};
}

// 每个胶囊只写"怎么算的"，数字本身一律来自后端：
// 前端不参与任何估算，否则页面和 SSH 里看到的对不上，比不显示更糟。
function statDefs(s){
  const cap = s.sock_cap || 0;
  return [
    {k:'CPU', pct:s.cpu, v:Math.round(s.cpu) + '%',
     tip:'CPU 占用 ' + s.cpu.toFixed(1) + '%\n两次刷新之间的平均值，全部核心合起来算'},
    {k:'内存', pct:s.mem_pct, v:fmtGB(s.mem_used) + '/' + fmtGB(s.mem_total),
     tip:'内存 ' + fmtGB(s.mem_used) + ' / ' + fmtGB(s.mem_total)
        + '（' + s.mem_pct.toFixed(1) + '%）\n按 MemTotal - MemAvailable 算，cache 可回收不算占用'},
    {k:'交换', pct:s.swap_pct, v:s.swap_total ? fmtGB(s.swap_used) + '/' + fmtGB(s.swap_total) : '无',
     off:!s.swap_total,
     tip:s.swap_total ? '交换分区 ' + fmtGB(s.swap_used) + ' / ' + fmtGB(s.swap_total)
                      + '（' + s.swap_pct.toFixed(1) + '%）\n开始吃交换通常意味着内存真不够了'
                      : '这台机器没配交换分区'},
    {k:'存储', pct:s.disk_pct, v:s.disk_total ? fmtGB(s.disk_used) + '/' + fmtGB(s.disk_total) : '—',
     off:!s.disk_total,
     tip:s.disk_total
        ? '磁盘已用 ' + fmtGB(s.disk_used) + ' / ' + fmtGB(s.disk_total)
          + '（' + s.disk_pct.toFixed(1) + '%）\n看的是 ' + (s.disk_mount || '/')
          + ' 所在分区（fanout 的状态、配置、日志写在这里），口径同 df：'
          + '\n百分比扣掉了 root 预留块，所以它到 100% 就是真的写不进去了'
        : '读不到磁盘占用（statfs 失败），不是这块盘真的空的'},
    {k:'负载', pct:s.load_pct, v:s.load1.toFixed(2),
     tip:'1 / 5 / 15 分钟负载 = ' + s.load1.toFixed(2) + ' / ' + s.load5.toFixed(2)
        + ' / ' + s.load15.toFixed(2) + '\n绿条按 ' + s.cores
        + ' 核归一，100% 表示可运行任务刚好排满 CPU'},
    {k:'TCP', pct:s.tcp_pct, v:String(s.tcp),
     tip:'在用 TCP socket ' + s.tcp + ' 个（含 TIME_WAIT）\n'
        + 'IPv4 ' + (s.tcp - (s.tcp6 || 0)) + ' + IPv6 ' + (s.tcp6 || 0) + '，两张表加起来才是本机总数\n'
        + '刻度是临时端口区间宽度' + (cap ? ' ' + cap + ' 个' : '（读不到）')
        + '，只用来比较多少，不是硬上限'},
    {k:'UDP', pct:s.udp_pct, v:String(s.udp),
     tip:'在用 UDP socket ' + s.udp + ' 个\nQUIC、DNS 这类流量都算在这里\n'
        + 'IPv4 ' + (s.udp - (s.udp6 || 0)) + ' + IPv6 ' + (s.udp6 || 0)
        + '：内核把两张表分开记，绑 [::] 的双栈监听只出现在 IPv6 那份里'},
    ratePill('上行', s.up_bps, s.up_pct, s.net_ready, s.net_if || '默认路由网卡', s.link_mbps, 'up'),
    ratePill('下行', s.down_bps, s.down_pct, s.net_ready, s.net_if || '默认路由网卡', s.link_mbps, 'down'),
  ];
}

function renderStats(s){
  $('#stats').innerHTML = statDefs(s).map(d => {
    const pct = Math.max(0, Math.min(100, d.pct || 0));
    const lvl = d.off ? ' off' : (pct >= 90 ? ' over' : (pct >= 75 ? ' hot' : ''));
    // title 里的换行要转成实体：HTML 解析器会把属性值里的裸换行折成一个空格，
    // 那样两行说明就糊成一行长文本了。
    const tip = esc(d.tip).replace(/\n/g, '&#10;');
    return '<span class="stat' + lvl + '" title="' + tip + '">'
      + '<span class="k">' + esc(d.k) + '</span>'
      + '<span class="bar"><i style="width:' + pct.toFixed(1) + '%"></i></span>'
      + '<span class="v">' + esc(d.v) + '</span></span>';
  }).join('');
}

function statsGone(msg){
  $('#stats').innerHTML = '<span class="stat off" title="' + esc(msg) + '">'
    + '<span class="k">负载</span><span class="v">—</span></span>';
}

async function tickStats(){
  if(statBusy) return;
  statBusy = true;
  try{
    renderStats(await api('/api/stats'));
  }catch(e){
    statsGone(e.message);
  }finally{
    // 渲染中途抛异常时也要放行：这个标志卡在 true，顶栏就再也不更新了
    statBusy = false;
  }
}
tickStats();
statTimer = setInterval(() => { if(!document.hidden) tickStats(); }, STAT_MS);

/* ───────────── 视图切换 ───────────── */


const VIEWS = {
  dashboard:{ el:'#view-dashboard', title:'出口总览', sub:'每条出口 = 一个独立 netns 隧道 = 一个出口 IP' },
  nodes:    { el:'#view-nodes',     title:'节点链接', sub:'所有入站与它们绑定的出口' },
  sub:      { el:'#view-sub',       title:'订阅',     sub:'一条地址管全部客户端' },
  settings: { el:'#view-settings',  title:'设置与连接', sub:'访问安全、选节点策略、隧道保活' },
};
function showView(name){
  if(!VIEWS[name]) name = 'dashboard';
  for(const [k,v] of Object.entries(VIEWS)) $(v.el).hidden = (k !== name);
  $$('.nav-item[data-view]').forEach(b => b.classList.toggle('on', b.dataset.view === name));
  $('#pageTitle').textContent = VIEWS[name].title;
  document.title = 'fanout · ' + VIEWS[name].title;
  location.hash = '#' + name;
  document.body.classList.remove('sb-open');
  if(name === 'sub') loadSub();
  if(name === 'settings') loadSettingsPage();
  if(name === 'nodes') renderNodes();
}
$$('.nav-item[data-view]').forEach(b => b.onclick = () => showView(b.dataset.view));
$('#menuBtn').onclick = () => document.body.classList.toggle('sb-open');
$('#scrim').onclick = () => document.body.classList.remove('sb-open');

/* ───────────── 弹窗 ───────────── */

function openModal(id){
  $('#' + id).classList.add('open');
  $('#scr').classList.add('open');
}
function closeModal(id){
  $('#' + id).classList.remove('open');
  if(!$$('.dlg.open, .drw.open').length) $('#scr').classList.remove('open');
}
document.addEventListener('click', e => {
  const c = e.target.closest('[data-close]');
  if(c) closeModal(c.dataset.close);
});
document.addEventListener('keydown', e => {
  if(e.key === 'Escape'){
    const open = $$('.dlg.open, .drw.open');
    if(open.length) open[open.length-1].classList.remove('open');
    else document.body.classList.remove('sb-open');
    if(!$$('.dlg.open, .drw.open').length) $('#scr').classList.remove('open');
  }
});
$('#scr').onclick = () => {
  $$('.dlg.open, .drw.open').forEach(m => m.classList.remove('open'));
  $('#scr').classList.remove('open');
};

/* ───────────── KPI ───────────── */

const CIRC = 2 * Math.PI * 33;
function renderKPI(){
  const ex = view.exits || [];
  const up = ex.filter(e => e.status === 'up').length;
  const starting = ex.filter(e => e.status === 'starting').length;
  const failed = ex.filter(e => e.status === 'failed').length;

  $('#kpiUp').textContent = up;
  $('#kpiUpTotal').textContent = '/ ' + ex.length;
  const sub = $('#kpiUpSub');
  if(!ex.length) sub.innerHTML = '还没有出口';
  else {
    const bits = [];
    if(starting) bits.push('<b class="warn">' + starting + '</b> 条连接中');
    if(failed) bits.push('<b class="bad">' + failed + '</b> 条失败');
    if(up) bits.push('<b>' + up + '</b> 条可直连');
    sub.innerHTML = bits.join(' · ') || '全部已停止';
  }
  const ring = $('#kpiRing');
  // hidden 是 HTMLElement 的反射属性，SVG 元素上赋值只会写出一个普通 JS 字段，
  // 标签里的 hidden 纹丝不动，圆环就再也不显示了。要改就改内容属性。
  ring.toggleAttribute('hidden', !ex.length);
  if(ex.length){
    const fg = ring.querySelector('.fgc');
    fg.setAttribute('stroke-dasharray', CIRC.toFixed(1));
    fg.setAttribute('stroke-dashoffset', (CIRC * (1 - up/ex.length)).toFixed(1));
  }

  const avail = regions.reduce((a,r) => a + num(r.available), 0);
  $('#kpiNodes').textContent = regions.length ? avail.toLocaleString() : '—';
  $('#kpiNodesSub').innerHTML = regions.length
    ? (avail ? '其中 <b>' + regions.length + '</b> 个国家有空位' : '没有空闲节点，试试关掉家宽限制')
    : '读取 VPN Gate 清单中…';

  $('#kpiRegions').textContent = regions.length ? regions.length : '—';
  const mine = new Set(ex.map(e => e.region).filter(Boolean));
  $('#kpiRegionsSub').textContent = mine.size ? '已在用 ' + mine.size + ' 个' : '开出口后自动统计';

  $('#kpiIp').textContent = view.public_ip || location.hostname || '—';

  const allLinks = allInbounds();
  $('#kpiLinks').textContent = allLinks.length;
  const bound = allLinks.filter(i => i.__exit).length;
  $('#kpiLinksSub').textContent = allLinks.length
    ? (bound ? '绑定出口 ' + bound + ' 条 · 直连 ' + (allLinks.length-bound) + ' 条' : '全部走直连')
    : '还没有节点链接';

  $('#navExits').textContent = ex.length;
  $('#navNodes').textContent = allLinks.length;

  // 侧栏后端状态
  const okBackend = !!view.backend;
  $('#sbDot').className = 'mini-dot' + (okBackend ? '' : ' bad');
  $('#sbBackend').textContent = okBackend ? backendName() : '后端不可用';
  $('#sbBackendSub').textContent = view.panel || view.panel_info || '没读到面板信息';
  $('#sbBackendSub').title = view.panel || view.panel_info || '';
}

function allInbounds(){
  const out = [];
  for(const e of (view.exits || [])){
    for(const i of (e.inbounds || [])) out.push(Object.assign({}, i, {__exit:e}));
  }
  for(const i of (view.direct || [])) out.push(Object.assign({}, i, {__exit:null}));
  return out;
}

/* ───────────── 出口卡片 ───────────── */

function visibleExits(){
  let list = view.exits || [];
  if(filter) list = list.filter(e => e.status === filter);
  const kw = query.trim().toLowerCase();
  if(kw){
    list = list.filter(e => [e.exit_ip, e.host, e.country, e.region, String(e.port)]
      .some(v => String(v || '').toLowerCase().includes(kw)));
  }
  const order = {up:0, starting:1, failed:2, stopped:3};
  return list.slice().sort((a,b) =>
    (order[a.status] ?? 9) - (order[b.status] ?? 9) || a.slot - b.slot);
}

function renderCounts(){
  const ex = view.exits || [];
  const c = {up:0, starting:0, failed:0};
  ex.forEach(e => { if(c[e.status] != null) c[e.status]++; });
  $('#fcAll').textContent = ex.length;
  $('#fcUp').textContent = c.up;
  $('#fcStarting').textContent = c.starting;
  $('#fcFailed').textContent = c.failed;
  $('#ecount').textContent = ex.length ? ex.length + ' 条' : '';
}

function exitCard(e){
  const st = e.status;
  const ip = e.exit_ip || (st === 'starting'
    ? '<span class="wait">连接中…</span>'
    : '<span class="wait">—</span>');
  // country 后端已经给成「🇯🇵 日本」，再拼国家码就重复了
  const place = esc(e.country || e.region || '未知地区');
  const ibs = e.inbounds || [];
  const chips = ibs.length
    ? ibs.map(i =>
        '<button class="chip' + (i.enable === false ? ' off' : '') + '" data-detail="' + i.id
        + '" title="' + esc((i.remark || i.protocol) + ' · ' + i.protocol + ' :' + i.port) + '">'
        + '<span class="p">' + esc(i.protocol) + '</span>'
        + '<span class="pt">:' + i.port + '</span></button>').join('')
    : '<span class="chip none">还没有节点链接</span>';

  // 失败和"正在重试"都要把原因写出来：只有"连接中…"的话，
  // 人分不清是在等节点应答，还是 WARP 那一跳根本没通、换多少节点都没用。
  const err = e.err && (st === 'failed' || st === 'starting')
    ? '<div class="errbox' + (st === 'failed' ? '' : ' soft') + '"><b>'
      + (st === 'failed' ? '连接失败' : '重试中') + '</b>' + esc(e.err) + '</div>' : '';

  const since = (st === 'up' && e.since)
    ? '<span class="it" title="自 ' + esc(agoFrom(e.since) || '—') + ' 起">' + ICON.clock
      + upTime(e.since) + '</span>' : '';
  const speed = e.node_speed ? '<span class="it">' + ICON.bolt + num(e.node_speed) + ' Mbps</span>' : '';
  const slot = '<span class="it">#' + e.slot + '</span>';

  // 标的是节点自己的本事，不是此刻在跑什么算法：VPN Gate 那批节点写死
  // AES-128-CBC，一个标记都不会亮；亮了才说明这条值得吃 AEAD-only 那档。
  const aead = e.aead
    ? '<span class="badge acc" title="节点声明支持 AEAD：打开设置里的「数据通道只要 AEAD」后，这条会走 GCM/ChaCha20 并放开内核 data channel offload">AEAD</span>'
    : '';

  const ep = (view.public_ip || location.hostname || '') + ':' + e.port;
  const auth = e.socks_user
    ? '<span class="auth">鉴权</span>'
    : '<span class="auth anon">无鉴权</span>';

  // 只有中转真的架起来了才占一行。标签写「中转」而不是「出口」：这串是
  // Cloudflare 的接入点，对外暴露的身份还是上面那个出口 IP，两者混不得。
  const warp = e.warp_ip
    ? '<div class="wipline' + (e.warp_live ? '' : ' dead') + '"><span class="lbl">中转</span>'
      + '<span class="copyable" data-copy="' + esc(e.warp_ip) + '" title="复制 Cloudflare 接入点">'
      + esc(e.warp_ip) + '</span>'
      + '<span class="badge ' + (e.warp_live ? 'ok' : 'warn') + '">'
      + (e.warp_live ? '已握手' : '未握手') + '</span></div>'
    : '';

  return '<article class="card ' + st + '">'
    + '<div class="hd">'
    +   '<span class="orb ' + st + '" title="' + (STATUS[st] || st) + '"></span>'
    +   '<div class="ttl">'
    +     '<div class="place">' + place + '</div>'
    +     '<div class="node" title="' + esc(e.host) + '">' + esc(e.host) + '</div>'
    +   '</div>'
    +   '<button class="ico" data-swap="' + e.slot + '" title="换一个节点（端口不变，出口 IP 变）">'
    +     ICON.swap + '</button>'
    +   '<button class="ico danger" data-stop="' + e.slot + '" title="停止这个出口">'
    +     ICON.stop + '</button>'
    + '</div>'
    + '<div class="ip"><span class="lbl">出口</span>'
    +   '<span class="copyable" data-copy="' + esc(e.exit_ip || '') + '" title="复制出口 IP">'
    +     ip + '</span></div>'
    + warp
    + '<div class="meta">' + slot + since + speed + aead + '</div>'
    + '<div class="sock">'
    +   '<span class="ep">' + ICON.server + '<span>' + esc(ep) + '</span>' + auth + '</span>'
    +   '<button class="ico" data-copysock="' + e.slot + '" title="复制 SOCKS5 地址">'
    +     ICON.copy + '</button>'
    +   '<button class="ico" data-cred="' + e.slot + '" title="SOCKS5 访问凭据">'
    +     ICON.lock + '</button>'
    + '</div>'
    + '<div class="chips">' + chips + '</div>'
    + err
    + '</article>';
}

// 出口总览页那条状态栏。数据全来自 /api/exits 的 warp 字段：握手与否是后端
// 进 netns 读 WireGuard 实况得到的，这里不自己判断，也不把注册值当在线值。
function renderWarpBar(){
  const bar = $('#wbar');
  if(!bar) return;
  const w = view.warp || {};
  bar.classList.toggle('on', !!w.enabled);
  const sw = $('#wbarSw');
  sw.checked = !!w.enabled;
  sw.disabled = !w.ready || warpBusy();
  const badge = $('#wbarBadge');
  // 缺 wireguard-tools 时开关照样能拨——后端会把它装上。这时候标"未开启"
  // 而不是"不可用"：说不可用是在让人去找终端，而这里没有需要他做的事。
  // 已经开着却还没装好，才需要单独一个状态，否则那几十秒看着像开关没生效。
  const st = !w.ready ? ['bad', '不可用']
    : w.last_err && !w.enabled ? ['warn', '上次没开成']
    : w.need_tools ? (w.enabled ? ['warn', '装依赖中'] : ['idle', '未开启'])
    : w.enabled ? ['ok', '已开启'] : ['idle', '未开启'];
  badge.className = 'badge ' + st[0];
  badge.textContent = st[1];
  $('#wbarVer').hidden = !w.version;
  $('#wbarVer').textContent = w.version || '';
  $('#wbarSub').innerHTML = warpSub(w);
}

function warpSub(w){
  if(!w.ready) return esc(w.reason || '这台机器跑不了中转');
  // 开关还关着、上次却没开成：这句比任何解释都该先看。作业里的失败几分钟后就淡出，
  // 而没解决的事必须挂在人每次都会扫一眼的地方，否则下一轮描述又只剩"连不上节点"。
  const fail = w.last_err && !w.enabled
    ? '<b class="warn">上次没开成：' + esc(w.last_err) + '</b>　' : '';
  if(w.need_tools){
    // 只报真正装包那一条：apt-get update -qq 是它的铺垫，写全了在 320 宽上
    // 要占十一行，而这一行下面还有开关和出口卡片。
    const cmd = '<code>' + esc(lastStep(w.pkg_cmd)) + '</code>';
    return fail + (w.enabled
      ? '正在装 wireguard-tools：' + cmd
      : '拨开开关会自动装 wireguard-tools：' + cmd);
  }
  if(!w.enabled) return fail + '关闭时出口直接从节点走。开启后每条出口先经 Cloudflare WARP 再到节点，'
    + '出口 IP 仍由节点决定。';
  const cls = !w.count ? '' : w.live >= w.count ? 'ok' : 'warn';
  let s = '已注册 <b>' + num(w.count) + '</b> 条 · 已握手 <b class="' + cls + '">'
    + num(w.live) + '</b>/' + num(w.count) + ' · 客户端 <b>' + esc(w.version || '—') + '</b>';
  if(w.stale > 0) s += '，<b class="warn">' + num(w.stale) + ' 条还按旧版本号注册着</b>';
  return s;
}

// 开关在作业跑完之前不给再按：半途翻第二次，等于把还在逐条重连的出口
// 又推进另一套路由里，最后哪条都没个确定状态。
function warpBusy(){
  return (jobs || []).some(j => j.status === 'running'
    && (j.summary || '').indexOf('WARP') >= 0);
}

$('#wbarSw').onchange = async e => {
  const sw = e.currentTarget;
  const on = sw.checked;
  const n = (view.exits || []).length;
  const w = view.warp || {};
  const tail = n
    ? '\n\n现有 ' + n + ' 条出口会逐条断开重连（一条一条来，不会同时抢节点），'
      + '出口 IP 还是节点的，只是中间多绕一层 Cloudflare。'
    : '\n\n现在没有出口，开关只对之后新建的出口生效。';
  // 缺依赖时别再说"请先装"：这一步是 fanout 自己做的，说清楚要等多久就行。
  const pre = !on ? '\n\n关闭会把 fanout 名下的 WARP 注册一并退掉。'
    : w.need_tools ? '\n\n本机还没有 wireguard-tools，第一步会用包管理器装上（'
        + w.pkg_cmd + '），源不慢的话几十秒。'
    : '\n\n前提是本机够得着 Cloudflare 的注册接口。';
  if(!confirm((on ? '开启' : '关闭') + ' WARP 中转？' + tail + pre)) {
    sw.checked = !on;
    return;
  }
  sw.disabled = true;
  try{
    const r = await api('/api/warp?on=' + (on ? 1 : 0), {method:'POST'});
    toast(r.message || ('中转已' + (on ? '开启' : '关闭')), 'ok');
  }catch(err){
    toast(err.message, 'bad');
    sw.checked = !on;   // 后端拒绝时开关保持原样，界面跟着退回去
  }
  sw.disabled = false;
  poll();
};

function renderExits(){
  const list = $('#list');
  const total = (view.exits || []).length;
  renderCounts();
  $('#exportAll').disabled = !allInbounds().some(i => i.__exit);
  $('#stopall').disabled = !total;

  if(booting){
    list.innerHTML = Array.from({length:3}, () =>
      '<div class="skel"><div class="l w40"></div><div class="l w25"></div>'
      + '<div class="l w60"></div><div class="l" style="margin:0"></div></div>').join('');
    return;
  }
  if(apiErr && !total){
    list.innerHTML = '<div class="empty" style="grid-column:1/-1">'
      + '<div class="glyph">' + ICON.bad + '</div>'
      + '<h3>读不到状态</h3><p>' + esc(apiErr) + '</p>'
      + '<div class="row"><button class="btn" onclick="location.reload()">重新登录 / 重试</button></div></div>';
    return;
  }
  if(!total){
    list.innerHTML = '<div class="empty" style="grid-column:1/-1">'
      + '<div class="glyph">' + ICON.inbox + '</div>'
      + '<h3>还没有出口</h3>'
      + '<p>出口 = 一条跑在独立 netns 里的 VPN Gate 隧道。开一条就得到一个固定出口 IP，'
      + '母机自己的 IP 不受影响。</p>'
      + '<div class="row">'
      +   '<button class="btn primary" id="newexit2">' + ICON.plus + '新建出口</button>'
      +   '<button class="btn" id="newnode2">先建一条节点链接</button>'
      + '</div></div>';
    return;
  }
  const vis = visibleExits();
  if(!vis.length){
    list.innerHTML = '<div class="empty" style="grid-column:1/-1;padding:32px">'
      + '<h3>没有匹配的出口</h3><p>换个筛选条件或清空搜索。</p></div>';
    return;
  }
  list.innerHTML = vis.map(exitCard).join('');
}

/* 停掉出口后它的入站会留在面板里。这些入站现在走直连，
   用户既看不出它们和 fanout 的关系，也没有清理入口，所以单独列出来。 */
function renderOrphans(){
  const box = $('#orphans');
  const list = view.direct || [];
  if(!list.length){ box.innerHTML = ''; return; }
  const hasUp = (view.exits || []).some(e => e.status === 'up');
  box.innerHTML = '<div class="panel" style="margin-top:6px">'
    + '<div class="ph"><h3>' + ICON.inbox + ' 未绑定出口的入站</h3>'
    + '<span class="n">' + list.length + ' 个，走直连不出口</span><span class="spacer"></span>'
    + (isXCL() ? ''
        : '<button class="btn sm" data-delorphans="1">' + ICON.trash + '批量清理</button>')
    + '</div><div class="pb">'
    + list.map(i =>
        '<div class="orow">'
        + '<span class="nm"><button class="chip" data-detail="' + i.id + '">'
        +   '<span class="p">' + esc(i.protocol) + '</span>'
        +   esc(i.remark || i.protocol) + ' <span class="pt">:' + i.port + '</span></button></span>'
        + '<span class="spacer"></span>'
        + (hasUp
            ? '<select class="inp obind" data-tag="' + esc(i.tag) + '" title="绑到哪条出口">'
              + exitOptions('') + '</select>'
            : '<span class="none">先开一条出口</span>')
        + (isXCL() ? ''
            : '<button class="ico danger" data-delone="' + i.id + '" data-name="'
              + esc((i.remark || i.protocol) + ' :' + i.port) + '" title="删除这个入站">'
              + ICON.trash + '</button>')
        + '</div>').join('')
    + '</div></div>';
}

/* ───────────── 出口组 ───────────── */

let poolMeta = null;   // /api/pools 的策略清单，第一次打开编辑器时才取
let poolEdit = '';     // 正在编辑的组 ID，空串表示新建
let poolMode = 'single';

function poolState(p){
  if(!p.running) return 'failed';
  return p.up > 0 ? 'up' : 'failed';
}

function renderPools(){
  const box = $('#pools');
  if(!box) return;
  if(booting){ box.innerHTML = ''; return; }
  const pools = view.pools || [];
  const head = '<div class="panel" style="margin-top:6px"><div class="ph">'
    + '<h3>' + ICON.swap + ' 出口组</h3>'
    + '<span class="n">' + pools.length + ' 个</span><span class="spacer"></span>'
    + '<button class="btn sm" id="newpool">' + ICON.plus + '新建出口组</button></div>';
  if(!pools.length){
    box.innerHTML = head + '<div class="pb"><div class="orow" style="border:0">'
      + '<span class="none">一条节点链接只绑一条出口，掉了就只能等它自己重连。'
      + '把几条出口编成一个组，组内自动选路：掉线换下一条、按次轮询、挑最快的、或同时抢跑。</span>'
      + '</div></div></div>';
    return;
  }
  box.innerHTML = head + '<div class="pb">'
    + pools.map(poolRow).join('') + '</div></div>';
}

function poolRow(p){
  const st = poolState(p);
  const mem = (p.members || []).map(m => {
    const ok = m.status === 'up';
    const bits = [m.status, m.exit_ip, m.latency_ms ? m.latency_ms + 'ms' : '', m.cooling ? '冷却中' : '', m.aead ? '支持 AEAD' : '']
      .filter(Boolean).join(' · ');
    return '<span class="chip' + (ok ? '' : ' off') + '" title="' + esc(m.host + ' · ' + bits) + '">'
      + '<span class="p">' + esc(m.status === 'up' ? 'OK' : (m.status === 'missing' ? '没了' : m.status)) + '</span>'
      + esc(m.host) + '</span>';
  }).join('');

  const ibs = (p.inbounds || []).length
    ? (p.inbounds || []).map(i =>
        '<button class="chip' + (i.enable === false ? ' off' : '') + '" data-detail="' + i.id
        + '" title="' + esc((i.remark || i.protocol) + ' · ' + i.protocol + ' :' + i.port) + '">'
        + '<span class="p">' + esc(i.protocol) + '</span>'
        + '<span class="pt">:' + i.port + '</span></button>').join('')
    : '<span class="chip none">还没有节点链接绑上来</span>';

  const warn = !p.running
    ? '<div class="errbox"><b>组没在跑</b>本机监听没起来，绑到它的链接会直接失败</div>'
    : (p.up === 0 ? '<div class="errbox"><b>组内没有可用出口</b>连接会失败，不会退回母机直连</div>' : '');

  const fillTag = p.auto_fill
    ? ' <span class="pt" title="掉线后先用在线出口顶上来，在线的不够才新建">自动补齐 ' + p.size + ' 条</span>'
    : '';
  // 没补齐时后端会写一句原因（在线出口都用上了 / 槽位余量不够 / 挑不到节点）。
  // 只在还缺人的时候显示，补齐了就闭嘴，否则一个正常的组永远挂着灰字。
  const fillNote = (p.auto_fill && p.fill_note && p.up < p.size)
    ? '<div class="hint" style="margin:-2px 0 8px">' + esc(p.fill_note) + '</div>'
    : '';

  return '<div class="poolblk">'
    + '<div class="orow">'
    + '<span class="orb ' + st + '" title="' + (p.running ? '监听中' : '未监听') + '"></span>'
    + '<span class="nm">' + esc(p.name)
    +   ' <span class="pt">' + esc(p.mode_label) + '</span>'
    +   ' <span class="pt">' + p.up + '/' + p.total + ' 可用</span>'
    +   fillTag + '</span>'
    + '<span class="spacer"></span>'
    + '<span class="none">' + esc(p.mode_desc || '') + '</span>'
    + '</div>'
    + '<div class="chips" style="margin:0 0 8px">' + mem + '</div>'
    + fillNote
    + '<div class="chips" style="margin:0 0 10px">' + ibs + '</div>'
    + warn
    + '<div class="acts" style="margin-bottom:12px">'
    +   '<button class="btn sm" data-pedit="' + esc(p.id) + '">编辑</button>'
    +   '<button class="btn sm" data-pcred="' + esc(p.id) + '" title="换本机 SOCKS5 口令，并同步到节点链接后端">重置口令</button>'
    +   '<button class="btn sm" data-pdel="' + esc(p.id) + '" data-name="' + esc(p.name) + '">删除</button>'
    + '</div></div>';
}

async function openPool(id){
  let meta;
  try{
    if(!poolMeta) poolMeta = await api('/api/pools');
    meta = poolMeta;
  }catch(e){ return toast(e.message, 'bad'); }

  const p = id ? (view.pools || []).find(x => x.id === id) : null;
  poolEdit = p ? p.id : '';
  poolMode = p ? p.mode : 'single';
  $('#poodlgtitle').textContent = p ? '编辑出口组' : '新建出口组';
  $('#poname').value = p ? p.name : '';
  $('#postep').value = p ? p.rr_step : (meta.rr_step || 5);

  $('#pomode').innerHTML = (meta.modes || []).map(m =>
    '<button type="button" data-pm="' + esc(m.mode) + '">' + esc(m.label) + '</button>').join('');
  paintPoolMode();

  // 已不在出口列表里的旧成员单独列出并默认不勾：
  // 勾着保存会被后端判成"出口不存在"而整次失败，悄悄丢掉又是在改用户的组。
  const cur = p ? (p.members || []).map(m => m.host) : [];
  const alive = view.exits || [];
  const dead = cur.filter(h => !alive.some(e => e.host === h));
  const rows = alive.slice().sort((a, b) => (a.status === 'up' ? 0 : 1) - (b.status === 'up' ? 0 : 1));
  $('#pohosts').innerHTML = rows.map(e =>
      '<label><input type="checkbox" value="' + esc(e.host) + '"'
      + (cur.indexOf(e.host) >= 0 ? ' checked' : '') + '>'
      + '<span class="h">' + esc(e.host) + '</span>'
      + '<span class="n">' + esc(e.country || e.region || '') + ' ' + esc(e.exit_ip || e.status) + '</span></label>'
    ).join('')
    + dead.map(h => '<label class="dead"><input type="checkbox" value="' + esc(h) + '">'
        + '<span class="h">' + esc(h) + '</span><span class="n">已失效，保存后从组里移除</span></label>').join('')
    || '<div class="none">还没有可用的出口，先开一条再建组。</div>';
  // 补位目标条数：已有组沿用它存的值，新建时按勾选条数起头
  $('#poofill').checked = p ? !!p.auto_fill : false;
  $('#posize').value = (p && p.size) ? p.size : 0;
  syncPoolSel();

  openModal('pooldlg');
}

function paintPoolMode(){
  $$('#pomode button').forEach(b => b.classList.toggle('on', b.dataset.pm === poolMode));
  const meta = (poolMeta && poolMeta.modes || []).find(m => m.mode === poolMode);
  $('#podesc').textContent = meta ? meta.desc : '';
  // 步长只对轮询有意义，其他模式下留着输入框只会让人以为调了有用
  $('#postepwrap').hidden = poolMode !== 'roundrobin';
}

function syncPoolSel(){
  const n = $$('#pohosts input:checked').length;
  $('#pomsel').textContent = '已选 ' + n + ' 条';
  $('#posave').disabled = n === 0;
  paintPoolFill(n);
}

// 维持条数的上限就是勾选的组员数：目标比组员还少，保存完组立刻"缺人"，
// 补位回路会凭空多开几条隧道去凑一个用户没要过的规模（后端同样会拒）。
// 开关关掉时把输入框整块收起——它是这个开关的参数，留着只会让人以为单独有效。
function paintPoolFill(n){
  const on = $('#poofill').checked;
  $('#posizewrap').hidden = !on;
  if(!on) return;
  const size = $('#posize');
  size.min = 1;
  size.max = Math.max(1, n);
  // 空着、0、比勾选数还大，都夹回"就等于勾选数"：
  // 开着开关最常见的意图就是"我勾几条就要维持几条"。
  const v = parseInt(size.value, 10);
  if(!(v >= 1) || v > n) size.value = Math.max(1, n);
}

$('#pomode').addEventListener('click', e => {
  const b = e.target.closest('[data-pm]');
  if(!b) return;
  poolMode = b.dataset.pm;
  paintPoolMode();
});
$('#pohosts').addEventListener('change', syncPoolSel);
$('#poofill').addEventListener('change', () => paintPoolFill($$('#pohosts input:checked').length));

$('#posave').onclick = async () => {
  const btn = $('#posave');
  const hosts = $$('#pohosts input:checked').map(i => i.value);
  if(!hosts.length) return toast('至少勾选一条出口', 'bad');
  const autoFill = $('#poofill').checked;
  const size = parseInt($('#posize').value, 10) || 0;
  if(autoFill && size > hosts.length) return toast('维持条数不能超过勾选的出口数', 'bad');
  btn.disabled = true;
  try{
    await api('/api/pool/save', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        id: poolEdit, name: $('#poname').value.trim(), mode: poolMode,
        rr_step: parseInt($('#postep').value, 10) || 5, hosts,
        auto_fill: autoFill, size,
      }),
    });
    toast(poolEdit ? '出口组已保存' : '出口组已创建', 'ok');
    closeModal('pooldlg');
    await poll();
  }catch(e){ toast(e.message, 'bad'); }
  btn.disabled = false;
};

document.addEventListener('click', async e => {
  const nb = e.target.closest('#newpool');
  if(nb) return openPool('');

  const ed = e.target.closest('[data-pedit]');
  if(ed) return openPool(ed.dataset.pedit);

  const del = e.target.closest('[data-pdel]');
  if(del){
    if(!confirm('删除出口组「' + del.dataset.name + '」？绑在它上面的节点链接会一起解绑回直连。')) return;
    const btn = del; btn.disabled = true;
    try{
      const r = await api('/api/pool/delete', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({id: del.dataset.pdel}),
      });
      toast('已删除' + ((r.unbound || []).length ? '，并解绑 ' + r.unbound.length + ' 条链接' : ''), 'ok');
      poolMeta = null;
      await poll();
    }catch(err){ toast(err.message, 'bad'); btn.disabled = false; }
    return;
  }

  const cr = e.target.closest('[data-pcred]');
  if(cr){
    const btn = cr; btn.disabled = true;
    try{
      const r = await api('/api/pool/cred', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({id: cr.dataset.pcred}),
      });
      toast('已重置本机口令：' + r.user + ' / ' + r.pass + '（只影响 127.0.0.1 这一跳）', 'ok');
      await poll();
    }catch(err){ toast(err.message, 'bad'); }
    btn.disabled = false;
  }
});

/* ───────────── 节点链接表格 ───────────── */

function renderNodes(){
  const body = $('#nodesBody');
  const all = allInbounds();
  $('#nodesCount').textContent = all.length + ' 条';
  const kw = nodeQuery.trim().toLowerCase();
  const list = kw ? all.filter(i => [i.remark, i.protocol, String(i.port)]
    .some(v => String(v || '').toLowerCase().includes(kw))) : all;

  if(!all.length){
    body.innerHTML = '<tr><td colspan="6"><div class="empty" style="border:0;padding:40px">'
      + '<div class="glyph">' + ICON.inbox + '</div><h3>还没有节点链接</h3>'
      + (isXCL() ? '<p>节点由 xray-cf-lite 生成，这里只决定它们走哪条出口。</p>'
                 : '<p>开出口时按模板复制，或者直接新建一条。</p>'
                 + '<div class="row"><button class="btn primary" id="newnode3">'
                 + ICON.plus + '新建节点</button></div>')
      + '</div></td></tr>';
    return;
  }
  if(!list.length){
    body.innerHTML = '<tr><td colspan="6" style="padding:28px;text-align:center;color:var(--text-3)">没有匹配项</td></tr>';
    return;
  }
  body.innerHTML = list.map(i => {
    const e = i.__exit;
    const st = e ? e.status : 'stopped';
    const badge = e
      ? (st === 'up' ? '<span class="badge ok"><i class="d"></i>已连通</span>'
        : st === 'starting' ? '<span class="badge warn"><i class="d"></i>连接中</span>'
        : st === 'failed' ? '<span class="badge bad"><i class="d"></i>出口失败</span>'
        : '<span class="badge idle"><i class="d"></i>出口已停</span>')
      : '<span class="badge idle">直连</span>';
    const exitCell = e
      ? '<span class="m">' + esc(e.exit_ip || '—') + '</span>'
        + '<div style="font-size:11px;color:var(--text-3)">' + esc(e.country || e.region) + '</div>'
      : '<span style="color:var(--text-3)">不走隧道</span>';
    return '<tr>'
      + '<td><div style="font-weight:550">' + esc(i.remark || (i.protocol + '-' + i.port)) + '</div>'
      +   '<div style="font-size:11px;color:var(--text-3)" class="m">' + esc(i.tag) + '</div></td>'
      + '<td><span class="badge ' + (PROTO_TINT[i.protocol] ?? 'idle') + '">'
      +   esc(i.protocol) + '</span></td>'
      + '<td class="m">' + i.port + '</td>'
      + '<td>' + exitCell + '</td>'
      + '<td>' + badge + (i.enable === false ? ' <span class="badge idle">已禁用</span>' : '') + '</td>'
      + '<td class="r"><button class="btn sm" data-detail="' + i.id + '">'
      +   ICON.eye + '详情</button></td>'
      + '</tr>';
  }).join('');
}

/* ───────────── 任务进度 ───────────── */

function renderJobs(){
  paintBuildJob();
  const box = $('#jobs');
  if(!jobs.length){ box.innerHTML = ''; return; }
  box.innerHTML = jobs.map(j => {
    const steps = (j.steps || []).map(s => {
      const ic = {ok:ICON.ok, failed:ICON.bad, running:ICON.run}[s.status] || ICON.wait;
      const t = s.detail ? s.label + ' — ' + s.detail : s.label;
      return '<span class="step ' + esc(s.status) + '" title="' + esc(t) + '">' + ic
        + '<span>' + esc(s.status === 'ok' && s.detail ? s.detail : s.label) + '</span></span>';
    }).join('');
    const pct = j.total ? Math.round(100 * num(j.done) / num(j.total)) : 0;
    const close = j.status === 'running' ? ''
      : '<button class="ico" data-job="' + esc(j.id) + '" title="关闭">' + ICON.x + '</button>';
    return '<div class="job ' + esc(j.status) + '">'
      + '<div class="top"><strong>' + esc(j.summary) + '</strong>'
      + '<span class="frac">' + j.done + '/' + j.total + '</span>'
      + '<span class="spacer"></span>'
      + (j.status === 'running'
          ? '<span class="badge acc"><i class="d"></i>进行中</span>'
          : j.status === 'done'
            ? '<span class="badge ok">' + ICON.ok + '完成</span>'
            : '<span class="badge bad">' + ICON.bad + '有失败</span>')
      + close + '</div>'
      + '<div class="prog"><i style="width:' + pct + '%"></i></div>'
      + '<div class="steps">' + steps + '</div></div>';
  }).join('');
}

// 自己编 openvpn 是个十几分钟到几十分钟的后台活，卡片里必须看得见跑到哪一步。
// 作业卡片本身渲染在出口页，用户点完按钮人还留在设置页，所以这里镜像一行进来；
// 取"最该看的那一步"：先失败、再进行中、都没有就看最后一条已完成的。
function paintBuildJob(){
  const box = $('#cliOvpnJob');
  if(!box) return;
  const j = (jobs || []).find(x => (x.summary || '').indexOf('源码编译 openvpn') === 0);
  if(!j){ box.hidden = true; box.textContent = ''; return; }
  const st = j.steps || [];
  const cur = st.find(s => s.status === 'failed')
    || st.find(s => s.status === 'running')
    || st.slice().reverse().find(s => s.status === 'ok');
  const head = j.status === 'running' ? '正在自己编译 openvpn'
    : j.status === 'failed' ? '自己编译 openvpn 没成功' : '自己编译 openvpn 已完成';
  let t = head + '（' + num(j.done) + '/' + num(j.total) + '）'
    + (cur ? '：' + cur.label : '');
  if(cur && cur.detail) t += '\n' + cur.detail;
  if(j.status !== 'running') t += '\n（这一行在出口页的作业卡片里关掉后消失）';
  box.textContent = t;
  box.hidden = false;
}

/* ───────────── 轮询 ───────────── */

function setFresh(){
  const el = $('#fresh'), txt = $('#freshTxt');
  el.classList.remove('stale','down');
  if(!lastOK){ txt.textContent = '连接中…'; return; }
  const s = Math.floor((Date.now() - lastOK)/1000);
  if(s > 20){ el.classList.add('down'); txt.textContent = '状态已断开'; return; }
  if(s > 7){ el.classList.add('stale'); }
  txt.textContent = s < 3 ? '实时' : (s < 60 ? s + ' 秒前更新' : Math.floor(s/60) + ' 分钟前更新');
}

let busy = false;
let apiErr = '';
async function poll(){
  clearTimeout(pollTimer);
  if(busy){ pollTimer = setTimeout(poll, 1200); return; }
  busy = true;
  let failed = 0;
  try{
    view = await api('/api/exits');
    apiErr = '';
    const p = view.panel || '';
    if(p && p !== lastPanel) toast('面板：' + p, 'bad');   // 只在文案变化时报，免得每轮刷屏
    lastPanel = p;
    // xray-cf-lite 的节点由它自己生成，fanout 这边只管把它们导到哪条出口
    $('#newnode').hidden = isXCL();
    // 链接由 xray-cf-lite 的订阅体系发，fanout 这边导不出来
    $('#exportAll').hidden = isXCL();
    renderExits();
    renderWarpBar();
    renderPools();
    renderOrphans();
    renderKPI();
    if(!$('#view-nodes').hidden) renderNodes();
    if($('#detail').classList.contains('open')) refreshDetailOwner();
  }catch(e){ failed++; apiErr = e.message; }
  try{ jobs = (await api('/api/jobs')) || []; renderJobs(); }catch(e){ failed++; }
  if(!regionsLoaded || !regions.length){
    try{
      regions = (await api('/api/regions')) || [];
      regionsLoaded = true;
      renderRegions();
      renderKPI();
    }catch(e){}
  }
  busy = false;
  // 任一读状态成功就算数据新鲜：/api/jobs 偶发失败不该让整个界面标成断开
  if(failed < 2) lastOK = Date.now();
  setFresh();
  booting = false;
  schedule();
}

// 有活干时快轮，闲下来慢轮，页面切到后台就不轮
function schedule(){
  clearTimeout(pollTimer);
  const active = jobs.some(j => j.status === 'running')
    || (view.exits || []).some(e => e.status === 'starting');
  let ms = active ? 1500 : 4000;
  if(document.hidden) ms = 15000;
  pollTimer = setTimeout(poll, ms);
}
document.addEventListener('visibilitychange', () => {
  if(!document.hidden){ poll(); }
  else schedule();
});
$('#refreshBtn').onclick = () => {
  const b = $('#refreshBtn');
  b.classList.add('ico','busy');
  b.disabled = true;
  regionsLoaded = false;
  poll().finally(() => { b.disabled = false; b.classList.remove('busy'); });
};
setInterval(setFresh, 2000);
// 分钟级重绘：让「已连接时长」自己往前走，弹窗开着时不动它
setInterval(() => {
  if($('#detail').classList.contains('open') || $('#wizard').classList.contains('open')) return;
  renderExits();
}, 30000);

/* ───────────── 新建向导 ───────────── */

function renderRegions(){
  const kw = $('#rgfilter').value.trim().toLowerCase();
  const list = regions.filter(r => !kw
    || r.code.toLowerCase().includes(kw) || r.name.toLowerCase().includes(kw));
  const total = regions.reduce((a,r) => a + num(r.available), 0);
  $('#regions').innerHTML = [
      '<button class="rg' + (region === '' ? ' on' : '') + '" data-rg="">'
      + '<b>不限地区</b><em>共 ' + total + ' 个可用</em></button>',
      '<button class="rg' + (region === '*' ? ' on' : '') + '" data-rg="*">'
      + '<b>每个国家</b><em>' + regions.length + ' 国各来几条</em></button>',
    ].concat(list.map(r =>
      '<button class="rg' + (region === r.code ? ' on' : '') + '" data-rg="' + esc(r.code) + '">'
      + '<b>' + esc(r.name || r.code) + '</b>'
      + '<em>' + r.available + ' 空闲 · ' + num(r.best_speed_mbps).toFixed(0) + ' Mbps'
      + (num(r.best_ping) ? ' · ' + num(r.best_ping) + 'ms' : '') + '</em></button>')).join('');
  updateAvail();
}

function availOf(code){
  if(code === '' || code === '*') return regions.reduce((a,r) => a + num(r.available), 0);
  const r = regions.find(x => x.code === code);
  return r ? num(r.available) : 0;
}

function updateAvail(){
  const want = num($('#count').value);
  const hint = $('#availhint');
  // 选了「每个国家」时，数量的意思是每国几个，提示要给出总条数
  $('#countlabel').textContent = region === '*' ? '每个国家几条' : '数量';
  if(region === '*'){
    const n = regions.length;
    const total = Math.min(n * want, availOf('*'));
    hint.className = 'hint';
    hint.textContent = n
      ? n + ' 个国家 × ' + want + '，一共 ' + total + ' 条出口'
      : '还没有可用节点';
    $('#go').disabled = !n || !want;
    $('#wzhint').textContent = n ? '槽位不够时先开节点多的地区' : '';
    return;
  }
  const avail = availOf(region);
  if(!avail){
    hint.className = 'hint bad';
    hint.textContent = '这个地区没有空闲节点';
  } else if(want > avail){
    hint.className = 'hint bad';
    hint.textContent = '只剩 ' + avail + ' 个，将全部使用';
  } else {
    hint.className = 'hint';
    hint.textContent = '可用 ' + avail + ' 个节点';
  }
  $('#go').disabled = !avail;
  $('#wzhint').textContent = avail ? '将开 ' + Math.min(want, avail) + ' 条出口' : '';
}

async function loadWizard(){
  try{
    regions = (await api('/api/regions')) || [];
    regionsLoaded = true;
    renderRegions();
  }catch(e){ toast('读取地区失败: ' + e.message, 'bad'); }

  const sel = $('#tpl');
  // xray-cf-lite 模式不能复制节点，向导退化成「只开出口」，之后在节点详情里挑出口
  if(isXCL()){
    $('#tplwrap').hidden = true;
    sel.innerHTML = '<option value="0">只开出口，不建节点</option>';
    return;
  }
  $('#tplwrap').hidden = false;
  try{
    // 已经挂在出口上的多半是上一批复制出来的，拿它当模板会套娃，
    // 所以把没绑出口的排在前面并默认选中
    const v = await api('/api/exits');
    const free = v.direct || [];
    const bound = (v.exits || []).flatMap(e => e.inbounds || []);
    inbounds = free.concat(bound);
    if(!inbounds.length){
      sel.innerHTML = '<option value="0">还没有节点</option>';
      $('#tplhint').textContent = '先用「新建节点」建一个，之后这里可以按它批量生成';
      return;
    }
    const opt = i => '<option value="' + i.id + '">'
      + esc(i.remark || ('端口 ' + i.port)) + ' · ' + esc(i.protocol) + ' :' + i.port + '</option>';
    sel.innerHTML =
      (free.length ? '<optgroup label="未绑定出口">' + free.map(opt).join('') + '</optgroup>' : '')
      + (bound.length ? '<optgroup label="已挂在出口上">' + bound.map(opt).join('') + '</optgroup>' : '')
      + '<option value="0">只开出口，不建节点</option>';
    $('#tplhint').textContent = '每个出口复制一份，客户端 UUID 保持一致，只有端口不同';
  }catch(e){
    sel.innerHTML = '<option value="0">' + backendName() + '不可用</option>';
    $('#tplhint').textContent = e.message;
  }
}

document.addEventListener('click', e => {
  if(e.target.closest('#newexit') || e.target.closest('#newexit2')){
    openModal('wizard');
    if(!regionsLoaded) loadWizard(); else { renderRegions(); loadWizard(); }
  }
  const rg = e.target.closest('[data-rg]');
  if(rg){
    region = rg.dataset.rg;
    // 「每个国家」是批量，默认每国 1 个，免得一点就开出几十条
    if(region === '*' && num($('#count').value) > 3) $('#count').value = '1';
    renderRegions();
  }
});
$('#rgfilter').oninput = renderRegions;
$('#minus').onclick = () => step(-1);
$('#plus').onclick = () => step(1);
function step(d){
  const el = $('#count');
  el.value = Math.min(20, Math.max(1, num(el.value) + d));
  updateAvail();
}
$('#count').oninput = updateAvail;

$('#go').onclick = async e => {
  const want = Math.min(num($('#count').value) || 1, availOf(region) || 1);
  const tpl = $('#tpl').value || '0';
  e.target.disabled = true;
  try{
    await api('/api/provision?count=' + want
      + (region === '*' ? '&every=1' : '&region=' + encodeURIComponent(region))
      + '&template=' + tpl, {method:'POST'});
    closeModal('wizard');
    showView('dashboard');
    poll();
  }catch(err){ toast(err.message, 'bad'); }
  e.target.disabled = false;
};

/* ───────────── 新建节点 ───────────── */

document.addEventListener('click', e => {
  if(e.target.closest('#newnode') || e.target.closest('#newnode2') || e.target.closest('#newnode3')){
    $('#nnhint').textContent = '';
    syncNodeForm();
    openModal('newnodebox');
  }
});

// 表单随协议/传输/安全层联动：只露出当前组合真正用得到的字段
function syncNodeForm(){
  const proto = $('#nproto').value;
  const net   = $('#nnet').value;
  const sec   = $('#nsec').value;

  // REALITY 靠模仿 TLS 握手工作，套在自带头部的传输上没有意义
  const realityOK = net === 'tcp' || net === 'xhttp' || net === 'grpc';
  const secSel = $('#nsec');
  for(const o of secSel.options){
    if(o.value === 'reality') o.disabled = !realityOK;
  }
  if(secSel.value === 'reality' && !realityOK) secSel.value = 'none';

  const cur = secSel.value;
  $('#nsniwrap').hidden  = cur !== 'tls';
  $('#ncertkeywrap').hidden = cur !== 'tls';
  $('#ndestwrap').hidden = cur !== 'reality';

  // Vision 只在 VLESS + 裸 TCP + TLS/REALITY 下有效
  const visionOK = proto === 'vless' && net === 'tcp' && cur !== 'none';
  $('#nvisionwrap').hidden = !visionOK;
  if(!visionOK) $('#nvision').checked = false;

  const needPath = net === 'ws' || net === 'httpupgrade' || net === 'xhttp' || net === 'grpc';
  $('#npathwrap').hidden = !needPath;
  $('#npathlabel').textContent = net === 'grpc' ? '服务名' : '路径';

  $('#nsechint').textContent =
    cur === 'reality' ? '密钥与 shortId 自动生成；REALITY 只在 tcp / xhttp / grpc 下可用' :
    cur === 'tls'     ? '不填证书就用自签，链接会带证书指纹让客户端固定信任' : '';
}
$('#nproto').onchange = syncNodeForm;
$('#nnet').onchange = syncNodeForm;
$('#nsec').onchange = syncNodeForm;

$('#ncreate').onclick = async e => {
  const q = new URLSearchParams({
    protocol: $('#nproto').value,
    network:  $('#nnet').value,
    security: $('#nsec').value,
    port:     ($('#nport').value || '').trim(),
    remark:   ($('#nremark').value || '').trim(),
    path:     ($('#npath').value || '').trim(),
    sni:      ($('#nsni').value || '').trim(),
    cert:     ($('#ncert').value || '').trim(),
    key:      ($('#nkey').value || '').trim(),
    dest:     ($('#ndest').value || '').trim(),
  });
  if($('#nvision').checked) q.set('vision', '1');
  e.target.disabled = true;
  try{
    const r = await api('/api/panel/inbound/new?' + q.toString(), {method:'POST'});
    toast('已创建 ' + r.protocol + ' 节点，端口 ' + r.port, 'ok');
    closeModal('newnodebox');
    $('#nport').value = '';
    $('#nremark').value = '';
    poll();
  }catch(err){ toast(err.message, 'bad'); }
  e.target.disabled = false;
};

/* ───────────── 出口操作 ───────────── */

document.addEventListener('click', async e => {
  const stop = e.target.closest('[data-stop]');
  if(stop){
    if(!confirm('停止这条出口？挂在它上面的节点链接会退回直连。')) return;
    stop.disabled = true;
    try{ await api('/api/stop?slot=' + stop.dataset.stop, {method:'POST'}); }
    catch(err){ toast(err.message, 'bad'); }
    poll();
    return;
  }
  const swap = e.target.closest('[data-swap]');
  if(swap){
    swap.disabled = true;
    swap.classList.add('busy');
    try{
      await api('/api/swap?slot=' + swap.dataset.swap, {method:'POST'});
      toast('正在换节点，端口不变', 'ok');
    }catch(err){ toast(err.message, 'bad'); }
    poll();
    return;
  }
  const cred = e.target.closest('[data-cred]');
  if(cred){ openCred(Number(cred.dataset.cred)); return; }
  const cs = e.target.closest('[data-copysock]');
  if(cs){
    const x = (view.exits || []).find(v => v.slot === Number(cs.dataset.copysock));
    if(x) copy(socksURL(credHost(x), x.port, x.socks_user, x.socks_pass));
    return;
  }
  const cp = e.target.closest('[data-copy]');
  if(cp){ if(cp.dataset.copy) copy(cp.dataset.copy); return; }
  const job = e.target.closest('[data-job]');
  if(job){
    try{ await api('/api/jobs/dismiss?id=' + job.dataset.job, {method:'POST'}); }catch(err){}
    poll();
    return;
  }
  const del = e.target.closest('[data-delorphans]');
  if(del){
    const list = view.direct || [];
    if(!confirm('删除这 ' + list.length + ' 个未绑定节点？此操作不可撤销。')) return;
    del.disabled = true;
    try{
      await api('/api/xui/delete?ids=' + list.map(i => i.id).join(','), {method:'POST'});
      toast('已清理 ' + list.length + ' 个入站', 'ok');
    }catch(err){ toast(err.message, 'bad'); }
    poll();
    return;
  }
  const one = e.target.closest('[data-delone]');
  if(one){
    if(!confirm('删除入站 ' + one.dataset.name + '？此操作不可撤销。')) return;
    one.disabled = true;
    try{
      await api('/api/xui/delete?ids=' + one.dataset.delone, {method:'POST'});
      toast('已删除 ' + one.dataset.name, 'ok');
    }catch(err){ toast(err.message, 'bad'); }
    poll();
  }
});

$('#stopall').onclick = async e => {
  if(!confirm('停止全部 ' + view.exits.length + ' 个出口？')) return;
  e.target.disabled = true;
  for(const x of view.exits){
    try{ await api('/api/stop?slot=' + x.slot, {method:'POST'}); }catch(err){}
  }
  e.target.disabled = false;
  poll();
};

/* ───────────── 节点详情 ───────────── */

// 详情弹窗的重绘要跟轮询解耦：正在编辑时被 poll 刷掉输入会很烦
async function openDetail(id){
  $('#dbody').innerHTML = '<div class="skel"><div class="l w40"></div>'
    + '<div class="l w25"></div><div class="l w60"></div><div class="l"></div></div>';
  curDetail = null;
  $('#ddel').disabled = true;
  openModal('detail');
  try{
    const d = await api('/api/xui/detail?id=' + id);
    curDetail = d;
    renderDetail(d);
    // xray-cf-lite 的节点归它自己管，不给删除
    $('#ddel').hidden = isXCL();
    $('#ddel').disabled = isXCL();
  }catch(err){
    $('#dbody').innerHTML = '<div class="errbox"><b>读取失败</b>' + esc(err.message) + '</div>';
  }
}

// ownerOf 找一条入站挂在哪个出口上：先看单出口，再看出口组。
// 返回 null 表示没绑，走直连。
function ownerOf(id){
  const e = (view.exits || []).find(x => (x.inbounds || []).some(i => i.id === id));
  if(e) return {kind: 'exit', ref: e};
  const p = (view.pools || []).find(x => (x.inbounds || []).some(i => i.id === id));
  if(p) return {kind: 'pool', ref: p};
  return null;
}

// curBound 把 ownerOf 的结果换成下拉框的选中值：
// 单出口用主机名，组用 pool-<id>，两者在同一个 select 里共存。
function curBound(o){
  if(!o) return '';
  return o.kind === 'pool' ? o.ref.identity : o.ref.host;
}

function ownerBadge(o){
  if(!o) return '<span class="badge idle">直连，不出口</span>';
  if(o.kind === 'pool'){
    const p = o.ref;
    const k = !p.running || p.up === 0 ? 'bad' : (p.up < p.total ? 'warn' : 'ok');
    return '<span class="badge ' + k + '"><i class="d"></i>'
      + esc(p.name) + ' · ' + esc(p.mode_label) + ' · ' + p.up + '/' + p.total + ' 可用</span>';
  }
  const owner = o.ref;
  return '<span class="badge ' + (owner.status === 'up' ? 'ok' : owner.status === 'starting' ? 'warn' : 'bad')
    + '"><i class="d"></i>' + esc(owner.country || owner.region || owner.host) + ' · '
    + esc(owner.exit_ip || STATUS[owner.status] || owner.status) + '</span>';
}

// 轮询只更新「当前出口」这一行，不动正在编辑的输入框
function refreshDetailOwner(){
  if(!curDetail) return;
  const el = $('#downer');
  if(!el) return;
  el.innerHTML = ownerBadge(ownerOf(curDetail.id));
}

// 出口下拉：列出所有已连通的隧道，外加「直连」。绑定按 Xray 的 inboundTag 走。
function exitOptions(currentHost){
  const up = (view.exits || []).filter(e => e.status === 'up');
  // 出口组排在单出口之前：会去看这个下拉的人多半正是为了保活才来的
  const pools = (view.pools || []).filter(p => p.running && p.up > 0);
  const pg = pools.length
    ? '<optgroup label="出口组（组内自动选路）">'
      + pools.map(p => '<option value="' + esc(p.identity) + '"'
          + (p.identity === currentHost ? ' selected' : '') + '>'
          + esc(p.name + ' · ' + p.mode_label + ' · ' + p.up + '/' + p.total) + '</option>').join('')
      + '</optgroup>'
    : '';
  return '<option value=""' + (currentHost ? '' : ' selected') + '>直连（不走隧道）</option>'
    + pg
    + '<optgroup label="单出口">'
    + up.map(e => '<option value="' + esc(e.host) + '"'
        + (e.host === currentHost ? ' selected' : '') + '>'
        + esc((e.exit_ip || e.host) + ' · ' + (e.country || e.region)) + '</option>').join('')
    + '</optgroup>';
}

function renderDetail(d){
  const owner = ownerOf(d.id);

  const clients = (d.clients || []).map((c, i) => {
    const link = (d.links || [])[i] || '';
    return '<div class="clt"><div class="ch">'
      + '<span class="em">' + esc(c.email) + '</span>'
      + '<span class="id" title="' + esc(c.id) + '">' + esc(c.id) + '</span>'
      + (c.enable === false ? '<span class="badge idle">停用</span>' : '')
      + '<span class="spacer"></span>'
      + (link ? '<button class="ico" data-copy="' + esc(link) + '" title="复制链接">' + ICON.copy + '</button>' : '')
      + '<button class="ico" data-creset="' + esc(c.email) + '" title="换一套凭据，旧链接立即失效">' + ICON.redo + '</button>'
      + '<button class="ico danger" data-cdel="' + esc(c.email) + '" title="删除这个客户端">' + ICON.trash + '</button>'
      + '</div>'
      + (link ? '<div class="share">' + esc(link) + '</div>' : '')
      + '</div>';
  }).join('');

  $('#dtitle').textContent = (d.remark || '节点') + ' · :' + d.port;
  const editable = !isXCL();
  const tlsLine = esc(d.protocol)
    + (d.network ? ' <span style="color:var(--text-3)">/</span> ' + esc(d.network) : '')
    + (d.tls && d.tls !== 'none'
        ? ' <span style="color:var(--text-3)">/</span> ' + esc(d.tls) : '');

  $('#dbody').innerHTML =
      '<dl class="kvs">'
    + '<dt>当前出口</dt><dd><span id="downer"></span></dd>'
    + '<dt>改绑到</dt><dd><select class="inp" id="dbind" data-tag="' + esc(d.tag) + '" '
    +   'style="max-width:280px;height:29px;font-size:12.5px">' + exitOptions(curBound(owner)) + '</select></dd>'
    + '<dt>协议</dt><dd>' + tlsLine + '</dd>'
    + '<dt>监听</dt><dd>' + esc(d.listen || '0.0.0.0') + '</dd>'
    + '<dt>inboundTag</dt><dd>' + esc(d.tag) + '</dd>'
    + '</dl>'
    + (editable ? (
        '<div class="grp"><div class="gl">编辑</div>'
      +   '<div class="frow">'
      +     '<div class="field"><label>备注</label>'
      +       '<input class="inp" id="dremark" type="text" value="' + esc(d.remark || '') + '"></div>'
      +     '<div class="field"><label>端口</label>'
      +       '<input class="inp mono" id="dport" type="text" inputmode="numeric" value="' + d.port + '"></div>'
      +   '</div>'
      +   '<div class="hdr-row">'
      +     '<label class="sw"><input type="checkbox" id="denable"'
      +       (d.enable === false ? '' : ' checked') + '><span class="track"></span>'
      +       '<span>启用</span></label>'
      +     '<span class="spacer"></span>'
      +     '<button class="btn primary sm" id="dsave">保存</button>'
      +   '</div></div>'
      + '<div class="divider"></div>'
      + '<div class="hdr-row"><h4>客户端凭据</h4><span class="n">'
      +   (d.clients || []).length + ' 套</span><span class="spacer"></span>'
      +   '<button class="btn sm" id="dcadd">' + ICON.plus + '添加一套</button></div>'
      + (clients || '<div class="hint">还没有客户端，点上面添加一套。</div>')
      + '<div class="hint">一套凭据可以发给一个人，单独重置后旧链接立即失效。</div>')
      : '<div class="errbox" style="background:var(--accent-soft);border-color:var(--accent-ring);color:var(--text-2)">'
        + '<b style="color:var(--accent)">由 xray-cf-lite 托管</b>'
        + '端口、UUID 和分享链接都去 xray-cf-lite 那边改。这里只决定它走哪条出口。</div>');
  refreshDetailOwner();
}

// 未绑定区的出口下拉，选中即绑
document.addEventListener('change', async e => {
  const sel = e.target.closest('.obind');
  if(!sel || !sel.value) return;
  sel.disabled = true;
  try{
    await api('/api/xui/bind?tag=' + encodeURIComponent(sel.dataset.tag)
      + '&host=' + encodeURIComponent(sel.value), {method:'POST'});
    toast('已绑定到出口', 'ok');
    poll();
  }catch(err){ toast(err.message, 'bad'); sel.disabled = false; }
});

// 出口下拉改动即生效。绑定按 inboundTag 走，host 传空表示解绑回直连。
document.addEventListener('change', async e => {
  const sel = e.target.closest('#dbind');
  if(!sel) return;
  sel.disabled = true;
  try{
    await api('/api/xui/bind?tag=' + encodeURIComponent(sel.dataset.tag)
      + '&host=' + encodeURIComponent(sel.value), {method:'POST'});
    toast(sel.value ? '已绑定' : '已解绑回直连', 'ok');
    await openDetail(curDetail.id);
    poll();
  }catch(err){ toast(err.message, 'bad'); }
  sel.disabled = false;
});

document.addEventListener('click', async e => {
  const link = e.target.closest('[data-detail]');
  if(link) return openDetail(link.dataset.detail);

  if(e.target.closest('#dsave')){
    const btn = e.target.closest('#dsave');
    btn.disabled = true;
    const q = new URLSearchParams({
      id: curDetail.id,
      port: ($('#dport').value || '').trim(),
      remark: ($('#dremark').value || '').trim(),
      enable: $('#denable').checked ? '1' : '0',
    });
    try{
      await api('/api/panel/inbound/update?' + q, {method:'POST'});
      toast('已保存', 'ok');
      await openDetail(curDetail.id);
      poll();
    }catch(err){ toast(err.message, 'bad'); btn.disabled = false; }
    return;
  }

  const add = e.target.closest('#dcadd');
  if(add){
    add.disabled = true;
    try{
      await api('/api/panel/client/add?id=' + curDetail.id, {method:'POST'});
      toast('已添加一套客户端凭据', 'ok');
      await openDetail(curDetail.id);
    }catch(err){ toast(err.message, 'bad'); add.disabled = false; }
    return;
  }

  const del = e.target.closest('[data-cdel]');
  if(del){
    if(!confirm('删除客户端 ' + del.dataset.cdel + '？它的链接会立即失效。')) return;
    del.disabled = true;
    try{
      await api('/api/panel/client/del?id=' + curDetail.id
        + '&email=' + encodeURIComponent(del.dataset.cdel), {method:'POST'});
      toast('已删除', 'ok');
      await openDetail(curDetail.id);
    }catch(err){ toast(err.message, 'bad'); del.disabled = false; }
    return;
  }

  const reset = e.target.closest('[data-creset]');
  if(reset){
    if(!confirm('重置 ' + reset.dataset.creset + ' 的凭据？已分发的旧链接会立即失效。')) return;
    reset.disabled = true;
    try{
      await api('/api/panel/client/reset?id=' + curDetail.id
        + '&email=' + encodeURIComponent(reset.dataset.creset), {method:'POST'});
      toast('已重置，旧链接失效', 'ok');
      await openDetail(curDetail.id);
    }catch(err){ toast(err.message, 'bad'); reset.disabled = false; }
    return;
  }

  // 详情抽屉里删掉当前这个入站
  const dd = e.target.closest('#ddel');
  if(dd && curDetail){
    const name = (curDetail.remark || curDetail.protocol || '节点') + ' :' + curDetail.port;
    if(!confirm('删除入站 ' + name + '？它的所有客户端链接都会失效，且不可撤销。')) return;
    dd.disabled = true;
    try{
      await api('/api/xui/delete?ids=' + curDetail.id, {method:'POST'});
      toast('已删除 ' + name, 'ok');
      curDetail = null;
      closeModal('detail');
      poll();
    }catch(err){ toast(err.message, 'bad'); dd.disabled = false; }
  }
});

$('#nq').oninput = e => { nodeQuery = e.target.value; renderNodes(); };
$('#q').oninput = e => { query = e.target.value; renderExits(); };
$$('#filters button').forEach(b => b.onclick = () => {
  filter = b.dataset.f;
  $$('#filters button').forEach(x => x.classList.toggle('on', x === b));
  renderExits();
});
$$('#layoutSeg button').forEach(b => b.onclick = () => {
  $$('#layoutSeg button').forEach(x => x.classList.toggle('on', x === b));
  $('#list').classList.toggle('list', b.dataset.l === 'list');
  try{ localStorage.setItem('fanout.layout', b.dataset.l); }catch(e){}
});
try{
  if(localStorage.getItem('fanout.layout') === 'list'){
    $('#list').classList.add('list');
    $$('#layoutSeg button').forEach(x => x.classList.toggle('on', x.dataset.l === 'list'));
  }
}catch(e){}

/* ───────────── SOCKS5 凭据 ───────────── */

function socksURL(host, port, user, pass){
  if(!user) return 'socks5://' + host + ':' + port;
  return 'socks5://' + user + ':' + pass + '@' + host + ':' + port;
}

// SOCKS5 端口监听在母机（跑 fanout 的这台服务器）上，客户端要连的是母机的
// 公网 IPv4，流量再从出口 IP 出去。出口 IP 是「出去以后」的地址，不能当连接地址。
// public_ip 是后端探测到的母机公网地址；探测不到才退回访问面板用的主机名。
function credHost(e){ return view.public_ip || location.hostname || (e && e.host); }

function openCred(slot){
  const e = (view.exits || []).find(x => x.slot === slot);
  if(!e){ toast('这个出口不在了', 'bad'); return; }
  curCred = {slot: slot, port: e.port, host: credHost(e)};
  $('#crtitle').textContent = (e.country || e.region) + ' · :' + e.port;
  $('#cruser').value = e.socks_user || '';
  $('#crpass').value = e.socks_pass || '';
  refreshCredURL();
  openModal('credbox');
}
function refreshCredURL(){
  if(!curCred) return;
  $('#crurl').textContent = socksURL(curCred.host, curCred.port,
    $('#cruser').value.trim(), $('#crpass').value.trim());
}
$('#cruser').oninput = refreshCredURL;
$('#crpass').oninput = refreshCredURL;

$('#crrand').onclick = () => {
  // 客户端和服务端都要能识别，只用无歧义、无需转义的字符
  const abc = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const gen = n => Array.from(crypto.getRandomValues(new Uint8Array(n)))
    .map(v => abc[v % abc.length]).join('');
  $('#cruser').value = 'fo' + gen(6);
  $('#crpass').value = gen(14);
  refreshCredURL();
};
$('#crcopy').onclick = () => { copy($('#crurl').textContent); };

$('#crsave').onclick = async e => {
  if(!curCred) return;
  const btn = e.target; btn.disabled = true;
  const q = new URLSearchParams({
    slot: curCred.slot,
    user: $('#cruser').value.trim(),
    pass: $('#crpass').value.trim(),
  });
  try{
    const r = await api('/api/cred?' + q, {method:'POST'});
    $('#cruser').value = r.user;
    $('#crpass').value = r.pass;
    refreshCredURL();
    toast('已保存，立即生效', 'ok');
    poll();
  }catch(err){ toast(err.message, 'bad'); }
  btn.disabled = false;
};

/* ───────────── 导出 ───────────── */

async function showExport(ids){
  if(!ids.length){ toast('没有可导出的节点', 'bad'); return; }
  $('#exbox').value = '读取中…';
  $('#excount').textContent = '';
  openModal('export');
  try{
    const d = await api('/api/xui/links?ids=' + ids.join(','));
    $('#exbox').value = (d.links || []).join('\n');
    $('#excount').textContent = (d.links || []).length + ' 条链接';
  }catch(err){ $('#exbox').value = '导出失败: ' + err.message; }
}
$('#exportAll').onclick = () =>
  showExport((view.exits || []).flatMap(x => (x.inbounds || []).map(i => i.id)));
$('#exportBound').onclick = () =>
  showExport(allInbounds().filter(i => i.__exit).map(i => i.id));
$('#exportAllNodes').onclick = () => showExport(allInbounds().map(i => i.id));
$('#copyall').onclick = () => { const v = $('#exbox').value; if(v) copy(v); };

/* ───────────── 订阅 ───────────── */

// 地址用 location.origin 拼：后端给的是访问路径下的相对部分，
// 这样反代、改端口、换路径之后拿到的都是用户此刻真正能访问的地址。
function showSub(d){
  $('#suburl').value = location.origin + d.path;
  const n = allInbounds().filter(i => i.__exit).length;
  $('#subcount').textContent = n ? n + ' 个已绑定节点' : '还没有节点，先开出口再建节点链接';
}
async function loadSub(){
  $('#suburl').value = '读取中…';
  try{ showSub(await api('/api/sub')); }
  catch(err){ $('#suburl').value = '读取失败: ' + err.message; }
}
$('#subBtn').onclick = () => showView('sub');
$('#subcopy').onclick = () => { const v = $('#suburl').value; if(v) copy(v); };
$('#subreset').onclick = async e => {
  if(!confirm('换一串口令？旧地址立刻失效，已经配过的客户端要重新填一次。')) return;
  e.target.disabled = true;
  try{
    showSub(await api('/api/sub/reset', {method:'POST'}));
    toast('已换新地址，旧地址立刻失效', 'ok');
  }catch(err){ toast(err.message, 'bad'); }
  e.target.disabled = false;
};

/* ───────────── 设置 ───────────── */

// 后端切换：把本机能用的模式列出来，装了的可选，没装的置灰并说明原因
async function loadBackendModes(){
  const sel = $('#setBackend');
  const hint = $('#setBackendHint');
  try{
    const m = await api('/api/panel/mode');
    curBackend = m.mode || '';
    sel.innerHTML = '<option value="">自动（按本机装了什么挑）</option>'
      + (m.modes || []).map(x =>
          '<option value="' + esc(x.mode) + '"' + (x.available ? '' : ' disabled')
          + '>' + esc(x.label) + (x.available ? '' : '（没装）') + '</option>').join('');
    sel.value = curBackend;
    const bad = (m.modes || []).filter(x => !x.available);
    hint.textContent = m.describe
      ? ('当前：' + m.describe + (bad.length ? '。灰掉的是本机没装的。' : ''))
      : '节点从哪来。装了 3x-ui 或 xray-cf-lite 就能直接接管，都没有就用自建。';
  }catch(err){
    sel.innerHTML = '<option value="">读取失败</option>';
    hint.textContent = err.message;
  }
}

const DEF = {
  health_interval:10, health_failures:3, health_timeout:6,
  backoff_min:5, backoff_max:60, connect_budget:35,
  max_tries:6, panel_debounce:1500, score_mode:'balanced', node_ttl:600,
};
function setV(id, v){ const el = $(id); if(el) el.value = (v == null ? '' : v); }
function getV(id, dflt){
  const el = $(id);
  if(!el) return dflt;
  const raw = el.value.trim();
  if(raw === '') return dflt;
  const n = Number(raw);
  return isFinite(n) ? n : dflt;
}

async function loadSettingsPage(){
  $('#setPw').value = '';
  $('#setPath').value = '';
  $('#setPathHint').textContent = '读取中…';
  loadBackendModes();
  loadClientBin();
  try{
    const s = await api('/api/settings');
    curSettings = s;
    $('#setPath').value = (s.base_path || '').replace(/^\//, '');
    $('#setPort').value = s.port || '';
    $('#setListen').value = s.listen_addr || '0.0.0.0';
    $('#setResi').checked = s.residential_only !== false;
    $('#setPathHint').textContent = '界面挂在这个路径下，扫端口的探不到。只能用字母数字和 - _。';
    $('#updCur').textContent = s.version || '-';
    $('#updLatest').textContent = '';
    $('#updNotes').hidden = true;
    $('#updApply').hidden = true;
    $('#updCheck').disabled = false;

    const c = s.conn || {};
    setV('#setHealthInterval', c.health_interval ?? DEF.health_interval);
    setV('#setHealthFails',     c.health_failures ?? DEF.health_failures);
    setV('#setHealthTimeout',   c.health_timeout ?? DEF.health_timeout);
    setV('#setBackoffMin',      c.backoff_min ?? DEF.backoff_min);
    setV('#setBackoffMax',      c.backoff_max ?? DEF.backoff_max);
    setV('#setConnectBudget',   c.connect_budget ?? DEF.connect_budget);
    setV('#setMaxTries',        c.max_tries ?? DEF.max_tries);
    setV('#setPanelDebounce',   c.panel_debounce ?? DEF.panel_debounce);
    setV('#setNodeTtl',         c.node_ttl ?? DEF.node_ttl);
    $('#setScoreMode').value = c.score_mode || DEF.score_mode;
    $('#setAeadOnly').checked = !!c.aead_only;
    markDirty(false);
  }catch(err){ $('#setPathHint').textContent = '读取失败: ' + err.message; }
}

let dirty = false;
function markDirty(v){
  dirty = v;
  $('#setSaved').textContent = v ? '有未保存的改动' : '改动不会自动生效，需要点保存';
  $('#setSaved').className = v ? 'hint bad' : 'hint';
}
$$('#view-settings input, #view-settings select').forEach(el => {
  el.addEventListener('input', () => markDirty(true));
  el.addEventListener('change', () => markDirty(true));
});
$('#setCancel').onclick = () => { if(dirty && !confirm('放弃未保存的改动？')) return; loadSettingsPage(); };

// 检查更新：问后端 GitHub 最新版，有新版就亮出更新按钮和更新内容
$('#updCheck').onclick = async e => {
  const b = e.currentTarget;
  b.disabled = true;
  try{
    const u = await api('/api/update/check');
    $('#updCur').textContent = u.current || '-';
    if(u.has_update){
      $('#updLatest').textContent = ' → 有新版本 ' + u.latest;
      $('#updApplyVer').textContent = u.latest;
      $('#updApply').hidden = false;
      $('#updNotes').textContent = u.notes || '（这个版本没写更新说明）';
      $('#updNotes').hidden = false;
      toast('发现新版本 ' + u.latest, 'info');
    } else {
      $('#updLatest').textContent = ' · 已是最新';
      $('#updApply').hidden = true;
      $('#updNotes').hidden = true;
      toast('已经是最新版', 'ok');
    }
  }catch(err){ toast(err.message, 'bad'); }
  b.disabled = false;
};

// 一键更新：后端下载替换二进制并重启服务，进程重启期间界面会短暂断连
$('#updApply').onclick = async e => {
  if(!confirm('更新到 ' + $('#updApplyVer').textContent + '？服务会重启，界面会短暂断开。')) return;
  const b = e.currentTarget;
  b.disabled = true;
  try{
    const r = await api('/api/update/apply', {method:'POST'});
    if(r.restarting){
      $('#updNotes').textContent = '已下载新版本，服务正在重启，几秒后刷新页面即可。';
      $('#updNotes').hidden = false;
      toast('更新中，服务重启后自动刷新', 'info');
      setTimeout(() => location.reload(), 6000);   // 给服务重启留点时间
    } else {
      toast(r.message || '已是最新版', 'ok');
      b.disabled = false;
    }
  }catch(err){
    toast(err.message, 'bad');
    b.disabled = false;
  }
};

// 内置客户端：出口连中间节点用的那两份程序。版本号常驻，
// "有没有新的"要点一下「检查更新」才问，免得每开一次页就打一次 GitHub 或包管理器。
let binState = null;   // 最近一次 /api/client/status 原文：弹确认框时要引用里面的命令

async function loadClientBin(){
  try{ paintClientBin(await api('/api/client/status'), false); }
  catch(err){ $('#cliXrayHint').textContent = '读本机客户端失败: ' + err.message; }
}

// 卡片底部那行小字：传空串就是收起，界面只在有话要说时多占一行。
function clientNote(msg){
  const n = $('#cliOvpnNote');
  if(!n) return;
  n.textContent = msg || '';
  n.hidden = !msg;
  const d = $('#cliWarpDiv');
  if(d) d.hidden = true;   // 分隔线跟着 WARP 那一段走，见 warpNote
}

// WARP 的说明单独占一段：它讲的是"重新注册"而不是"升级二进制"，
// 和上面 openvpn 那条不是一个话题，挤在同一行里两边都读不下去。
function warpNote(msg){
  const n = $('#cliWarpNote');
  if(!n) return;
  n.textContent = msg || '';
  n.hidden = !msg;
  const d = $('#cliWarpDiv');
  if(d) d.hidden = !msg;
}

// checked 表示这份状态带比对结果；没比对时不能显示"已是最新"，
// 那是把"还没查过"说成"查过且没问题"。openvpn 比的是本机仓库里的版本，
// 不是社区最新版——Debian 稳定版常年停在 2.5.x，照上游比会天天误报。
function paintClientBin(c, checked){
  binState = c;
  $('#cliXray').textContent = c.current || '未知';
  // 用的是 fanout 自己编的那份时必须标出来：胶囊上那个号就不再是"系统包里那份"了，
  // 不标会让人以为 apt 已经升到 2.7.9，之后查安全公告会找错对象。
  $('#cliOvpn').textContent = !c.openvpn ? '未安装'
    : c.openvpn + (c.openvpn_source_active ? '（自编译）' : '');
  $('#cliApply').hidden = true;
  $('#cliOvpnApply').hidden = true;
  $('#cliOvpnRepoOff').hidden = true;
  $('#cliOvpnBuild').hidden = true;
  $('#cliOvpnSrcOff').hidden = true;
  $('#cliCheck').disabled = false;
  // "已是最新"只有在 fanout 真能替换这份二进制时才轮得到它说：接管模式下
  // has_update 恒为 false（后端压根不动它），照原样显示就成了三台版本不同的机器
  // 同时报"已是最新"。管不着的时候只报数，不下判断。
  $('#cliXrayLatest').textContent = !checked || !c.latest ? ''
    : !c.updatable ? ' · 上游 ' + c.latest
    : c.has_update ? ' → ' + c.latest : ' · 已是最新';
  // openvpn 的基准是 GitHub 官方 release（OpenVPN/openvpn），跟机器上的发行版无关：
  // 拿各台自己的仓库号当"最新版"，才会出现三台三个号各自都叫最新。
  // 仓库能给到哪一号不占胶囊——那是下面那颗升级按钮的事，装出来的就是它。
  $('#cliOvpnLatest').textContent = !checked || !c.openvpn_upstream ? ''
    : c.openvpn_behind_upstream ? ' · 上游 ' + c.openvpn_upstream : ' · 已是上游最新';
  $('#cliXrayHint').textContent = c.updatable
    ? 'Xray 走官方发布，openvpn 走系统包管理器。'
    : (c.reason || '这台机器上没有可由 fanout 替换的 Xray。');
  if(checked && c.updatable && c.has_update && c.latest){
    $('#cliApplyVer').textContent = c.latest;
    $('#cliApply').hidden = false;
  }
  // 按钮装的是 openvpn_target：发行版仓库和 OpenVPN 官方 apt 源两边问完取最高的那个号。
  // 只问发行版仓库时，Ubuntu 26.04 上官方明明发了 2.7.1，界面却只能报仓库里的 2.6.20，
  // 还是"明明有新版却说升不到"。反过来官方源更旧（noble 只到 2.6.10）时它不会被选中，
  // 免得一次"升级"把人降到旧版。
  if(checked && c.openvpn_updatable && c.openvpn_has_update && c.openvpn_target){
    $('#cliOvpnApplyVer').textContent = c.openvpn_target;
    $('#cliOvpnApply').hidden = false;
  }
  // 接了官方源就得给一条等号的原路退回，不能只写在 README 里让人自己找文件
  const undo = $('#cliOvpnRepoOff');
  if(undo) undo.hidden = !(checked && c.openvpn_repo_wired);
  // 源码编译这条路：判据全在后端（deb 家族 + 确实落后 + apt 和官方源都够不到那个号
  // + 那个号还没编好），前端只看 openvpn_can_build，不在这里重比版本号。
  const build = $('#cliOvpnBuild');
  if(build && checked && c.openvpn_can_build && c.openvpn_build_ver){
    $('#cliOvpnBuildVer').textContent = c.openvpn_build_ver;
    build.hidden = false;
  }
  // 撤销源码版不给 checked 门槛：只要当前在用就该随时退得掉，
  // 哪怕用户没点过「检查更新」（后端还会再核一遍前缀在不在自己目录下面）
  const srcOff = $('#cliOvpnSrcOff');
  if(srcOff) srcOff.hidden = !c.openvpn_source_active;
  // 正在用编出来的那份时，把系统包那个号也摆出来，不然两个号只有一个看得见
  const srcNote = c.openvpn_source_active && c.openvpn_apt
    ? '隧道在跑的是自己编译的 ' + c.openvpn + '（' + c.openvpn_source_bin + '），系统包里是 '
      + c.openvpn_apt + '，没被覆盖。'
    : '';
  // 这行只在有话非说不可时装满：认不出家族、没有包管理器、索引没刷动，
  // 或者官方已经 2.7.9 而 apt 最高只给到 2.6.x——后者不说就成了"明明有新版却说没有"
  clientNote(checked ? [c.openvpn_reason, c.openvpn_note, srcNote].filter(Boolean).join('\n') : '');
  paintWarpBin(c, checked);
  if(c.check_error) toast('问最新版失败: ' + c.check_error, 'bad');
  if(c.warp_check_error) toast('问 WARP 最新版失败: ' + c.warp_check_error, 'bad');
}

// WARP 那颗胶囊上的号是"注册时上报给 Cloudflare 的客户端版本"，不是本机某个
// 二进制的版本号：fanout 用内核 WireGuard 直连，机器上没有属于它的 warp 客户端。
// 所以基准取自官方 apt 源的包索引（Cloudflare 没发 WARP 的 GitHub release），
// 按钮做的是重新注册，说成"升级客户端"就是骗人的。
function paintWarpBin(c, checked){
  const pill = $('#cliWarp');
  if(!pill) return;
  pill.textContent = c.warp_version || '未知';
  // 号相同却还有旧注册时不能写「→ 同一个号」——那是"升级到自己"。
  // 后端在这两种情况下都会把 has_update 置真（版本号落后，或手上的注册落后）。
  $('#cliWarpLatest').textContent = !checked || !c.warp_latest ? ''
    : c.warp_latest !== c.warp_version ? ' → ' + c.warp_latest
    : c.warp_has_update ? ' · ' + num(c.warp_stale) + ' 条待重注册' : ' · 已是最新';
  const apply = $('#cliWarpApply');
  // 重连作业跑着的时候不给第二次入口：按钮点下去是按当前各条出口逐条重连的，
  // 半途再来一次只会让两边互相踩。
  const canApply = !!(checked && c.warp_can_apply && c.warp_has_update && c.warp_latest && !warpBusy());
  if(canApply) $('#cliWarpApplyVer').textContent = c.warp_latest;
  apply.hidden = !canApply;
  const lines = [];
  if(!c.warp_ready && c.warp_reason) lines.push(c.warp_reason);
  else if(c.warp_need_tools)
    lines.push('本机还没有 wireguard-tools，开启中转时会自动装：' + lastStep(c.warp_pkg_cmd) + '。');
  if(!c.warp_enabled) lines.push('中转未开启：这个号只在中转打开后用于注册。');
  else if(checked && c.warp_stale > 0)
    lines.push('有 ' + c.warp_stale + ' 条出口还按旧版本号注册着。');
  if(canApply) lines.push('按钮换的是上报的版本号和每条出口的密钥对，不下载任何二进制；出口 IP 不变。');
  warpNote(lines.join('\n'));
}

// 检查更新：只有这一步会打 GitHub 的 API、叫一次本机的包管理器
$('#cliCheck').onclick = async e => {
  const b = e.currentTarget;
  b.disabled = true;
  $('#cliXrayLatest').textContent = ' 查询中…';
  clientNote('');
  try{
    const c = await api('/api/client/status?check=1');
    paintClientBin(c, true);
    if(c.has_update) toast('Xray 有新版本 ' + c.latest, 'info');
    else if(c.latest && !c.updatable) toast('Xray 上游最新是 ' + c.latest + '，但这份不由 fanout 升级', 'ok');
    else if(c.latest) toast('Xray 已是最新版', 'ok');
    if(c.openvpn_upstream) toast(c.openvpn_behind_upstream
      ? 'openvpn 官方最新 ' + c.openvpn_upstream + '，本机 ' + (c.openvpn || '未知')
        + (c.openvpn_target ? '，能升到 ' + c.openvpn_target : '')
      : 'openvpn 已是官方最新（' + c.openvpn_upstream + '）', c.openvpn_behind_upstream ? 'info' : 'ok');
  }catch(err){
    $('#cliXrayLatest').textContent = '';
    clientNote('查询失败: ' + err.message);
    toast(err.message, 'bad');
  }
  b.disabled = false;
};

// 更新内置 Xray：下载、试跑、原子替换、用旧配置重新拉起，全程失败都会退回旧版
$('#cliApply').onclick = async e => {
  if(!confirm('更新内置 Xray 到 ' + $('#cliApplyVer').textContent + '？\n入站会重启一次，已连上的节点链接会掉线重连。')) return;
  const b = e.currentTarget;
  const label = b.innerHTML;
  b.disabled = true;
  b.textContent = '下载并校验中…';
  try{
    const r = await api('/api/client/xray/apply', {method:'POST'});
    toast(r.message || '已更新', 'ok');
    $('#cliXrayHint').textContent = r.message || '已更新';
  }catch(err){
    toast(err.message, 'bad');
  }
  b.innerHTML = label;   // 文案里的版本号由下面的重读覆盖
  loadClientBin();
};

// 按最新客户端版本重新注册 WARP：换上报的版本号，每条出口换一对密钥、
// 拿一个新的 Cloudflare 接入点。确认框里必须写明不下载任何二进制——
// fanout 用内核 WireGuard，机器上根本没有属于它的 warp 客户端可"升级"。
$('#cliWarpApply').onclick = async e => {
  const d = binState || {};
  if(!confirm('按 ' + ($('#cliWarpApplyVer').textContent || d.warp_latest || '最新版')
      + ' 重新注册 WARP？\n\n现有 ' + num(d.warp_count) + ' 条出口会逐条断开重连，'
      + '每条换一对密钥、向 Cloudflare 要一个新的接入点；节点和出口 IP 都不变。\n\n'
      + '这一步不下载、也不替换任何二进制（fanout 用内核 WireGuard，不跑 warp-cli）。')) return;
  const b = e.currentTarget;
  const label = b.innerHTML;
  b.disabled = true;
  b.textContent = '已开始逐条重新注册…';
  try{
    const r = await api('/api/client/warp/apply', {method:'POST'});
    toast(r.message || '已开始重新注册', 'ok');
  }catch(err){
    toast(err.message, 'bad');
    b.innerHTML = label;
    b.disabled = false;
  }
  loadClientBin();
  poll();
};

// 升级 openvpn：命令由本机发行版决定，确认框里把原文摊开再点。
// 耗时看镜像源，几十秒到几分钟都算正常。
$('#cliOvpnApply').onclick = async e => {
  const d = binState || {};
  const cmd = d.openvpn_cmd || '（没读到命令，请先「检查更新」）';
  // 需要接官方源时，将要写进机器的那一行必须先在确认框里摊开：这等于在别人的
  // 机器上留下一个第三方 apt 源，不是能被顺手点掉的复选框
  const repo = d.openvpn_repo_line
    ? '\n\n这一步还会在机器上新接一个 OpenVPN 官方 apt 源（只为装 openvpn 这一个包），'
      + '之后系统的包升级会跟着它走；不想留着点「撤销官方源」。'
    : '';
  if(!confirm('把 openvpn 升到 ' + (d.openvpn_target || '最新版') + '？\n\n' + cmd + repo +
      '\n\n已在跑的隧道不会中断（它们挂在旧进程上），新建出口或换节点之后才用新版。')) return;
  const b = e.currentTarget;
  const label = b.innerHTML;
  b.disabled = true;
  b.textContent = '包管理器执行中…';
  try{
    const r = await api('/api/client/openvpn/apply', {method:'POST'});
    toast(r.message || '已执行', 'ok');
    clientNote(r.message || '已执行');
  }catch(err){
    toast(err.message, 'bad');
    clientNote('执行失败：' + err.message);
  }
  b.innerHTML = label;
  loadClientBin();
};

// 撤销官方源：删掉 fanout 写的那两份 apt 文件并刷一次索引。已装的 openvpn 不动，
// 免得有人以为撤销会把客户端卸掉。
$('#cliOvpnRepoOff').onclick = async e => {
  if(!confirm('删掉 fanout 写入的 OpenVPN 官方源和签名密钥，并刷新一次包索引？\n\n已装好的 openvpn 不会被动到，正在跑的隧道也不受影响。')) return;
  const b = e.currentTarget;
  const label = b.innerHTML;
  b.disabled = true;
  try{
    const r = await api('/api/client/openvpn/repo?off=1', {method:'POST'});
    toast(r.message || '已撤销', 'ok');
    clientNote(r.message || '已撤销');
  }catch(err){
    toast(err.message, 'bad');
  }
  b.innerHTML = label;
  loadClientBin();
};

// 自己编译 openvpn：apt 和官方源都给不到官方最新时才出现这颗按钮。
// 确认框里摊开的是后端算好的完整步骤（下载哪个包、怎么验签、apt 装什么、
// configure 参数、装去哪个目录），因为它要在机器上装编译器、往 /usr/local 写东西。
$('#cliOvpnBuild').onclick = async e => {
  const d = binState || {};
  const ver = d.openvpn_build_ver || '';
  const dir = d.openvpn_build_path || '/usr/local/fanout-openvpn/' + ver;
  const cmd = d.openvpn_build_cmd || '（没读到步骤，请先「检查更新」）';
  if(!confirm('从 OpenVPN 官方源码包编一份 ' + ver + '？\n\n' + cmd +
      '\n\n三件事先说清：\n'
      + '· 会 apt 装编译器（build-essential 那一套），编完不卸；\n'
      + '· 编出来的只放进 ' + dir + '，系统那份 openvpn 一个字不改；\n'
      + '· 自己编的没人跟安全更新，官方再出新版时这颗按钮会再出现。\n'
      + '\n全程十几分钟到几十分钟，中间可以关掉页面，进度会留在这里。')) return;
  const b = e.currentTarget;
  const label = b.innerHTML;
  b.disabled = true;
  try{
    const r = await api('/api/client/openvpn/build', {method:'POST'});
    toast(r.message || '已开始编译', 'ok');
    clientNote('已开始后台编译，进度在这张卡下面。');
    paintBuildJob();
  }catch(err){
    toast(err.message, 'bad');
    clientNote('没能开始：' + err.message);
  }
  b.innerHTML = label;
  loadClientBin();
};

// 撤销源码版：删掉那棵树和记录，隧道回到系统包里那份。已装的系统包不受影响。
$('#cliOvpnSrcOff').onclick = async e => {
  const d = binState || {};
  if(!confirm('删掉自己编译的 openvpn ' + (d.openvpn_source_ver || '') + '\n\n删的是 '
      + (d.openvpn_source_bin || '') + ' 所在的那棵树和 fanout 那条记录，系统包里的 openvpn 不动。\n'
      + '已在跑的隧道挂在旧进程上，新建出口、换节点或重启服务之后才用系统那份。')) return;
  const b = e.currentTarget;
  const label = b.innerHTML;
  b.disabled = true;
  try{
    const r = await api('/api/client/openvpn/source?off=1', {method:'POST'});
    toast(r.message || '已撤销', 'ok');
    clientNote(r.message || '已撤销');
  }catch(err){
    toast(err.message, 'bad');
    clientNote('撤销失败：' + err.message);
  }
  b.innerHTML = label;
  loadClientBin();
};
function nextURL(port, listen, path){
  const host = (listen && listen !== '0.0.0.0') ? listen : location.hostname;
  return location.protocol + '//' + host + ':' + port + (path ? '/' + path : '') + '/';
}

$('#setSave').onclick = async e => {
  e.target.disabled = true;
  const body = {};
  const pw = $('#setPw').value.trim();
  if(pw) body.password = pw;
  body.base_path = $('#setPath').value.trim();
  const port = parseInt($('#setPort').value.trim(), 10);
  if(port) body.port = port;
  body.listen_addr = $('#setListen').value;
  body.residential_only = $('#setResi').checked;
  body.conn = {
    health_interval:  getV('#setHealthInterval', DEF.health_interval),
    health_failures:  getV('#setHealthFails', DEF.health_failures),
    health_timeout:   getV('#setHealthTimeout', DEF.health_timeout),
    backoff_min:      getV('#setBackoffMin', DEF.backoff_min),
    backoff_max:      getV('#setBackoffMax', DEF.backoff_max),
    connect_budget:   getV('#setConnectBudget', DEF.connect_budget),
    max_tries:        getV('#setMaxTries', DEF.max_tries),
    panel_debounce:   getV('#setPanelDebounce', DEF.panel_debounce),
    node_ttl:         getV('#setNodeTtl', DEF.node_ttl),
    score_mode:       $('#setScoreMode').value,
    aead_only:        $('#setAeadOnly').checked,
  };

  const portChanged = curSettings && (port !== curSettings.port
    || body.listen_addr !== (curSettings.listen_addr || '0.0.0.0'));

  try{
    // 后端和其它设置分属两个接口，先切后端：切失败就别继续，免得用户以为整单都生效了
    const backend = $('#setBackend').value;
    if(curBackend !== null && backend !== curBackend){
      const r = await api('/api/panel/mode', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({mode: backend}),
      });
      curBackend = r.mode || '';
      $('#setBackendHint').textContent = '当前：' + (r.describe || r.kind || '已切换');
    }
    await api('/api/settings', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify(body),
    });
    markDirty(false);
    if(portChanged){
      const url = nextURL(port, body.listen_addr, body.base_path);
      $('#setPortHint').innerHTML = '监听已切换，请从新地址打开：<a href="' + esc(url) + '">' + esc(url) + '</a>';
      toast('监听已切换，用新地址重新打开', 'bad');
      // 端口变了当前连接会断，不自动跳转，让用户看清新地址
    } else {
      toast('已保存', 'ok');
      // 路径可能变了，重新加载到新路径下
      const np = body.base_path;
      const cur = ((curSettings && curSettings.base_path) || '').replace(/^\//, '');
      if(np !== cur){
        location.href = location.protocol + '//' + location.host + (np ? '/' + np : '') + '/';
        return;
      }
      loadSettingsPage();
      poll();
    }
  }catch(err){ toast(err.message, 'bad'); }
  e.target.disabled = false;
};

/* ───────────── 启动 ───────────── */

const hash = (location.hash || '').replace('#','');
if(VIEWS[hash]) showView(hash); else showView('dashboard');
poll();
})();
