/*
 * UDP Relay Manager — single epoll loop + tiny HTTP /api/v1 + INI in /etc
 * -----------------------------------------------------------------------
 * House Rules implemented:
 *  1) One hot path loop (epoll). All sockets O_NONBLOCK.
 *  2) No frameworks; tiny HTTP server for /api/v1/*.
 *  3) Signals:
 *       - SIGHUP  -> re-read /etc/udp_relay.conf and apply (hot reload)
 *       - SIGINT/SIGTERM -> graceful exit
 *  4) Config only in /etc. Runtime POST /api/v1/config persists to /etc/udp_relay.conf.
 *  5) HTTP contract:
 *       GET  /api/v1/status        -> JSON status (≤ 8 KiB)
 *       GET  /api/v1/config        -> returns INI text
 *       POST /api/v1/config        -> replace INI text; apply & persist
 *       POST /api/v1/action/<verb> -> verbs: set, append, append_range, clear, reset
 *     Added:
 *       GET  /ui                   -> embedded Web UI (same-origin)
 *       GET  /ui.js                -> UI logic
 *       GET  /                     -> 302 → /ui
 *       OPTIONS *                  -> CORS preflight
 *
 * Build:
 *   gcc -O2 -Wall -Wextra -std=gnu11 -o udp_relay_manager udp_relay_manager.c
 *
 * Runtime:
 *   ./udp_relay_manager   (no arguments)
 *
 * Config file: /etc/udp_relay.conf   (no --config flag by design)
 *
 * INI format (no sections; '#' or ';' are comments):
 *   # HTTP bind + control port
 *   http_bind=127.0.0.1
 *   control_port=9000
 *
 *   # UDP listener defaults
 *   src_ip=0.0.0.0
 *   rcvbuf=1048576
 *   sndbuf=1048576
 *   bufsz=9000
 *   tos=0
 *
 *   # One or more binds: bind=<SRC>[:<DST_LIST>]
 *   # DST token forms: "port" | "ip:port" | "start-end" | "ip:start-end"
 *   bind=5801:9000,9001,7000-7002,192.168.0.10:7500
 *   bind=5802
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* ------------------- tunables & constants ------------------- */

#define MAX_RELAYS      64
#define MAX_DESTS       128
#define MAX_BINDS       64
#define MAX_LINE        1024
#define MAX_EVENTS      128
#define MAX_HTTP_CONN   64
#define HTTP_BUF_MAX    65536         /* max request buffer; config POST can be big */
#define STATUS_CAP      8192          /* soft cap for status JSON payload */
#define CFG_PATH        "/etc/udp_relay.conf"
#define CFG_TMP_PATH    "/etc/udp_relay.conf.tmp"

/* ------------------- small utils ---------------------------- */

static inline uint64_t now_ns(void){
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec*1000000000ull + ts.tv_nsec;
}

static char* trim(char *s){
    while (isspace((unsigned char)*s)) s++;
    if (!*s) return s;
    char *e = s + strlen(s) - 1;
    while (e > s && isspace((unsigned char)*e)) e--;
    e[1] = '\0';
    return s;
}

static int parse_int_bounded(const char *s, int lo, int hi){
    if (!s || !*s) return -1;
    char *end=NULL; long v=strtol(s,&end,10);
    if (end==s || *end!='\0') return -1;
    if (v<lo || v>hi) return -1;
    return (int)v;
}

static int set_nonblock(int fd){
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl<0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

/* ------------------- UI assets + CORS helpers ---------------- */

/* Embedded UI HTML (served at /ui) */
static const char UI_HTML[] =
"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/>"
"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"/>"
"<title>UDP Relay Manager · WebUI</title>"
"<style>"
":root{--bg:#0f1116;--panel:#151823;--muted:#8a93a5;--text:#e8ecf1;--accent:#7bd389;--warn:#e7b75f;--err:#ff7a7a}"
"*{box-sizing:border-box}body{margin:0;font:14px/1.4 system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text)}"
"header{display:flex;gap:.75rem;flex-wrap:wrap;align-items:center;padding:12px 16px;background:#0c0f17;position:sticky;top:0;z-index:2;border-bottom:1px solid #1e2231}"
"h1{font-size:16px;margin:0 auto 0 0;letter-spacing:.2px}.row{display:flex;gap:.5rem;align-items:center}"
"label{font-size:12px;color:var(--muted)}input,button,textarea,select{background:var(--panel);color:var(--text);border:1px solid #242b3d;border-radius:10px;padding:8px 10px;outline:0}"
"input,select{height:36px}button{cursor:pointer}button.primary{background:linear-gradient(180deg,#1f6b43,#165538);border-color:#1f6b43}"
"button.ghost{background:transparent;border-color:#2a3247}button.warn{background:#3b2e13;border-color:#5c4723;color:#ffd990}"
"main{max-width:1200px;margin:16px auto;padding:0 16px;display:grid;grid-template-columns:1.1fr .9fr;gap:16px}"
"section{background:var(--panel);border:1px solid #20273a;border-radius:16px;overflow:hidden}"
"section h2{margin:0;padding:10px 12px;border-bottom:1px solid #20273a;font-size:13px;color:#aab3c7;background:#121626;letter-spacing:.3px}"
".pad{padding:12px}.chips{display:flex;flex-wrap:wrap;gap:8px}.chip{border:1px dashed #2a3247;border-radius:20px;padding:6px 10px;display:flex;gap:8px;align-items:center;user-select:none}"
".chip[draggable=true]{cursor:grab}.chip .tag{opacity:.65;font-size:12px}"
".grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px}"
".dest{min-height:84px;border:2px dashed #2b344d;border-radius:14px;display:flex;align-items:center;justify-content:center;gap:10px;padding:12px;transition:.15s}"
".dest.drag-over{border-color:var(--accent);background:#0f1a14}"
".muted{color:var(--muted)}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,\"Liberation Mono\",monospace}"
".rowline{display:flex;justify-content:space-between;gap:6px;border:1px solid #252d40;border-radius:10px;padding:8px 10px;margin-bottom:8px}"
"textarea.ini{width:100%;min-height:220px;resize:vertical}.log{height:140px;overflow:auto;background:#0c0f17;border:1px solid #1e2231;border-radius:10px;padding:8px}"
".ok{color:var(--accent)}.warn{color:var(--warn)}.err{color:var(--err)}"
"</style></head><body>"
"<header>"
"<h1>UDP Relay Manager · WebUI</h1>"
"<button class='primary' id='refresh'>Refresh</button>"
"</header>"
"<main>"
"<section><h2>Destinations — drag binds onto a box</h2>"
"<div class='pad'>"
"<div class='chips' id='bindChips'></div>"
"<div id='destGrid' class='grid' style='margin-top:12px'></div>"
"<div id='adhocBox' style='margin-top:12px;display:none'>"
"  <div class='row' style='gap:8px;margin-bottom:8px'>"
"    <label>Ad-hoc receiver</label>"
"    <input id='rxHost' value='127.0.0.1' style='width:160px'/>"
"    <label>port</label>"
"    <input id='rxPort' value='5600' style='width:100px'/>"
"  </div>"
"  <div id='adhocDrop' class='dest'><div>"
"    <div class='muted'>Drop a bind here to route it to</div>"
"    <div class='mono' id='rxLabel'>127.0.0.1:5600</div>"
"  </div></div>"
"  <div style='margin-top:8px' class='muted'>Ad-hoc: clears only previously mapped binds pointing to this exact destination.</div>"
"</div>"
"</div>"
"</section>"

"<section><h2>Live Status</h2><div class='pad' id='statusBox'><div class='muted'>Loading…</div></div></section>"

"<section><h2>Destinations (add/remove & persist)</h2>"
"<div class='pad'>"
"  <div id='destList'></div>"
"  <div class='row' style='gap:8px;margin-top:8px'>"
"    <input id='newDestHost' placeholder='host (e.g. 127.0.0.1)' style='width:200px'/>"
"    <input id='newDestPort' placeholder='port (e.g. 5600)' style='width:120px'/>"
"    <button id='addDest'>Add destination</button>"
"    <button class='warn' id='saveDests'>Save destinations</button>"
"  </div>"
"  <div style='margin-top:6px' class='muted'>Destinations are stored in <span class='mono'>/etc/udp_relay.conf</span> as <span class='mono'>dest=host:port</span> lines (or a single <span class='mono'>ui_destinations=</span> line). They’re for the UI only.</div>"
"</div>"
"</section>"

"<section><h2>Binds & Config</h2><div class='pad'>"
"  <div class='row' style='gap:8px;margin-bottom:8px'>"
"    <input id='newBindPort' placeholder='e.g. 5700' style='width:140px'/>"
"    <button id='addBind'>Add bind</button>"
"    <button class='warn' id='applyCfg'>Apply config</button>"
"  </div>"
"  <div id='bindList' style='margin-bottom:10px'></div>"
"  <label>Config (INI)</label>"
"  <textarea id='cfgText' class='ini mono' spellcheck='false'></textarea>"
"</div></section>"

"<section><h2>Log</h2><div class='pad'><div id='log' class='log mono'></div></div></section>"
"</main>"
"<script src='/ui.js'></script>"
"</body></html>";

/* Embedded UI JS (served at /ui.js) */
static const char UI_JS[] =
"(function(){"
"const $=s=>document.querySelector(s);"
"const log=(m,c='')=>{const el=$('#log');const d=document.createElement('div');if(c)d.className=c;d.textContent=`[${new Date().toLocaleTimeString()}] ${m}`;el.prepend(d)};"
"const state={status:null,ini:'',dests:[]};"
"const GET=p=>fetch(p,{method:'GET'}).then(r=>{if(!r.ok)throw new Error(`${r.status} ${r.statusText}`);return p.includes('/status')?r.json():r.text()});"
"const POST=(p,b)=>fetch(p,{method:'POST',body:b}).then(async r=>{if(!r.ok)throw new Error(`${r.status} ${r.statusText}`);try{return await r.json()}catch{return await r.text()}});"
"const action=(v,o)=>POST(`/api/v1/action/${v}`,JSON.stringify(o||{}));"

"/* -------- destinations model -------- */"
"function normDest(s){s=String(s).trim();if(!s)return null;let host='127.0.0.1',port='';if(/^[0-9]+$/.test(s)){port=s;}else{const m=s.match(/^\\[?([A-Za-z0-9:._-]+)\\]?:([0-9]+)$/);if(!m)return null;host=m[1];port=m[2];}return `${host}:${port}`;}"
"function parseDestinationsFromIni(txt){const dests=new Set();const lines=txt.split(/\\n/);for(const ln of lines){let m=ln.match(/^\\s*dest\\s*=\\s*(\\S+)/);if(m){const d=normDest(m[1]);if(d)dests.add(d);continue;}m=ln.match(/^\\s*ui_destinations\\s*=\\s*(.+)$/);if(m){for(const t of m[1].split(',')){const d=normDest(t);if(d)dests.add(d)}}}return Array.from(dests);} "
"function writeDestinationsToIni(txt,destArr){/* remove old dest lines and ui_destinations line, then write dest= per item */"
"  const out=[];const lines=txt.split(/\\n/);"
"  for(const ln of lines){if(/^\\s*dest\\s*=/.test(ln)) continue; if(/^\\s*ui_destinations\\s*=/.test(ln)) continue; out.push(ln);} "
"  if(out.length && out[out.length-1]!=='') out.push('');"
"  for(const d of destArr){out.push(`dest=${d}`);} "
"  return out.join('\\n');"
"}"

"/* -------- UI renderers -------- */"
"function makeBindChip(port,stats){const el=document.createElement('div');el.className='chip';el.draggable=true;el.dataset.port=String(port);el.innerHTML=`<strong>bind ${port}</strong> <span class='tag'>in: ${stats.pkts_in||0}</span>`;el.addEventListener('dragstart',e=>{e.dataTransfer.setData('text/plain',String(port));e.dataTransfer.effectAllowed='copy'});return el}"
"function renderBindChips(s){const wrap=$('#bindChips');wrap.innerHTML='';const rel=(s&&s.relays)?s.relays:[];for(const r of rel){wrap.appendChild(makeBindChip(r.port,r))}}"

"function bindDropZone(el, destStr){el.addEventListener('dragover',e=>{e.preventDefault();el.classList.add('drag-over');e.dataTransfer.dropEffect='copy'});"
"el.addEventListener('dragleave',()=>el.classList.remove('drag-over'));"
"el.addEventListener('drop',async e=>{e.preventDefault();el.classList.remove('drag-over');const srcPort=parseInt(e.dataTransfer.getData('text/plain'),10);if(!srcPort)return;"
" try{await rebindToDestination(srcPort,destStr);}catch(err){log(`Drop failed: ${err}`,'err')}});}"
"function renderDestGrid(){const grid=$('#destGrid');grid.innerHTML='';const dests=state.dests; if(dests.length===0){$('#adhocBox').style.display='block';return;} $('#adhocBox').style.display='none';"
" for(const d of dests){const card=document.createElement('div');card.className='dest';card.innerHTML=`<div><div class='muted'>Drop a bind to route →</div><div class='mono'>${d}</div></div>`;bindDropZone(card,d);grid.appendChild(card);} }"

"function renderDestList(){const box=$('#destList');box.innerHTML='';if(!state.dests.length){box.innerHTML=\"<div class='muted'>No saved destinations. Use the fields below to add some.</div>\";return;} for(const d of state.dests){const row=document.createElement('div');row.className='rowline';row.innerHTML=`<div class='mono'>dest=${d}</div>`;const rm=document.createElement('button');rm.textContent='Remove';rm.onclick=()=>{state.dests=state.dests.filter(x=>x!==d);$('#cfgText').value=writeDestinationsToIni(state.ini,state.dests);renderDestList();renderDestGrid();};row.appendChild(rm);box.appendChild(row);} }"

"/* -------- Status & config -------- */"
"async function loadStatus(){try{const s=await GET('/api/v1/status');state.status=s;renderBindChips(s);renderStatus(s);}catch(err){$('#statusBox').innerHTML=`<span class='err'>Status error:</span> ${err}`}}"
"function renderStatus(s){const box=$('#statusBox');if(!s||!Array.isArray(s.relays)){box.innerHTML='<div class=\"muted\">No relays</div>';return}const frag=document.createDocumentFragment();for(const r of s.relays){const line=document.createElement('div');line.className='rowline';const left=document.createElement('div');left.innerHTML=`<strong>bind ${r.port}</strong><div class='muted'>pkts_in ${r.pkts_in} · bytes_out ${r.bytes_out} · send_errs ${r.send_errs}</div>`;const right=document.createElement('div');const ip=document.createElement('input');ip.placeholder='ip (optional)';ip.style.width='160px';const port=document.createElement('input');port.placeholder='port';port.style.width='90px';const set=document.createElement('button');set.textContent='Set dest';set.onclick=async()=>{const d=port.value.trim();if(!d){log('Port required','warn');return}const host=(ip.value.trim()||'127.0.0.1');const token=`${host}:${d}`;try{await action('set',{port:r.port,dests:[token]});log(`bind ${r.port} → ${token}`,'ok');await loadStatus()}catch(err){log(`set failed: ${err}`,'err')}};const clr=document.createElement('button');clr.textContent='Clear';clr.onclick=async()=>{try{await action('clear',{port:r.port});log(`cleared ${r.port}`,'ok');await loadStatus()}catch(err){log(`clear failed: ${err}`,'err')}};right.appendChild(ip);right.appendChild(port);right.appendChild(set);right.appendChild(clr);const dests=document.createElement('div');dests.className='chips';dests.style.marginTop='6px';if(Array.isArray(r.dests)&&r.dests.length){for(const d of r.dests){const c=document.createElement('div');c.className='chip';c.innerHTML=`<span class='tag'>→</span><strong>${d.ip}:${d.port}</strong> <span class='tag'>pkts ${d.pkts}</span>`;dests.appendChild(c)}}else{const m=document.createElement('div');m.className='muted';m.textContent='no destinations';dests.appendChild(m)}line.appendChild(left);line.appendChild(right);frag.appendChild(line);frag.appendChild(dests)}box.innerHTML='';box.appendChild(frag)}"

"async function loadConfig(){try{const t=await GET('/api/v1/config');state.ini=String(t||'').replace(/\\r/g,'');state.dests=parseDestinationsFromIni(state.ini);$('#cfgText').value=state.ini;renderBindListFromIni();renderDestList();renderDestGrid();maybeShowAdhoc();}catch(err){state.ini='';$('#cfgText').value='';$('#bindList').innerHTML=`<span class='err'>Config error:</span> ${err}`}}"

"/* -------- Binds in INI -------- */"
"function renderBindListFromIni(){const lines=state.ini.split(/\\n/);const binds=[];for(const ln of lines){const m=ln.match(/^\\s*bind\\s*=\\s*(\\d+)/);if(m)binds.push(parseInt(m[1],10))}const list=$('#bindList');list.innerHTML='';if(!binds.length){list.innerHTML='<div class=\"muted\">No binds in config.</div>';return}for(const p of binds){const row=document.createElement('div');row.className='rowline';row.innerHTML=`<div><strong class='mono'>bind=${p}</strong></div>`;const rm=document.createElement('button');rm.textContent='Remove';rm.onclick=()=>removeBindInIni(p);row.appendChild(rm);list.appendChild(row)}}"
"function removeBindInIni(port){const before=state.ini.split(/\\n/);const after=before.filter(ln=>!ln.match(new RegExp(`^\\\\s*bind\\\\s*=\\\\s*${port}(\\\\b|:)`)));state.ini=after.join('\\n');$('#cfgText').value=state.ini;renderBindListFromIni()}"
"function addBindInIni(port){const p=parseInt(port,10);if(!(p>0&&p<65536)){log('Invalid bind port','err');return}if(new RegExp(`^\\\\s*bind\\\\s*=\\\\s*${p}(\\\\b|:)`,'m').test(state.ini)){log(`bind ${p} already exists`,'warn');return}if(!/\\n$/.test(state.ini))state.ini+='\\n';state.ini+=`bind=${p}\\n`;$('#cfgText').value=state.ini;renderBindListFromIni()}"

"/* -------- Destinations edit -------- */"
"function maybeShowAdhoc(){const has=state.dests.length>0;$('#adhocBox').style.display=has?'none':'block';}"
"$('#addDest').onclick=()=>{const h=($('#newDestHost').value.trim()||'127.0.0.1');const p=parseInt($('#newDestPort').value.trim(),10);if(!(p>0&&p<65536)){log('Invalid dest port','err');return}const d=`${h}:${p}`;if(!state.dests.includes(d)) state.dests.push(d);$('#cfgText').value=writeDestinationsToIni(state.ini,state.dests);renderDestList();renderDestGrid();maybeShowAdhoc();};"
"$('#saveDests').onclick=async()=>{try{state.ini=$('#cfgText').value;await POST('/api/v1/config',state.ini);log('Destinations saved','ok');await refreshAll()}catch(err){log(`Save destinations failed: ${err}`,'err')}};"

"/* -------- Ad-hoc drop (when no saved destinations) -------- */"
"function rxSync(){const s=`${($('#rxHost').value.trim()||'127.0.0.1')}:${($('#rxPort').value.trim()||'5600')}`;$('#rxLabel').textContent=s;}"
"$('#rxHost')&&$('#rxHost').addEventListener('input',rxSync);$('#rxPort')&&$('#rxPort').addEventListener('input',rxSync);"
"function setupAdhoc(){const dz=$('#adhocDrop');if(!dz)return;bindDropZone(dz,()=>($('#rxHost').value.trim()||'127.0.0.1')+':' + ($('#rxPort').value.trim()||'5600'));rxSync();}"

"/* -------- Core drop behavior: per-destination clear-then-set -------- */"
"async function rebindToDestination(srcPort,dest){const destStr=(typeof dest==='function')?dest():String(dest);if(!/^[^:]+:[0-9]+$/.test(destStr)) throw new Error(`Bad destination: ${destStr}`);const rels=(state.status&&state.status.relays)?state.status.relays:[];"
"  log(`Routing bind ${srcPort} → ${destStr} (clearing that destination on others first)…`);"
"  /* Clear any binds currently forwarding to destStr */"
"  for(const r of rels){if(Array.isArray(r.dests)&&r.dests.some(d=>`${d.ip}:${d.port}`===destStr)){await action('clear',{port:r.port});}}"
"  /* Now set mapping for srcPort */"
"  await action('set',{port:srcPort,dests:[destStr]});"
"  log(`OK: ${srcPort} now → ${destStr}`,'ok');"
"  await loadStatus();"
"}"

"/* -------- Wiring buttons -------- */"
"$('#addBind').onclick=()=>addBindInIni($('#newBindPort').value.trim());"
"$('#applyCfg').onclick=async()=>{try{await POST('/api/v1/config',$('#cfgText').value);log('Config applied & reloaded','ok');await refreshAll()}catch(err){log(`Apply failed: ${err}`,'err')}};"
"$('#refresh').onclick=()=>refreshAll();"

"/* -------- Boot -------- */"
"async function refreshAll(){await Promise.all([loadStatus(),loadConfig()]);}"
"setupAdhoc();refreshAll();setInterval(()=>loadStatus().catch(()=>{}),1500);"
"})();";


/* CORS-capable HTTP helpers */
static void http_write(int fd, const char *buf, size_t n){ if(n) (void)send(fd, buf, n, 0); }
static void http_printf(int fd, const char *fmt, ...){
    char out[4096]; va_list ap; va_start(ap,fmt);
    int n = vsnprintf(out, sizeof(out), fmt, ap);
    va_end(ap);
    if(n<0) return; if(n>(int)sizeof(out)) n=(int)sizeof(out);
    http_write(fd, out, (size_t)n);
}
static void http_send_headers(int fd, const char *status_line, const char *ctype, ssize_t clen, const char *extra){
    http_printf(fd, "%s\r\n", status_line);
    if(ctype) http_printf(fd, "Content-Type: %s\r\n", ctype);
    if(clen>=0) http_printf(fd, "Content-Length: %zd\r\n", clen);
    http_printf(fd, "Connection: close\r\n");
    /* CORS */
    http_printf(fd, "Access-Control-Allow-Origin: *\r\n");
    http_printf(fd, "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n");
    http_printf(fd, "Access-Control-Allow-Headers: Content-Type\r\n");
    http_printf(fd, "Cache-Control: no-store\r\n");
    if(extra && *extra) http_printf(fd, "%s", extra);
    http_printf(fd, "\r\n");
}

/* Legacy helper (kept for tiny responses) — always 200 text/plain with CORS */
static void http_send(int fd, const char *fmt, ...){
    char body[4096];
    va_list ap; va_start(ap,fmt);
    int n=vsnprintf(body,sizeof(body),fmt,ap);
    va_end(ap);
    if (n<0) return;
    if (n > (int)sizeof(body)) n = (int)sizeof(body);
    http_send_headers(fd, "HTTP/1.1 200 OK", "text/plain", n, NULL);
    http_write(fd, body, (size_t)n);
}

/* ------------------- config model --------------------------- */

struct dest {
    struct sockaddr_in addr;
    uint64_t pkts_out;
};

struct relay {
    int src_port;
    int fd;
    struct dest dests[MAX_DESTS];
    int dest_cnt;
    uint64_t pkts_in, bytes_in, bytes_out, send_errs, last_rx_ns;
};

struct config {
    char http_bind[64];  /* default 127.0.0.1 */
    int  control_port;   /* default 9000 */
    char src_ip[64];     /* default 0.0.0.0 */
    int  rcvbuf, sndbuf; /* 0 = skip */
    int  bufsz;          /* default 9000 */
    int  tos;            /* 0 = skip */
    int  bind_count;
    char bind_lines[MAX_BINDS][MAX_LINE];
};

static struct config G;                    /* current config */
static struct relay REL[MAX_RELAYS];       /* active relays */
static int REL_N = 0;

static volatile sig_atomic_t WANT_RELOAD = 0;
static volatile sig_atomic_t WANT_EXIT   = 0;

static int EPFD = -1;                      /* epoll fd */
static int HTTP_LFD = -1;                  /* http listen fd */

/* ------------------- INI load/save -------------------------- */

static void cfg_defaults(struct config *c){
    memset(c, 0, sizeof(*c));
    snprintf(c->http_bind, sizeof(c->http_bind), "127.0.0.1");
    c->control_port = 9000;
    snprintf(c->src_ip, sizeof(c->src_ip), "0.0.0.0");
    c->rcvbuf=0; c->sndbuf=0; c->bufsz=9000; c->tos=0;
    c->bind_count=0;
}

static int load_file(const char *path, char **out, size_t *outlen){
    FILE *fp=fopen(path,"rb"); if(!fp) return -1;
    fseek(fp,0,SEEK_END); long sz=ftell(fp); fseek(fp,0,SEEK_SET);
    if (sz<0) { fclose(fp); return -1; }
    char *buf=malloc((size_t)sz+1); if(!buf){ fclose(fp); return -1; }
    if ((long)fread(buf,1,(size_t)sz,fp)!=sz){ free(buf); fclose(fp); return -1; }
    buf[sz]=0;
    fclose(fp);
    *out=buf; if(outlen)*outlen=(size_t)sz;
    return 0;
}

static int save_file_atomic(const char *path_tmp, const char *path, const char *data, size_t len){
    int rc=-1;
    FILE *fp=fopen(path_tmp,"wb");
    if(!fp) return -1;
    if (fwrite(data,1,len,fp)!=len){ fclose(fp); return -1; }
    if (fflush(fp)!=0){ fclose(fp); return -1; }
    if (fsync(fileno(fp))!=0){ fclose(fp); return -1; }
    if (fclose(fp)!=0) return -1;
    if (rename(path_tmp, path)!=0) return -1;
    rc=0;
    return rc;
}

static int load_ini_text(const char *text, struct config *c){
    cfg_defaults(c);
    char *dup=strdup(text); if(!dup) return -1;
    char *saveptr=NULL;
    for(char *line=strtok_r(dup,"\n",&saveptr); line; line=strtok_r(NULL,"\n",&saveptr)){
        char *s=trim(line);
        if(!*s || *s=='#' || *s==';') continue;
        char *eq=strchr(s,'=');
        if(!eq) continue;
        *eq=0;
        char *key=trim(s), *val=trim(eq+1);
        if(!strcmp(key,"http_bind")){
            snprintf(c->http_bind,sizeof(c->http_bind),"%s",val);
        } else if(!strcmp(key,"control_port")){
            int v=parse_int_bounded(val,1,65535); if(v>0) c->control_port=v;
        } else if(!strcmp(key,"src_ip")){
            snprintf(c->src_ip,sizeof(c->src_ip),"%s",val);
        } else if(!strcmp(key,"rcvbuf")){
            int v=parse_int_bounded(val,1024,64*1024*1024); if(v>0) c->rcvbuf=v;
        } else if(!strcmp(key,"sndbuf")){
            int v=parse_int_bounded(val,1024,64*102*1024*5); if(v>0) c->sndbuf=v; /* generous */
        } else if(!strcmp(key,"bufsz")){
            int v=parse_int_bounded(val,512,64*1024); if(v>0) c->bufsz=v;
        } else if(!strcmp(key,"tos")){
            int v=parse_int_bounded(val,0,255); if(v>=0) c->tos=v;
        } else if(!strcmp(key,"bind")){
            if(c->bind_count<MAX_BINDS){
                snprintf(c->bind_lines[c->bind_count++],MAX_LINE,"%s",val);
            }
        }
        /* unknown keys ignored */
    }
    free(dup);
    return 0;
}

static int load_ini_file(struct config *c){
    char *txt=NULL; size_t len=0;
    if (load_file(CFG_PATH,&txt,&len)!=0) {
        /* missing file is not fatal; run with defaults */
        cfg_defaults(c);
        return 0;
    }
    int rc=load_ini_text(txt,c);
    free(txt);
    return rc;
}

/* ------------------- relay creation / teardown --------------- */

static int sockaddr_equal(const struct sockaddr_in *a, const struct sockaddr_in *b){
    return a->sin_family==b->sin_family &&
           a->sin_port==b->sin_port &&
           a->sin_addr.s_addr==b->sin_addr.s_addr;
}

static int add_dest(struct relay *r, const char *ip, int port){
    if (r->dest_cnt >= MAX_DESTS) return -1;
    struct dest *d=&r->dests[r->dest_cnt];
    memset(d,0,sizeof(*d));
    d->addr.sin_family=AF_INET;
    d->addr.sin_port=htons(port);
    if (inet_pton(AF_INET, ip, &d->addr.sin_addr)!=1) return -1;
    d->pkts_out=0;
    r->dest_cnt++;
    return 0;
}

static int parse_dest_token(struct relay *r, const char *tok){
    char buf[128]; snprintf(buf,sizeof(buf),"%s",tok);
    char *s=trim(buf);
    char *ip_part=NULL, *port_part=s;
    char *colon=strchr(s,':');
    if (colon){ *colon=0; ip_part=s; port_part=colon+1; }
    const char *ip = ip_part ? ip_part : "127.0.0.1";
    char *dash=strchr(port_part,'-');
    if (dash){
        *dash=0;
        int a=parse_int_bounded(port_part,1,65535);
        int b=parse_int_bounded(dash+1,1,65535);
        if (a<0 || b<0) return -1;
        if (a>b){ int t=a; a=b; b=t; }
        for (int p=a; p<=b; p++){
            if (add_dest(r,ip,p)<0) break;
        }
        return 0;
    } else {
        int p=parse_int_bounded(port_part,1,65535);
        if (p<0) return -1;
        return add_dest(r,ip,p);
    }
}

static int parse_dest_list(struct relay *r, const char *list, bool replace){
    struct relay tmp={0};
    if (list && *list){
        char *dup=strdup(list); if(!dup) return -1;
        char *save=NULL;
        for(char *tok=strtok_r(dup,",",&save); tok; tok=strtok_r(NULL,",",&save)){
            if (parse_dest_token(&tmp, trim(tok))<0){ free(dup); return -1; }
        }
        free(dup);
    }
    if (replace){
        r->dest_cnt=0; r->pkts_in=r->bytes_in=r->bytes_out=r->send_errs=0;
        for (int j=0;j<MAX_DESTS;j++) r->dests[j].pkts_out=0;
    }
    for (int i=0;i<tmp.dest_cnt && r->dest_cnt<MAX_DESTS;i++){
        r->dests[r->dest_cnt++] = tmp.dests[i];
    }
    return 0;
}

static int make_udp_socket(const char *bind_ip, int port, int rcvbuf, int sndbuf, int tos){
    int s=socket(AF_INET,SOCK_DGRAM,0);
    if (s<0) { perror("socket"); return -1; }
    int one=1;
    setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
#ifdef SO_REUSEPORT
    setsockopt(s,SOL_SOCKET,SO_REUSEPORT,&one,sizeof(one));
#endif
    if (rcvbuf>0) setsockopt(s,SOL_SOCKET,SO_RCVBUF,&rcvbuf,sizeof(rcvbuf));
    if (sndbuf>0) setsockopt(s,SOL_SOCKET,SO_SNDBUF,&sndbuf,sizeof(sndbuf));
#ifdef IP_TOS
    if (tos>0) setsockopt(s,IPPROTO_IP,IP_TOS,&tos,sizeof(tos));
#endif
    struct sockaddr_in a={0};
    a.sin_family=AF_INET;
    a.sin_port=htons(port);
    if (inet_pton(AF_INET, bind_ip, &a.sin_addr)!=1){
        fprintf(stderr,"Bad src_ip: %s\n", bind_ip);
        close(s); return -1;
    }
    if (bind(s,(struct sockaddr*)&a,sizeof(a))<0){
        perror("bind"); close(s); return -1;
    }
    if (set_nonblock(s)<0){ perror("fcntl"); close(s); return -1; }
    return s;
}

static void close_relays(void){
    for (int i=0;i<REL_N;i++){
        if (REL[i].fd>=0){
            epoll_ctl(EPFD, EPOLL_CTL_DEL, REL[i].fd, NULL);
            close(REL[i].fd);
        }
    }
    memset(REL,0,sizeof(REL));
    REL_N=0;
}

static int apply_config_relays(const struct config *c){
    close_relays();
    for (int i=0;i<c->bind_count;i++){
        if (REL_N >= MAX_RELAYS){ fprintf(stderr,"Too many binds\n"); break; }
        char line[MAX_LINE]; snprintf(line,sizeof(line),"%s", c->bind_lines[i]);
        char *sep=strchr(line,':');
        int sport=-1; char *list=NULL;
        if (sep){ *sep=0; sport=parse_int_bounded(trim(line),1,65535); list=trim(sep+1); }
        else sport=parse_int_bounded(trim(line),1,65535);
        if (sport<0){ fprintf(stderr,"Bad bind line: %s\n", c->bind_lines[i]); continue; }

        struct relay *r=&REL[REL_N];
        memset(r,0,sizeof(*r));
        r->src_port=sport;
        r->fd=make_udp_socket(c->src_ip, sport, c->rcvbuf, c->sndbuf, c->tos);
        if (r->fd<0){ fprintf(stderr,"Bind failed %d\n", sport); continue; }

        struct epoll_event ev={.events=EPOLLIN, .data.fd=r->fd};
        if (epoll_ctl(EPFD, EPOLL_CTL_ADD, r->fd, &ev)<0){ perror("epoll_ctl add udp"); close(r->fd); continue; }

        if (list && *list){
            if (parse_dest_list(r, list, true)<0){
                fprintf(stderr,"Bad dest list on %d, starting empty\n", sport);
                r->dest_cnt=0;
            }
        }
        fprintf(stderr,"Bound %d (dests=%d) on %s (bufsz=%d rcv=%d snd=%d tos=%d)\n",
                sport, r->dest_cnt, c->src_ip, c->bufsz, c->rcvbuf, c->sndbuf, c->tos);
        REL_N++;
    }
    return (REL_N>0)?0:-1;
}

/* ------------------- HTTP tiny server (nonblocking) ---------- */

struct http_conn {
    int fd;
    char *buf;        /* request buffer */
    size_t cap, len;  /* capacity / used */
    size_t need;      /* body bytes expected (Content-Length) */
    int    have_hdr;  /* header parsed? */
};
static struct http_conn HC[MAX_HTTP_CONN];

static struct http_conn* hc_get(int fd){
    for (int i=0;i<MAX_HTTP_CONN;i++) if (HC[i].fd==fd) return &HC[i];
    for (int i=0;i<MAX_HTTP_CONN;i++) if (HC[i].fd==0){
        HC[i].fd=fd; HC[i].cap=4096; HC[i].len=0; HC[i].need=0; HC[i].have_hdr=0;
        HC[i].buf=malloc(HC[i].cap);
        return &HC[i];
    }
    return NULL;
}
static void hc_del(int fd){
    for (int i=0;i<MAX_HTTP_CONN;i++) if (HC[i].fd==fd){
        free(HC[i].buf); HC[i].buf=NULL; HC[i].fd=0; HC[i].cap=HC[i].len=HC[i].need=HC[i].have_hdr=0;
        epoll_ctl(EPFD, EPOLL_CTL_DEL, fd, NULL);
        close(fd);
        return;
    }
}

static struct http_conn* hc_find(int fd){
    for (int i=0;i<MAX_HTTP_CONN;i++) if (HC[i].fd==fd) return &HC[i];
    return NULL;
}

static int http_listen(const char *ip, int port){
    int s=socket(AF_INET,SOCK_STREAM,0); if(s<0){perror("socket");return -1;}
    int one=1; setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
#ifdef SO_REUSEPORT
    setsockopt(s,SOL_SOCKET,SO_REUSEPORT,&one,sizeof(one));
#endif
    struct sockaddr_in a={0}; a.sin_family=AF_INET; a.sin_port=htons(port);
    if (inet_pton(AF_INET, ip, &a.sin_addr)!=1){ fprintf(stderr,"Bad http_bind: %s\n", ip); close(s); return -1; }
    if (bind(s,(struct sockaddr*)&a,sizeof(a))<0){ perror("http bind"); close(s); return -1; }
    if (set_nonblock(s)<0){ perror("http nb"); close(s); return -1; }
    if (listen(s,16)<0){ perror("listen"); close(s); return -1; }
    return s;
}

/* ---- very tiny JSON helpers (sufficient for our schemas) ---- */

static int json_get_int(const char *body, const char *key, int defv){
    const char *p = strstr(body, key);
    if(!p) return defv;
    const char *col=strchr(p,':'); if(!col) return defv;
    col++;
    while (*col && isspace((unsigned char)*col)) col++;
    char tmp[32]={0}; int i=0;
    while (*col && (isdigit((unsigned char)*col) || *col=='-') && i<31) tmp[i++]=*col++;
    int v=parse_int_bounded(tmp,-2147483647,2147483647);
    return (v==-1)?defv:v;
}

static int json_extract_port(const char *b){ return json_get_int(b,"\"port\"", -1); }

static char* json_extract_array_slice(const char *body, const char *key){
    const char *k=strstr(body,key); if(!k) return NULL;
    const char *lb=strchr(k,'['); if(!lb) return NULL;
    const char *rb=strchr(lb,']'); if(!rb) return NULL;
    size_t n=(size_t)(rb - (lb+1));
    char *out=malloc(n+1); if(!out) return NULL;
    memcpy(out, lb+1, n); out[n]=0;
    return out;
}

/* dests: ["9000","1.2.3.4:7000","7000-7005"] */
static int apply_set_like(int port, const char *body, bool replace){
    if (port<=0) return -1;
    struct relay *r=NULL; for (int i=0;i<REL_N;i++) if (REL[i].src_port==port){ r=&REL[i]; break; }
    if (!r) return -2;

    char *arr = json_extract_array_slice(body, "\"dests\"");
    if (!arr) return -3;

    struct relay tmp={0};
    char *s=arr;
    while (*s){
        while (*s && (isspace((unsigned char)*s) || *s==',')) s++;
        if (!*s) break;
        if (*s=='"'){
            s++; char *e=strchr(s,'"'); if(!e) break;
            *e=0;
            if (parse_dest_token(&tmp,s)<0){ free(arr); return -4; }
            s=e+1;
        } else {
            char *e=s; while(*e && *e!=',') e++;
            char sv=*e; *e=0;
            if (strlen(s)) if(parse_dest_token(&tmp,trim(s))<0){ *e=sv; free(arr); return -4; }
            *e=sv; s=e;
        }
    }
    free(arr);

    if (replace){
        r->dest_cnt=0; r->pkts_in=r->bytes_in=r->bytes_out=r->send_errs=0;
        for(int j=0;j<MAX_DESTS;j++) r->dests[j].pkts_out=0;
    }
    for (int i=0;i<tmp.dest_cnt && r->dest_cnt<MAX_DESTS;i++)
        r->dests[r->dest_cnt++]=tmp.dests[i];
    return 0;
}

/* append_range: {"port":5801,"ip":"1.2.3.4","start":7000,"end":7005} (ip optional, default 127.0.0.1) */
static int apply_append_range(const char *body){
    int port=json_extract_port(body); if(port<=0) return -1;
    int start=json_get_int(body,"\"start\"", -1);
    int end  =json_get_int(body,"\"end\"", -1);
    if (start<=0 || end<=0) return -1;
    if (start>end){ int t=start; start=end; end=t; }

    const char *k=strstr(body,"\"ip\"");
    char ip[64]="127.0.0.1";
    if (k){
        const char *q=strchr(k,'"'); if(q){ q=strchr(q+1,'"'); if(q){ const char *q2=strchr(q+1,'"'); if(q2){
            size_t n=(size_t)(q2-(q+1)); if (n>0 && n<sizeof(ip)){ memcpy(ip,q+1,n); ip[n]=0; }
        }}}
    }
    struct relay *r=NULL; for (int i=0;i<REL_N;i++) if (REL[i].src_port==port){ r=&REL[i]; break; }
    if (!r) return -2;

    for (int p=start; p<=end && r->dest_cnt<MAX_DESTS; p++){
        if (add_dest(r, ip, p)<0) break;
    }
    return 0;
}

/* ------------------- HTTP route handlers --------------------- */

/* JSON status writer with CORS */
static void http_handle_status(int fd){
    char out[STATUS_CAP+1];
    size_t off = 0;
    #define PUT(fmt,...) do{ int _n=snprintf(out+off, sizeof(out)-off, fmt, ##__VA_ARGS__); if(_n<0) _n=0; if((size_t)_n>sizeof(out)-off) _n=(int)(sizeof(out)-off); off += (size_t)_n; }while(0)
    PUT("{\"relays\":[");
    for(int i=0;i<REL_N;i++){
        if(i) PUT(",");
        struct relay *r=&REL[i];
        PUT("{\"port\":%d,\"pkts_in\":%" PRIu64 ",\"bytes_in\":%" PRIu64 ",\"bytes_out\":%" PRIu64 ",\"send_errs\":%" PRIu64 ",\"last_rx_ns\":%" PRIu64 ",\"dests\":[",
            r->src_port, r->pkts_in, r->bytes_in, r->bytes_out, r->send_errs, r->last_rx_ns);
        for(int j=0;j<r->dest_cnt;j++){
            if(j) PUT(",");
            char ip[INET_ADDRSTRLEN]; inet_ntop(AF_INET,&r->dests[j].addr.sin_addr,ip,sizeof(ip));
            PUT("{\"ip\":\"%s\",\"port\":%d,\"pkts\":%" PRIu64 "}", ip, ntohs(r->dests[j].addr.sin_port), r->dests[j].pkts_out);
        }
        PUT("]}");
    }
    PUT("]}\n");
    http_send_headers(fd, "HTTP/1.1 200 OK", "application/json", (ssize_t)off, NULL);
    http_write(fd, out, off);
}

static void http_handle_get_config(int fd){
    char *txt=NULL; size_t len=0;
    if (load_file(CFG_PATH,&txt,&len)!=0){
        const char *m="missing config\n";
        http_send_headers(fd, "HTTP/1.1 404 Not Found", "text/plain", (ssize_t)strlen(m), NULL);
        http_write(fd, m, strlen(m));
        return;
    }
    http_send_headers(fd, "HTTP/1.1 200 OK", "text/plain; charset=utf-8", (ssize_t)len, NULL);
    http_write(fd, txt, len);
    free(txt);
}

static void http_handle_post_config(int fd, const char *body, size_t len){
    if (save_file_atomic(CFG_TMP_PATH, CFG_PATH, body, len)!=0){
        const char *m="persist failed\n";
        http_send_headers(fd, "HTTP/1.1 500 Internal Server Error", "text/plain", (ssize_t)strlen(m), NULL);
        http_write(fd, m, strlen(m));
        return;
    }
    struct config newc;
    if (load_ini_text(body, &newc)!=0){
        const char *m="bad ini\n";
        http_send_headers(fd, "HTTP/1.1 400 Bad Request", "text/plain", (ssize_t)strlen(m), NULL);
        http_write(fd, m, strlen(m));
        return;
    }
    G = newc; /* swap */
    apply_config_relays(&G);
    const char *ok="{\"ok\":true}\n";
    http_send_headers(fd, "HTTP/1.1 200 OK", "application/json", (ssize_t)strlen(ok), NULL);
    http_write(fd, ok, strlen(ok));
}

static void http_handle_action(int fd, const char *verb, const char *body){
    int rc=-1;
    if (!strcmp(verb,"set")){
        int port=json_extract_port(body);
        rc=apply_set_like(port, body, true);
    } else if (!strcmp(verb,"append")){
        int port=json_extract_port(body);
        rc=apply_set_like(port, body, false);
    } else if (!strcmp(verb,"append_range")){
        rc=apply_append_range(body);
    } else if (!strcmp(verb,"clear")){
        int port=json_extract_port(body);
        if (port>0){
            struct relay *r=NULL; for (int i=0;i<REL_N;i++) if (REL[i].src_port==port){ r=&REL[i]; break; }
            if (r){ r->dest_cnt=0; rc=0; }
        }
    } else if (!strcmp(verb,"reset")){
        int port=json_extract_port(body);
        if (port>0){
            struct relay *r=NULL; for (int i=0;i<REL_N;i++) if (REL[i].src_port==port){ r=&REL[i]; break; }
            if (r){ r->pkts_in=r->bytes_in=r->bytes_out=r->send_errs=0;
                    for(int j=0;j<r->dest_cnt;j++) r->dests[j].pkts_out=0;
                    rc=0; }
        }
    } else {
        const char *m="unknown verb\n";
        http_send_headers(fd, "HTTP/1.1 404 Not Found", "text/plain", (ssize_t)strlen(m), NULL);
        http_write(fd, m, strlen(m));
        return;
    }
    if (rc==0){
        const char *ok="{\"ok\":true}\n";
        http_send_headers(fd, "HTTP/1.1 200 OK", "application/json", (ssize_t)strlen(ok), NULL);
        http_write(fd, ok, strlen(ok));
    } else {
        const char *m="bad action\n";
        http_send_headers(fd, "HTTP/1.1 400 Bad Request", "text/plain", (ssize_t)strlen(m), NULL);
        http_write(fd, m, strlen(m));
    }
}

/* ------------------- request parsing/dispatch ---------------- */

static void http_process_request(int fd, struct http_conn *hc){
    /* Parse Request-Line */
    char *hdr = hc->buf;
    char *hdr_end = strstr(hdr, "\r\n\r\n");
    if (!hdr_end) return; /* need more */

    char method[8]={0}, path[256]={0};
    if (sscanf(hdr,"%7s %255s",method,path)!=2){
        http_send_headers(fd,"HTTP/1.1 400 Bad Request","text/plain",0,NULL); hc_del(fd); return;
    }

    /* Content-Length (optional) */
    size_t clen=0;
    char *cl = strcasestr(hdr,"Content-Length:");
    if (cl) clen = (size_t)strtoul(cl+15,NULL,10);

    size_t hdrlen = (size_t)(hdr_end + 4 - hdr);
    size_t have_body = (hc->len > hdrlen) ? hc->len - hdrlen : 0;
    if (have_body < clen) return; /* need more body */

    const char *body = hc->buf + hdrlen;

    /* CORS preflight */
    if (!strcmp(method,"OPTIONS")){
        http_send_headers(fd, "HTTP/1.1 204 No Content", NULL, 0, NULL);
        hc_del(fd);
        return;
    }

    /* Root → redirect to /ui */
    if (!strcmp(method,"GET") && !strcmp(path,"/")){
        http_send_headers(fd, "HTTP/1.1 302 Found", "text/plain", 0, "Location: /ui\r\n");
        hc_del(fd);
        return;
    }

    /* Serve UI */
    if (!strcmp(method,"GET") && !strcmp(path,"/ui")){
        http_send_headers(fd, "HTTP/1.1 200 OK", "text/html; charset=utf-8", (ssize_t)strlen(UI_HTML), NULL);
        http_write(fd, UI_HTML, strlen(UI_HTML));
        hc_del(fd);
        return;
    }
    if (!strcmp(method,"GET") && !strcmp(path,"/ui.js")){
        http_send_headers(fd, "HTTP/1.1 200 OK", "application/javascript; charset=utf-8", (ssize_t)strlen(UI_JS), NULL);
        http_write(fd, UI_JS, strlen(UI_JS));
        hc_del(fd);
        return;
    }

    /* API routes */
    if (!strcmp(method,"GET") && !strcmp(path,"/api/v1/status")){
        http_handle_status(fd);
        hc_del(fd);
        return;
    } else if (!strcmp(method,"GET") && !strcmp(path,"/api/v1/config")){
        http_handle_get_config(fd);
        hc_del(fd);
        return;
    } else if (!strcmp(method,"POST") && !strcmp(path,"/api/v1/config")){
        http_handle_post_config(fd, body, clen);
        hc_del(fd);
        return;
    } else if (!strcmp(method,"POST") && !strncmp(path,"/api/v1/action/",15)){
        const char *verb = path + 15;
        http_handle_action(fd, verb, body);
        hc_del(fd);
        return;
    }

    /* Default 404 */
    http_send_headers(fd,"HTTP/1.1 404 Not Found","text/plain",0,NULL);
    hc_del(fd);
}

/* ------------------- signal handlers ------------------------- */

static void sig_handler(int sig){
    if (sig==SIGHUP) WANT_RELOAD=1;
    else if (sig==SIGINT || sig==SIGTERM) WANT_EXIT=1;
}

/* ------------------- main loop -------------------------------- */

int main(void){
    /* signals */
    struct sigaction sa={0};
    sa.sa_handler = sig_handler;
    sigaction(SIGHUP,&sa,NULL);
    sigaction(SIGINT,&sa,NULL);
    sigaction(SIGTERM,&sa,NULL);
    signal(SIGPIPE, SIG_IGN);

    /* epoll */
    EPFD = epoll_create1(EPOLL_CLOEXEC);
    if (EPFD<0){ perror("epoll_create1"); return 1; }

    /* config */
    if (load_ini_file(&G)!=0){ fprintf(stderr,"Bad INI, using defaults\n"); cfg_defaults(&G); }
    if (G.bufsz<=0) G.bufsz=9000;

    /* http listen */
    HTTP_LFD = http_listen(G.http_bind, G.control_port);
    if (HTTP_LFD<0){ fprintf(stderr,"HTTP listen failed\n"); return 1; }
    struct epoll_event ev={.events=EPOLLIN, .data.fd=HTTP_LFD};
    epoll_ctl(EPFD, EPOLL_CTL_ADD, HTTP_LFD, &ev);

    /* relays */
    if (apply_config_relays(&G)!=0){
        fprintf(stderr,"No valid bind entries; exiting.\n");
        return 1;
    }

    /* main epoll loop */
    struct epoll_event events[MAX_EVENTS];
    char *udp_buf = malloc((size_t)G.bufsz);
    if (!udp_buf){ perror("malloc"); return 1; }

    while (!WANT_EXIT){
        if (WANT_RELOAD){
            WANT_RELOAD=0;
            struct config nc;
            if (load_ini_file(&nc)==0){
                G=nc;
                if (HTTP_LFD>=0){
                    epoll_ctl(EPFD, EPOLL_CTL_DEL, HTTP_LFD, NULL);
                    close(HTTP_LFD);
                }
                HTTP_LFD = http_listen(G.http_bind, G.control_port);
                if (HTTP_LFD>=0){
                    struct epoll_event ev2={.events=EPOLLIN, .data.fd=HTTP_LFD};
                    epoll_ctl(EPFD, EPOLL_CTL_ADD, HTTP_LFD, &ev2);
                }
                apply_config_relays(&G);
                if (udp_buf){ free(udp_buf); }
                udp_buf = malloc((size_t)G.bufsz);
                if (!udp_buf){ perror("malloc"); break; }
                fprintf(stderr,"Reloaded config\n");
            } else {
                fprintf(stderr,"Reload requested but failed to parse config\n");
            }
        }

        int n = epoll_wait(EPFD, events, MAX_EVENTS, 1000 /*ms*/);
        if (n<0){
            if (errno==EINTR) continue;
            perror("epoll_wait");
            break;
        }
        for (int i=0;i<n;i++){
            int fd = events[i].data.fd;
            uint32_t evs = events[i].events;

            if (fd==HTTP_LFD && (evs & EPOLLIN)){
                while (1){
                    int c=accept(HTTP_LFD, NULL, NULL);
                    if (c<0){ if (errno==EAGAIN||errno==EWOULDBLOCK) break; else { perror("accept"); break; } }
                    set_nonblock(c);
                    struct http_conn *hc=hc_get(c);
                    if (!hc){ close(c); continue; }
                    struct epoll_event cev={.events=EPOLLIN, .data.fd=c};
                    epoll_ctl(EPFD, EPOLL_CTL_ADD, c, &cev);
                }
                continue;
            }

            /* HTTP client readable */
            struct http_conn *hc = hc_find(fd);
            if (hc && hc->fd==fd){
                if (evs & (EPOLLHUP|EPOLLERR)){ hc_del(fd); continue; }
                if (evs & EPOLLIN){
                    char tmp[4096];
                    while (1){
                        ssize_t r=recv(fd,tmp,sizeof(tmp),0);
                        if (r>0){
                            if (hc->len + (size_t)r > HTTP_BUF_MAX){
                                hc_del(fd); break;
                            }
                            if (hc->len + (size_t)r > hc->cap){
                                size_t ncap = hc->cap*2; if (ncap < hc->len+(size_t)r) ncap = hc->len+(size_t)r;
                                if (ncap>HTTP_BUF_MAX) ncap=HTTP_BUF_MAX;
                                char *nb=realloc(hc->buf,ncap); if(!nb){ hc_del(fd); break; }
                                hc->buf=nb; hc->cap=ncap;
                            }
                            memcpy(hc->buf+hc->len, tmp, (size_t)r);
                            hc->len += (size_t)r;
                            http_process_request(fd, hc);
                        } else if (r==0){
                            hc_del(fd); break;
                        } else {
                            if (errno==EAGAIN||errno==EWOULDBLOCK) break;
                            hc_del(fd); break;
                        }
                    }
                }
                continue;
            }

            /* UDP readable on a relay */
            if (evs & EPOLLIN){
                /* find which relay */
                struct relay *r=NULL; for (int k=0;k<REL_N;k++) if (REL[k].fd==fd){ r=&REL[k]; break; }
                if (!r) continue;

                while (1){
                    ssize_t m = recv(fd, udp_buf, (size_t)G.bufsz, 0);
                    if (m>0){
                        r->pkts_in++; r->bytes_in += (uint64_t)m; r->last_rx_ns = now_ns();
                        /* snapshot current dests (plain array copy) */
                        struct dest snap[MAX_DESTS]; int cnt=r->dest_cnt;
                        if (cnt>MAX_DESTS) cnt=MAX_DESTS;
                        if (cnt>0) memcpy(snap, r->dests, (size_t)cnt*sizeof(struct dest));
                        for (int d=0; d<cnt; d++){
                            if (sendto(fd, udp_buf, (size_t)m, 0, (struct sockaddr*)&snap[d].addr, sizeof(snap[d].addr))<0){
                                if (!(errno==EAGAIN||errno==EWOULDBLOCK)) r->send_errs++;
                            } else {
                                r->bytes_out += (uint64_t)m;
                                /* bump pkts_out on real slot by matching addr */
                                for (int j=0;j<r->dest_cnt;j++){
                                    if (sockaddr_equal(&r->dests[j].addr, &snap[d].addr)){
                                        r->dests[j].pkts_out++;
                                        break;
                                    }
                                }
                            }
                        }
                    } else if (m<0){
                        if (errno==EAGAIN||errno==EWOULDBLOCK) break;
                        /* other errors: drop */
                        break;
                    } else { /* m==0 not meaningful for UDP */ break; }
                }
            }
        }
    }

    /* graceful */
    if (HTTP_LFD>=0){ epoll_ctl(EPFD, EPOLL_CTL_DEL, HTTP_LFD, NULL); close(HTTP_LFD); }
    close_relays();
    for (int i=0;i<MAX_HTTP_CONN;i++) if (HC[i].fd) hc_del(HC[i].fd);
    if (udp_buf) free(udp_buf);
    if (EPFD>=0) close(EPFD);
    return 0;
}
