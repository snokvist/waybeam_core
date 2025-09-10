<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1"/>
  <title>UDP Relay Manager · WebUI</title>
  <style>
    :root{
      --bg:#0f1116;--panel:#151823;--muted:#8a93a5;--text:#e8ecf1;--accent:#7bd389;--warn:#e7b75f;--err:#ff7a7a;
      --green:#13391f;--green-b:#1f6b43;--blue:#0f2a45;--blue-b:#2366a2;--yellow:#3b2e13;--yellow-b:#a68124
    }
    *{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
    body{margin:0;font:15px/1.45 system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text)}
    header{display:flex;gap:.75rem;flex-wrap:wrap;align-items:center;padding:14px 16px;background:#0c0f17;position:sticky;top:0;z-index:2;border-bottom:1px solid #1e2231}
    h1{font-size:18px;margin:0 auto 0 0;letter-spacing:.2px}
    button,input,textarea,select{font:inherit}
    label{font-size:12px;color:var(--muted)}
    input,button,textarea,select{background:var(--panel);color:var(--text);border:1px solid #242b3d;border-radius:12px;padding:12px 14px;outline:0}
    button{cursor:pointer;min-height:44px;border-radius:14px}
    button.primary{background:linear-gradient(180deg,#1f6b43,#165538);border-color:#1f6b43}
    button.warn{background:#3b2e13;border-color:#5c4723;color:#ffd990}
    .pill{border-radius:999px;padding:8px 12px}
    main{max-width:1200px;margin:16px auto;padding:0 12px;display:grid;grid-template-columns:1.05fr .95fr;gap:14px}
    @media(max-width:980px){main{grid-template-columns:1fr;gap:12px}}
    section{background:var(--panel);border:1px solid #20273a;border-radius:18px;overflow:hidden}
    section h2{margin:0;padding:10px 12px;border-bottom:1px solid #20273a;font-size:14px;color:#aab3c7;background:#121626;letter-spacing:.3px}
    .pad{padding:12px}
    .chips{display:flex;flex-wrap:wrap;gap:10px}
    .chip{border:2px dashed #2a3247;border-radius:22px;padding:10px 14px;display:flex;gap:10px;align-items:center;user-select:none;min-height:44px;min-width:120px;touch-action:none}
    .chip[draggable=true]{cursor:grab}
    .chip.selected{outline:3px solid #4ea2ff}
    .chip .tag{opacity:.7;font-size:12px}
    .chip .x{margin-left:8px;border:none;background:transparent;color:#ffb3b3;font-weight:700;cursor:pointer;padding:2px 6px;border-radius:8px;min-height:0}
    .chip .x:hover{background:#2a0f0f}.chip .x:active{transform:scale(0.96)}
    .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px}
    .dest{min-height:100px;border:3px dashed #2b344d;border-radius:16px;display:flex;align-items:center;justify-content:space-between;gap:10px;padding:14px;transition:.15s;touch-action:none}
    .dest.drag-over{transform:scale(0.99)}
    .dest .info{display:flex;flex-direction:column;gap:4px}
    .dest .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;font-size:14px}
    .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
    .muted{color:var(--muted)}
    .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace}
    .rowline{display:flex;justify-content:space-between;gap:8px;border:1px solid #252d40;border-radius:12px;padding:10px 12px;margin-bottom:8px}
    textarea.ini{width:100%;min-height:220px;resize:vertical;border-radius:14px}
    .log{height:160px;overflow:auto;background:#0c0f17;border:1px solid #1e2231;border-radius:12px;padding:10px}
    .ok{color:var(--accent)}.warn{color:var(--warn)}.err{color:var(--err)}
    .g{background:var(--green);border-color:var(--green-b)}
    .b{background:var(--blue);border-color:var(--blue-b)}
    .y{background:var(--yellow);border-color:var(--yellow-b)}
    .dest .actions{display:flex;gap:8px}
  </style>
</head>
<body>
  <header>
    <h1>UDP Relay Manager · WebUI</h1>
    <button class="primary pill" id="refresh">Refresh</button>
    <button class="warn pill" id="clearAll">Clear ALL</button>
  </header>

  <main>
    <section>
      <h2>Binds — drag or tap-then-tap</h2>
      <div class="pad">
        <div class="chips" id="bindChips"></div>
      </div>
    </section>

    <section>
      <h2>Destinations</h2>
      <div class="pad">
        <div class="muted" style="margin-bottom:8px">Green=Video (1→1), Blue=Many→1 (mavlink/OSD), Yellow=1→Many (split)</div>
        <div id="destGridG" class="grid" style="margin-bottom:12px"></div>
        <div id="destGridB" class="grid" style="margin-bottom:12px"></div>
        <div id="destGridY" class="grid"></div>
      </div>
    </section>

    <section>
      <h2>Live Status</h2>
      <div class="pad" id="statusBox"><div class="muted">Loading…</div></div>
    </section>

    <section>
      <h2>Manage Config</h2>
      <div class="pad">
        <div class="row">
          <input id="newBindPort" placeholder="add bind (e.g. 5704)" style="min-width:160px"/>
          <button id="addBind">Add bind</button>

          <input id="newDestHost" placeholder="host (e.g. 127.0.0.1)" style="min-width:200px"/>
          <input id="newDestPort" placeholder="port (e.g. 5600)" style="min-width:140px"/>
          <select id="newDestType">
            <option value="green">green (1→1)</option>
            <option value="blue">blue (many→1)</option>
            <option value="yellow">yellow (1→many)</option>
          </select>
          <button id="addDest">Add destination</button>

          <button class="warn" id="saveCfg">Save config</button>
        </div>

        <div id="bindList" style="margin:10px 0"></div>

        <label>Config (INI)</label>
        <textarea id="cfgText" class="ini mono" spellcheck="false"></textarea>
      </div>
    </section>

    <section>
      <h2>Log</h2>
      <div class="pad"><div id="log" class="log mono"></div></div>
    </section>
  </main>

  <script>
  (function(){
    const $ = s => document.querySelector(s);
    const log = (m, c='') => {
      const el = $('#log');
      const d = document.createElement('div');
      if (c) d.className = c;
      d.textContent = `[${new Date().toLocaleTimeString()}] ${m}`;
      el.prepend(d);
    };

    // --- HTTP helpers ---
    const GET = p =>
      fetch(p).then(r => { if(!r.ok) throw new Error(r.statusText); return p.includes('/status') ? r.json() : r.text(); });

    const POST_JSON = (p, obj) =>
      fetch(p, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(obj||{}) })
        .then(async r => { if(!r.ok) throw new Error(await r.text()); try{ return await r.json(); }catch{ return await r.text(); }});

    const POST_TEXT = (p, txt) =>
      fetch(p, { method:'POST', headers:{'Content-Type':'text/plain; charset=utf-8'}, body:txt })
        .then(async r => { if(!r.ok) throw new Error(await r.text()); try{ return await r.json(); }catch{ return await r.text(); }});

    const action = (verb, o) => POST_JSON(`/api/v1/action/${verb}`, o||{});

    // --- State ---
    const state = { status:null, ini:'', dG:[], dB:[], dY:[], selected:null };

    // --- Parse helpers for UI-only config keys ---
    const normDest = s => {
      s = String(s||'').trim();
      const m = s.match(/^([^:\s]+):([0-9]+)$/);
      return m ? `${m[1]}:${m[2]}` : null;
    };

    function parseDests(txt){
      const g=new Set(), b=new Set(), y=new Set();
      for(const ln of txt.split(/\n/)){
        let m;
        if((m=ln.match(/^\s*dest_green\s*=\s*(\S+)/))){ const d=normDest(m[1]); if(d) g.add(d); continue; }
        if((m=ln.match(/^\s*dest_blue\s*=\s*(\S+)/))){  const d=normDest(m[1]); if(d) b.add(d); continue; }
        if((m=ln.match(/^\s*dest_yellow\s*=\s*(\S+)/))){const d=normDest(m[1]); if(d) y.add(d); continue; }

        if((m=ln.match(/^\s*ui_dest_green\s*=\s*(.+)$/))) m[1].split(',').forEach(t=>{ const d=normDest(t); if(d) g.add(d); });
        if((m=ln.match(/^\s*ui_dest_blue\s*=\s*(.+)$/)))  m[1].split(',').forEach(t=>{ const d=normDest(t); if(d) b.add(d); });
        if((m=ln.match(/^\s*ui_dest_yellow\s*=\s*(.+)$/))) m[1].split(',').forEach(t=>{ const d=normDest(t); if(d) y.add(d); });
      }
      return { g:[...g], b:[...b], y:[...y] };
    }

    function writeDests(txt, {g,b,y}){
      const out=[];
      for(const ln of txt.split(/\n/)){
        if(/^\s*(dest_green|dest_blue|dest_yellow|ui_dest_green|ui_dest_blue|ui_dest_yellow)\s*=/.test(ln)) continue;
        out.push(ln);
      }
      if(out.length && out[out.length-1] !== '') out.push('');
      for(const d of g) out.push(`dest_green=${d}`);
      for(const d of b) out.push(`dest_blue=${d}`);
      for(const d of y) out.push(`dest_yellow=${d}`);
      return out.join('\n');
    }

    // --- Loaders ---
    async function loadStatus(){
      try{
        const s = await GET('/api/v1/status');
        state.status = s;
        renderBinds(s);
        renderStatus(s);
      }catch(e){
        $('#statusBox').innerHTML = `<span class=err>${e}</span>`;
      }
    }

    async function loadConfig(){
      const t = await GET('/api/v1/config');
      state.ini = String(t||'').replace(/\r/g,'');
      const {g,b,y} = parseDests(state.ini);
      state.dG = g; state.dB = b; state.dY = y;
      $('#cfgText').value = state.ini;
      renderConfigLists();
      renderDestGrids();
    }

    // --- Status helpers ---
    const relays = () => (state.status && state.status.relays) || [];
    const findRelay = p => relays().find(r => r.port === p);
    const listTokens = r => (r.dests || []).map(d => `${d.ip}:${d.port}`);

    async function removeDestFromPort(port, dest){
      await action('clear_to', { port, dest });
    }
    async function clearDestinationEverywhere(dest){
      for(const r of relays()){
        if(listTokens(r).includes(dest)) await removeDestFromPort(r.port, dest);
      }
    }
    async function clearAll(){
      for(const r of relays()) await action('clear', { port:r.port });
    }

    // Drops:
    async function dropGreen(srcPort, dest){
      await clearDestinationEverywhere(dest);                 // enforce 1→1 globally
      await action('set', { port:srcPort, dests:[dest] });    // replace on that bind
      log(`bind ${srcPort} → ${dest} (exclusive)`, 'ok');
      await loadStatus();
    }
    async function dropBlue(srcPort, dest){                    // many→1 allowed
      const r = findRelay(srcPort); if(!r) return;
      const tokens = new Set(listTokens(r));
      if(!tokens.has(dest)){
        await action('append', { port:srcPort, dests:[dest] });
        log(`bind ${srcPort} +→ ${dest}`, 'ok');
      }else{
        log(`already mapped: ${srcPort} has ${dest}`, 'warn');
      }
      await loadStatus();
    }
    async function dropYellow(srcPort, dest){                  // 1→many on the bind
      return dropBlue(srcPort, dest);
    }

    // --- DnD & tap-to-apply on dest cards ---
    function bindDropZone(el, dest, type){
      const onDo = (src) => {
        if (type==='g') return dropGreen(src, dest);
        if (type==='b') return dropBlue(src, dest);
        return dropYellow(src, dest);
      };
      const allow = e => { e.preventDefault(); e.stopPropagation(); };
      el.addEventListener('dragenter', allow);
      el.addEventListener('dragover', e => { allow(e); el.classList.add('drag-over'); });
      el.addEventListener('dragleave', () => el.classList.remove('drag-over'));
      el.addEventListener('drop', e => {
        allow(e); el.classList.remove('drag-over');
        const txt = e.dataTransfer.getData('text/plain');
        const p = parseInt(txt, 10);
        if (p) onDo(p).catch(err => log(err, 'err'));
      });
      el.addEventListener('click', () => {
        if (state.selected) onDo(state.selected).catch(err => log(err, 'err'));
      });
    }

    // --- UI builders ---
    function makeDestCard(dest, type){
      const card = document.createElement('div');
      card.className = `dest ${type}`;
      const label = (type==='g') ? 'Video (1→1)' : (type==='b') ? 'Many→1' : '1→Many';
      card.innerHTML =
        `<div class='info'>
           <div class='muted'>${label}</div>
           <div class='mono'>${dest}</div>
         </div>
         <div class='actions'>
           <button class='pill' data-cc='1'>Clear this</button>
         </div>`;
      bindDropZone(card, dest, type);
      card.querySelector('button[data-cc]')?.addEventListener('click', async (e)=>{
        e.stopPropagation();
        await clearDestinationEverywhere(dest);
        log(`Cleared ${dest} from all binds`, 'ok');
        await loadStatus();
      });
      return card;
    }

    function renderDestGrids(){
      const g = $('#destGridG'), b = $('#destGridB'), y = $('#destGridY');
      g.innerHTML = ''; b.innerHTML = ''; y.innerHTML = '';
      if(!state.dG.length && !state.dB.length && !state.dY.length){
        const m = document.createElement('div');
        m.className='muted'; m.textContent='No destinations configured. Use Manage Config to add dest_* lines.';
        g.appendChild(m); return;
      }
      for(const d of state.dG) g.appendChild(makeDestCard(d,'g'));
      for(const d of state.dB) b.appendChild(makeDestCard(d,'b'));
      for(const d of state.dY) y.appendChild(makeDestCard(d,'y'));
    }

    function renderBinds(s){
      const wrap = $('#bindChips');
      const sel = state.selected;
      wrap.innerHTML = '';
      (s.relays||[]).forEach(r => {
        const el = document.createElement('div');
        el.className = 'chip';
        el.draggable = true;
        el.dataset.port = String(r.port);
        el.innerHTML = `<strong>bind ${r.port}</strong> <span class='tag'>in:${r.pkts_in||0}</span>`;
        el.addEventListener('dragstart', e => {
          e.dataTransfer.setData('text/plain', String(r.port));
          e.dataTransfer.effectAllowed = 'copy';
        });
        el.addEventListener('click', () => {
          if (state.selected === r.port){ state.selected = null; el.classList.remove('selected'); }
          else {
            state.selected = r.port;
            document.querySelectorAll('.chip').forEach(c => c.classList.remove('selected'));
            el.classList.add('selected');
          }
        });
        if (sel === r.port) el.classList.add('selected');
        wrap.appendChild(el);
      });
    }

    function renderStatus(s){
      const box = $('#statusBox');
      if(!s || !Array.isArray(s.relays)){ box.innerHTML = '<div class=muted>No relays</div>'; return; }
      const frag = document.createDocumentFragment();
      for(const r of s.relays){
        const outPkts = Array.isArray(r.dests) ? r.dests.reduce((a,d)=>a+(d.pkts||0),0) : 0;
        const oneToOne = (Array.isArray(r.dests) && r.dests.length===1);
        const row = document.createElement('div');
        row.className = 'rowline';

        const left = document.createElement('div');
        left.innerHTML =
          `<strong>bind ${r.port}</strong>
           <div class='muted'>
             in pkts ${r.pkts_in} · out pkts ${outPkts}${oneToOne ? ' (1→1)' : ''}
             · out bytes ${r.bytes_out} · errs ${r.send_errs}
           </div>`;

        const right = document.createElement('div');
        const clr = document.createElement('button');
        clr.textContent = 'Clear bind';
        clr.onclick = () => action('clear',{port:r.port})
          .then(()=>{ log(`cleared ${r.port}`,'ok'); loadStatus(); })
          .catch(e=>log(e,'err'));
        right.appendChild(clr);

        const dests = document.createElement('div');
        dests.className = 'chips';
        dests.style.marginTop = '6px';

        if(Array.isArray(r.dests) && r.dests.length){
          for(const d of r.dests){
            const token = `${d.ip}:${d.port}`;
            const c = document.createElement('div');
            c.className = 'chip';
            c.innerHTML = `<span class='tag'>→</span><strong>${token}</strong> <span class='tag'>pkts ${d.pkts}</span>`;
            const x = document.createElement('button');
            x.className = 'x';
            x.title = 'Remove this destination from this bind';
            x.textContent = '×';
            x.onclick = (e) => {
              e.stopPropagation();
              removeDestFromPort(r.port, token)
                .then(()=>{ log(`Removed ${token} from bind ${r.port}`,'ok'); loadStatus(); })
                .catch(err=>log(err,'err'));
            };
            c.appendChild(x);
            dests.appendChild(c);
          }
        } else {
          const m = document.createElement('div');
          m.className = 'muted';
          m.textContent = 'no destinations';
          dests.appendChild(m);
        }

        row.appendChild(left);
        row.appendChild(right);
        frag.appendChild(row);
        frag.appendChild(dests);
      }
      box.innerHTML = '';
      box.appendChild(frag);
    }

    function renderConfigLists(){
      const binds = [];
      for(const ln of state.ini.split(/\n/)){
        const m = ln.match(/^\s*bind\s*=\s*(\d+)/);
        if (m) binds.push(+m[1]);
      }
      const list = $('#bindList');
      list.innerHTML = '';
      if(!binds.length){ list.innerHTML = '<div class=muted>No binds in config.</div>'; return; }
      for(const p of binds){
        const row = document.createElement('div');
        row.className = 'rowline';
        row.innerHTML = `<div class=mono>bind=${p}</div>`;
        const rm = document.createElement('button');
        rm.textContent = 'Remove';
        rm.onclick = () => {
          state.ini = state.ini.split(/\n/).filter(l => !l.match(new RegExp(`^\\s*bind\\s*=\\s*${p}(\\b|:)`))).join('\n');
          $('#cfgText').value = state.ini;
          renderConfigLists();
        };
        row.appendChild(rm);
        list.appendChild(row);
      }
    }

    // --- Controls ---
    $('#addBind').onclick = () => {
      const v = parseInt($('#newBindPort').value, 10);
      if(!(v>0 && v<65536)) return log('Invalid bind port', 'err');
      if(new RegExp(`^\\s*bind\\s*=\\s*${v}(\\b|:)`,'m').test(state.ini)) return log('bind exists','warn');
      state.ini += (/\n$/.test(state.ini)?'':'\n') + `bind=${v}\n`;
      $('#cfgText').value = state.ini;
      renderConfigLists();
    };

    $('#addDest').onclick = () => {
      const h = $('#newDestHost').value.trim() || '127.0.0.1';
      const p = parseInt($('#newDestPort').value, 10);
      if(!(p>0 && p<65536)) return log('Invalid dest port','err');
      const t = $('#newDestType').value;
      const d = `${h}:${p}`;
      if(t==='green'  && !state.dG.includes(d)) state.dG.push(d);
      if(t==='blue'   && !state.dB.includes(d)) state.dB.push(d);
      if(t==='yellow' && !state.dY.includes(d)) state.dY.push(d);
      state.ini = writeDests(state.ini, { g:state.dG, b:state.dB, y:state.dY });
      $('#cfgText').value = state.ini;
      renderDestGrids();
    };

    $('#saveCfg').onclick = async () => {
      try{
        await POST_TEXT('/api/v1/config', $('#cfgText').value);
        log('Config saved & reloaded','ok');
        await refreshAll();
      }catch(e){ log(e,'err'); }
    };

    $('#refresh').onclick = () => refreshAll();

    $('#clearAll').onclick = async () => {
      try{
        await clearAll();
        log('All mappings cleared','ok');
        await loadStatus();
      }catch(e){ log(e,'err'); }
    };

    async function refreshAll(){
      await Promise.all([loadConfig(), loadStatus()]);
    }

    // Kickoff & poll
    refreshAll();
    setInterval(()=>loadStatus().catch(()=>{}), 1500);
  })();
  </script>
</body>
</html>
