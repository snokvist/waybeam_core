// app.js — Waybeam Ultralite (Alpine component)
window.app = function app(){
  return {
    // ------------ State ------------
    wsUrl:      localStorage.getItem('hail.ws')    || 'ws://192.168.2.1:8089/',
    mjpeg:      localStorage.getItem('hail.mjpeg') || '/mjpeg',

    connected:false, uiConnected:false, connDownTimer:null, lastConnLogTs:0,
    step:'role', role:'beacon',

    nodes:{}, beacon:null, porthole:null, relay:null,

    // UI helpers
    portholePickerOpen:false,

    // Beam/UI params
    params:{
      lane:'Default',
      isp:{ exposure:15 },
      image:{ contrast:50, hue:50, luminance:50 },
      video0:{ codec:'h265', fps:60, size:'1280x720', bitrate:8000, rcMode:'cbr', gopSize:10 },
      audio:{ enabled:false, srate:8000, codec:'opus' },
      records:{ enabled:false }
    },

    // Destination port for cast
    castPort: Number(localStorage.getItem('hail.castPort') || 5600),

    // Base Accept
    acceptBase:{
      isp:{ exposure:{ min:5, max:16, step:1 } },
      image:{
        contrast:{ min:0, max:100, step:5 },
        hue:{ min:0, max:100, step:5 },
        luminance:{ min:0, max:100, step:5 },
      },
      video0:{
        codec: ['h265','h264'],
        fps:   [10,30,60,90,120],
        size:  ['1280x720','1920x1080','1080x1440'],
        rcMode:['cbr','avbr'],
        gopSize:[0.25,0.5,0.75,1,2,3,5,10],
        bitrate:{ min:256, max:20000, step:256 }
      }
    },
    // Dynamic Accept per node
    acceptNode:{},

    stats:{ tx:0, rx:0 },
    eventLog:[], logExpanded:false,

    ws:null, reconn:null, keepAlive:null, backoffMs:5000,
    selfNodesTimer: null,

    // scanner
    scanPrefix:'192.168.2',
    isScanning:false, scanDone:false, scanFound:[],
    scanned:0, scanTotal:254, scanPercent:0,

    // Control generation skip list
    autoSkipKeys: new Set([
      'lane',
      'isp.exposure',
      'image.contrast','image.hue','image.luminance',
      'video0.bitrate','video0.codec','video0.fps','video0.size','video0.rcMode','video0.gopSize',
      'audio.enabled','records.enabled',
    ]),

    // Inline MJPEG preview
    inlinePreviewOpen:false,
    inlinePreviewUrl:'',
    inlineState:'idle',  // 'idle' | 'loading' | 'ok' | 'fail'
    inlineTimer:null,

    // Debounce timers
    _debounceTimers:{},

    // ------------ Derived ------------
    get all(){ return Object.values(this.nodes); },

    staticPorthole(){
      return {
        src_id: 'static:multicast',
        ip: '224.0.0.1',
        destination: '224.0.0.1',
        alias: 'Multicast',
        roles: ['porthole'],
        caps: [],
        lastSeen: '—',
        lastSeenMs: Date.now()
      };
    },
    get beacons(){ return this.all.filter(n => (n.roles||[]).includes('beacon')); },
    get portholes(){
      const dyn = this.all.filter(n => (n.roles||[]).includes('porthole'));
      return [ this.staticPorthole(), ...dyn ];
    },
    get relays(){ return this.all.filter(n => (n.roles||[]).includes('relay')); },

    // ------------ Init ------------
    init(){
      this.connect();
      setInterval(this.purgeStale.bind(this), 1000);
    },

    // ------------ UI helpers ------------
    prettyStep(){
      const map = {
        role:'Role', beacon:'Beacon', porthole:'Porthole', relay:'Relay',
        actions_beacon:'Actions — Beacon', actions_porthole:'Actions — Porthole', actions_relay:'Actions — Relay'
      };
      return map[this.step] || 'Waybeam';
    },
    prettyLabel(path){
      try{
        const parts = String(path).split('.');
        const nice = parts.map(p=>{
          const withSpaces = p.replace(/([a-z0-9])([A-Z])/g,'$1 $2').replace(/_/g,' ');
          return withSpaces.replace(/\brc\b/i,'RC')
                           .replace(/\bgop\b/i,'GOP')
                           .replace(/\bip\b/i,'IP')
                           .replace(/\bfps\b/i,'FPS')
                           .replace(/\bkbps\b/i,'kbps')
                           .replace(/\bopus\b/i,'Opus')
                           .replace(/\bh264\b/i,'H.264')
                           .replace(/\bh265\b/i,'H.265')
                           .replace(/\bvideo0\b/i,'Video 0')
                           .replace(/\bisp\b/i,'ISP')
                           .replace(/\bui\b/i,'UI')
                           .replace(/\bws\b/i,'WS')
                           .replace(/\bpsk\b/i,'PSK')
                           .replace(/^\w/, c=>c.toUpperCase());
        });
        return nice.join(' · ');
      }catch{ return String(path); }
    },
    selectRole(r){ this.role = r; this.step = r; },
    goBack(){
      const m = {
        role:'role',
        beacon:'role',
        porthole:'role',
        relay:'role',
        actions_beacon:'beacon',
        actions_porthole:'porthole',
        actions_relay:'relay'
      };
      this.step = m[this.step] || 'role';
    },
    openSettings(){ document.getElementById('dlg').showModal(); },
    saveSettings(){
      localStorage.setItem('hail.ws', this.wsUrl);
      localStorage.setItem('hail.mjpeg', this.mjpeg);
      this.log('info','Saved settings');
    },

    laneOptions(){
      const acc = this.listGet('lane', null);
      if (acc && acc.length) return acc.map(String);
      const caps = (this.beacon && Array.isArray(this.beacon.caps)) ? this.beacon.caps.map(String) : [];
      const lanes = caps.filter(Boolean);
      return lanes.length ? Array.from(new Set(lanes)) : ['Default'];
    },

    // Destination port handling
    setCastPort(p){
      const v = Number(p);
      if (!Number.isFinite(v)) return;
      this.castPort = v;
      localStorage.setItem('hail.castPort', String(v));
      this.log('info', `Port set to ${v}`, '#c8e6ff');
    },
    portOptions(){
      const acc = this.activeAccept('porthole');
      const tryPaths = ['dest.port', 'port', 'video.port', 'udp.port'];
      for (const path of tryPaths){
        const v = this.pathGet(acc, path);
        if (Array.isArray(v) && v.length) {
          return v.map(Number).filter(n => Number.isFinite(n));
        }
      }
      return [5600,5601,5602,5603];
    },

    // ------------ Selection handlers ------------
    selectBeacon(n){
      this.beacon = n; this.step='actions_beacon';
      if(!this.porthole) this.porthole = this.staticPorthole();
      this.portholePickerOpen = false;
      this.doRequestFor('beacon', true);
    },
    selectPorthole(n){
      this.porthole = n;
      this.step = (this.step==='actions_beacon') ? 'actions_beacon' : 'actions_porthole';
    },
    // New: picker inside Beacon (no navigation)
    selectPortholeForBeacon(n){
      this.porthole = n;
      this.portholePickerOpen = false;
      this.log('info', `Selected porthole: ${n.alias||n.ip}`, '#d6f1ff');
    },
    selectRelay(n){ this.relay = n; this.step='actions_relay'; },

    // ------------ Inline MJPEG preview ------------
    toggleInlinePreview(){
      if(!this.beacon){ this.log('err','Pick a Beacon first'); return; }
      if(this.inlinePreviewOpen){ this.closeInlinePreview(); return; }
      this.loadInlinePreview();
    },
    loadInlinePreview(){
      const ip = this.beacon.ip;
      const path = this.mjpeg.startsWith('/') ? this.mjpeg : ('/'+this.mjpeg);
      this.inlinePreviewUrl = `http://${ip}${path}?t=${Date.now()}`;
      this.inlineState = 'loading';
      this.inlinePreviewOpen = true;

      clearTimeout(this.inlineTimer);
      this.inlineTimer = setTimeout(()=>{
        if(this.inlineState==='loading'){ this.inlineState='fail'; }
      }, 2000);
    },
    closeInlinePreview(){
      this.inlinePreviewOpen = false;
      this.inlineState = 'idle';
      clearTimeout(this.inlineTimer);
      try{
        if(this.$refs.mjpegImg) this.$refs.mjpegImg.src = 'about:blank';
      }catch{}
    },
    onInlineImgLoaded(){
      this.inlineState = 'ok';
      clearTimeout(this.inlineTimer);
    },
    onInlineImgError(){
      this.inlineState = 'fail';
      clearTimeout(this.inlineTimer);
    },
    mjpegHref(){
      if(!this.beacon) return '#';
      const ip = this.beacon.ip;
      const path = this.mjpeg.startsWith('/') ? this.mjpeg : ('/'+this.mjpeg);
      return `http://${ip}${path}`;
    },

    // ------------ Event log ------------
    log(kind,msg,color){
      const last = this.eventLog[0];
      if(last && last.knd===kind && last.msg===msg) return;
      const d = new Date(), t = d.toLocaleTimeString();
      const entry = {t, knd:kind, msg, c: color || (kind==='err' ? '#ff6b8b' : kind==='ack' ? '#2ecc71' : '#aab0c7'), k: (Date.now().toString(36)+Math.random().toString(36).slice(2,6))};
      this.eventLog.unshift(entry); if(this.eventLog.length>10) this.eventLog.pop();
      queueMicrotask(()=>{ const el=document.getElementById('log'); if(el) el.scrollTop=0; });
    },

    // ------------ Node housekeeping ------------
    purgeStale(){
      const now = Date.now(), cutoff = now - 10000;
      let changed = false;
      for(const [sid, n] of Object.entries(this.nodes)){
        if(!n.lastSeenMs || n.lastSeenMs < cutoff){
          delete this.nodes[sid]; changed = true;
          if(this.beacon && this.beacon.src_id===sid){ this.beacon=null; if(this.step==='actions_beacon') this.step='beacon'; }
          if(this.porthole && this.porthole.src_id===sid){ this.porthole=null; if(this.step!=='role') this.step='porthole'; }
          if(this.relay && this.relay.src_id===sid){ this.relay=null; if(this.step==='actions_relay') this.step='relay'; }
          delete this.acceptNode[sid];
        }
      }
      if(changed){ this.nodes = { ...this.nodes }; }
    },

    // ------------ WS (stable + keepalive) ------------
    reconnect(){ try{ this.ws && this.ws.close(); }catch{}; this.backoffMs = 5000; this.connect(); },
    connect(){
      clearTimeout(this.reconn);
      if(this.ws){ try{ this.ws.onopen=this.ws.onclose=this.ws.onerror=this.ws.onmessage=null; this.ws.close(); }catch{} }
      this.connected=false; this.setUiConnected(false);

      let ws;
      try{ ws = new WebSocket(this.wsUrl); }catch(e){ this.log('err','Bad WS URL'); return; }
      this.ws = ws;

      ws.onopen = () => {
        this.connected = true; this.setUiConnected(true);
        const now = Date.now();
        if(now - this.lastConnLogTs > 15000){ this.log('info','WS connected','#71d7ff'); this.lastConnLogTs = now; }
        clearInterval(this.keepAlive);
        this.keepAlive = setInterval(()=>{ try{ if(this.ws && this.ws.readyState===1) this.ws.send(JSON.stringify({op:'ping'})); }catch{} }, 20000);

        try { this.send({op:'nodes'}); } catch {}
        try { this.send({op:'beacon'}); } catch {}

        this.startSelfNodesPoll();
        this.backoffMs = 5000;
      };
      ws.onclose = () => {
        this.connected = false; this.setUiConnected(false);
        clearInterval(this.keepAlive);
        this.stopSelfNodesPoll();
        const delay = this.backoffMs;
        this.reconn = setTimeout(()=>this.connect(), delay);
        this.backoffMs = Math.min(this.backoffMs * 2, 30000);
      };
      ws.onerror = () => { /* ignore */ };

      ws.onmessage = (ev) => {
        let s = typeof ev.data==='string'? ev.data : '';
        s = s.replace(/\u0000+$/,'').trim(); if(!s) return;
        try{
          const e = JSON.parse(s);
          this.stats.rx++;
          if(e.ev==='rx'){
            const m = e.meta||{}, sid = String(m.src_id||''); if(!sid) return;
            const old = this.nodes[sid] || {};
            const roles = this.extractRoles(e,m);
            this.nodes = { ...this.nodes, [sid]: {
              ...old, src_id: sid,
              ip: m.ip || old.ip, port: Number(m.port || old.port || 0),
              alias: (e.hail && e.hail.alias) || old.alias,
              roles: roles.length? roles : (old.roles||[]),
              caps: (e.app && e.app.caps) ? e.app.caps : (old.caps||[]),
              lastSeen: new Date().toLocaleTimeString(),
              lastSeenMs: Date.now()
            }};

            // ---- App-level ACK/ERR handling ----
            if(e.app && e.app.kind){
              const a = e.app;
              if(a.kind==='ack' && a.topic==='beam'){
                const act = a.action||'';
                const code = a.code||a.data?.code||'';
                const state = a.state||a.data?.state||'';
                this.log('ack', `beam.${act} → state=${state||'ok'} code=${code||'-'}`, '#9ff0b8');

                // Apply only if ACK is from the active node
                const active = this.activeNode();
                if(act==='request' && a.data){
                  if(a.data.params && active && active.src_id===sid){
                    this.applyParams(a.data.params);
                    this.log('info','Loaded current params','#bcd9ff');
                  }
                  if(a.data.accept){
                    this.applyAcceptNode(sid, a.data.accept);
                    this.log('info',`Updated acceptable ranges/options for ${sid.slice(0,8)}`,'#d0ffd0');
                  }
                }
              } else if (e.app && e.app.kind==='err' && e.app.topic==='beam') {
                this.log('err', `beam.${e.app.action||'?'} error`, '#ff9da7');
              }
            }
          }
          else if(e.ev==='nodes' && Array.isArray(e.nodes)){
            for(const n of e.nodes){
              const sid = String(n.src_id||''); if(!sid) continue;
              const old = this.nodes[sid] || {};
              this.nodes = { ...this.nodes, [sid]: {
                ...old, src_id:sid,
                ip: n.ip || old.ip,
                port: Number(n.port || old.port || 0),
                alias: n.alias || old.alias,
                roles: Array.isArray(n.roles)? n.roles : (old.roles||[]),
                caps: Array.isArray(n.caps)? n.caps : (old.caps||[]),
                lastSeen: new Date().toLocaleTimeString(),
                lastSeenMs: Date.now()
              }};
            }
          }
        }catch(err){ this.log('err','Bad JSON frame'); console.warn(err); }
      };
    },
    setUiConnected(on){
      clearTimeout(this.connDownTimer);
      if(on){ this.uiConnected = true; return; }
      this.connDownTimer = setTimeout(()=>{ this.uiConnected = false; }, 1200);
    },
    send(obj){ try{ if(this.ws && this.ws.readyState===1) this.ws.send(JSON.stringify(obj)); }catch(e){} },
    unicast(dst, cfg){ this.send({op:'unicast', dst:String(dst), type:'DATA', hop:0, ttl:0, ack:1, app: cfg.app || null}); },

    // ------------ Builders & Actions ------------
    genId(){ return 'cmd-'+Math.random().toString(16).slice(2,10); },

    buildParamsPayload(){
      const prune = (v) => {
        if (Array.isArray(v)) return v.slice();
        if (v && typeof v === 'object') {
          const out = {};
          for (const [k, val] of Object.entries(v)) {
            const pv = prune(val);
            if (pv !== undefined) out[k] = pv;
          }
          return out;
        }
        if (typeof v === 'number' || typeof v === 'string' || typeof v === 'boolean') return v;
        return undefined;
      };
      const { lane, ...rest } = this.params;
      return prune(rest);
    },

    buildPartialParams(path, value){
      const obj = {};
      this.pathSet(obj, path, value);
      return obj;
    },

// Return array of static control paths (always exposed in UI)
staticParamPaths(){
  // mirrors the static controls shown in UI; exclude 'lane'
  return Array.from(this.autoSkipKeys).filter(k => k !== 'lane');
},

// Return list of param paths currently exposed (statics + visible autos)
exposedParamPaths(role='beacon'){
  const statics = this.staticParamPaths();

  // Only auto-controls that are currently visible (i.e. have a value)
  const grouped = this.autoControlsGrouped(this.activeAccept(role));
  const autos = [
    ...grouped.ranges.map(c => c.path),
    ...grouped.selects.map(c => c.path),
    ...grouped.toggles.map(c => c.path),
  ];

  // de-dup
  return Array.from(new Set([...statics, ...autos]));
},

// Build a sparse "mask" object from paths, with null values (backend treats as “refresh these”)
buildParamsMaskFromPaths(paths){
  const mask = {};
  for(const p of (paths||[])){ this.pathSet(mask, p, null); }
  return mask;
},

    nodeForRole(role){
      if(role==='beacon') return this.beacon;
      if(role==='porthole') return this.porthole;
      if(role==='relay') return this.relay;
      return this.activeNode();
    },
    activeNode(){
      if(this.step==='actions_beacon') return this.beacon;
      if(this.step==='actions_porthole') return this.porthole;
      if(this.step==='actions_relay') return this.relay;
      return null;
    },
    activeRole(){
      if(this.step==='actions_beacon') return 'beacon';
      if(this.step==='actions_porthole') return 'porthole';
      if(this.step==='actions_relay') return 'relay';
      return this.role || 'beacon';
    },

    doPartialUpdate(path, value, role){
      const r = role || this.activeRole();
      const node = this.nodeForRole(r);
      if(!node){ this.log('err',`Pick a ${r} first`); return; }
      const app = {
        v:1, id:this.genId(), kind:'cmd', topic:'beam', action:'update',
        data:{ lane: this.params.lane || 'Default', params: this.buildPartialParams(path, value) }
      };
      this.unicast(`${node.ip}:${node.port}`, { app });
      this.stats.tx++;
      this.log('tx', `update ${r}:${path}=${String(value)}`, '#f2ffa6');
    },

    debouncedPartial(path, value, role, ms=150){
      const key = `${role||this.activeRole()}:${path}`;
      clearTimeout(this._debounceTimers[key]);
      this._debounceTimers[key] = setTimeout(()=>{
        this.doPartialUpdate(path, this.paramGet(path), role);
      }, ms);
    },

    buildDst(){
      const host = this.porthole ? this.porthole.ip : '';
      const port = Number(this.castPort || 0) || 5600;
      const to   = host ? `${host}:${port}` : '';
      return { host, port, to };
    },

buildCast(){
  const dst = this.buildDst();
  return {
    v:1, id:this.genId(), kind:'cmd', topic:'beam', action:'cast',
    data:{
      to: dst.to,                              // single source of truth for destination
      lane: this.params.lane || 'Default',
      params: this.buildParamsPayload()
    }
  };
},
    buildStop(){ return { v:1, id:this.genId(), kind:'cmd', topic:'beam', action:'stop', data:{ beam_id:'0' } }; },
buildUpdate(){
  const dst = this.buildDst();
  return {
    v:1, id:this.genId(), kind:'cmd', topic:'beam', action:'update',
    data:{
      to: dst.to,                              // keep aligned with cast
      lane: this.params.lane || 'Default',
      params: this.buildParamsPayload()
    }
  };
},
buildRequest(role='beacon'){
  const paths = this.exposedParamPaths(role);      // statics + visible autos
  if(paths.length===0){
    // fall back to classic empty request → backend returns full params
    return { v:1, id:this.genId(), kind:'cmd', topic:'beam', action:'request', data:{} };
  }
  // Send a compact path mask to save bytes; backend replies with data.params
  return {
    v:1, id:this.genId(), kind:'cmd', topic:'beam', action:'request',
    data:{
      lane: this.params.lane || 'Default',
      mask: paths,                   // << array of "a.b.c" paths
      requestMode: 'maskPaths'       // optional hint for backend
    }
  };
},

    doCast(){
      if(!this.beacon){ this.log('err','Pick a Beacon first'); return; }
      if(!this.porthole){ this.log('err','Pick a Porthole first'); return; }
      const app = this.buildCast();
      this.unicast(`${this.beacon.ip}:${this.beacon.port}`, { app });
      this.stats.tx++; this.log('tx', `cast → ${this.porthole.ip}:${this.castPort}`, '#c7e7ff');
    },
    doStop(){
      if(!this.beacon){ this.log('err','Pick a Beacon first'); return; }
      const app = this.buildStop();
      this.unicast(`${this.beacon.ip}:${this.beacon.port}`, { app });
      this.stats.tx++; this.log('tx', `stop`, '#ffd2a6');
    },
    doUpdate(){
      if(!this.beacon){ this.log('err','Pick a Beacon first'); return; }
      const app = this.buildUpdate();
      this.unicast(`${this.beacon.ip}:${this.beacon.port}`, { app });
      this.stats.tx++; this.log('tx', `update (full)`, '#f2ffa6');
    },

    doRequestFor(role, silent){
      let node = null;
      if(role==='beacon') node = this.beacon;
      else if(role==='porthole') node = this.porthole;
      else if(role==='relay') node = this.relay;
      if(!node){ if(!silent) this.log('err',`Pick a ${role} first`); return; }
      const app = this.buildRequest(role);
      this.unicast(`${node.ip}:${node.port}`, { app });
      this.stats.tx++; if(!silent) this.log('tx',`${role}.request current`,'#b3ecff');
    },

    // ------------ Param helpers & unified change handlers ------------
    pathGet(obj, path){
      try{ return String(path).split('.').reduce((o,k)=> (o && (k in o)) ? o[k] : undefined, obj); }
      catch{ return undefined; }
    },
    pathSet(obj, path, value){
      const ks = String(path).split('.');
      let cur = obj;
      for (let i=0;i<ks.length-1;i++){
        const k = ks[i];
        if (!cur[k] || typeof cur[k] !== 'object') cur[k] = {};
        cur = cur[k];
      }
      cur[ks[ks.length-1]] = value;
    },
    paramGet(path){ return this.pathGet(this.params, path); },
    normalizeBool(v){
      if (typeof v === 'boolean') return v;
      if (typeof v === 'number') return v !== 0;
      if (typeof v === 'string'){
        const s=v.trim().toLowerCase();
        if (s==='1'||s==='true'||s==='yes'||s==='on') return true;
        if (s==='0'||s==='false'||s==='no'||s==='off') return false;
      }
      return !!v;
    },
    coerceToLike(current, incoming){
      if (typeof current === 'number'){
        if (typeof incoming === 'number') return incoming;
        const n = Number(incoming);
        return Number.isFinite(n) ? n : current;
      }
      if (typeof current === 'boolean') return this.normalizeBool(incoming);
      return incoming;
    },
    setParam(path, v){
      const cur = this.paramGet(path);
      this.pathSet(this.params, path, this.coerceToLike(cur, v));
    },

    onRange(path, v, role){ this.setParam(path, v); this.debouncedPartial(path, this.paramGet(path), role, 150); },
    onSelect(path, v, role){ this.setParam(path, v); this.doPartialUpdate(path, this.paramGet(path), role); },
    onToggle(path, v, role){ this.setParam(path, v); this.doPartialUpdate(path, this.paramGet(path), role); },

    autoControlsGrouped(acceptObj){
      const acc = acceptObj || this.activeAccept();
      const ranges=[], selects=[], toggles=[];
      const walk=(base, node)=>{
        if (!node || typeof node!=='object' || Array.isArray(node)) return;
        for (const k of Object.keys(node)){
          const child = node[k];
          const path = base ? `${base}.${k}` : k;

          if (this.autoSkipKeys.has(path)) continue;

          const cur = this.paramGet(path);
          if (typeof cur === 'undefined') {
            if (child && typeof child === 'object' && !Array.isArray(child)) walk(path, child);
            continue;
          }

          if (Array.isArray(child) && child.length){
            selects.push({ path, label:path, options:child.slice() });
            continue;
          }

          if (child && typeof child==='object' && ('min' in child) && ('max' in child)){
            ranges.push({ path, label:path, min:child.min, max:child.max, step:('step' in child)?child.step:1 });
            continue;
          }

          if (typeof cur === 'boolean'){
            const hasRange = child && typeof child==='object' && (('min' in child)||('max' in child));
            const hasList  = Array.isArray(child) && child.length;
            if (!hasRange && !hasList) {
              toggles.push({ path, label:path });
              continue;
            }
          }

          if (child && typeof child==='object' && !Array.isArray(child)) walk(path, child);
        }
      };
      walk('', acc);
      return { ranges, selects, toggles };
    },

    activeAccept(role){
      let node = null;
      if(role==='beacon') node = this.beacon;
      else if(role==='porthole') node = this.porthole;
      else if(role==='relay') node = this.relay;
      else node = this.activeNode();

      const base = this.acceptBase;
      if(node && node.src_id && this.acceptNode[node.src_id]){
        return this.mergeAccept(base, this.acceptNode[node.src_id]);
      }
      return base;
    },

    rangeGet(path, part, fallback){
      const v = this.pathGet(this.activeAccept('beacon'), path);
      if(v && typeof v==='object' && !Array.isArray(v) && part in v) return v[part];
      return fallback;
    },
    listGet(path, fallback){
      const v = this.pathGet(this.activeAccept('beacon'), path);
      if(Array.isArray(v) && v.length) return v;
      return fallback || [];
    },

    extractRoles(e,m){
      const r = (e && e.app && (e.app.r||e.app.roles)) || (e && e.hail && e.hail.roles) || (m && m.roles) || [];
      return Array.isArray(r) ? r.map(String) : [];
    },

    applyParams(obj){
      if(!obj || typeof obj!=='object') return;
      const deepMerge = (dst, src) => {
        for (const [k, v] of Object.entries(src)) {
          if (v && typeof v === 'object' && !Array.isArray(v)) {
            if (!dst[k] || typeof dst[k] !== 'object' || Array.isArray(dst[k])) dst[k] = {};
            deepMerge(dst[k], v);
          } else {
            dst[k] = v;
          }
        }
        return dst;
      };
      deepMerge(this.params, obj);
    },
    applyAcceptNode(sid, newAcc){
      const merged = this.mergeAccept(this.acceptNode[sid]||{}, newAcc||{});
      this.acceptNode = { ...this.acceptNode, [sid]: merged };
    },
    mergeAccept(dst, src){
      const out = JSON.parse(JSON.stringify(dst||{}));
      const rec = (o, s)=>{
        if(!s || typeof s!=='object') return o;
        for(const k of Object.keys(s)){
          const sv = s[k], dv = o[k];
          if(Array.isArray(sv)){ o[k] = sv.slice(); }
          else if(sv && typeof sv==='object'){
            if(!dv || typeof dv!=='object' || Array.isArray(dv)){ o[k] = {}; }
            rec(o[k], sv);
          } else {
            o[k] = sv;
          }
        }
        return o;
      };
      return rec(out, src);
    },

    // Scanner helpers (unchanged)
    wsHostIp(){
      try{ const u = new URL(this.wsUrl); return (u.hostname || '').trim(); }
      catch{ const m = String(this.wsUrl||'').match(/\/\/([^:/]+)/); return m? m[1] : ''; }
    },
    async scanSubnet(){
      const prefix = (this.scanPrefix||'').trim().replace(/\.$/,'');
      if(!/^\d+\.\d+\.\d+$/.test(prefix)){ this.log('err','Use prefix like 192.168.2'); return; }
      if(this.isScanning) return;

      this.isScanning = true; this.scanDone=false; this.scanFound = [];
      const base = Array.from({length:254}, (_,i)=>`${prefix}.${i+1}`);

      const uniq = (arr)=>Array.from(new Set(arr.filter(Boolean)));
      const prioritized = uniq([ this.wsHostIp(), `${prefix}.1`, `${prefix}.254` ]);
      const hosts = prioritized.concat(base.filter(ip => !prioritized.includes(ip)));

      this.scanned = 0; this.scanTotal = hosts.length; this.scanPercent = 0;

      const TIMEOUT_HTTP = 900;
      const CONCURRENCY = 48;

      const addFound = (url, note='health: ok')=>{
        if(!this.scanFound.find(x=>x.url===url)){
          this.scanFound.push({url, note});
          this.scanFound.sort((a,b)=>a.url.localeCompare(b.url));
        }
      };
      const bumpProgress = ()=>{
        this.scanned++;
        this.scanPercent = Math.min(100, Math.round(this.scanned / this.scanTotal * 100));
      };
      const healthProbe = async(host)=>{
        const ctrl = new AbortController();
        const to = setTimeout(()=>ctrl.abort(), TIMEOUT_HTTP);
        try{
          const r = await fetch(`http://${host}:8089/health`, {signal: ctrl.signal, cache:'no-store', mode:'cors'});
          clearTimeout(to);
          return !!(r && r.ok);
        }catch(_){ try{clearTimeout(to);}catch{}; return false; }
      };

      let cursor = 0;
      const worker = async ()=>{
        while(cursor < hosts.length){
          const i = cursor++;
          const host = hosts[i];
          const ok = await healthProbe(host);
          if(ok) addFound(`ws://${host}:8089/`);
          bumpProgress();
          await Promise.resolve();
        }
      };

      await Promise.all(Array.from({length:CONCURRENCY}, worker));

      this.isScanning=false; this.scanDone=true;
      if(!this.scanFound.length) this.log('info','No /health endpoints found.');
    },

    startSelfNodesPoll(){
      this.stopSelfNodesPoll();
      const tick = () => { try{ this.send({op:'nodes'}); }catch{} };
      tick();
      this.selfNodesTimer = setInterval(tick, 5000);
    },
    stopSelfNodesPoll(){
      if(this.selfNodesTimer){ clearInterval(this.selfNodesTimer); this.selfNodesTimer = null; }
    },
  }
}
