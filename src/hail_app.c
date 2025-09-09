#define _POSIX_C_SOURCE 200809L
// hail_app.c — application layer glue for Hail v1
// Actions: beam.cast / beam.update / beam.stop / beam.request
// Debug: set APP_DEBUG=1 to see verbose logs

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>   // strcasecmp
#include <ctype.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "hail.h"
#include "hail_app.h"

/* ---------------- tiny utils ---------------- */

static void trim_copy(const char* s, size_t n, char* out, size_t oz){
  if(!out||!oz) return;
  const char* p=s; const char* q=s+n;
  while(p<q && (*p==' '||*p=='\t'||*p=='\r'||*p=='\n')) p++;
  while(q>p && (q[-1]==' '||q[-1]=='\t'||q[-1]=='\r'||q[-1]=='\n')) q--;
  size_t m=(size_t)(q-p);
  if(m>=oz) m=oz-1;
  if(m) memcpy(out,p,m);
  out[m]=0;
}

static int file_exists(const char* path){ struct stat st; return (path && *path && stat(path,&st)==0); }

static int write_file(const char* path, const char* s){
  if(!path||!*path) return 0;
  FILE* f=fopen(path,"w"); if(!f) return -1;
  int rc = fputs(s,f) < 0 ? -1 : 0; fclose(f); return rc;
}

/* ---------------- recent-id ring for de-dupe ---------------- */

static int rt_seen_id(app_runtime_t* rt, const char* id){
  if(!rt || !id || !*id) return 0;
  for(int i=0;i<APP_RECENT_MAX;i++){
    if(rt->recent_ids[i][0] && strcmp(rt->recent_ids[i], id)==0) return 1;
  }
  return 0;
}
static void rt_note_id(app_runtime_t* rt, const char* id){
  if(!rt || !id || !*id) return;
  int p = rt->recent_pos % APP_RECENT_MAX;
  snprintf(rt->recent_ids[p], sizeof rt->recent_ids[p], "%s", id);
  rt->recent_pos = (p+1) % APP_RECENT_MAX;
}

/* ---------------- csv allow-list ---------------- */

static int csv_contains(const char* csv, const char* tok){
  if(!csv||!*csv) return 1; /* empty => allow all */
  size_t n=strlen(tok);
  const char* p=csv;
  while(*p){
    while(*p==' '||*p==',') p++;
    const char* q=p; while(*q && *q!=',') q++;
    if ((size_t)(q-p)==n && strncmp(p,tok,n)==0) return 1;
    p = (*q==',')? q+1 : q;
  }
  return 0;
}

/* ---------------- minimal JSON helpers (local, no external deps) -------- */

typedef struct {
  char id[64], kind[16], topic[24], action[24];
  /* whole message JSON kept for path lookups */
  char *json_dup;            /* owned copy */
  const char* data_json;     /* alias to json_dup */
} app_msg_t_local;

static int sfind_key(const char* j, const char* key, const char** val_out){
  char pat[64]; snprintf(pat,sizeof pat,"\"%s\"",key);
  const char* p=strstr(j,pat); if(!p) return 0;
  p=strchr(p+strlen(pat),':'); if(!p) return 0; p++;
  while(*p==' '||*p=='\t'||*p=='\r'||*p=='\n') p++;
  *val_out = p;
  return 1;
}

/* Extract "key":"value" */
static int jf_str_local(const char* j, const char* key, char* out, size_t outsz){
  const char* p; if(!sfind_key(j,key,&p) || *p!='"') return 0;
  p++; const char* q=p;
  while(*q && !(*q=='"' && q[-1] != '\\')) q++;
  if(*q!='"') return 0;
  size_t n=(size_t)(q-p); if(n>=outsz) n=outsz-1;
  memcpy(out,p,n); out[n]=0; return 1;
}

/* Extract integer/bool/null/number/string (unquoted) for path under data.<path>.
 * For strings, returns unquoted; for numbers/bools, returns raw.
 */
static int json_path_value(const char* json, const char* path, char* out, size_t outsz){
  if(!json||!path||!*path||!out||!outsz) return 0;

  char full[256];
  if (snprintf(full, sizeof full, "data.%s", path) >= (int)sizeof full) return 0;

  /* tokenize by '.' without strtok_r */
  const char* toks[16]; int nt=0;
  const char* s=full; const char* seg=s;
  while(*s && nt < (int)(sizeof toks/sizeof toks[0])){
    if(*s=='.'){ toks[nt++]=seg; seg=s+1; }
    s++;
  }
  if(seg && *seg) toks[nt++]=seg;
  if(nt==0) return 0;

  const char* cur = json;
  for(int i=0;i<nt;i++){
    char key[64]; size_t kn=0;
    const char* t=toks[i];
    while(t[kn] && t[kn]!='.') kn++;
    if(kn >= sizeof key) kn = sizeof key - 1;
    memcpy(key,t,kn); key[kn]=0;

    char pat[96]; int pn = snprintf(pat,sizeof pat,"\"%s\"",key);
    if(pn <= 0 || pn >= (int)sizeof pat) return 0;

    const char* k = strstr(cur, pat); if(!k) return 0;
    const char* colon = strchr(k + pn, ':'); if(!colon) return 0;
    const char* v = colon + 1;
    while(*v==' '||*v=='\t'||*v=='\r'||*v=='\n') v++;

    int last = (i==nt-1);
    if(!last){
      if(*v!='{') return 0;
      cur = v; continue;
    }

    if(*v=='"'){
      v++; const char* e=v;
      while(*e && !(*e=='"' && e[-1] != '\\')) e++;
      if(*e!='"') return 0;
      size_t n=(size_t)(e-v); if(n>=outsz) n=outsz-1; memcpy(out,v,n); out[n]=0; return 1;
    } else {
      const char* e=v;
      while(*e && *e!=',' && *e!='}' && *e!=']' && *e!='\n' && *e!='\r') e++;
      trim_copy(v,(size_t)(e-v),out,outsz);
      return out[0]?1:0;
    }
  }
  return 0;
}

/* Extract raw JSON value (keeps braces/quotes) for data.<path>, malloc'ed to *out_json.
 * We only need object for "params", but support string/number minimally.
 */
static int jf_any_copy_local(const char* json, const char* path, char** out_json){
  if(!json||!path||!out_json) return -1;
  *out_json=NULL;

  char full[256];
  if (snprintf(full, sizeof full, "data.%s", path) >= (int)sizeof full) return -1;

  /* find where "data" appears to narrow search */
  const char* p = strstr(json, "\"data\"");
  if(!p) p=json;

  /* Build a bounded key pattern: "\"<key>\"" where <key> is full+5 (skip "data.") */
  const char* key_in_data = full + 5;
  char pat[96];
  size_t maxk = sizeof(pat) - 3; /* room for two quotes and NUL */
  size_t klen = strlen(key_in_data);
  if(klen > maxk) klen = maxk;
  pat[0] = '"';
  memcpy(pat+1, key_in_data, klen);
  pat[1 + klen] = '"';
  pat[2 + klen] = 0;

  const char* k = strstr(p, pat); if(!k) return -1;
  const char* c = strchr(k + strlen(pat), ':'); if(!c) return -1;
  c++; while(*c==' '||*c=='\t'||*c=='\r'||*c=='\n') c++;

  /* if object or array: balance braces/brackets */
  if(*c=='{' || *c=='['){
    char open = *c, close = (*c=='{')?'}':']';
    int depth=0; const char* q=c;
    do{
      if(*q==open) depth++;
      else if(*q==close) depth--;
      else if(*q=='"' ){ q++; while(*q && !(*q=='"' && q[-1] != '\\')) q++; }
      q++;
    }while(*q && depth>0);
    if(depth!=0) return -1;
    size_t n=(size_t)(q - c);
    char* buf=(char*)malloc(n+1); if(!buf) return -1;
    memcpy(buf,c,n); buf[n]=0; *out_json=buf; return 0;
  }

  /* string */
  if(*c=='"'){
    const char* v=c; v++;
    const char* e=v; while(*e && !(*e=='"' && e[-1] != '\\')) e++;
    if(*e!='"') return -1;
    size_t n=(size_t)(e - c + 1);
    char* buf=(char*)malloc(n+1); if(!buf) return -1;
    memcpy(buf,c,n); buf[n]=0; *out_json=buf; return 0;
  }

  /* number/bool/null until comma/brace */
  const char* e=c;
  while(*e && *e!=',' && *e!='}' && *e!=']' && *e!='\n' && *e!='\r') e++;
  size_t n=(size_t)(e - c);
  char* buf=(char*)malloc(n+1); if(!buf) return -1;
  memcpy(buf,c,n); buf[n]=0; *out_json=buf; return 0;
}

/* ---------------- app message parse/free (local) ---------------- */

static int app_parse_message_local(const char* app_json, app_msg_t_local* m){
  if(!app_json||!m) return -1;
  memset(m,0,sizeof *m);
  m->json_dup = strdup(app_json);
  if(!m->json_dup) return -1;
  m->data_json = m->json_dup;

  /* copy a few fields (best-effort) */
  (void)jf_str_local(m->json_dup,"id",m->id,sizeof m->id);
  (void)jf_str_local(m->json_dup,"kind",m->kind,sizeof m->kind);
  (void)jf_str_local(m->json_dup,"topic",m->topic,sizeof m->topic);
  (void)jf_str_local(m->json_dup,"action",m->action,sizeof m->action);

  return 0;
}
static void app_free_message_local(app_msg_t_local* m){
  if(!m) return;
  if(m->json_dup){ free(m->json_dup); m->json_dup=NULL; }
  m->data_json=NULL;
}

/* ---------------- ACK builder ---------------- */

static void build_ack_json(char* out, size_t outsz,
                           const app_msg_t_local* in, const char* state, app_code_t code,
                           const char* detail){
  const char* code_str =
    (code==APP_OK)?"OK":(code==APP_NO_PATH)?"NO_PATH":(code==APP_TIMEOUT)?"TIMEOUT":
    (code==APP_BUSY)?"BUSY":(code==APP_DENIED)?"DENIED":(code==APP_BAD_ARGS)?"BAD_ARGS":"INTERNAL";
  int n = snprintf(out,outsz,
    "{\"v\":1,\"id\":\"%s\",\"kind\":\"ack\",\"topic\":\"%s\",\"action\":\"%s\","
    "\"data\":{\"state\":\"%s\",\"code\":\"%s\"",
    in->id[0]?in->id:"", in->topic, in->action, state, code_str);
  if(n<0 || (size_t)n>=outsz){ if(outsz) out[0]=0; return; }
  if (detail && *detail){
    n += snprintf(out+n, outsz-n, ",\"detail\":\"%s\"", detail);
  }
  snprintf(out+n, outsz-n, "}}");
}

/* ACK with JSON payload (for request) */
static void build_ack_json_with_payload(char* out, size_t outsz,
                                        const app_msg_t_local* in, const char* state, app_code_t code,
                                        const char* json_payload){
  const char* code_str =
    (code==APP_OK)?"OK":(code==APP_NO_PATH)?"NO_PATH":(code==APP_TIMEOUT)?"TIMEOUT":
    (code==APP_BUSY)?"BUSY":(code==APP_DENIED)?"DENIED":(code==APP_BAD_ARGS)?"BAD_ARGS":"INTERNAL";
  int n = snprintf(out,outsz,
    "{\"v\":1,\"id\":\"%s\",\"kind\":\"ack\",\"topic\":\"%s\",\"action\":\"%s\","
    "\"data\":{\"state\":\"%s\",\"code\":\"%s\"",
    in->id[0]?in->id:"", in->topic, in->action, state, code_str);
  if(n<0 || (size_t)n>=outsz){ if(outsz) out[0]=0; return; }
  if(json_payload && *json_payload){
    n += snprintf(out+n, outsz-n, ",\"params\":%s", json_payload);
  }
  snprintf(out+n, outsz-n, "}}");
}

/* ---------------- identity + dst filtering ---------------- */

static void app_get_self_alias(hail_ctx* h, char* out, size_t outsz){
  if(!out || outsz==0) return;
  out[0]=0;
  hail_node_t me; memset(&me,0,sizeof me);
  hail_self_node(h,&me);
  if(me.alias[0]) snprintf(out,outsz,"%s",me.alias);
}

/* local jf_str wrapper that uses our local JSON helper */
static int jf_str(const char* j, const char* key, char* out, size_t outsz){
  return jf_str_local(j,key,out,outsz);
}

static int app_is_my_dst(hail_ctx* h, const app_msg_t_local* m){
  char want_id[128]="", want_alias[128]="";
  (void)jf_str(m->data_json,"dst_id",want_id,sizeof want_id);
  (void)jf_str(m->data_json,"dst_alias",want_alias,sizeof want_alias);

  if(!want_id[0] && !want_alias[0]){
    char dsts[256]="";
    if(jf_str(m->data_json,"dst",dsts,sizeof dsts)){
      if(!strncmp(dsts,"alias:",6)){
        size_t len=strlen(dsts+6); if(len>=sizeof want_alias) len=sizeof want_alias - 1;
        memcpy(want_alias,dsts+6,len); want_alias[len]=0;
      }else if(!strncmp(dsts,"id:",3)){
        size_t len=strlen(dsts+3); if(len>=sizeof want_id) len=sizeof want_id - 1;
        memcpy(want_id,dsts+3,len); want_id[len]=0;
      }
    }
  }

  const char* my_id = hail_get_src_id(h);
  char my_alias[128]=""; app_get_self_alias(h,my_alias,sizeof my_alias);

  int id_ok = (!want_id[0])    || (my_id && strcmp(my_id,want_id)==0);
  int al_ok = (!want_alias[0]) || (my_alias[0] && strcmp(my_alias,want_alias)==0);
  return id_ok && al_ok;
}

/* ---------------- reusable: export nested JSON to env ---------------- */

static int jf_any_copy(const char* json, const char* path, char** out_json){
  return jf_any_copy_local(json,path,out_json);
}

static void app_export_env_json_subpath(const app_msg_t_local* msg,
                                        const char* subpath,
                                        const char* envname,
                                        const char* fallback_json /* e.g., "{}" */)
{
  if(!msg || !subpath || !*subpath || !envname || !*envname) return;

  char *raw = NULL;
  if (jf_any_copy(msg->data_json, subpath, &raw) == 0 && raw){
    /* Export as VALUE via setenv (copies value), then free raw */
    setenv(envname, raw, 1);
    free(raw);
  } else if (fallback_json){
    setenv(envname, fallback_json, 1);
  }
}

/* Extract a top-level field (object/array/string/number) from a raw JSON string.
+ * Similar to jf_any_copy_local, but operates on the given JSON directly (no "data." prefix).
+ * Returns 0 on success with *out_json malloc'ed, else -1.
+ */
static int top_level_copy_field(const char* json, const char* key, char** out_json){
  if(!json||!key||!out_json) return -1;
  *out_json=NULL;
  char pat[96];
  size_t klen=strlen(key);
  if(klen+2 >= sizeof pat) return -1;
  pat[0]='"'; memcpy(pat+1,key,klen); pat[1+klen]='"'; pat[2+klen]=0;

  const char* k = strstr(json, pat); if(!k) return -1;
  const char* c = strchr(k + strlen(pat), ':'); if(!c) return -1;
  c++; while(*c==' '||*c=='\t'||*c=='\r'||*c=='\n') c++;

  /* object/array */
  if(*c=='{' || *c=='['){
    char open=*c, close=(*c=='{')?'}':']';
    int depth=0; const char* q=c;
    do{
      if(*q==open) depth++;
      else if(*q==close) depth--;
      else if(*q=='"'){ q++; while(*q && !(*q=='"' && q[-1] != '\\')) q++; }
      q++;
    }while(*q && depth>0);
    if(depth!=0) return -1;
    size_t n=(size_t)(q-c);
    char* buf=(char*)malloc(n+1); if(!buf) return -1;
    memcpy(buf,c,n); buf[n]=0; *out_json=buf; return 0;
  }
  /* string */
  if(*c=='"'){
    const char* v=c+1; const char* e=v;
    while(*e && !(*e=='"' && e[-1] != '\\')) e++;
    if(*e!='"') return -1;
    size_t n=(size_t)(e - c + 1);
    char* buf=(char*)malloc(n+1); if(!buf) return -1;
    memcpy(buf,c,n); buf[n]=0; *out_json=buf; return 0;
  }
  /* number/bool/null */
  const char* e=c;
  while(*e && *e!=',' && *e!='}' && *e!=']' && *e!='\n' && *e!='\r') e++;
  size_t n=(size_t)(e-c);
  char* buf=(char*)malloc(n+1); if(!buf) return -1;
  memcpy(buf,c,n); buf[n]=0; *out_json=buf; return 0;
}




/* ---------------- JSON key resolver with back-compat ---------------- */

static int json_resolve_key(const char* data_json, const char* key, char* out, size_t outsz){
  if(!data_json || !key || !*key) return 0;

  /* 1) exact under data.<key> */
  if(json_path_value(data_json, key, out, outsz)) return 1;

  return 0;
}

/* ---------------- reusable: expand {placeholders} ---------------- */

static void expand_template_placeholders(char* out, size_t outsz,
                                         const char* tpl,
                                         const app_msg_t_local* msg,
                                         const char* to, const char* lane, const char* via)
{
  if(!out||!outsz){ return; }
  out[0]=0;
  if(!tpl || !*tpl){ return; }

  size_t o=0;
  const char* p=tpl;
  while(*p && o+8<outsz){
    if(*p=='{'){
      const char* end=strchr(p,'}');
      if(end){
        char key[128]; size_t kn=(size_t)(end-(p+1));
        if(kn>=sizeof key) kn=sizeof key-1;
        memcpy(key,p+1,kn); key[kn]=0;

        char val[256]; val[0]=0;
        if(!strcmp(key,"to"))   { if(to  && *to ) snprintf(val,sizeof val,"%s",to); }
        else if(!strcmp(key,"lane")) { if(lane&&*lane) snprintf(val,sizeof val,"%s",lane); }
        else if(!strcmp(key,"via"))  { if(via &&*via)  snprintf(val,sizeof val,"%s",via); }
        else {
          (void)json_resolve_key(msg->data_json, key, val, sizeof val);
        }

        if(val[0]) o += snprintf(out+o, outsz-o, "%s", val);
        p = end+1;
        continue;
      }
    }
    out[o++] = *p++;
  }
  out[o]=0;
}

/* ---------------- reusable: busy-file guard + system() ---------------- */

static int app_run_child_with_busy_guard(const app_modules_t* cfg, const char* cmdline){
  if(!cmdline||!*cmdline) return APP_BAD_ARGS;
  if (cfg->beacon_busy_file[0] && file_exists(cfg->beacon_busy_file)) return APP_BUSY;

  if(getenv("APP_DEBUG")){
    fprintf(stderr, "[APP-DEBUG] exec: %s\n", cmdline);
  }

  if (cfg->beacon_busy_file[0]) (void)write_file(cfg->beacon_busy_file,"1\n");
  int rc = system(cmdline);
  if (cfg->beacon_busy_file[0]) unlink(cfg->beacon_busy_file);

  return (rc==0)? APP_OK : APP_INTERNAL;
}

/* ---------------- reusable: popen capture for request ---------------- */

static int run_cmd_capture(const char* cmd, char* out, size_t outsz){
  if(!cmd||!*cmd||!out||!outsz) return -1;
  FILE* f = popen(cmd, "r");
  if(!f) return -1;
  size_t o=0;
  while(!feof(f) && o+1<outsz){
    int c=fgetc(f);
    if(c==EOF) break;
    out[o++]=(char)c;
  }
  out[o]=0;
  int st = pclose(f);
  return (st==0) ? 0 : -1;
}


/* ========================== RELAY handlers ========================== */

static int handle_relay_update(hail_ctx* h,
                               const hail_meta_t* meta,
                               const struct sockaddr_in* from,
                               const app_modules_t* cfg,
                               app_runtime_t* rt,
                               const app_msg_t_local* msg)
{
  (void)h; (void)meta; (void)from; (void)rt;
  if(!cfg->relay_exec_update[0]) return APP_NO_PATH;

  char lane[32]="Default", mode[32]="", ssid[64]="", psk[96]="", chan[16]="";
  (void)jf_str(msg->data_json,"lane",lane,sizeof lane);
  (void)jf_str(msg->data_json,"mode",mode,sizeof mode);         /* ap|sta|wfb-ng|… */
  (void)jf_str(msg->data_json,"ssid",ssid,sizeof ssid);
  (void)jf_str(msg->data_json,"psk",psk,sizeof psk);
  (void)jf_str(msg->data_json,"channel",chan,sizeof chan);

  if(lane[0] && !csv_contains(cfg->relay_allow_lanes, lane)) return APP_BAD_ARGS;

  if(lane[0]) setenv("HAIL_LANE", lane, 1);
  if(mode[0]) setenv("HAIL_MODE", mode, 1);
  if(ssid[0]) setenv("HAIL_SSID", ssid, 1);
  if(psk[0])  setenv("HAIL_PSK",  psk,  1);
  if(chan[0]) setenv("HAIL_CHANNEL", chan, 1);

  app_export_env_json_subpath(msg, "params", "HAIL_PARAMS", "{}");
  char* data_raw = NULL;
  if (top_level_copy_field(msg->data_json, "data", &data_raw) == 0 && data_raw){
    setenv("HAIL_DATA", data_raw, 1);
    free(data_raw);
  }

  char cmd[1024];
  expand_template_placeholders(cmd,sizeof cmd, cfg->relay_exec_update, msg, NULL, lane, NULL);
  return app_run_child_with_busy_guard(cfg, cmd);
}

static int handle_relay_start(hail_ctx* h,
                              const hail_meta_t* meta,
                              const struct sockaddr_in* from,
                              const app_modules_t* cfg,
                              app_runtime_t* rt,
                              const app_msg_t_local* msg)
{
  (void)h; (void)meta; (void)from; (void)rt;
  if(!cfg->relay_exec_start[0]) return APP_NO_PATH;

  char lane[32]="Default"; (void)jf_str(msg->data_json,"lane",lane,sizeof lane);
  if(lane[0] && !csv_contains(cfg->relay_allow_lanes, lane)) return APP_BAD_ARGS;
  if(lane[0]) setenv("HAIL_LANE", lane, 1);

  app_export_env_json_subpath(msg, "params", "HAIL_PARAMS", "{}");

  char cmd[1024];
  expand_template_placeholders(cmd,sizeof cmd, cfg->relay_exec_start, msg, NULL, lane, NULL);
  return app_run_child_with_busy_guard(cfg, cmd);
}

static int handle_relay_stop(hail_ctx* h,
                             const hail_meta_t* meta,
                             const struct sockaddr_in* from,
                             const app_modules_t* cfg,
                             app_runtime_t* rt,
                             const app_msg_t_local* msg)
{
  (void)h; (void)meta; (void)from; (void)rt;
  if(!cfg->relay_exec_stop[0]) return APP_NO_PATH;

  char lane[32]=""; (void)jf_str(msg->data_json,"lane",lane,sizeof lane);
  if(lane[0] && !csv_contains(cfg->relay_allow_lanes, lane)) return APP_BAD_ARGS;
  if(lane[0]) setenv("HAIL_LANE", lane, 1);

  char cmd[1024];
  expand_template_placeholders(cmd,sizeof cmd, cfg->relay_exec_stop, msg, NULL, lane, NULL);
  return app_run_child_with_busy_guard(cfg, cmd);
}

static int handle_relay_request(hail_ctx* h,
                                const hail_meta_t* meta,
                                const struct sockaddr_in* from,
                                const app_modules_t* cfg,
                                app_runtime_t* rt,
                                const app_msg_t_local* msg,
                                char* out, size_t outsz)
{
  (void)h; (void)meta; (void)from; (void)rt; (void)msg;
  if(!cfg->relay_exec_request[0]) return APP_NO_PATH;

  out[0]=0;
  if(run_cmd_capture(cfg->relay_exec_request, out, outsz)==0 && out[0]){
    return 0; /* success, caller wraps in ACK with payload */
  }
  return APP_INTERNAL;
}

/* ========================== PORTHOLE handlers ========================== */

static int handle_porthole_update(hail_ctx* h,
                                  const hail_meta_t* meta,
                                  const struct sockaddr_in* from,
                                  const app_modules_t* cfg,
                                  app_runtime_t* rt,
                                  const app_msg_t_local* msg)
{
  (void)h; (void)meta; (void)from; (void)rt;
  if(!cfg->porthole_exec_update[0]) return APP_NO_PATH;

  char listen[96]="", port[16]="", lane[32]="Default";
  (void)jf_str(msg->data_json,"listen",listen,sizeof listen);  /* e.g. 0.0.0.0 */
  (void)jf_str(msg->data_json,"port",  port,  sizeof port);    /* e.g. 5600   */
  (void)jf_str(msg->data_json,"lane",  lane,  sizeof lane);

  if(lane[0] && !csv_contains(cfg->porthole_allow_lanes, lane)) return APP_BAD_ARGS;

  if(listen[0]) setenv("HAIL_LISTEN", listen, 1);
  if(port[0])   setenv("HAIL_PORT",   port,   1);
  if(lane[0])   setenv("HAIL_LANE",   lane,   1);

  /* telemetry + other knobs ride in params{} */
  app_export_env_json_subpath(msg, "params", "HAIL_PARAMS", "{}");
  char* data_raw = NULL;
  if (top_level_copy_field(msg->data_json, "data", &data_raw) == 0 && data_raw){
    setenv("HAIL_DATA", data_raw, 1);
    free(data_raw);
  }

  char cmd[1024];
  expand_template_placeholders(cmd,sizeof cmd, cfg->porthole_exec_update, msg, NULL, lane, NULL);
  return app_run_child_with_busy_guard(cfg, cmd);
}

static int handle_porthole_stop(hail_ctx* h,
                                const hail_meta_t* meta,
                                const struct sockaddr_in* from,
                                const app_modules_t* cfg,
                                app_runtime_t* rt,
                                const app_msg_t_local* msg)
{
  (void)h; (void)meta; (void)from; (void)rt;
  if(!cfg->porthole_exec_stop[0]) return APP_NO_PATH;
  char cmd[1024];
  expand_template_placeholders(cmd,sizeof cmd, cfg->porthole_exec_stop, msg, NULL, NULL, NULL);
  return app_run_child_with_busy_guard(cfg, cmd);
}

static int handle_porthole_control(hail_ctx* h,
                                   const hail_meta_t* meta,
                                   const struct sockaddr_in* from,
                                   const app_modules_t* cfg,
                                   app_runtime_t* rt,
                                   const app_msg_t_local* msg)
{
  (void)h; (void)meta; (void)from; (void)rt;
  if(!cfg->porthole_exec_control[0]) return APP_NO_PATH;

  char cmdkey[64]="";  /* e.g. "record:start" or "restart" */
  (void)jf_str(msg->data_json,"cmd",cmdkey,sizeof cmdkey);
  if(cmdkey[0]) setenv("HAIL_CMD", cmdkey, 1);

  app_export_env_json_subpath(msg, "params", "HAIL_PARAMS", "{}");

  char cmd[1024];
  expand_template_placeholders(cmd,sizeof cmd, cfg->porthole_exec_control, msg, NULL, NULL, NULL);
  return app_run_child_with_busy_guard(cfg, cmd);
}

static int handle_porthole_request(hail_ctx* h,
                                   const hail_meta_t* meta,
                                   const struct sockaddr_in* from,
                                   const app_modules_t* cfg,
                                   app_runtime_t* rt,
                                   const app_msg_t_local* msg,
                                   char* out, size_t outsz)
{
  (void)h; (void)meta; (void)from; (void)rt; (void)msg;
  if(!cfg->porthole_exec_request[0]) return APP_NO_PATH;
  out[0]=0;
  if(run_cmd_capture(cfg->porthole_exec_request, out, outsz)==0 && out[0]){
    return 0;
  }
  return APP_INTERNAL;
}

/* ====================== CONSTELLATION (sync stub) ===================== */

static int handle_constellation_sync(hail_ctx* h,
                                     const hail_meta_t* meta,
                                     const struct sockaddr_in* from,
                                     const app_modules_t* cfg,
                                     app_runtime_t* rt,
                                     const app_msg_t_local* msg)
{
  (void)h; (void)meta; (void)from; (void)rt; (void)msg;
  if(!cfg->constellation_exec_sync[0]) return APP_NO_PATH;

  /* Expose entire data{} so the script can inspect members (beacons/portholes/lanes) */
  if(msg && msg->data_json && msg->data_json[0]) setenv("HAIL_DATA", msg->data_json, 1);

  char cmd[1024];
  expand_template_placeholders(cmd,sizeof cmd, cfg->constellation_exec_sync, msg, NULL, NULL, NULL);
  return app_run_child_with_busy_guard(cfg, cmd);
}







/* ========================== BEACON handlers ========================== */

static int handle_beacon_beam_cast(hail_ctx* h,
                                   const hail_meta_t* meta,
                                   const struct sockaddr_in* from,
                                   const app_modules_t* cfg,
                                   app_runtime_t* rt,
                                   const app_msg_t_local* msg)
{
  (void)h; (void)meta; (void)from; (void)rt;
  if(!cfg->beacon_exec_beam_cast[0]) return APP_NO_PATH;

  char to[96]="", via[64]="", lane[32]="Default";
  (void)jf_str(msg->data_json,"to",to,sizeof to);
  (void)jf_str(msg->data_json,"via",via,sizeof via);
  (void)jf_str(msg->data_json,"lane",lane,sizeof lane);

  if(!to[0]) return APP_BAD_ARGS;
  if(!csv_contains(cfg->beacon_allow_lanes, lane)) return APP_BAD_ARGS;

  /* Export env for child */
  if(to[0])   setenv("HAIL_TO",   to,   1);
  if(lane[0]) setenv("HAIL_LANE", lane, 1);
  if(via[0])  setenv("HAIL_VIA",  via,  1);

  app_export_env_json_subpath(msg, "params", "HAIL_PARAMS", "{}");
  /* Also export the full data{} so scripts can parse one JSON */
  char* data_raw = NULL;
  if (top_level_copy_field(msg->data_json, "data", &data_raw) == 0 && data_raw){
    setenv("HAIL_DATA", data_raw, 1);
    free(data_raw);
  }

  char cmd[1024];
  expand_template_placeholders(cmd,sizeof cmd, cfg->beacon_exec_beam_cast, msg, to, lane, via);

  return app_run_child_with_busy_guard(cfg, cmd);
}

static int handle_beacon_beam_update(hail_ctx* h,
                                     const hail_meta_t* meta,
                                     const struct sockaddr_in* from,
                                     const app_modules_t* cfg,
                                     app_runtime_t* rt,
                                     const app_msg_t_local* msg)
{
  (void)h; (void)meta; (void)from; (void)rt;
  if(!cfg->beacon_exec_beam_update[0]) return APP_NO_PATH;

  char to[96]="", via[64]="", lane[32]="Default";
  (void)jf_str(msg->data_json,"to",to,sizeof to);
  (void)jf_str(msg->data_json,"via",via,sizeof via);
  (void)jf_str(msg->data_json,"lane",lane,sizeof lane);

  if(to[0] && !csv_contains(cfg->beacon_allow_lanes, lane)) return APP_BAD_ARGS;

  /* Export env for child */
  if(to[0])   setenv("HAIL_TO",   to,   1);
  if(lane[0]) setenv("HAIL_LANE", lane, 1);
  if(via[0])  setenv("HAIL_VIA",  via,  1);

  app_export_env_json_subpath(msg, "params", "HAIL_PARAMS", "{}");
  /* Also export the full data{} so scripts can parse one JSON */
  char* data_raw = NULL;
  if (top_level_copy_field(msg->data_json, "data", &data_raw) == 0 && data_raw){
    setenv("HAIL_DATA", data_raw, 1);
    free(data_raw);
  }

  char cmd[1024];
  expand_template_placeholders(cmd,sizeof cmd, cfg->beacon_exec_beam_update, msg, to, lane, via);

  return app_run_child_with_busy_guard(cfg, cmd);
}

static int handle_beacon_beam_stop(hail_ctx* h,
                                   const hail_meta_t* meta,
                                   const struct sockaddr_in* from,
                                   const app_modules_t* cfg,
                                   app_runtime_t* rt,
                                   const app_msg_t_local* msg)
{
  (void)h; (void)meta; (void)rt; (void)from;
  if(!cfg->beacon_exec_beam_stop[0]) return APP_NO_PATH;

  char beam_id[64]="";
  (void)jf_str(msg->data_json,"beam_id",beam_id,sizeof beam_id);
  if(!beam_id[0]) return APP_BAD_ARGS;

  char cmd[1024]; cmd[0]=0;
  expand_template_placeholders(cmd,sizeof cmd, cfg->beacon_exec_beam_stop, msg, NULL, NULL, NULL);

  if(getenv("APP_DEBUG")){
    fprintf(stderr,"[APP-DEBUG] STOP beam_id=%s\n", beam_id);
  }

  return app_run_child_with_busy_guard(cfg, cmd);
}

/* Return JSON payload for current settings (request) */
static int handle_beacon_beam_request(hail_ctx* h,
                                      const hail_meta_t* meta,
                                      const struct sockaddr_in* from,
                                      const app_modules_t* cfg,
                                      app_runtime_t* rt,
                                      const app_msg_t_local* msg,
                                      char* json_out, size_t json_out_sz)
{
  (void)h; (void)meta; (void)from; (void)rt;
  if(!cfg->beacon_exec_beam_request[0]) return APP_NO_PATH;

  /* Only enhancement: pass optional data.mask to child as HAIL_MASK */
  if (msg && msg->data_json && msg->data_json[0]) {
    char *mask_raw = NULL;
    /* Try to grab any JSON value at top-level key "mask" (object/array/string/number) */
    if (top_level_copy_field(msg->data_json, "mask", &mask_raw) == 0 && mask_raw) {
      setenv("HAIL_MASK", mask_raw, 1);
      free(mask_raw);
    } else {
      /* Fallback: if it's a plain string, our small jf_str() can fetch it */
      char mask_str[256] = "";
      if (jf_str(msg->data_json, "mask", mask_str, sizeof mask_str)) {
        setenv("HAIL_MASK", mask_str, 1);
      } else {
        /* No mask provided — avoid leaking a stale value into the tool */
        unsetenv("HAIL_MASK");
      }
    }
  } else {
    unsetenv("HAIL_MASK");
  }

  if(getenv("APP_DEBUG")){
    fprintf(stderr,"[APP-DEBUG] REQUEST tool: %s\n", cfg->beacon_exec_beam_request);
  }

  json_out[0]=0;
  return run_cmd_capture(cfg->beacon_exec_beam_request, json_out, json_out_sz);
}

/* ---------------- dispatcher ---------------- */

int app_handle_rx(hail_ctx* h,
                  const hail_meta_t* meta,
                  const char* app_json, size_t app_len,
                  const struct sockaddr_in* from,
                  const app_modules_t* cfg,
                  app_runtime_t* rt)
{
  (void)app_len;
  if(!h || !app_json || !from || !cfg || !rt) return -1;

  app_msg_t_local m;
  if(app_parse_message_local(app_json,&m)!=0){ return 0; }  /* not ours / OOM */

  /* ---- de-dupe by app id (preferred) or hail msg_id (fallback) ---- */
  char dedupe_id[64]="";
  if(m.id[0]){
    snprintf(dedupe_id, sizeof dedupe_id, "%s", m.id);
  } else if(meta && meta->msg_id[0]){
    snprintf(dedupe_id, sizeof dedupe_id, "%s", meta->msg_id);
  }
  if(dedupe_id[0] && rt_seen_id(rt, dedupe_id)){
    if(getenv("APP_DEBUG")){
      fprintf(stderr, "[APP-DEBUG] duplicate cmd ignored id=%s\n", dedupe_id);
    }
    app_free_message_local(&m);
    return 0;
  }

  /* Only act on commands */
  if (strcmp(m.kind,"cmd")!=0){ app_free_message_local(&m); return 0; }

  /* Destination filtering */
  if (!app_is_my_dst(h, &m)) { app_free_message_local(&m); return 0; }

  if(getenv("APP_DEBUG")){
    char my_alias[64]=""; app_get_self_alias(h,my_alias,sizeof my_alias);
    char want_id[64]=""; jf_str(m.data_json,"dst_id",want_id,sizeof want_id);
    char want_alias[64]=""; jf_str(m.data_json,"dst_alias",want_alias,sizeof want_alias);
    fprintf(stderr,"[APP-DEBUG] my_id=%s my_alias=%s want_id=%s want_alias=%s\n",
      hail_get_src_id(h) ? hail_get_src_id(h) : "", my_alias, want_id, want_alias);
    fprintf(stderr,"[APP-DEBUG] role_check beacon => cfg:%d\n",
            (cfg && cfg->roles_csv[0] && csv_contains(cfg->roles_csv,"beacon")) ? 1 : 0);
  }

  int handled = 0;
  app_code_t code = APP_BAD_ARGS;
  const char* state = "error";

  /* === BEACON role (by config only) === */
  if (cfg && cfg->roles_csv[0] && csv_contains(cfg->roles_csv,"beacon")){

    if (!strcmp(m.topic,"beam") && !strcmp(m.action,"cast")){
      handled = 1; code = handle_beacon_beam_cast(h,meta,from,cfg,rt,&m);
      state = (code==APP_OK) ? "connected" : (code==APP_BUSY ? "busy" : (code==APP_NO_PATH ? "no_path" : "error"));

    } else if (!strcmp(m.topic,"beam") && !strcmp(m.action,"update")){
      handled = 1; code = handle_beacon_beam_update(h,meta,from,cfg,rt,&m);
      state = (code==APP_OK) ? "updated" : (code==APP_BUSY ? "busy" : (code==APP_NO_PATH ? "no_path" : "error"));

    } else if (!strcmp(m.topic,"beam") && !strcmp(m.action,"stop")){
      handled = 1; code = handle_beacon_beam_stop(h,meta,from,cfg,rt,&m);
      state = (code==APP_OK) ? "stopped" : (code==APP_BUSY ? "busy" : (code==APP_NO_PATH ? "no_path" : "error"));

    } else if (!strcmp(m.topic,"beam") && !strcmp(m.action,"request")){
      handled = 1;
      char jb[4096]; /* capture JSON from helper script */
      int rc = handle_beacon_beam_request(h,meta,from,cfg,rt,&m,jb,sizeof jb);
      code = (rc==0 && jb[0]) ? APP_OK : (rc==APP_NO_PATH ? APP_NO_PATH : APP_INTERNAL);
      state = (code==APP_OK) ? "ok" : (code==APP_NO_PATH ? "no_path" : "error");

      if(dedupe_id[0]) rt_note_id(rt, dedupe_id);

      char ip[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &from->sin_addr, ip, sizeof ip);

      if(code!=APP_OK){
        char ack[512];
        build_ack_json(ack,sizeof ack,&m,state,code,"");
        hail_send_unicast(h, ip, (uint16_t)ntohs(from->sin_port), "DATA", 0, 0, 0, ack);
        app_free_message_local(&m);
        return 1;
      }

      /* Split top-level {"params":{…}, "accept":{…}} if present.
         If not present, treat jb as the bare params object (legacy). */
      char *pjson=NULL, *ajson=NULL;
      int has_params = (top_level_copy_field(jb,"params",&pjson)==0 && pjson);
      int has_accept = (top_level_copy_field(jb,"accept",&ajson)==0 && ajson);

      char ack[4600]; int n=0;
      const char* code_str = "OK";
      n = snprintf(ack,sizeof ack,
                   "{\"v\":1,\"id\":\"%s\",\"kind\":\"ack\",\"topic\":\"%s\",\"action\":\"%s\","
                   "\"data\":{\"state\":\"%s\",\"code\":\"%s\"",
                   m.id[0]?m.id:"", m.topic, m.action, state, code_str);

      if(n<0 || (size_t)n>=sizeof ack){ if(pjson) free(pjson); if(ajson) free(ajson); app_free_message_local(&m); return 1; }

      if(has_params){
        n += snprintf(ack+n, sizeof ack - n, ",\"params\":%s", pjson);
      }else{
        /* legacy: whole jb is the params object */
        n += snprintf(ack+n, sizeof ack - n, ",\"params\":%s", jb);
      }
      if(has_accept){
        n += snprintf(ack+n, sizeof ack - n, ",\"accept\":%s", ajson);
      }
      snprintf(ack+n, sizeof ack - n, "}}");

      if(pjson) free(pjson);
      if(ajson) free(ajson);

      hail_send_unicast(h, ip, (uint16_t)ntohs(from->sin_port), "DATA", 0, 0, 0, ack);
      app_free_message_local(&m);
      return 1;
    }

  }

    /* === RELAY role === */
  if (cfg && cfg->roles_csv[0] && csv_contains(cfg->roles_csv,"relay")){
    if (!strcmp(m.topic,"relay") && !strcmp(m.action,"update")){
      handled = 1; code = handle_relay_update(h,meta,from,cfg,rt,&m);
      state = (code==APP_OK) ? "updated" : (code==APP_BUSY?"busy":(code==APP_NO_PATH?"no_path":"error"));

    } else if (!strcmp(m.topic,"relay") && !strcmp(m.action,"start")){
      handled = 1; code = handle_relay_start(h,meta,from,cfg,rt,&m);
      state = (code==APP_OK) ? "started" : (code==APP_BUSY?"busy":(code==APP_NO_PATH?"no_path":"error"));

    } else if (!strcmp(m.topic,"relay") && !strcmp(m.action,"stop")){
      handled = 1; code = handle_relay_stop(h,meta,from,cfg,rt,&m);
      state = (code==APP_OK) ? "stopped" : (code==APP_BUSY?"busy":(code==APP_NO_PATH?"no_path":"error"));

    } else if (!strcmp(m.topic,"relay") && !strcmp(m.action,"request")){
      handled = 1;
      char jb[4096];
      int rc = handle_relay_request(h,meta,from,cfg,rt,&m,jb,sizeof jb);
      code = (rc==0 && jb[0]) ? APP_OK : (rc==APP_NO_PATH ? APP_NO_PATH : APP_INTERNAL);
      state = (code==APP_OK) ? "ok" : (code==APP_NO_PATH ? "no_path" : "error");

      if(dedupe_id[0]) rt_note_id(rt, dedupe_id);
      char ack[4600];
      build_ack_json_with_payload(ack,sizeof ack,&m,state,code,(code==APP_OK)?jb:NULL);
      char ip[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &from->sin_addr, ip, sizeof ip);
      hail_send_unicast(h, ip, (uint16_t)ntohs(from->sin_port), "DATA", 0, 0, 0, ack);
      app_free_message_local(&m);
      return 1;
    }
  }

  /* === PORTHOLE role === */
  if (cfg && cfg->roles_csv[0] && csv_contains(cfg->roles_csv,"porthole")){
    if (!strcmp(m.topic,"porthole") && !strcmp(m.action,"update")){
      handled = 1; code = handle_porthole_update(h,meta,from,cfg,rt,&m);
      state = (code==APP_OK) ? "updated" : (code==APP_BUSY?"busy":(code==APP_NO_PATH?"no_path":"error"));

    } else if (!strcmp(m.topic,"porthole") && !strcmp(m.action,"stop")){
      handled = 1; code = handle_porthole_stop(h,meta,from,cfg,rt,&m);
      state = (code==APP_OK) ? "stopped" : (code==APP_BUSY?"busy":(code==APP_NO_PATH?"no_path":"error"));

    } else if (!strcmp(m.topic,"porthole") && !strcmp(m.action,"control")){
      handled = 1; code = handle_porthole_control(h,meta,from,cfg,rt,&m);
      state = (code==APP_OK) ? "ok" : (code==APP_BUSY?"busy":(code==APP_NO_PATH?"no_path":"error"));

    } else if (!strcmp(m.topic,"porthole") && !strcmp(m.action,"request")){
      handled = 1;
      char jb[4096];
      int rc = handle_porthole_request(h,meta,from,cfg,rt,&m,jb,sizeof jb);
      code = (rc==0 && jb[0]) ? APP_OK : (rc==APP_NO_PATH ? APP_NO_PATH : APP_INTERNAL);
      state = (code==APP_OK) ? "ok" : (code==APP_NO_PATH ? "no_path" : "error");

      if(dedupe_id[0]) rt_note_id(rt, dedupe_id);
      char ack[4600];
      build_ack_json_with_payload(ack,sizeof ack,&m,state,code,(code==APP_OK)?jb:NULL);
      char ip[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &from->sin_addr, ip, sizeof ip);
      hail_send_unicast(h, ip, (uint16_t)ntohs(from->sin_port), "DATA", 0, 0, 0, ack);
      app_free_message_local(&m);
      return 1;
    }
  }

  /* === CONSTELLATION (sync) === */
  if (!strcmp(m.topic,"constellation") && !strcmp(m.action,"sync")){
    handled = 1; code = handle_constellation_sync(h,meta,from,cfg,rt,&m);
    state = (code==APP_OK) ? "ok" : (code==APP_NO_PATH ? "no_path" : "error");
  }





  if (handled){
    if(dedupe_id[0]) rt_note_id(rt, dedupe_id);
    if(getenv("APP_DEBUG")){
      fprintf(stderr, "[APP] handled cmd topic=%s action=%s -> state=%s code=%d\n",
              m.topic, m.action, state, code);
    }

    char ack[512];
    build_ack_json(ack,sizeof ack,&m,state,code,"");
    char ip[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &from->sin_addr, ip, sizeof ip);
    hail_send_unicast(h, ip, (uint16_t)ntohs(from->sin_port), "DATA", 0, 0, 0, ack);
    app_free_message_local(&m);
    return 1;
  }

  app_free_message_local(&m);
  return 0;
}
