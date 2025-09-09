// waybeam_core.c — line-oriented Waybeam Core for Hail v1 (no ncurses)
// Build: gcc -O2 -Wall -Wextra -std=c11 waybeam_core.c -L. -lhail -lpthread -o waybeam_core

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <errno.h>
#include <string.h>
#include "hail_ws.h"
#include "hail.h"
#include "hail_app.h"

#if defined(_WIN32)
  #include <string.h>   // _strnicmp
  #define strncasecmp _strnicmp
#else
  #include <strings.h>  // strncasecmp (POSIX)
#endif

static app_modules_t g_mods;     /* loaded from config -> app layer */
static app_runtime_t g_rt = { .state = ST_INIT };

static ws_server* g_ws = NULL;
static int g_verbose_rx = 0;     /* demo verbose flag (can be set from config or REPL) */
static int g_debug = 0;          /* NEW: --debug gates LOGF() and REPL */

/* --- portable strdup --- */
static char* xstrdup(const char* s){
    if(!s) return NULL;
    size_t n=strlen(s)+1;
    char* p=(char*)malloc(n);
    if(!p) return NULL;
    memcpy(p,s,n);
    return p;
}

/* ---------- logging to stderr ----------
   LOGF now respects --debug (quiet unless enabled).
   Use fprintf(stderr,...) directly for startup/bind/id summaries. */
#define LOGF(...) do { if (g_debug) { fprintf(stderr, __VA_ARGS__); fflush(stderr); } } while(0)

/* --- small string helpers for config parsing --- */
static void trim_inplace(char *s){
    if(!s) return;
    char *p=s, *q=s + strlen(s);
    while(p<q && (*p==' '||*p=='\t'||*p=='\r'||*p=='\n')) p++;
    while(q>p && (q[-1]==' '||q[-1]=='\t'||q[-1]=='\r'||q[-1]=='\n')) q--;
    size_t n = (size_t)(q-p);
    if(p!=s) memmove(s,p,n);
    s[n]=0;
}

static void strip_inline_comment(char *s){
    int in_str = 0, esc = 0;
    for(char *p=s; *p; ++p){
        char c = *p;
        if(esc){ esc=0; continue; }
        if(c=='\\'){ esc=1; continue; }
        if(c=='\"'){ in_str = !in_str; continue; }
        if(!in_str && (c=='#' || c==';')){ *p=0; break; }
    }
    trim_inplace(s);
}

static void unquote_inplace(char *s){
    size_t n = strlen(s);
    if(n>=2 && s[0]=='\"' && s[n-1]=='\"'){
        memmove(s, s+1, n-2);
        s[n-2]=0;
    }
    trim_inplace(s);
}

static void cmd_print_last_hail(hail_ctx *h){
    char hb[1600];
    int n = hail_last_hail(h, hb, sizeof hb);
    if (n > 0) {
        LOGF("Last hail{} slice (%d bytes):\n%.*s\n", n, n, hb);
    } else {
        LOGF("No last hail{} stored yet.\n");
    }
}

static void cmd_print_last_json(hail_ctx *h){
    char jb[2000];
    int n = hail_last_json(h, jb, sizeof jb);
    if (n > 0) {
        LOGF("Last full JSON (%d bytes):\n%.*s\n", n, n, jb);
    } else {
        LOGF("No last JSON stored yet.\n");
    }
}

/* ---------- tiny CSV splitter ---------- */
static size_t split_csv(char *s, char *out[], size_t max){
    size_t n=0; char *p=s;
    while(*p && n<max){
        while(*p==' '||*p==',') p++;
        if(!*p) break;
        out[n++]=p;
        while(*p && *p!=',') p++;
        if(*p){ *p=0; p++; }
    }
    return n;
}

/* ---------- simple config ---------- */
typedef struct {
    char     bind_ip[64];
    uint16_t bind_port;
    char     src_id[64];
    char     roles[256];
    char     caps[256];
    int      pref_unicast;      /* -1 = unset */
    int      max_app_bytes;     /* -1 = unset */
    int      relay_ok;          /* -1 = unset */
    int      require_signing;   /* 0/1 */
    char     psk_hex[128];      /* even-length hex string */
    int      beacon_interval_ms;/* -1 = unset */
    int      expiry_seconds;    /* -1 = unset */
    char     announce_json[512];
    int      verbose_rx;        /* 0/1, demo-only */
    char     declared_ip[64];
    char     node_id_file[128];
    char     alias[64];

    /* WS bridge */
    int      ws_enable;         /* 0/1 */
    char     ws_listen[64];
    uint16_t ws_port;

    /* Beacon app exec hooks */
    char     beacon_exec_beam_cast[256];
    char     beacon_exec_beam_update[256];   /* NEW */
    char     beacon_exec_beam_request[256];  /* NEW */
    char     beacon_exec_beam_stop[256];
    char     beacon_allow_lanes[128];
    char     beacon_busy_file[128];

    /* Relay */
    char     relay_exec_update[256];
    char     relay_exec_start[256];
    char     relay_exec_stop[256];
    char     relay_exec_request[256];
    char     relay_allow_lanes[128];

    /* Porthole */
    char     porthole_exec_update[256];
    char     porthole_exec_stop[256];
    char     porthole_exec_control[256];
    char     porthole_exec_request[256];
    char     porthole_allow_lanes[128];

    /* Constellation */
    char     constellation_exec_sync[256];

} demo_cfg_t;

static void cfg_default(demo_cfg_t *c){
    memset(c,0,sizeof *c);
    strcpy(c->bind_ip, "0.0.0.0");
    c->bind_port = 0;
    c->pref_unicast = -1;
    c->max_app_bytes = -1;
    c->relay_ok = -1;
    c->require_signing = 0;
    c->beacon_interval_ms = -1;
    c->expiry_seconds = -1;
    c->verbose_rx = 0;  /* default OFF */
    c->announce_json[0] = 0;
    c->declared_ip[0] = 0;
    c->node_id_file[0] = 0;     /* use library default unless set */
    c->alias[0] = 0;

    /* WS */
    c->ws_enable = 0;           /* default OFF */
    snprintf(c->ws_listen,sizeof c->ws_listen,"0.0.0.0");
    c->ws_port = 8089;

    /* beacon app */
    c->beacon_exec_beam_cast[0]=0;
    c->beacon_exec_beam_update[0]=0;   /* NEW */
    c->beacon_exec_beam_request[0]=0;  /* NEW */
    c->beacon_exec_beam_stop[0]=0;
    //snprintf(c->beacon_allow_lanes, sizeof c->beacon_allow_lanes, "udp");
    //snprintf(c->beacon_busy_file, sizeof c->beacon_busy_file, "/tmp/beacon_busy");

    c->relay_exec_update[0] = 0;
    c->relay_exec_start[0]  = 0;
    c->relay_exec_stop[0]   = 0;
    c->relay_exec_request[0]= 0;
    c->relay_allow_lanes[0] = 0;  /* empty => no lane restriction */

    c->porthole_exec_update[0]  = 0;
    c->porthole_exec_stop[0]    = 0;
    c->porthole_exec_control[0] = 0;
    c->porthole_exec_request[0] = 0;
    c->porthole_allow_lanes[0]  = 0;

    c->constellation_exec_sync[0] = 0;


}

static void on_exit(void){ if (g_ws) { ws_stop(g_ws); g_ws=NULL; } }

/* very small JSON "string value" fetcher: finds "key":"value" and copies value */
static int jf_str(const char* j, const char* key, char* out, size_t outsz){
    char pat[64];
    const char *p,*q;
    size_t n;
    if(!j||!key||!out||!outsz) return 0;
    snprintf(pat,sizeof pat,"\"%s\"",key);
    p = strstr(j,pat);
    if(!p) return 0;
    p = strchr(p+strlen(pat),':');
    if(!p) return 0;
    p++;
    while(*p==' '||*p=='\t') p++;
    if(*p!='"') return 0;
    p++;
    q=p;
    while(*q && !(*q=='\"' && q[-1] != '\\')) q++;
    if(*q!='"') return 0;
    n=(size_t)(q-p);
    if(n>=outsz) n=outsz-1;
    memcpy(out,p,n);
    out[n]=0;
    return 1;
}

/* Flexible hex parser. */
static int hex2bin(const char *hex, unsigned char *out, size_t *outlen){
    size_t w = 0;
    int have_hi = 0;      /* 0 = expecting high nibble, 1 = have high nibble */
    unsigned hi = 0;

    for (const char *p = hex; *p; ++p){
        unsigned char c = (unsigned char)*p;

        /* Skip separators and whitespace */
        if (c==' ' || c=='\t' || c=='\n' || c=='\r' ||
            c==',' || c==':'  || c=='_'  || c=='-')
            continue;

        /* Tolerate 0x / 0X prefixes anywhere */
        if ((c=='x' || c=='X') && p>hex && (p[-1]=='0')) continue;

        unsigned v;
        if (c>='0' && c<='9') v = (unsigned)(c - '0');
        else if (c>='a' && c<='f') v = (unsigned)(c - 'a' + 10);
        else if (c>='A' && c<='F') v = (unsigned)(c - 'A' + 10);
        else return -1; /* not hex, not a separator */

        if (!have_hi){
            hi = v;
            have_hi = 1;
        } else {
            if (w >= *outlen) return -1; /* no room */
            out[w++] = (unsigned char)((hi << 4) | v);
            have_hi = 0;
        }
    }

    if (have_hi) return -1;      /* odd number of hex nibbles */
    *outlen = w;
    return (w > 0) ? 0 : -1;     /* require at least one byte */
}

static void cfg_load_file(demo_cfg_t *c, const char *path){
    FILE *f=fopen(path,"r");
    if(!f){ fprintf(stderr,"[CFG] cannot open %s: %s\n", path, strerror(errno)); return; }

    char line[1024];
    while(fgets(line,sizeof line,f)){
        /* strip CRLF and leading/trailing WS early */
        trim_inplace(line);
        if(!line[0] || line[0]=='#' || line[0]==';') continue;

        /* key=value */
        char *eq = strchr(line,'=');
        if(!eq) continue;
        *eq = 0;
        char *k = line;
        char *v = eq+1;

        trim_inplace(k);
        strip_inline_comment(v);   /* removes trailing #... or ;... unless quoted */
        unquote_inplace(v);        /* remove optional surrounding quotes */

        if(!*k) continue;

        #define ISK(s) (!strcmp(k,(s)))
        if(ISK("bind_ip"))              snprintf(c->bind_ip,sizeof c->bind_ip,"%s",v);
        else if(ISK("bind_port"))       c->bind_port   = (uint16_t)atoi(v);
        else if(ISK("src_id"))          snprintf(c->src_id,sizeof c->src_id,"%s",v);
        else if(ISK("roles"))           snprintf(c->roles,sizeof c->roles,"%s",v);
        else if(ISK("caps"))            snprintf(c->caps,sizeof c->caps,"%s",v);
        else if(ISK("pref_unicast"))    c->pref_unicast = atoi(v);
        else if(ISK("max_app_bytes"))   c->max_app_bytes= atoi(v);
        else if(ISK("relay_ok"))        c->relay_ok     = atoi(v);
        else if(ISK("require_signing")) c->require_signing= atoi(v);
        else if(ISK("psk_hex"))         snprintf(c->psk_hex,sizeof c->psk_hex,"%s",v);
        else if(ISK("beacon_interval_ms")) c->beacon_interval_ms= atoi(v);
        else if(ISK("expiry_seconds"))  c->expiry_seconds= atoi(v);
        else if(ISK("announce_json"))   snprintf(c->announce_json,sizeof c->announce_json,"%s",v);
        else if(ISK("verbose_rx"))      c->verbose_rx   = atoi(v);
        else if(ISK("declared_ip"))     snprintf(c->declared_ip, sizeof c->declared_ip, "%s", v);
        else if(ISK("node_id_file"))    snprintf(c->node_id_file, sizeof c->node_id_file, "%s", v);
        else if(ISK("alias"))           snprintf(c->alias, sizeof c->alias, "%s", v);

        /* WS bridge keys */
        else if(ISK("ws_enable"))       c->ws_enable = atoi(v);
        else if(ISK("ws_listen"))       snprintf(c->ws_listen,sizeof c->ws_listen,"%s",v);
        else if(ISK("ws_port"))         c->ws_port   = (uint16_t)atoi(v);

        /* Relay */
        else if(ISK("relay.exec.update"))  snprintf(c->relay_exec_update,  sizeof c->relay_exec_update,  "%s", v);
        else if(ISK("relay.exec.start"))   snprintf(c->relay_exec_start,   sizeof c->relay_exec_start,   "%s", v);
        else if(ISK("relay.exec.stop"))    snprintf(c->relay_exec_stop,    sizeof c->relay_exec_stop,    "%s", v);
        else if(ISK("relay.exec.request")) snprintf(c->relay_exec_request, sizeof c->relay_exec_request, "%s", v);
        else if(ISK("relay.lanes"))        snprintf(c->relay_allow_lanes,  sizeof c->relay_allow_lanes,  "%s", v);

        /* Porthole */
        else if(ISK("porthole.exec.update"))  snprintf(c->porthole_exec_update,  sizeof c->porthole_exec_update,  "%s", v);
        else if(ISK("porthole.exec.stop"))    snprintf(c->porthole_exec_stop,    sizeof c->porthole_exec_stop,    "%s", v);
        else if(ISK("porthole.exec.control")) snprintf(c->porthole_exec_control, sizeof c->porthole_exec_control, "%s", v);
        else if(ISK("porthole.exec.request")) snprintf(c->porthole_exec_request, sizeof c->porthole_exec_request, "%s", v);
        else if(ISK("porthole.lanes"))        snprintf(c->porthole_allow_lanes,  sizeof c->porthole_allow_lanes,  "%s", v);

        /* Constellation */
        else if(ISK("constellation.exec.sync")) snprintf(c->constellation_exec_sync, sizeof c->constellation_exec_sync, "%s", v);



        /* beacon exec hooks */
        else if(ISK("beacon.exec.beam.cast"))    snprintf(c->beacon_exec_beam_cast,   sizeof c->beacon_exec_beam_cast,   "%s",v);
        else if(ISK("beacon.exec.beam.update"))  snprintf(c->beacon_exec_beam_update, sizeof c->beacon_exec_beam_update, "%s",v);   /* NEW */
        else if(ISK("beacon.exec.beam.request")) snprintf(c->beacon_exec_beam_request,sizeof c->beacon_exec_beam_request,"%s",v);   /* NEW */
        else if(ISK("beacon.exec.beam.stop"))    snprintf(c->beacon_exec_beam_stop,   sizeof c->beacon_exec_beam_stop,   "%s",v);
        else if(ISK("beacon.lanes"))             snprintf(c->beacon_allow_lanes,      sizeof c->beacon_allow_lanes,      "%s",v);
        else if(ISK("beacon.busy_file"))         snprintf(c->beacon_busy_file,        sizeof c->beacon_busy_file,        "%s",v);
        #undef ISK
    }
    fclose(f);
}

/* ---------- escape for log ---------- */
static void escape_bytes_for_log(const char* s, size_t n, char* out, size_t outsz, size_t maxshow){
    if (!outsz) return;
    size_t o = 0, shown = 0;
    for (size_t i=0; i<n && shown<maxshow && o+4 < outsz; ++i){
        unsigned char c = (unsigned char)s[i];
        if (c >= 32 && c <= 126 && c != '\\') {
            out[o++] = (char)c;
        } else if (c == '\\') {
            if (o+2 >= outsz) break;
            out[o++]='\\'; out[o++]='\\';
        } else {
            if (o+4 >= outsz) break;
            static const char H[]="0123456789ABCDEF";
            out[o++]='\\'; out[o++]='x';
            out[o++]=H[(c>>4)&0xF]; out[o++]=H[c&0xF];
        }
        shown++;
    }
    if (shown < n && o+3 < outsz){ out[o++]='.'; out[o++]='.'; out[o++]='.'; }
    out[o]=0;
}


/* ---------- minimal JSON helpers used only for pretty dump ---------- */
static const char* json_find_key(const char* j, const char* key){
    char pat[64]; snprintf(pat,sizeof pat,"\"%s\"",key);
    const char* p=strstr(j,pat); if(!p) return NULL;
    p=strchr(p+strlen(pat),':'); if(!p) return NULL;
    p++; while(*p==' '||*p=='\t') p++;
    return p;
}
static int json_get_str(const char* j, const char* key, char* out, size_t outlen){
    const char* p=json_find_key(j,key); if(!p || *p!='\"') return -1;
    p++; const char* q=p; while(*q && *q!='\"') q++;
    if(*q!='\"') return -1;
    size_t n=(size_t)(q-p); if(n>=outlen) n=outlen-1;
    memcpy(out,p,n); out[n]=0; return 0;
}
static int json_get_int64(const char* j, const char* key, long long* out){
    const char* p=json_find_key(j,key);
    if(!p) return -1;
    char* e=NULL;
    long long v=strtoll(p,&e,10);
    if(e==p) return -1;
    *out=v;
    return 0;
}
static int json_get_bool01(const char* j, const char* key, int* out){
    const char* p=json_find_key(j,key); if(!p) return -1;
    if(!strncmp(p,"true",4)){ *out=1; return 0; }
    if(!strncmp(p,"false",5)){ *out=0; return 0; }
    long long v; if(json_get_int64(j,key,&v)==0){ *out=(int)(v!=0); return 0; }
    return -1;
}
static int json_find_array_slice(const char* j, const char* key, const char** beg, size_t* len){
    const char* p=json_find_key(j,key); if(!p || *p!='[') return -1;
    int d=0; const char* q=p;
    do{ if(*q=='[') d++; else if(*q==']') d--; q++; }while(*q && d>0);
    if(d!=0) return -1;
    *beg=p; *len=(size_t)(q-p); return 0;
}
static void json_array_to_csv(const char* arr, size_t len, char* out, size_t outsz){
    size_t o=0; int in_str=0; int first=1;
    for(size_t i=0;i<len && o+2<outsz;i++){
        char c=arr[i];
        if(c=='\"'){ in_str=!in_str; continue; }
        if(in_str){
            if(c=='\\' && i+1<len){ i++; c=arr[i]; }
            out[o++]=c;
        } else if (c==',' && !first){
            out[o++]=','; out[o++]=' ';
        } else if (c=='[' || c==']' || c==' '){
        } else {
            if(!first){ out[o++]=','; out[o++]=' '; }
            while(i<len && arr[i]!=',' && arr[i]!=']'){ if(o+1<outsz) out[o++]=arr[i]; i++; }
            i--;
        }
        first=0;
    }
    out[o]=0;
}

/* ---------- nodes table printer ---------- */
static void print_nodes(hail_ctx *h){
    size_t need = hail_nodes_snapshot_with_self(h, NULL, 0, 0);
    hail_node_t *arr = (hail_node_t*)calloc(need?need:1, sizeof *arr);
    size_t got = hail_nodes_snapshot_with_self(h, arr, need, 0);
    printf("Nodes (%zu):\n", got);
    for(size_t i=0;i<got;i++){
        char ip[INET_ADDRSTRLEN]; snprintf(ip,sizeof ip,"%s", inet_ntoa(arr[i].ip));
        printf("  - %s @ %s:%u active=%d signed=%d hop=%d pref_uni=%d max_app=%d relay_ok=%d%s%s\n",
            arr[i].src_id, ip, arr[i].port, arr[i].active, arr[i].signed_ok,
            arr[i].last_hop, arr[i].pref_unicast, arr[i].max_app_bytes, arr[i].relay_ok,
            arr[i].alias[0] ? " alias=" : "", arr[i].alias[0] ? arr[i].alias : "");
    }
    free(arr);
}

/* Pretty dump of hail{} properties (using the stashed last_hail + last_app) */
static void dump_hail_props(hail_ctx *ctx, const struct sockaddr_in* from, const char* rx_type){
    char hail_buf[1400]; int hl = hail_last_hail(ctx, hail_buf, sizeof hail_buf);
    char app_buf [1400]; int al = hail_last_app (ctx, app_buf , sizeof app_buf );
    if(hl<=0){ return; }

    char msg_id[64]="", correl[64]="", src_id[64]="", ip_decl[64]="", nonce[96]="", alias[64]="";
    long long ts=0, hop=0, ttl=0, max_app=-1, exp_in=-1;
    int pref_uni=-1, relay_ok=-1, ack=0;

    (void)json_get_str(hail_buf,"msg_id",msg_id,sizeof msg_id);
    (void)json_get_str(hail_buf,"correl_id",correl,sizeof correl);
    (void)json_get_str(hail_buf,"src_id",src_id,sizeof src_id);
    (void)json_get_str(hail_buf,"ip",ip_decl,sizeof ip_decl);
    (void)json_get_str(hail_buf,"nonce",nonce,sizeof nonce);
    (void)json_get_str(hail_buf,"alias",alias,sizeof alias);

    json_get_int64(hail_buf,"ts",&ts);
    json_get_int64(hail_buf,"hop",&hop);
    json_get_int64(hail_buf,"ttl",&ttl);

    { int v; if(json_get_bool01(hail_buf,"pref_unicast",&v)==0) pref_uni=v; }
    json_get_int64(hail_buf,"max_app_bytes",&max_app);
    json_get_int64(hail_buf,"expires_in",&exp_in);
    { int v; if(json_get_bool01(hail_buf,"relay_ok",&v)==0) relay_ok=v; }
    { int v; if(json_get_bool01(hail_buf,"ack",&v)==0) ack=v; }

    const char *roles=NULL,*caps=NULL; size_t rlen=0,clen=0;
    json_find_array_slice(hail_buf,"roles",&roles,&rlen);
    json_find_array_slice(hail_buf,"caps",&caps,&clen);

    char roles_csv[256]="", caps_csv[256]="";
    if(roles) json_array_to_csv(roles,rlen,roles_csv,sizeof roles_csv);
    if(caps)  json_array_to_csv(caps,clen,caps_csv,sizeof caps_csv);

    char ts_h[64]="";
    if(ts>0){
        time_t t=(time_t)ts; struct tm *pt=localtime(&t);
        if(pt){ struct tm tmv=*pt; strftime(ts_h,sizeof ts_h,"%Y-%m-%d %H:%M:%S",&tmv); }
    }
    long long skew = 0; if(ts>0){ time_t now=time(NULL); skew = (long long)now - ts; }

    char app_esc[512];
    escape_bytes_for_log(app_buf, (al>0?al:(int)strlen(app_buf)), app_esc, sizeof app_esc, 256);

    LOGF("\n=== RX %s DETAIL ===\n", rx_type);
    LOGF("From           : %s:%u (declared ip: %s)\n",
         inet_ntoa(from->sin_addr), ntohs(from->sin_port), ip_decl[0]?ip_decl:"(none)");
    LOGF("IDs            : msg_id=%s  correl_id=%s  src_id=%s\n",
         msg_id[0]?msg_id:"(none)", correl[0]?correl:"(none)", src_id[0]?src_id:"(none)");
    if(alias[0]) LOGF("Alias          : %s\n", alias);
    LOGF("Route          : hop=%lld  ttl=%lld\n", hop, ttl);
    LOGF("Time           : ts=%lld (%s)  skew=%+llds\n", ts, ts_h[0]?ts_h:"n/a", skew);
    LOGF("Advertised     : pref_unicast=%s  max_app_bytes=%lld  expires_in=%lld  relay_ok=%s  ack=%s\n",
         (pref_uni<0?"(n/a)":(pref_uni?"true":"false")),
         max_app, exp_in,
         (relay_ok<0?"(n/a)":(relay_ok?"true":"false")),
         ack?"1":"0");
    if(roles) LOGF("Roles          : %s\n", roles_csv[0]?roles_csv:"(empty)"); else LOGF("Roles          : (absent)\n");
    if(caps)  LOGF("Caps           : %s\n",  caps_csv[0]?caps_csv:"(empty)"); else LOGF("Caps           : (absent)\n");
    if(nonce[0]) LOGF("Nonce          : %s\n", nonce); else LOGF("Nonce          : (absent)\n");
    LOGF("App            : %s\n", app_esc);
    LOGF("========================\n");
}

/* ---------- hail callbacks ---------- */
static void on_msg(hail_ctx *ctx, const hail_meta_t *m,
                   const char *appjson, size_t alen,
                   const struct sockaddr_in *from)
{
    char ipbuf[INET_ADDRSTRLEN];
    struct in_addr a; a.s_addr = m->src_ip;
    snprintf(ipbuf,sizeof ipbuf,"%s", inet_ntoa(a));

    char app_esc[512];
    escape_bytes_for_log(appjson, alen, app_esc, sizeof app_esc, 256);

    /* App dispatch (single call) */
    (void)app_handle_rx(ctx, m, appjson, alen, from, &g_mods, &g_rt);

    LOGF("[RX] %s from %s:%u id=%s hop=%d ttl=%d sig=%s | app=%s\n",
         m->type, ipbuf, m->src_port, m->msg_id,
         m->hop, m->ttl, (m->signed_ok?"OK":(m->signed_present?"BAD":"none")),
         app_esc);

    if (g_verbose_rx && (!strcmp(m->type,"BEACON") || !strcmp(m->type,"ANNOUNCE"))) {
        dump_hail_props(ctx, from, m->type);
    }
    if (g_ws) ws_push_rx(g_ws, m, appjson, alen);

    /* show app-level ACKs (kind:"ack") */
    if(appjson && strstr(appjson,"\"kind\":\"ack\"")){
        char id[64]="", topic[24]="", action[16]="", code[16]="", state[16]="";
        (void)jf_str(appjson,"id",id,sizeof id);
        (void)jf_str(appjson,"topic",topic,sizeof topic);
        (void)jf_str(appjson,"action",action,sizeof action);
        if(strstr(appjson,"\"data\"")){
            (void)jf_str(appjson,"state",state,sizeof state);
            (void)jf_str(appjson,"code",code,sizeof code);
        }
        LOGF("[WAYBEAM-ACK] id=%s topic=%s action=%s state=%s code=%s\n",
             id[0]?id:"", topic[0]?topic:"", action[0]?action:"",
             state[0]?state:"", code[0]?code:"");
    }
}

static void on_delivery(hail_ctx *ctx, const char *msg_id,
                        const struct sockaddr_in *to, hail_delivery_result_t res)
{
    (void)ctx;
    LOGF("[DELIVERY] %s -> %s:%u : %s\n",
         msg_id, inet_ntoa(to->sin_addr), ntohs(to->sin_port),
         (res==HAIL_DELIVER_OK ? "OK" : "TIMEOUT"));

    if (g_ws) ws_push_delivery(g_ws, msg_id, to, (res==HAIL_DELIVER_OK));
}

/* ---------- simple line input ---------- */
static int read_line_nonblock(char *buf, size_t bufsz){
    fd_set rfds; FD_ZERO(&rfds); FD_SET(STDIN_FILENO,&rfds);
    struct timeval tv = {0,0};
    int s = select(STDIN_FILENO+1,&rfds,NULL,NULL,&tv);
    if(s > 0 && FD_ISSET(STDIN_FILENO,&rfds)){
        if(!fgets(buf,(int)bufsz,stdin)) return 0;
        size_t n=strlen(buf);
        while(n && (buf[n-1]=='\n' || buf[n-1]=='\r')) buf[--n]=0;
        return 1;
    }
    return 0;
}

static void usage_line(void){
    if(!g_debug) return; /* only show REPL help in --debug mode */
    printf("\nCommands: "
           "[b]eacon  [a]nnounce  [d]ata-bcast  [p]ing  [u]nicast-ack  [t]opoq  "
           "[k]ey(PSK)  [s]ign-toggle  [r]efresh-nodes  [n]odes-print  "
           "[x]verbose-toggle  [h]last-hail  [j]last-json  [q]uit\n> ");
    fflush(stdout);
}

/* True if roles="a,b,c" contains role token exactly (case-insensitive) */
static int roles_has(const char *roles, const char *role){
    if(!roles || !*roles || !role || !*role) return 0;
    size_t rl = strlen(role);
    const char *p = roles;
    while(*p){
        /* skip separators */
        while(*p==',' || *p==' ' || *p=='\t') p++;
        const char *start = p;
        while(*p && *p!=',' && *p!=' ' && *p!='\t') p++;
        size_t n = (size_t)(p - start);
        if(n == rl && strncasecmp(start, role, rl) == 0) return 1;
    }
    return 0;
}

/* ---------- main ---------- */
int main(int argc, char **argv){
    const char *cfg_path = NULL;

    for(int i=1;i<argc;i++){
        if(!strcmp(argv[i],"--config") && i+1<argc){ cfg_path=argv[++i]; }
        else if(!strcmp(argv[i],"--debug")){ g_debug=1; }
        else {
            fprintf(stderr,"Usage: %s [--config file] [--debug]\n(unknown arg: %s)\n", argv[0], argv[i]);
        }
    }

    demo_cfg_t cfg; cfg_default(&cfg);
    if(cfg_path) cfg_load_file(&cfg, cfg_path);

    const char *bind_ip = cfg.bind_ip[0]?cfg.bind_ip:"0.0.0.0";
    uint16_t bind_port  = cfg.bind_port;

    hail_ctx *h = hail_create(bind_ip, bind_port, cfg.src_id[0]?cfg.src_id:NULL);
    if(!h){ perror("hail_create"); return 1; }

    hail_set_on_message(h, on_msg);
    hail_set_on_delivery(h, on_delivery);

    /* Identity persistence / override */
    if (cfg.node_id_file[0]) {
        hail_set_nodeid_path(h, cfg.node_id_file);
    }

    /* src_id set/ensure */
    if (cfg.src_id[0]) {
        if (hail_set_src_id(h, cfg.src_id) != 0) {
            fprintf(stderr, "[WARN] bad src_id in config, using persisted/auto id.\n");
            (void)hail_ensure_src_id(h);
        }
    } else {
        (void)hail_ensure_src_id(h);
    }

    /* Alias */
    if (cfg.alias[0]) hail_set_alias(h, cfg.alias);

    /* Show where the src_id came from and whether it was persisted (ALWAYS visible) */
    const char *node_path = cfg.node_id_file[0] ? cfg.node_id_file : "/etc/hail_nodeid";
    int had_file_before = (access(node_path, R_OK) == 0);
    int has_file_after  = (access(node_path, R_OK) == 0);

    const char *id_origin = "unknown";
    if (cfg.src_id[0]) {
        id_origin = has_file_after ? (had_file_before ? "config (kept), file existed"
                                                      : "config (persisted)")
                                   : "config (NOT persisted)";
    } else if (had_file_before) {
        id_origin = "loaded from file";
    } else {
        id_origin = has_file_after ? "auto-generated & saved"
                                   : "auto-generated (failed to save)";
    }

    const char *sid = hail_get_src_id(h);
    fprintf(stderr, "[ID] src_id=%s  origin=%s  path=%s\n", sid ? sid : "(null)", id_origin, node_path);

    /* declared_ip */
    if (cfg.declared_ip[0]) {
        hail_set_declared_ip(h, cfg.declared_ip);
    } else if (strcmp(bind_ip, "0.0.0.0") != 0) {
        hail_set_declared_ip(h, bind_ip);
    }

    /* Config into Hail */
    if(cfg.roles[0]){
        char *tmp=xstrdup(cfg.roles);
        char *arr[HAIL_MAX_ROLES];
        size_t n=split_csv(tmp,arr,HAIL_MAX_ROLES);
        hail_set_roles(h, (const char**)arr, (int)n);
        free(tmp);
    }

    if(cfg.caps[0]){
        char *tmp=xstrdup(cfg.caps);
        char *arr[HAIL_MAX_CAPS];
        size_t n=split_csv(tmp,arr,HAIL_MAX_CAPS);
        hail_set_caps(h, (const char**)arr, (int)n);
        free(tmp);
    }

    if(cfg.pref_unicast!=-1)  hail_set_pref_unicast(h, cfg.pref_unicast);
    if(cfg.max_app_bytes!=-1) hail_set_max_app_bytes(h, cfg.max_app_bytes);
    if(cfg.relay_ok!=-1)      hail_set_relay_ok(h, cfg.relay_ok);
    hail_require_signing(h, cfg.require_signing);

    size_t psk_bytes = 0;
    if(cfg.psk_hex[0]){
        unsigned char key[64]; size_t klen = sizeof key;
        int rc = hex2bin(cfg.psk_hex, key, &klen);
        if (rc == 0 && klen > 0) {
            hail_set_psk(h, key, klen);
            psk_bytes = klen;
            LOGF("[SEC] PSK set (%zu bytes).\n", klen);
        } else {
            fprintf(stderr,"[SEC] Invalid psk_hex in config (couldn't parse %s).\n", cfg.psk_hex);
        }
    }
    if(cfg.beacon_interval_ms!=-1) hail_set_beacon_interval_ms(h, cfg.beacon_interval_ms);
    if(cfg.expiry_seconds!=-1)     hail_set_expiry_seconds(h, cfg.expiry_seconds);

    g_verbose_rx = cfg.verbose_rx ? 1 : 0;

    unsigned effective_port = cfg.bind_port ? cfg.bind_port : HAIL_DEFAULT_PORT;
    const char *decl_ip = cfg.declared_ip[0] ? cfg.declared_ip
                         : (strcmp(bind_ip,"0.0.0.0") ? bind_ip : "0.0.0.0");

    /* Modules into app-layer globals (with NEW update/request) */
    memset(&g_mods,0,sizeof g_mods);
    snprintf(g_mods.roles_csv,                 sizeof g_mods.roles_csv,                 "%s", cfg.roles);
    snprintf(g_mods.beacon_exec_beam_cast,     sizeof g_mods.beacon_exec_beam_cast,     "%s", cfg.beacon_exec_beam_cast);
    snprintf(g_mods.beacon_exec_beam_update,   sizeof g_mods.beacon_exec_beam_update,   "%s", cfg.beacon_exec_beam_update);
    snprintf(g_mods.beacon_exec_beam_request,  sizeof g_mods.beacon_exec_beam_request,  "%s", cfg.beacon_exec_beam_request);
    snprintf(g_mods.beacon_exec_beam_stop,     sizeof g_mods.beacon_exec_beam_stop,     "%s", cfg.beacon_exec_beam_stop);
    snprintf(g_mods.beacon_allow_lanes,        sizeof g_mods.beacon_allow_lanes,        "%s", cfg.beacon_allow_lanes);
    snprintf(g_mods.beacon_busy_file,          sizeof g_mods.beacon_busy_file,          "%s", cfg.beacon_busy_file);
    /* Relay */
    snprintf(g_mods.relay_exec_update,  sizeof g_mods.relay_exec_update,  "%s", cfg.relay_exec_update);
    snprintf(g_mods.relay_exec_start,   sizeof g_mods.relay_exec_start,   "%s", cfg.relay_exec_start);
    snprintf(g_mods.relay_exec_stop,    sizeof g_mods.relay_exec_stop,    "%s", cfg.relay_exec_stop);
    snprintf(g_mods.relay_exec_request, sizeof g_mods.relay_exec_request, "%s", cfg.relay_exec_request);
    snprintf(g_mods.relay_allow_lanes,  sizeof g_mods.relay_allow_lanes,  "%s", cfg.relay_allow_lanes);

    /* Porthole */
    snprintf(g_mods.porthole_exec_update,  sizeof g_mods.porthole_exec_update,  "%s", cfg.porthole_exec_update);
    snprintf(g_mods.porthole_exec_stop,    sizeof g_mods.porthole_exec_stop,    "%s", cfg.porthole_exec_stop);
    snprintf(g_mods.porthole_exec_control, sizeof g_mods.porthole_exec_control, "%s", cfg.porthole_exec_control);
    snprintf(g_mods.porthole_exec_request, sizeof g_mods.porthole_exec_request, "%s", cfg.porthole_exec_request);
    snprintf(g_mods.porthole_allow_lanes,  sizeof g_mods.porthole_allow_lanes,  "%s", cfg.porthole_allow_lanes);

    /* Constellation */
    snprintf(g_mods.constellation_exec_sync, sizeof g_mods.constellation_exec_sync, "%s", cfg.constellation_exec_sync);





/* Role presence: either declared in roles= or any exec/lanes set */
int has_beacon        = roles_has(cfg.roles, "beacon");
int has_relay         = roles_has(cfg.roles, "relay");
int has_porthole      = roles_has(cfg.roles, "porthole");
int has_constellation = roles_has(cfg.roles, "constellation");


/* Running config banner (ALWAYS visible) */
fprintf(stderr,
    "=== Waybeam Core: running config ===\n"
    "[RUN] bind=%s:%u  declared_ip=%s  alias=%s\n"
    "[RUN] roles=%s  caps=%s\n"
    "[RUN] pref_unicast=%s  max_app_bytes=%s  relay_ok=%s\n"
    "[SEC] require_signing=%d  psk_bytes=%zu\n"
    "[TIMERS] beacon_interval_ms=%d  expiry_seconds=%d\n"
    "[WS] %s %s:%u\n",
    bind_ip, effective_port, decl_ip, (cfg.alias[0]?cfg.alias:""),
    (cfg.roles[0]?cfg.roles:""), (cfg.caps[0]?cfg.caps:""),
    (cfg.pref_unicast!=-1? (cfg.pref_unicast?"1":"0") : "(default)"),
    (cfg.max_app_bytes!=-1? (cfg.max_app_bytes==0 ? "0" : "(set)") : "(default)"),
    (cfg.relay_ok!=-1? (cfg.relay_ok?"1":"0") : "(default)"),
    (cfg.require_signing?1:0), psk_bytes,
    (cfg.beacon_interval_ms!=-1? cfg.beacon_interval_ms : 3000),
    (cfg.expiry_seconds!=-1? cfg.expiry_seconds : HAIL_DEFAULT_EXPIRES_IN),
    (cfg.ws_enable? "enabled":"disabled"),
    (cfg.ws_listen[0]?cfg.ws_listen:"0.0.0.0"),
    (cfg.ws_port?cfg.ws_port:8089)
);

/* Conditionally print per-role sections based on what’s actually loaded */

if (has_beacon){
    fprintf(stderr,
        "[WAYBEAM.beacon]\n"
        "  cast   : %s\n"
        "  update : %s\n"
        "  request: %s\n"
        "  stop   : %s\n"
        "  lanes  : %s\n"
        "  busy   : %s\n",
        (cfg.beacon_exec_beam_cast[0]?    cfg.beacon_exec_beam_cast    : "(unset)"),
        (cfg.beacon_exec_beam_update[0]?  cfg.beacon_exec_beam_update  : "(unset)"),
        (cfg.beacon_exec_beam_request[0]? cfg.beacon_exec_beam_request : "(unset)"),
        (cfg.beacon_exec_beam_stop[0]?    cfg.beacon_exec_beam_stop    : "(unset)"),
        (cfg.beacon_allow_lanes[0]?       cfg.beacon_allow_lanes       : "(unset)"),
        (cfg.beacon_busy_file[0]?         cfg.beacon_busy_file         : "(unset)")
    );
}

if (has_relay){
    fprintf(stderr,
        "[WAYBEAM.relay]\n"
        "  start  : %s\n"
        "  update : %s\n"
        "  stop   : %s\n"
        "  request: %s\n"
        "  lanes  : %s\n",
        (cfg.relay_exec_start[0]?   cfg.relay_exec_start   : "(unset)"),
        (cfg.relay_exec_update[0]?  cfg.relay_exec_update  : "(unset)"),
        (cfg.relay_exec_stop[0]?    cfg.relay_exec_stop    : "(unset)"),
        (cfg.relay_exec_request[0]? cfg.relay_exec_request : "(unset)"),
        (cfg.relay_allow_lanes[0]?  cfg.relay_allow_lanes  : "(unset)")
    );
}

if (has_porthole){
    fprintf(stderr,
        "[WAYBEAM.porthole]\n"
        "  update : %s\n"
        "  stop   : %s\n"
        "  control: %s\n"
        "  request: %s\n"
        "  lanes  : %s\n",
        (cfg.porthole_exec_update[0]?  cfg.porthole_exec_update  : "(unset)"),
        (cfg.porthole_exec_stop[0]?    cfg.porthole_exec_stop    : "(unset)"),
        (cfg.porthole_exec_control[0]? cfg.porthole_exec_control : "(unset)"),
        (cfg.porthole_exec_request[0]? cfg.porthole_exec_request : "(unset)"),
        (cfg.porthole_allow_lanes[0]?  cfg.porthole_allow_lanes  : "(unset)")
    );
}

if (has_constellation){
    fprintf(stderr,
        "[WAYBEAM.constellation]\n"
        "  sync   : %s\n",
        (cfg.constellation_exec_sync[0]? cfg.constellation_exec_sync : "(unset)")
    );
}

/* Banner + optional initial announce */
printf("Waybeam Core  %s  (bound %s:%u)\n", hail_version(), bind_ip, effective_port);
    usage_line();
    if(cfg.announce_json[0]){ hail_send_announce(h, cfg.announce_json); }

    /* WS bridge */
    if (cfg.ws_enable) {
        g_ws = ws_start(cfg.ws_listen[0]?cfg.ws_listen:"0.0.0.0",
                        cfg.ws_port?cfg.ws_port:8089, h);
        if (g_ws) fprintf(stderr, "[WS] listening on %s:%u\n",
                          (cfg.ws_listen[0]?cfg.ws_listen:"0.0.0.0"),
                          (cfg.ws_port?cfg.ws_port:8089));
        else      fprintf(stderr, "[WS] failed to start.\n");
    }
    atexit(on_exit);      // ensures ws is stopped on process exit

    int tick_ms = 0;
    int nodes_tick = 0;

    char line[1024]={0};
    for(;;){
        hail_poll(h, 100);
        tick_ms += 100; nodes_tick += 100;

        if (tick_ms >= 3000){
            tick_ms = 0;
            hail_send_beacon(h);
            LOGF("[TX] BEACON (timer)\n");
        }
        if (nodes_tick >= 2000){
            nodes_tick = 0;
            (void)hail_nodes_snapshot(h, NULL, 0, 0);
        }

        /* REPL only when --debug */
        if (g_debug && read_line_nonblock(line,sizeof line)){
            if (!line[0]) { usage_line(); continue; }
            char cmd = tolower((unsigned char)line[0]);

            if (cmd=='q'){ printf("Bye.\n"); break; }
            else if (cmd=='x'){ g_verbose_rx = !g_verbose_rx; LOGF("[DBG] verbose_rx=%s\n", g_verbose_rx?"ON":"OFF"); }

            else if (cmd=='b'){ hail_send_beacon(h); LOGF("[TX] BEACON\n"); }

            else if (cmd=='a'){
                const char *app = (strlen(line)>2) ? line+2 : cfg.announce_json;
                hail_send_announce(h, app); LOGF("[TX] ANNOUNCE app=%s\n", app);
            }

            else if (cmd=='d'){
                int ttl = 2; const char *json = "{\"waybeam_core\":\"broadcast\"}";
                if (strlen(line)>2){
                    char *p=line+2; while(*p==' ') p++;
                    if (*p){
                        ttl = atoi(p);
                        while(*p && *p!=' ') p++;
                        while(*p==' ') p++;
                        if (*p) json = p;
                    }
                }
                if(ttl<0) ttl=0;
                if(ttl>5) ttl=5;
                hail_send_data_broadcast(h, ttl, json);
                LOGF("[TX] DATA broadcast ttl=%d app=%s\n", ttl, json);
            }

            else if (cmd=='r'){ (void)hail_nodes_snapshot(h, NULL, 0, 0); LOGF("[NODES] refreshed.\n"); }
            else if (cmd=='n'){ print_nodes(h); }
            else if (cmd=='h'){ cmd_print_last_hail(h); }
            else if (cmd=='j'){ cmd_print_last_json(h); }

            else if (cmd=='p'){
                char ip[64]=""; unsigned port=HAIL_DEFAULT_PORT; const char *json="null";
                if (strlen(line)>2){
                    char *p=line+2; while(*p==' ') p++;
                    if (*p){
                        char *q=p; while(*q && *q!=' ') q++; snprintf(ip,sizeof ip,"%.*s",(int)(q-p),p);
                        p=q; while(*p==' ') p++;
                        if (*p){ port=(unsigned)atoi(p); while(*p && *p!=' ') p++; while(*p==' ') p++; }
                        if (*p){ json=p; }
                    }
                }
                if (!ip[0]) { printf("Usage: p <ip> [port] [json]\n"); }
                else { hail_send_ping(h, ip, (uint16_t)port, json); LOGF("[TX] PING -> %s:%u app=%s\n", ip, port, json); }
            }

            else if (cmd=='u'){
                char ip[64]=""; unsigned port=HAIL_DEFAULT_PORT; int retries=3, tmo=400; const char *json="{\"cmd\":\"echo\"}";
                if (strlen(line)>2){
                    char *p=line+2; while(*p==' ') p++;
                    if (*p){
                        char *q=p; while(*q && *q!=' ') q++; snprintf(ip,sizeof ip,"%.*s",(int)(q-p),p); p=q; while(*p==' ') p++;
                        if (*p){ port=atoi(p); while(*p && *p!=' ') p++; while(*p==' ') p++; }
                        if (*p){ retries=atoi(p); while(*p && *p!=' ') p++; while(*p==' ') p++; }
                        if (*p){ tmo=atoi(p); while(*p && *p!=' ') p++; while(*p==' ') p++; }
                        if (*p){ json=p; }
                    }
                }
                if (!ip[0]) { printf("Usage: u <ip> [port] [retries] [timeout_ms] [json]\n"); }
                else {
                    int rc = hail_send_data_unicast_reliable(h, ip, (uint16_t)port, json, retries, tmo);
                    LOGF("[TX] DATA reliable -> %s:%u (%d tries, %d ms) -> %s\n",
                         ip, port, retries, tmo, (rc==0?"ACKed":"TIMEOUT"));
                }
            }

            else if (cmd=='t'){
                int ttl = 2; if (strlen(line)>2) ttl = atoi(line+2);
                if(ttl<0) ttl=0;
                hail_request_topology(h, ttl);
                LOGF("[TX] TOPOQ ttl=%d (expect TOPOA unicast replies)\n", ttl);
            }

            else if (cmd=='k'){
                if (strlen(line)<=2){ hail_set_psk(h, NULL, 0); LOGF("[SEC] PSK cleared.\n"); }
                else {
                    char *p=line+2; while(*p==' ') p++;
                    unsigned char tmp[32]; size_t out=sizeof tmp;
                    if(hex2bin(p,tmp,&out)==0 && out>0){ hail_set_psk(h,tmp,out); LOGF("[SEC] PSK set (%zu bytes).\n", out); }
                    else LOGF("[SEC] Invalid hex; PSK unchanged.\n");
                }
            }

            else if (cmd=='s'){ static int req=0; req=!req; hail_require_signing(h, req); LOGF("[SEC] require_signing = %s\n", req?"yes":"no"); }
            else { usage_line(); continue; }

            usage_line();
        }
    }

    if (g_ws) { ws_stop(g_ws); g_ws=NULL; }
    hail_destroy(h);
    return 0;
}
