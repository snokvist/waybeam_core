// hail_ws.c — tiny dependency-free WebSocket bridge (RFC6455, text frames only)
#define _GNU_SOURCE
#include "hail_ws.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <strings.h>  // for strncasecmp

#define SEND_JSON(fd, lit) send_text_frame((fd), (lit), strlen(lit))

/* ====== helpers for top-level JSON (no deps) ====== */
typedef struct {
  const char* op;       int op_len;
  const char* dst;      int dst_len;
  int ttl_set, ttl;
  int hop_set, hop;
  int ack_set, ack;
  const char* type;     int type_len;
  char* app_json;       /* malloc'ed, NUL-terminated */
} cmd_t;

static void skip_ws(const char** p){ while(**p==' '||**p=='\t'||**p=='\r'||**p=='\n') (*p)++; }
static int match_key(const char* p, const char* k){ int n=(int)strlen(k); return (strncmp(p,k,n)==0)?n:0; }
static char* sdup_n(const char* s, size_t n){ char* r=(char*)malloc(n+1); if(!r) return NULL; memcpy(r,s,n); r[n]=0; return r; }

static char* copy_json_value_(const char* p){
  while(*p==' '||*p=='\t') p++;
  if(*p=='{'){ int d=0; const char* q=p; do{ if(*q=='{')d++; else if(*q=='}')d--; q++; }while(*q && d>0); return sdup_n(p,(size_t)(q-p)); }
  if(*p=='['){ int d=0; const char* q=p; do{ if(*q=='[')d++; else if(*q==']')d--; q++; }while(*q && d>0); return sdup_n(p,(size_t)(q-p)); }
  if(*p=='"'){ const char* q=p+1; while(*q && !(*q=='"' && q[-1] != '\\')) q++; if(*q=='"') q++; return sdup_n(p,(size_t)(q-p)); }
  const char* q=p; while(*q && *q!=',' && *q!='}' && *q!='\r' && *q!='\n') q++; while(q>p && (q[-1]==' '||q[-1]=='\t')) q--;
  return sdup_n(p,(size_t)(q-p));
}
static int parse_int_value(const char* p, int* out){
  while(*p && *p!=':' ) p++; if(*p!=':') return 0; p++; skip_ws(&p);
  char* end=NULL; long v = strtol(p,&end,10);
  if(end==p) return 0; *out=(int)v; return 1;
}
static int parse_str_value(const char* p, const char** s, int* slen){
  while(*p && *p!=':' ) p++; if(*p!=':') return 0; p++; skip_ws(&p);
  if(*p!='"') return 0; p++;
  const char* start = p; while(*p && !(*p=='"' && p[-1] != '\\')) p++; if(*p!='"') return 0;
  *s = start; *slen = (int)(p - start); return 1;
}
static int parse_any_value_copy(const char* p, char** out){
  while(*p && *p!=':' ) p++; if(*p!=':') return 0; p++; skip_ws(&p);
  char* v = copy_json_value_(p); if(!v) return 0;
  size_t n=strlen(v); while(n && (v[n-1]==' '||v[n-1]=='\t'||v[n-1]=='\r'||v[n-1]=='\n'||v[n-1]==',')) v[--n]=0;
  *out = v; return 1;
}

static void parse_cmd_top(const char* txt, cmd_t* c){
  memset(c,0,sizeof *c);
  const char* p = txt; skip_ws(&p); if(*p!='{') return; p++; int depth=1;
  while(*p && depth>0){
    skip_ws(&p);
    if(*p=='"'){
      if(depth==1){
        int n;
        if((n=match_key(p,"\"op\"")))        { parse_str_value(p+n, &c->op,   &c->op_len); }
        else if((n=match_key(p,"\"dst\"")))  { parse_str_value(p+n, &c->dst,  &c->dst_len); }
        else if((n=match_key(p,"\"ttl\"")))  { int v; if(parse_int_value(p+n,&v)){ c->ttl_set=1; c->ttl=v; } }
        else if((n=match_key(p,"\"hop\"")))  { int v; if(parse_int_value(p+n,&v)){ c->hop_set=1; c->hop=v; } }
        else if((n=match_key(p,"\"ack\"")))  { int v; if(parse_int_value(p+n,&v)){ c->ack_set=1; c->ack=v?1:0; } }
        else if((n=match_key(p,"\"type\""))) { parse_str_value(p+n, &c->type, &c->type_len); }
        else if((n=match_key(p,"\"app\"")))  { if(!c->app_json) parse_any_value_copy(p+n, &c->app_json); }
      }
      p++; while(*p && !(*p=='"' && p[-1] != '\\')) p++; if(*p=='"') p++;
    } else if(*p=='{'){ depth++; p++; }
      else if(*p=='}'){ depth--; p++; }
      else { p++; }
  }
  if(!c->app_json) c->app_json = sdup_n("null",4);
}
static char* normalize_app_json_(char* s_in){
  if(!s_in) return sdup_n("null",4);
  const char* p = s_in; while(*p==' '||*p=='\t'||*p=='\r'||*p=='\n') p++;
  if(p[0]=='n' && !strncmp(p,"null",4)){ free(s_in); return sdup_n("null",4); }
  if(p[0]=='{' || p[0]=='['){ size_t n=strlen(p); while(n && (p[n-1]==' '||p[n-1]=='\t'||p[n-1]=='\r'||p[n-1]=='\n')) n--; char* out=sdup_n(p,n); free(s_in); return out; }
  free(s_in); return sdup_n("null",4);
}

/* ===================== minimal SHA1 + Base64 (for handshake) ===================== */
typedef struct { unsigned h[5]; unsigned long long nbits; unsigned char buf[64]; } sha1_t;
static void sha1_init(sha1_t* s){
  s->h[0]=0x67452301; s->h[1]=0xEFCDAB89; s->h[2]=0x98BADCFE; s->h[3]=0x10325476; s->h[4]=0xC3D2E1F0;
  s->nbits=0; memset(s->buf,0,sizeof s->buf);
}
static void sha1_blk(sha1_t* s, const unsigned char* p){
  unsigned w[80];
  for(int i=0;i<16;i++) w[i]=(p[4*i]<<24)|(p[4*i+1]<<16)|(p[4*i+2]<<8)|p[4*i+3];
  for(int i=16;i<80;i++){ unsigned v=w[i-3]^w[i-8]^w[i-14]^w[i-16]; w[i]=(v<<1)|(v>>31); }
  unsigned a=s->h[0],b=s->h[1],c=s->h[2],d=s->h[3],e=s->h[4];
  for(int i=0;i<80;i++){
    unsigned f,k;
    if(i<20){ f=(b&c)|((~b)&d); k=0x5A827999; }
    else if(i<40){ f=b^c^d; k=0x6ED9EBA1; }
    else if(i<60){ f=(b&c)|(b&d)|(c&d); k=0x8F1BBCDC; }
    else         { f=b^c^d; k=0xCA62C1D6; }
    unsigned t=((a<<5)|(a>>27))+f+e+k+w[i];
    e=d; d=c; c=(b<<30)|(b>>2); b=a; a=t;
  }
  s->h[0]+=a; s->h[1]+=b; s->h[2]+=c; s->h[3]+=d; s->h[4]+=e;
}
static void sha1_update(sha1_t* s, const void* data, size_t len){
  const unsigned char* p=(const unsigned char*)data;
  size_t r=(s->nbits/8)%64; s->nbits += (unsigned long long)len*8;
  if(r){
    size_t n=64-r; if(n>len) n=len; memcpy(s->buf+r,p,n);
    if(r+n==64) sha1_blk(s,s->buf);
    p+=n; len-=n;
  }
  while(len>=64){ sha1_blk(s,p); p+=64; len-=64; }
  if(len) memcpy(s->buf,p,len);
}
static void sha1_final(sha1_t* s, unsigned char out[20]){
  size_t r=(s->nbits/8)%64; s->buf[r++]=0x80;
  if(r>56){ while(r<64) s->buf[r++]=0; sha1_blk(s,s->buf); r=0; }
  while(r<56) s->buf[r++]=0;
  unsigned long long n=s->nbits;
  for(int i=7;i>=0;i--) s->buf[r++]=(unsigned char)((n>>(i*8))&0xFF);
  sha1_blk(s,s->buf);
  for(int i=0;i<5;i++){
    out[4*i  ]=(s->h[i]>>24)&255; out[4*i+1]=(s->h[i]>>16)&255;
    out[4*i+2]=(s->h[i]>>8 )&255; out[4*i+3]= s->h[i]     &255;
  }
}
static int b64enc(const unsigned char* in, int n, char* out, int outsz){
  static const char T[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  int o=0;
  for(int i=0;i<n;i+=3){
    unsigned v=(in[i]<<16) | ((i+1<n?in[i+1]:0)<<8) | (i+2<n?in[i+2]:0);
    if(o+4>=outsz) return -1;
    out[o++]=T[(v>>18)&63];
    out[o++]=T[(v>>12)&63];
    out[o++]=(i+1<n)?T[(v>>6)&63]:'=';
    out[o++]=(i+2<n)?T[v&63]:'=';
  }
  if(o<outsz) out[o]=0;
  return o;
}

/* ===================== outbound event ring ===================== */
typedef struct { char* s; size_t n; } blob_t;
#define QN 128
typedef struct { blob_t q[QN]; int r,w; pthread_mutex_t m; } ring_t;
static void rq_init(ring_t* r){ memset(r,0,sizeof *r); pthread_mutex_init(&r->m,NULL); }
static void rq_push(ring_t* r, const char* s, size_t n){
  pthread_mutex_lock(&r->m);
  int next=(r->w+1)%QN;
  if(next==r->r){ free(r->q[r->r].s); r->r=(r->r+1)%QN; }
  r->q[r->w].s=(char*)malloc(n);
  if(r->q[r->w].s){ memcpy(r->q[r->w].s,s,n); r->q[r->w].n=n; r->w=next; }
  pthread_mutex_unlock(&r->m);
}
static int rq_pop(ring_t* r, blob_t* out){
  int ok=0;
  pthread_mutex_lock(&r->m);
  if(r->r!=r->w){ *out=r->q[r->r]; r->q[r->r].s=NULL; r->q[r->r].n=0; r->r=(r->r+1)%QN; ok=1; }
  pthread_mutex_unlock(&r->m);
  return ok;
}

/* ===================== clients + server state ===================== */
typedef struct { int fd; int alive; } cli_t;
#define MAXC 8

struct ws_server {
  int lfd;
  struct sockaddr_in addr;
  pthread_t th;
  volatile int stop;
  hail_ctx* hail;
  ring_t q;
  cli_t cs[MAXC];
  char last_self_hail[2048];
  int  last_self_hail_len;
  char self_id[HAIL_ID_LEN];
};

/* ===================== forward decls ===================== */
static void* th_main(void* arg);
static int   handshake_ws(int fd);
static int   send_text_frame(int fd, const char* txt, size_t n);
static int   read_text_frame(int fd, char* out, size_t outsz);
static void  send_all(struct ws_server* s, const char* txt, size_t n);
static void  handle_request(struct ws_server* s, int fd, char* txt);

/* ===================== public API ===================== */
ws_server* ws_start(const char* ip, uint16_t port, hail_ctx* hail){
  ws_server* s=(ws_server*)calloc(1,sizeof *s);
  if(!s) return NULL;
  s->hail=hail; rq_init(&s->q);

  s->lfd=socket(AF_INET,SOCK_STREAM,0);
  if(s->lfd<0){ free(s); return NULL; }
  int yes=1; setsockopt(s->lfd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof yes);

  memset(&s->addr,0,sizeof s->addr);
  s->addr.sin_family=AF_INET; s->addr.sin_port=htons(port);
  inet_pton(AF_INET, ip?ip:"0.0.0.0", &s->addr.sin_addr);

  if(bind(s->lfd,(struct sockaddr*)&s->addr,sizeof s->addr)!=0){ close(s->lfd); free(s); return NULL; }
  if(listen(s->lfd,8)!=0){ close(s->lfd); free(s); return NULL; }

  if(pthread_create(&s->th,NULL,th_main,s)!=0){ close(s->lfd); free(s); return NULL; }


  memset(s->last_self_hail, 0, sizeof s->last_self_hail);
s->last_self_hail_len = 0;

const char* sid = hail_get_src_id(s->hail);
if (sid) {
  // keep a copy so we can quick-compare against rx/meta.src_id later if needed
  strncpy(s->self_id, sid, HAIL_ID_LEN-1);
  s->self_id[HAIL_ID_LEN-1] = 0;
}

  return s;
}

void ws_stop(ws_server* s){
  if(!s) return;
  s->stop=1;
  shutdown(s->lfd,SHUT_RDWR);
  close(s->lfd);
  pthread_join(s->th,NULL);
  for(int i=0;i<MAXC;i++) if(s->cs[i].fd>0) close(s->cs[i].fd);
  blob_t b; while(rq_pop(&s->q,&b)) free(b.s);
  free(s);
}

/* --- tiny JSON slicers (local to hail_ws.c) --- */
static int json_find_array_slice_(const char* j, const char* key, const char** beg, size_t* len){
  if(!j||!key) return -1;
  const char* p = strstr(j, key); if(!p) return -1;
  p = strchr(p, '['); if(!p) return -1;
  int d=0; const char* q=p;
  do{ if(*q=='[') d++; else if(*q==']') d--; q++; }while(*q && d>0);
  if(d!=0) return -1;
  *beg=p; *len=(size_t)(q-p); return 0;
}
static int json_find_string_(const char* j, const char* key, char* out, size_t outsz){
  if(!j||!key||!out||outsz<2) return -1;
  const char* p = strstr(j, key); if(!p) return -1;
  p = strchr(p, '\"'); if(!p) return -1; /* first quote */
  p = strchr(p+1, '\"'); if(!p) return -1; /* start of value? */
  const char* v = p+1; const char* e = strchr(v, '\"'); if(!e) return -1;
  size_t n = (size_t)(e - v); if(n >= outsz) n = outsz-1;
  memcpy(out, v, n); out[n]=0; return 0;
}



/* ===================== push events ===================== */
void ws_push_rx(ws_server* s, const hail_meta_t* m, const char* app_json, size_t alen){
  if(!s) return;

  /* Convert src_ip to dotted quad */
  char ip[INET_ADDRSTRLEN];
  struct in_addr a; a.s_addr=m->src_ip;
  snprintf(ip,sizeof ip,"%s", inet_ntoa(a));

  /* Basic meta (as before) */
  char meta[512];
  snprintf(meta,sizeof meta,
    "{\"type\":\"%s\",\"msg_id\":\"%s\",\"src_id\":\"%s\",\"ip\":\"%s\",\"port\":%u,"
    "\"hop\":%d,\"ttl\":%d,\"ack\":%d,\"sig_present\":%d,\"sig_ok\":%d}",
    m->type, m->msg_id, m->src_id, ip, m->src_port,
    m->hop, m->ttl, m->ack_req, m->signed_present, m->signed_ok);

  /* NEW: forward the most recent hail{} header slice verbatim (roles, caps, alias, etc.) */
  char hail_buf[2000];
  int  hail_len = hail_last_hail(s->hail, hail_buf, sizeof hail_buf);
  const char* hail_json = (hail_len>0) ? hail_buf : "null";

  /* Allocate one line: ev + meta + hail + app */
  size_t need = strlen(meta) + (size_t)alen + (size_t)(hail_len>0?hail_len:4) + 96;
  char* line  = (char*)malloc(need);
  if(!line) return;

  int n = snprintf(line, need,
    "{\"ev\":\"rx\",\"meta\":%s,\"hail\":%s,\"app\":%.*s}\n",
    meta, hail_json, (int)alen, (int)alen?app_json:"null");

  if(n>0) rq_push(&s->q,line,(size_t)n);
  free(line);
}

void ws_push_delivery(ws_server* s, const char* msg_id, const struct sockaddr_in* to, int ok){
  if(!s) return;
  char ip[INET_ADDRSTRLEN];
  snprintf(ip,sizeof ip,"%s", inet_ntoa(to->sin_addr));
  char line[256];
  int n=snprintf(line,sizeof line,
    "{\"ev\":\"delivery\",\"msg_id\":\"%s\",\"to\":\"%s:%u\",\"result\":\"%s\"}\n",
    msg_id, ip, ntohs(to->sin_port), ok?"OK":"TIMEOUT");
  if(n>0) rq_push(&s->q,line,(size_t)n);
}

/* ===================== requests (client -> server) ===================== */
static void handle_nodes(ws_server* s, int fd){
  size_t need=hail_nodes_snapshot_with_self(s->hail,NULL,0,0);
  hail_node_t* arr=(hail_node_t*)calloc(need?need:1,sizeof *arr);
  size_t n=hail_nodes_snapshot_with_self(s->hail,arr,need,0);

const char* self_id = s->self_id[0] ? s->self_id : hail_get_src_id(s->hail);
const char* hail_buf = s->last_self_hail;
int hl = s->last_self_hail_len;


  /* rough size: ~320 per node when roles/caps present */
  char* out=(char*)malloc(96 + n*360);
  int o=snprintf(out,96 + n*360,"{\"ev\":\"nodes\",\"nodes\":[");
  for(size_t i=0;i<n;i++){
    char ip[INET_ADDRSTRLEN];
    snprintf(ip,sizeof ip,"%s", inet_ntoa(arr[i].ip));

    /* base row */
    o+=snprintf(out+o,96+n*360-o,
      "%s{\"src_id\":\"%s\",\"ip\":\"%s\",\"port\":%u,\"active\":%d,"
      "\"pref_unicast\":%d,\"max_app_bytes\":%d,\"relay_ok\":%d,"
      "\"alias\":\"%s\"",
      (i?",":""), arr[i].src_id, ip, arr[i].port, arr[i].active,
      arr[i].pref_unicast, arr[i].max_app_bytes, arr[i].relay_ok, arr[i].alias);

    /* --- NEW: inject roles/caps/alias for *self* from last_hail{} --- */
    if(hl>0 && self_id && !strncmp(arr[i].src_id, self_id, HAIL_ID_LEN-1)){
      const char *rb=NULL,*cb=NULL; size_t rlen=0, clen=0;
      if(json_find_array_slice_(hail_buf,"\"roles\"", &rb, &rlen)==0 && rlen>=2){
        o+=snprintf(out+o,96+n*360-o, ",\"roles\":%.*s", (int)rlen, rb);
      }
      if(json_find_array_slice_(hail_buf,"\"caps\"",  &cb, &clen)==0 && clen>=2){
        o+=snprintf(out+o,96+n*360-o, ",\"caps\":%.*s", (int)clen, cb);
      }
      /* alias from self hail (if non-empty and not already set) */
      if(arr[i].alias[0]==0){
        char alias[64]; if(json_find_string_(hail_buf,"\"alias\"", alias, sizeof alias)==0 && alias[0]){
          o+=snprintf(out+o,96+n*360-o, ",\"alias\":\"%s\"", alias);
        }
      }
    }

    o+=snprintf(out+o,96+n*360-o,"}");
  }
  o+=snprintf(out+o,96+n*360-o,"]}\n");
  send_text_frame(fd,out,(size_t)o);
  free(out); free(arr);
}


/* ====== dispatcher ====== */
static void handle_request(ws_server* s, int fd, char* txt){
  cmd_t cmd; parse_cmd_top(txt, &cmd);
  if(!cmd.op || cmd.op_len<=0){ SEND_JSON(fd,"{\"ev\":\"err\",\"msg\":\"no op\"}\n"); free(cmd.app_json); return; }

  char dip[64]=""; unsigned dport=HAIL_DEFAULT_PORT;
  if(cmd.dst && cmd.dst_len>0){
    int n = cmd.dst_len; if(n >= (int)sizeof(dip)) n = (int)sizeof(dip)-1;
    memcpy(dip, cmd.dst, n); dip[n]=0; char* c=strchr(dip,':'); if(c){ *c=0; dport=(unsigned)atoi(c+1); }
  }

  int ttl = cmd.ttl_set ? cmd.ttl : 2;
  int hop = cmd.hop_set ? cmd.hop : 0;
  int ack = cmd.ack_set ? cmd.ack : 0;
  char  typebuf[16]; const char* type = "DATA";
  if(cmd.type && cmd.type_len>0){ int n = cmd.type_len; if(n >= (int)sizeof(typebuf)) n = (int)sizeof(typebuf)-1; memcpy(typebuf, cmd.type, n); typebuf[n]=0; type = typebuf; }

  char* app = normalize_app_json_(cmd.app_json); cmd.app_json=NULL;

  if(!strncmp(cmd.op,"nodes",5) && cmd.op_len==5){
    handle_nodes(s,fd);
  }
  else if(!strncmp(cmd.op,"beacon",6) && cmd.op_len==6){
  hail_send_beacon(s->hail);

  // Try to capture the *self* beacon that was just emitted
  // (Many builds place the just-built beacon JSON into last_hail; this is a cheap best-effort.)
  s->last_self_hail_len = hail_last_hail(s->hail, s->last_self_hail, sizeof s->last_self_hail);
  if (s->last_self_hail_len > 0) {
    // Optional: sanity check that JSON contains our src_id to be extra sure
    if (s->self_id[0] && !strstr(s->last_self_hail, s->self_id)) {
      // Not ours — discard
      s->last_self_hail_len = 0;
      s->last_self_hail[0]  = 0;
    }
  }

  SEND_JSON(fd,"{\"ev\":\"ok\"}\n");
}
  else if(!strncmp(cmd.op,"announce",8) && cmd.op_len==8){
    fprintf(stderr,"[WS] announce app=%s\n", app);
    hail_send_announce(s->hail, app); SEND_JSON(fd,"{\"ev\":\"ok\"}\n");
  }
  else if(!strncmp(cmd.op,"topoq",5) && cmd.op_len==5){
    hail_request_topology(s->hail, ttl); SEND_JSON(fd,"{\"ev\":\"ok\"}\n");
  }
  else if(!strncmp(cmd.op,"ping",4) && cmd.op_len==4){
    if(dip[0]){ fprintf(stderr,"[WS] ping dst=%s:%u app=%s\n", dip, dport, app); hail_send_ping(s->hail, dip, (uint16_t)dport, app); }
    SEND_JSON(fd,"{\"ev\":\"ok\"}\n");
  }
  else if(!strncmp(cmd.op,"unicast",7) && cmd.op_len==7){
    if(dip[0]){
      if(ack){
        char mid[HAIL_MSGID_LEN]={0};
        fprintf(stderr,"[WS] uni REL dst=%s:%u app=%s\n", dip, dport, app);
        int rc = hail_send_data_unicast_reliable_async(s->hail, dip, (uint16_t)dport, app, 3, 400, mid);
        SEND_JSON(fd, rc==0 ? "{\"ev\":\"ok\"}\n" : "{\"ev\":\"err\",\"msg\":\"queue-full\"}\n");
      } else {
        fprintf(stderr,"[WS] uni FNF dst=%s:%u type=%s hop=%d ttl=%d app=%s\n", dip, dport, type, hop, ttl, app);
        hail_send_unicast(s->hail, dip, (uint16_t)dport, type, hop, ttl, 0, app);
        SEND_JSON(fd,"{\"ev\":\"ok\"}\n");
      }
    } else {
      SEND_JSON(fd,"{\"ev\":\"err\",\"msg\":\"missing dst\"}\n");
    }
  }
  else if(!strncmp(cmd.op,"broadcast",9) && cmd.op_len==9){
    fprintf(stderr,"[WS] bcast ttl=%d app=%s\n", ttl, app);
    hail_send_data_broadcast(s->hail, ttl, app); SEND_JSON(fd,"{\"ev\":\"ok\"}\n");
  }
  else{
    SEND_JSON(fd,"{\"ev\":\"err\",\"msg\":\"bad op\"}\n");
  }

  if(app) free(app);
}

/* Read the entire HTTP header until CRLFCRLF, with a safety cap */
static int recv_http_header(int fd, char* buf, int bufsz) {
  int n = 0;
  while (n < bufsz - 1) {
    int r = recv(fd, buf + n, bufsz - 1 - n, 0);
    if (r <= 0) return -1;
    n += r;
    buf[n] = 0;
    if (strstr(buf, "\r\n\r\n") || strstr(buf, "\n\n")) break;
    if (n > 8192) return -1;
  }
  return n;
}

static int handshake_ws(int fd){
  char hdr[16384];
  int n = recv_http_header(fd, hdr, sizeof hdr);
  if (n <= 0) return -1;


  // quick HTTP /health for discovery (CORS-enabled)
if (strncasecmp(hdr, "GET ", 4) == 0) {
  const char *p = hdr + 4;
  if (!strncasecmp(p, "/health", 7)) {
    const char* resp =
      "HTTP/1.1 200 OK\r\n"
      "Access-Control-Allow-Origin: *\r\n"
      "Content-Type: text/plain; charset=utf-8\r\n"
      "Cache-Control: no-store\r\n"
      "Content-Length: 2\r\n"
      "\r\n"
      "OK";
    send(fd, resp, (int)strlen(resp), 0);
    return 1; // handled: caller will close()
  }
}
  if (strncasecmp(hdr, "GET ", 4) != 0) return -1;
  if (!strcasestr(hdr, "upgrade: websocket")) return -1;
  if (!strcasestr(hdr, "connection: upgrade")) return -1;

  const char* k = strcasestr(hdr, "sec-websocket-key:");
  if (!k) return -1;
  k += strlen("sec-websocket-key:");
  while (*k==' ' || *k=='\t') k++;

  char key[128] = {0};
  size_t m = strcspn(k, "\r\n");
  if (m == 0 || m >= sizeof key) return -1;
  memcpy(key, k, m);
  key[m] = 0;

  char cat[128+36];
  snprintf(cat,sizeof cat,"%s%s", key, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
  unsigned char dg[20]; sha1_t s; sha1_init(&s); sha1_update(&s,cat,strlen(cat)); sha1_final(&s,dg);
  char acc[64]; if (b64enc(dg,20,acc,sizeof acc) < 0) return -1;

  char resp[512];
  int rn = snprintf(resp, sizeof resp,
    "HTTP/1.1 101 Switching Protocols\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Accept: %s\r\n"
    "\r\n", acc);

  return send(fd, resp, rn, 0) == rn ? 0 : -1;
}

static int send_text_frame(int fd, const char* txt, size_t n){
  unsigned char hdr[10]; int h=0; hdr[h++]=0x81; /* FIN+text */
  if(n<126){ hdr[h++]=(unsigned char)n; }
  else if(n<=0xFFFF){ hdr[h++]=126; hdr[h++]=(n>>8)&255; hdr[h++]=n&255; }
  else { hdr[h++]=127; for(int i=7;i>=0;i--) hdr[h++]=(n>>(8*i))&255; }
  if(send(fd,hdr,h,0)!=h) return -1;
  return send(fd,txt,(int)n,0)==(int)n ? 0 : -1;
}

static int read_text_frame(int fd, char* out, size_t outsz){
  unsigned char h[2];
  if(recv(fd,h,2,MSG_WAITALL)!=2) return -1;
  int opcode=h[0]&0x0F; int masked=h[1]&0x80; unsigned long long len=h[1]&0x7F;
  if(opcode==0x8) return -1;
  if(opcode!=0x1) return -1;

  if(len==126){
    unsigned char x[2]; if(recv(fd,x,2,MSG_WAITALL)!=2) return -1;
    len=(x[0]<<8)|x[1];
  }else if(len==127){
    unsigned char x[8]; if(recv(fd,x,8,MSG_WAITALL)!=8) return -1;
    len=0; for(int i=0;i<8;i++) len=(len<<8)|x[i];
    if(len>65535) return -1;
  }

  unsigned char mask[4]={0,0,0,0};
  if(masked){ if(recv(fd,mask,4,MSG_WAITALL)!=4) return -1; }
  if(len>=outsz) return -1;

  if(recv(fd,(unsigned char*)out,(int)len,MSG_WAITALL)!=(int)len) return -1;
  if(masked) for(size_t i=0;i<len;i++) out[i]^=mask[i&3];
  return (int)len;
}

/* ===================== thread loop ===================== */
static void add_client(ws_server* s, int fd){
  for(int i=0;i<MAXC;i++){
    if(s->cs[i].fd<=0){ s->cs[i].fd=fd; s->cs[i].alive=1; return; }
  }
  close(fd);
}

static void send_all(ws_server* s, const char* txt, size_t n){
  for(int i=0;i<MAXC;i++){
    int fd=s->cs[i].fd;
    if(fd>0 && send_text_frame(fd,txt,n)!=0){ close(fd); s->cs[i].fd=0; }
  }
}

static void* th_main(void* arg){
  ws_server* s=(ws_server*)arg;
  for(;;){
    fd_set rf; FD_ZERO(&rf); FD_SET(s->lfd,&rf); int maxfd=s->lfd;
    for(int i=0;i<MAXC;i++){
      if(s->cs[i].fd>0){ FD_SET(s->cs[i].fd,&rf); if(s->cs[i].fd>maxfd) maxfd=s->cs[i].fd; }
    }
    struct timeval tv={0,100*1000}; /* 100 ms */
    int rc=select(maxfd+1,&rf,NULL,NULL,&tv);
    if(rc<0){ if(errno==EINTR) continue; break; }

    if(FD_ISSET(s->lfd,&rf)){
      int cfd=accept(s->lfd,NULL,NULL);
      if(cfd>0 && handshake_ws(cfd)==0) add_client(s,cfd);
      else if(cfd>0) close(cfd);
    }

    /* read client requests */
    char buf[8192];
    for(int i=0;i<MAXC;i++){
      int fd=s->cs[i].fd;
      if(fd>0 && FD_ISSET(fd,&rf)){
        int n=read_text_frame(fd,buf,sizeof buf);
        if(n<=0){ close(fd); s->cs[i].fd=0; }
        else { buf[n]=0; handle_request(s,fd,buf); }
      }
    }

    /* broadcast queued events */
    blob_t b;
    while(rq_pop(&s->q,&b)){ send_all(s,b.s,b.n); free(b.s); }

    if(s->stop) break;
  }
  return NULL;
}
