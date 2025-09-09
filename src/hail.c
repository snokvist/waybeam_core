#define _GNU_SOURCE
#include "hail.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <ifaddrs.h>
#include <net/if.h>



/* ------------------ version ------------------ */
const char* hail_version(void){
    return "Hail/"
        #define STR2(x) #x
        #define STR(x) STR2(x)
        STR(HAIL_VERSION_MAJOR) "." STR(HAIL_VERSION_MINOR) "." STR(HAIL_VERSION_PATCH)
        #undef STR
        #undef STR2
    ;
}





/* ===========================================================
   Tiny SHA-256 + HMAC (HAIL_CRYPTO_TINY)
   Compact public-domain-ish implementation.
   =========================================================== */

typedef struct {
    uint32_t h[8];
    uint64_t len;
    unsigned char buf[64];
    size_t idx;
} hail_sha256_ctx;

static uint32_t ROR(uint32_t x, uint32_t n){ return (x>>n)|(x<<(32-n)); }
static uint32_t Ch(uint32_t x,uint32_t y,uint32_t z){ return (x&y)^(~x&z); }
static uint32_t Maj(uint32_t x,uint32_t y,uint32_t z){ return (x&y)^(x&z)^(y&z); }
static uint32_t S0(uint32_t x){ return ROR(x,2)^ROR(x,13)^ROR(x,22); }
static uint32_t S1(uint32_t x){ return ROR(x,6)^ROR(x,11)^ROR(x,25); }
static uint32_t s0(uint32_t x){ return ROR(x,7)^ROR(x,18)^(x>>3); }
static uint32_t s1(uint32_t x){ return ROR(x,17)^ROR(x,19)^(x>>10); }

static const uint32_t K256[64]={
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha256_init(hail_sha256_ctx *c){
    c->h[0]=0x6a09e667; c->h[1]=0xbb67ae85; c->h[2]=0x3c6ef372; c->h[3]=0xa54ff53a;
    c->h[4]=0x510e527f; c->h[5]=0x9b05688c; c->h[6]=0x1f83d9ab; c->h[7]=0x5be0cd19;
    c->len=0; c->idx=0;
}

static void sha256_compress(hail_sha256_ctx *c, const unsigned char *p){
    uint32_t w[64];
    for(int i=0;i<16;i++){
        w[i]=(((uint32_t)p[i*4])<<24)|(((uint32_t)p[i*4+1])<<16)|(((uint32_t)p[i*4+2])<<8)|((uint32_t)p[i*4+3]);
    }
    for(int i=16;i<64;i++) w[i]=s1(w[i-2])+w[i-7]+s0(w[i-15])+w[i-16];
    uint32_t a=c->h[0], b=c->h[1], cc=c->h[2], d=c->h[3], e=c->h[4], f=c->h[5], g=c->h[6], h=c->h[7];
    for(int i=0;i<64;i++){
        uint32_t T1=h+S1(e)+Ch(e,f,g)+K256[i]+w[i];
        uint32_t T2=S0(a)+Maj(a,b,cc);
        h=g; g=f; f=e; e=d+T1; d=cc; cc=b; b=a; a=T1+T2;
    }
    c->h[0]+=a; c->h[1]+=b; c->h[2]+=cc; c->h[3]+=d; c->h[4]+=e; c->h[5]+=f; c->h[6]+=g; c->h[7]+=h;
}

static void sha256_update(hail_sha256_ctx *c, const void *data, size_t len){
    const unsigned char *p=(const unsigned char*)data;
    c->len += len;
    while(len--){
        c->buf[c->idx++]=*p++;
        if(c->idx==64){ sha256_compress(c,c->buf); c->idx=0; }
    }
}

static void sha256_final(hail_sha256_ctx *c, unsigned char out[32]){
    uint64_t bitlen = c->len * 8;
    c->buf[c->idx++]=0x80;
    if(c->idx>56){
        while(c->idx<64) c->buf[c->idx++]=0;
        sha256_compress(c,c->buf); c->idx=0;
    }
    while(c->idx<56) c->buf[c->idx++]=0;
    for(int i=7;i>=0;i--) c->buf[c->idx++]=(unsigned char)((bitlen>>(i*8))&0xFF);
    sha256_compress(c,c->buf);
    for(int i=0;i<8;i++){
        out[i*4+0]=(unsigned char)(c->h[i]>>24);
        out[i*4+1]=(unsigned char)(c->h[i]>>16);
        out[i*4+2]=(unsigned char)(c->h[i]>>8);
        out[i*4+3]=(unsigned char)(c->h[i]);
    }
}

static void hmac_sha256(const unsigned char *key, size_t keylen,
                        const unsigned char *msg, size_t msglen,
                        unsigned char mac[32]){
    unsigned char k_ipad[64], k_opad[64], kh[32];
    unsigned char keyblk[64]; memset(keyblk,0,64);
    if(keylen>64){
        hail_sha256_ctx t; sha256_init(&t); sha256_update(&t,key,keylen); sha256_final(&t,kh);
        memcpy(keyblk,kh,32);
    } else memcpy(keyblk,key,keylen);
    for(int i=0;i<64;i++){ k_ipad[i]=keyblk[i]^0x36; k_opad[i]=keyblk[i]^0x5c; }
    hail_sha256_ctx c; sha256_init(&c); sha256_update(&c,k_ipad,64); sha256_update(&c,msg,msglen); sha256_final(&c,kh);
    sha256_init(&c); sha256_update(&c,k_opad,64); sha256_update(&c,kh,32); sha256_final(&c,mac);
}

/* Base64 encode (RFC4648, no wrap). out must have >= 4*ceil(n/3)+1 bytes. */
static int b64_encode(const unsigned char* in, size_t n, char* out, size_t outsz){
    size_t o=0;
    for(size_t i=0; i<n; i+=3){
        unsigned v = in[i] << 16;
        int rem = (int)(n - i);
        if(rem > 1) v |= in[i+1] << 8;
        if(rem > 2) v |= in[i+2];
        if(o+4 >= outsz) return -1;
        static const char *B64="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        out[o++] = B64[(v>>18)&63];
        out[o++] = B64[(v>>12)&63];
        out[o++] = (rem>1) ? B64[(v>>6)&63] : '=';
        out[o++] = (rem>2) ? B64[v&63]      : '=';
    }
    if(o<outsz) out[o]=0;
    return (int)o;
}

/* ===========================================================
   Internals
   =========================================================== */

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

struct seen_entry { uint64_t id; time_t ts; };


typedef struct {
    char  key[32]; size_t len;
    int   require; /* drop unsigned when PSK present? */
} hail_psk_t;

typedef struct {
    char     id[HAIL_ID_LEN];
    struct in_addr ip;
    uint16_t port;
    int64_t  last_seen_ts;
    int      last_hop;
    int      signed_ok;
    int      pref_unicast;
    int      max_app_bytes;
    int      relay_ok; /* -1 unknown, 0 false, 1 true */
    char alias[64];
} node_entry_t;


#define HAIL_MAX_PENDING_ACK 64
typedef struct {
    int in_use;
    char msg_id[HAIL_MSGID_LEN];
    struct sockaddr_in to;
    int retries_left;
    int per_try_timeout_ms;
    int64_t next_deadline_ms;   /* monotonic-ish, in ms since epoch */
    char app[HAIL_MAX_PACKET];  /* copy of app JSON we send */
} hail_pend_ack_t;

struct hail_ctx {
    int                 sock;
    struct sockaddr_in  bind_addr;
    uint16_t            port;
    char                src_id[HAIL_ID_LEN];
    hail_on_message_fn  on_msg;
    hail_on_delivery_fn on_delivery;

    /* broadcast fanout list */
    struct sockaddr_in  bcast_list[32];
    int                 bcast_count;

    /* local addresses (for self-drop across multi-NIC) */
    struct in_addr      local_addrs[32];
    int                 local_addr_count;

    /* dedup ring */
    struct seen_entry   seen[HAIL_REPLAY_RING];
    size_t              seen_pos;

    /* replay cache (src_id+nonce hash) */
    uint64_t            replay[HAIL_REPLAY_RING];
    time_t              replay_ts[HAIL_REPLAY_RING];
    size_t              replay_pos;

    /* rx/tx buffer */
    char                buf[HAIL_MAX_PACKET+64];

    /* security */
    hail_psk_t          psk;

    /* advertised props */
    char   *roles[HAIL_MAX_ROLES]; size_t n_roles;
    char   *caps[HAIL_MAX_CAPS];   size_t n_caps;
    int     pref_unicast;
    int     max_app_bytes;
    int     relay_ok;

    /* timers */
    int     beacon_interval_ms;
    int     expiry_seconds;

    /* nodes */
    node_entry_t nodes[HAIL_MAX_NODES];
    size_t       n_nodes;

        /* debug stash of last RX */
    char last_json[HAIL_MAX_PACKET+1];
    char last_hail[1024];
    char last_app[1024];

    char declared_ip[16];  /* "0.0.0.0" by default */

    char alias[64];               /* optional friendly name */
    char nodeid_path[128];        /* where we load/store src_id; default set in hail_create */
    hail_pend_ack_t pend[HAIL_MAX_PENDING_ACK];

};


/* ------------------ helpers ------------------ */
static int write_all(int fd, const void *p, size_t n){
    const unsigned char *b=(const unsigned char*)p;
    while(n){
        ssize_t w=write(fd,b,n);
        if(w<0){ if(errno==EINTR) continue; return -1; }
        b+=w; n-=w;
    }
    return 0;
}


static int64_t now_ms(void){
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec*1000 + ts.tv_nsec/1000000;
}

static void pend_init(hail_ctx* ctx){ for(int i=0;i<HAIL_MAX_PENDING_ACK;i++) ctx->pend[i].in_use=0; }

static int pend_alloc(hail_ctx* ctx){
    for(int i=0;i<HAIL_MAX_PENDING_ACK;i++) if(!ctx->pend[i].in_use) return i;
    return -1;
}



static int is_local_ip(hail_ctx* ctx, uint32_t net_order_ip){
    for(int i=0;i<ctx->local_addr_count;i++){
        if (ctx->local_addrs[i].s_addr == net_order_ip) return 1;
    }
    return 0;
}


void hail_set_declared_ip(hail_ctx *ctx, const char *ip_str){
    if(!ctx) return;
    if(!ip_str || !*ip_str) { snprintf(ctx->declared_ip, sizeof ctx->declared_ip, "0.0.0.0"); return; }
    snprintf(ctx->declared_ip, sizeof ctx->declared_ip, "%s", ip_str);
}

int hail_last_json(hail_ctx *ctx, char *out, size_t outsz){
    if (!ctx || !out || outsz == 0) return 0;
    size_t n = strnlen(ctx->last_json, sizeof(ctx->last_json));
    if (n == 0) return 0;
    if (n >= outsz) n = outsz - 1;
    memcpy(out, ctx->last_json, n);
    out[n] = 0;
    return (int)n;
}
int hail_last_hail(hail_ctx *ctx, char *out, size_t outsz){
    if (!ctx || !out || outsz == 0) return 0;
    size_t n = strnlen(ctx->last_hail, sizeof(ctx->last_hail));
    if (n == 0) return 0;
    if (n >= outsz) n = outsz - 1;
    memcpy(out, ctx->last_hail, n);
    out[n] = 0;
    return (int)n;
}
int hail_last_app(hail_ctx *ctx, char *out, size_t outsz){
    if (!ctx || !out || outsz == 0) return 0;
    size_t n = strnlen(ctx->last_app, sizeof(ctx->last_app));
    if (n == 0) return 0;
    if (n >= outsz) n = outsz - 1;
    memcpy(out, ctx->last_app, n);
    out[n] = 0;
    return (int)n;
}


static int parse_hex_bytes(const char *hex, unsigned char *out, size_t *outlen){
    size_t w=0; int have_hi=0; unsigned hi=0;
    for(const char *p=hex; *p; ++p){
        unsigned char c=(unsigned char)*p;
        if(c==' '||c=='\t'||c==':'||c=='-'||c=='_'||c==',') continue;
        if((c=='x'||c=='X') && p>hex && p[-1]=='0') continue;
        unsigned v;
        if(c>='0'&&c<='9') v=c-'0';
        else if(c>='a'&&c<='f') v=c-'a'+10;
        else if(c>='A'&&c<='F') v=c-'A'+10;
        else return -1;
        if(!have_hi){ hi=v; have_hi=1; }
        else{
            if(w>=*outlen) return -1;
            out[w++]=(unsigned char)((hi<<4)|v);
            have_hi=0;
        }
    }
    if(have_hi) return -1;
    *outlen=w;
    return (w>0)?0:-1;
}


void hail_set_alias(hail_ctx *ctx, const char *alias){
    if(!ctx) return;
    if(!alias) { ctx->alias[0]=0; return; }
    snprintf(ctx->alias, sizeof ctx->alias, "%s", alias);
}

void hail_set_nodeid_path(hail_ctx *ctx, const char *path){
    if(!ctx) return;
    if(!path || !*path) return;
    snprintf(ctx->nodeid_path, sizeof ctx->nodeid_path, "%s", path);
}

int hail_set_src_id(hail_ctx *ctx, const char *hex){
    if(!ctx || !hex || !*hex) return -1;
    /* accept 8..32 hex nybbles (4..16 bytes), then print as lowercase hex without separators */
    unsigned char buf[16]; size_t blen=sizeof buf;
    if(parse_hex_bytes(hex, buf, &blen)!=0 || blen<4) return -1;
    /* store as compact lowercase hex, 2 chars per byte */
    size_t o=0;
    for(size_t i=0;i<blen && o+2<sizeof ctx->src_id; i++){
        o += (size_t)snprintf(ctx->src_id+o, sizeof ctx->src_id - o, "%02x", buf[i]);
    }
    ctx->src_id[o]=0;
    return 0;
}


const char* hail_get_src_id(const hail_ctx *ctx){
    if(!ctx) return NULL;
    return ctx->src_id;
}



static uint64_t rnd64(void){
    uint64_t x=0;
    FILE* f=fopen("/dev/urandom","rb");
    if(f){ fread(&x,1,sizeof x,f); fclose(f); }
    else { x = ((uint64_t)rand()<<32) ^ (uint64_t)rand(); }
    return x;
}

static void hex64(char out[17], uint64_t v){
    static const char h[]="0123456789abcdef";
    for(int i=15;i>=0;i--){ out[i]=h[v&0xF]; v>>=4; }
    out[16]=0;
}

static void hex_n(const unsigned char *bytes, size_t n, char *out){
    static const char h[]="0123456789abcdef";
    for(size_t i=0;i<n;i++){ out[i*2]=h[(bytes[i]>>4)&0xF]; out[i*2+1]=h[bytes[i]&0xF]; }
}

static void mk_msgid(char out[HAIL_MSGID_LEN]){
    char a[17], b[17];
    hex64(a, rnd64()); hex64(b, rnd64());
    memcpy(out, a, 8); out[8]='-'; memcpy(out+9, b, 8); out[17]=0; /* NUL at index 17 */
}

/* ---- helper: emit local TOPOA immediately after a TOPOQ ---- */
static void emit_local_topoa(hail_ctx *ctx, const char *correl_id){
    /* Build neighbors JSON (same structure as RX TOPOQ handling) */
    time_t now = time(NULL);
    char nb[800]; size_t o = 0;
    o += snprintf(nb + o, sizeof nb - o, "{\"neighbors\":[");
    int first = 1;
    for (size_t i = 0; i < ctx->n_nodes; i++) {
        node_entry_t *e = &ctx->nodes[i];
        int active = ((now - e->last_seen_ts) <= ctx->expiry_seconds);
        if (!active) continue;
        char ipbuf[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &e->ip, ipbuf, sizeof ipbuf);
        o += snprintf(nb + o, sizeof nb - o,
                      "%s{\"src_id\":\"%s\",\"ip\":\"%s\",\"port\":%u,\"age\":%ld}",
                      first ? "" : ",", e->id, ipbuf, (unsigned)e->port,
                      (long)(now - e->last_seen_ts));
        first = 0;
        if (o > 700) break;
    }
    o += snprintf(nb + o, sizeof nb - o, "]}");

    /* Synthesize meta as if we received it from ourselves */
    hail_meta_t m; memset(&m, 0, sizeof m);
    snprintf(m.type, sizeof m.type, "%s", "TOPOA");
    mk_msgid(m.msg_id);
    if (correl_id && *correl_id) snprintf(m.correl_id, sizeof m.correl_id, "%s", correl_id);
    snprintf(m.src_id, sizeof m.src_id, "%s", ctx->src_id);
    m.src_ip   = ctx->bind_addr.sin_addr.s_addr;   /* network order already */
    m.src_port = ctx->port;                        /* host order per struct */
    m.ts = (int64_t)time(NULL);
    m.hop = 0; m.ttl = 0; m.ack_req = 0;
    m.signed_present = 0; m.signed_ok = 0;

    struct sockaddr_in from = ctx->bind_addr;

    if (ctx->on_msg) ctx->on_msg(ctx, &m, nb, strlen(nb), &from);
}


static void fill_self_node_(hail_ctx *ctx, hail_node_t *n){
    memset(n, 0, sizeof *n);
    /* id */
    snprintf(n->src_id, sizeof n->src_id, "%s", ctx->src_id[0] ? ctx->src_id : "0000000000000000");
    /* ip preference: declared_ip (if any) else bound ip */
    if (ctx->declared_ip[0]) {
        inet_pton(AF_INET, ctx->declared_ip, &n->ip);
    } else {
        n->ip = ctx->bind_addr.sin_addr;
    }
    n->port          = ctx->port;
    n->last_seen_ts  = time(NULL);
    n->last_hop      = 0;
    n->signed_ok     = 1;          /* local trust */
    n->active        = 1;
    n->pref_unicast  = ctx->pref_unicast;
    n->max_app_bytes = ctx->max_app_bytes;
    n->relay_ok      = ctx->relay_ok;
    snprintf(n->alias, sizeof n->alias, "%s", ctx->alias);
}

void hail_self_node(hail_ctx *ctx, hail_node_t *out){
    if (!ctx || !out) return;
    fill_self_node_(ctx, out);
}

size_t hail_nodes_snapshot_with_self(hail_ctx *ctx, hail_node_t *buf, size_t max, int include_expired){
    size_t base = hail_nodes_snapshot(ctx, NULL, 0, include_expired); /* current neighbors only */
    size_t need = base + 1;
    if (!buf) return need;

    size_t w = 0;
    if (w < max) { fill_self_node_(ctx, &buf[w++]); }
    if (w < max) {
        /* write the rest right after self */
        w += hail_nodes_snapshot(ctx, buf + w, max - w, include_expired);
    } else {
        /* even if caller passed too small 'max', still report total needed */
    }
    return w;
}



static int make_nonblock(int fd){
    int fl=fcntl(fd,F_GETFL,0);
    return fcntl(fd,F_SETFL, fl|O_NONBLOCK);
}

static void build_broadcast_list(hail_ctx* ctx){
    ctx->bcast_count = 0;
    ctx->local_addr_count = 0;   /* <-- reset */

    struct ifaddrs *ifas=NULL;
    if(getifaddrs(&ifas)!=0) goto fallback;

    for(struct ifaddrs *ifa=ifas; ifa; ifa=ifa->ifa_next){
        if(!ifa->ifa_addr) continue;
        if(!(ifa->ifa_flags & IFF_UP)) continue;
        if(ifa->ifa_addr->sa_family != AF_INET) continue;
        if(ifa->ifa_flags & IFF_LOOPBACK) continue;

        /* record the local IPv4 */
        struct sockaddr_in *la = (struct sockaddr_in*)ifa->ifa_addr;
        if (la && ctx->local_addr_count < (int)(sizeof(ctx->local_addrs)/sizeof(ctx->local_addrs[0]))) {
            ctx->local_addrs[ctx->local_addr_count++] = la->sin_addr;
        }

        /* add the interface's broadcast (if present) to fanout */
        if(!(ifa->ifa_flags & IFF_BROADCAST)) continue;
        struct sockaddr_in *ba = (struct sockaddr_in*)ifa->ifa_broadaddr;
        if(!ba) continue;

        if(ctx->bcast_count < (int)(sizeof(ctx->bcast_list)/sizeof(ctx->bcast_list[0]))){
            struct sockaddr_in dst={0};
            dst.sin_family=AF_INET;
            dst.sin_port=htons(ctx->port);
            dst.sin_addr=ba->sin_addr;
            ctx->bcast_list[ctx->bcast_count++]=dst;
        }
    }
    freeifaddrs(ifas);


    /* Ensure the bound IP is also considered local (if not INADDR_ANY) */
    if (ctx->bind_addr.sin_addr.s_addr != htonl(INADDR_ANY)) {
        int present = 0;
        for (int i=0;i<ctx->local_addr_count;i++){
            if (ctx->local_addrs[i].s_addr == ctx->bind_addr.sin_addr.s_addr){ present=1; break; }
        }
        if (!present && ctx->local_addr_count < (int)(sizeof(ctx->local_addrs)/sizeof(ctx->local_addrs[0]))) {
            ctx->local_addrs[ctx->local_addr_count++] = ctx->bind_addr.sin_addr;
        }
    }




fallback:
    if(ctx->bcast_count==0){
        struct sockaddr_in dst={0};
        dst.sin_family=AF_INET; dst.sin_port=htons(ctx->port);
        inet_pton(AF_INET,"255.255.255.255",&dst.sin_addr);
        ctx->bcast_list[ctx->bcast_count++]=dst;
    }
}

static int send_json_to(hail_ctx* ctx, const char* json, const struct sockaddr_in* to){
    size_t n=strlen(json);
    if(n>HAIL_MAX_PACKET) return -1;
    ssize_t w=sendto(ctx->sock, json, n, 0, (const struct sockaddr*)to, sizeof *to);
    return (w==(ssize_t)n)?0:-1;
}






/* ---------- tiny JSON lookups (shallow) ---------- */

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

static int json_get_int(const char* j, const char* key, long long* out){
    const char* p=json_find_key(j,key); if(!p) return -1;
    char* e=NULL;
    long long v=strtoll(p,&e,10);
    if(e==p){ return -1; }
    *out=v; return 0;
}

static int json_get_bool01(const char* j, const char* key, int* out){
    const char* p=json_find_key(j,key); if(!p) return -1;
    if(!strncmp(p,"true",4)){ *out=1; return 0; }
    if(!strncmp(p,"false",5)){ *out=0; return 0; }
    long long v; if(json_get_int(j,key,&v)==0){ *out=(int)(v!=0); return 0; }
    return -1;
}


int hail_ensure_src_id(hail_ctx *ctx){
    if(!ctx) return -1;

    /* If an ID is already set (via hail_create param or hail_set_src_id),
       still make sure it EXISTS ON DISK so the demo can initialize /etc/hail_nodeid. */
    if(ctx->src_id[0]){
        FILE *f = fopen(ctx->nodeid_path, "r");
        if (f){
            fclose(f);                 /* file exists -> done */
            return 0;
        }
        /* Persist current src_id best-effort */
        int wfd = open(ctx->nodeid_path, O_CREAT|O_TRUNC|O_WRONLY, 0644);
        if(wfd>=0){
            (void)write_all(wfd, ctx->src_id, strlen(ctx->src_id));
            (void)write_all(wfd, "\n", 1);
            close(wfd);
            return 0;
        }
        return -1; /* couldn't persist, but src_id remains set in memory */
    }

    /* 1) try read existing file */
    FILE *f = fopen(ctx->nodeid_path, "r");
    if(f){
        char line[128]={0};
        if(fgets(line,sizeof line,f)){
            /* trim newline/space */
            size_t n=strlen(line);
            while(n && (line[n-1]=='\n' || line[n-1]=='\r' || line[n-1]==' ' || line[n-1]=='\t')) line[--n]=0;
            if(n>=8 && n<sizeof ctx->src_id){
                snprintf(ctx->src_id, sizeof ctx->src_id, "%s", line);
                fclose(f);
                return 0;
            }
        }
        fclose(f);
        /* fallthrough -> create */
    }

    /* 2) create random 8 bytes (16 hex chars) */
    unsigned char rnd[8]={0};
    int fd=open("/dev/urandom", O_RDONLY);
    if(fd>=0){
        ssize_t r=read(fd,rnd,sizeof rnd);
        close(fd);
        if(r!=(ssize_t)sizeof rnd){
            /* fallback to time/pid if urandom fails */
            uint64_t seed = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 16);
            for(size_t i=0;i<sizeof rnd;i++){ seed = seed*6364136223846793005ULL + 1; rnd[i]=(unsigned char)(seed>>56); }
        }
    } else {
        uint64_t seed = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 16);
        for(size_t i=0;i<sizeof rnd;i++){ seed = seed*6364136223846793005ULL + 1; rnd[i]=(unsigned char)(seed>>56); }
    }

    size_t o=0;
    for(size_t i=0;i<sizeof rnd && o+2<sizeof ctx->src_id; i++){
        o += (size_t)snprintf(ctx->src_id+o, sizeof ctx->src_id - o, "%02x", rnd[i]);
    }
    ctx->src_id[o]=0;

    /* 3) write file (best effort) */
    int wfd = open(ctx->nodeid_path, O_CREAT|O_TRUNC|O_WRONLY, 0644);
    if(wfd>=0){
        (void)write_all(wfd, ctx->src_id, strlen(ctx->src_id));
        (void)write_all(wfd, "\n", 1);
        close(wfd);
        return 0;
    }
    return -1; /* couldn't persist, but src_id is set in memory */
}




/* exact hail object slice */
static int json_find_hail_slice(const char* j, const char** hail, size_t* len){
    const char* p=json_find_key(j,"hail");
    if(!p || *p!='{') return -1;
    int depth=0; const char* q=p;
    do{ if(*q=='{') depth++; else if(*q=='}') depth--; q++; }while(*q && depth>0);
    if(depth!=0) return -1;
    *hail=p; *len=(size_t)(q-p); return 0;
}

/* app slice */
static int json_find_app_slice(const char* j, const char** app, size_t* len){
    const char* p = json_find_key(j, "app");
    if (!p) return -1;

    const char* q = p;

    if (*q == 'n') { /* null */
        if (!strncmp(q, "null", 4)) {
            *app = q;
            *len = 4;
            return 0;
        }
        return -1;
    }

    if (*q == '{') { /* object */
        int d = 0;
        do {
            if      (*q == '{') d++;
            else if (*q == '}') d--;
            q++;
        } while (*q && d > 0);
        if (d != 0) return -1;
        *app = p;
        *len = (size_t)(q - p);
        return 0;
    }

    if (*q == '[') { /* array */
        int d = 0;
        do {
            if      (*q == '[') d++;
            else if (*q == ']') d--;
            q++;
        } while (*q && d > 0);
        if (d != 0) return -1;
        *app = p;
        *len = (size_t)(q - p);
        return 0;
    }

    if (*q == '\"') { /* string */
        q++;
        while (*q && *q != '\"') q++;
        if (*q != '\"') return -1;
        q++; /* include closing quote */
        *app = p;
        *len = (size_t)(q - p);
        return 0;
    }

    /* number / bool / bare */
    while (*q && *q != ',' && *q != '}') {
        q++;
    }
    *app = p;
    *len = (size_t)(q - p);
    return 0;
}

/* seen msgid ring (dedup) */
static int seen_has(hail_ctx* ctx, uint64_t id){
    time_t now=time(NULL);
    for(size_t i=0;i<HAIL_REPLAY_RING;i++){
        if(ctx->seen[i].id==id && (now-ctx->seen[i].ts)<10) return 1;
    }
    return 0;
}
static void seen_add(hail_ctx* ctx, uint64_t id){
    ctx->seen[ctx->seen_pos].id=id;
    ctx->seen[ctx->seen_pos].ts=time(NULL);
    ctx->seen_pos=(ctx->seen_pos+1)%HAIL_REPLAY_RING;
}

/* replay cache key = hash(src_id || nonce_hex) */
static uint64_t hash_srcid_nonce(const char* src_id, const char* nonce16){
    uint64_t h=1469598103934665603ULL;
    for(const char* p=src_id; *p; ++p){ h^=(unsigned char)*p; h*=1099511628211ULL; }
    for(int i=0;i<HAIL_NONCE_HEXLEN && nonce16[i]; ++i){ h^=(unsigned char)nonce16[i]; h*=1099511628211ULL; }
    return h;
}
static int replay_seen(hail_ctx* ctx, uint64_t key){
    time_t now=time(NULL);
    for(size_t i=0;i<HAIL_REPLAY_RING;i++){
        if(ctx->replay[i]==key && (now-ctx->replay_ts[i])<HAIL_REPLAY_WINDOW_SEC) return 1;
    }
    return 0;
}
static void replay_add(hail_ctx* ctx, uint64_t key){
    ctx->replay[ctx->replay_pos]=key;
    ctx->replay_ts[ctx->replay_pos]=time(NULL);
    ctx->replay_pos=(ctx->replay_pos+1)%HAIL_REPLAY_RING;
}

/* node table */
static node_entry_t* node_get(hail_ctx* ctx, const char* src_id, int create){
    for(size_t i=0;i<ctx->n_nodes;i++){
        if(!strncmp(ctx->nodes[i].id,src_id,HAIL_ID_LEN)) return &ctx->nodes[i];
    }
    if(!create) return NULL;
    if(ctx->n_nodes>=HAIL_MAX_NODES) return NULL;
    node_entry_t *e=&ctx->nodes[ctx->n_nodes++];
    memset(e,0,sizeof *e);
    snprintf(e->id,sizeof e->id,"%s",src_id);
    e->relay_ok=-1; e->max_app_bytes=-1;
    return e;
}

/* canonical hail builder (without sig), fixed key order */
#define EMIT(...) do{ int n_=snprintf(out+o, outsz-o, __VA_ARGS__); if(n_<=0 || (size_t)n_>=outsz-o) return -1; o+=n_; }while(0)
static int build_canonical_hail(char *out, size_t outsz,
                                const char *type, const char *msg_id, const char *correl_id,
                                const char *src_id, const char *alias, const char *ip, unsigned port,
                                long long ts, int hop, int ttl,
                                int ack_req,
                                int pref_unicast, int max_app_bytes, int expires_in, int relay_ok,
                                const char **roles, size_t n_roles,
                                const char **caps,  size_t n_caps,
                                const char *nonce_or_null){
    size_t o=0;
    EMIT("{\"v\":1,\"type\":\"%s\",\"msg_id\":\"%s\",", type, msg_id);
    if(correl_id && correl_id[0]) EMIT("\"correl_id\":\"%s\",", correl_id);
    else                          EMIT("\"correl_id\":null,");
    EMIT("\"src_id\":\"%s\",\"ip\":\"%s\",\"port\":%u,\"ts\":%lld,\"hop\":%d,\"ttl\":%d,",
         src_id, ip, port, ts, hop, ttl);

    if(n_roles>0){
        EMIT("\"roles\":[");
        for(size_t i=0;i<n_roles;i++) EMIT(i?",\"%s\"":"\"%s\"", roles[i]);
        EMIT("],");
    }
    if(n_caps>0){
        EMIT("\"caps\":[");
        for(size_t i=0;i<n_caps;i++) EMIT(i?",\"%s\"":"\"%s\"", caps[i]);
        EMIT("],");
    }
    if (alias && alias[0]) {
        EMIT("\"alias\":\"%s\",", alias);   // no leading comma here, but DO add a trailing comma
    }

    EMIT("\"pref_unicast\":%s,", pref_unicast?"true":"false");
    if(max_app_bytes>=0) EMIT("\"max_app_bytes\":%d,", max_app_bytes);
    EMIT("\"expires_in\":%d,", (expires_in>0?expires_in:HAIL_DEFAULT_EXPIRES_IN));
    if(relay_ok>=0) EMIT("\"relay_ok\":%s,", relay_ok?"true":"false");
    if(ack_req)     EMIT("\"ack\":1,");
    if(nonce_or_null) EMIT("\"nonce\":\"%s\"", nonce_or_null);
    else { if(o>0 && out[o-1]==',') o--; }
    if(out[o-1]!='}') EMIT("}");
    return 0;
}
#undef EMIT

/* outer JSON with sig + app */
static int build_outer(char *out, size_t outsz,
                       const char *hail_part, const unsigned char *sig, size_t siglen,
                       const char *app, size_t app_len){
    if(sig && siglen){
        char b64[64]; int bl=b64_encode(sig,siglen,b64,sizeof b64); if(bl<0) return -1;
        int n=snprintf(out, outsz, "{\"hail\":%s,\"sig\":\"%s\",\"app\":%.*s}", hail_part, b64, (int)app_len, app);
        if(n<=0 || (size_t)n>=outsz) return -1;
        return 0;
    } else {
        int n=snprintf(out, outsz, "{\"hail\":%s,\"app\":%.*s}", hail_part, (int)app_len, app);
        if(n<=0 || (size_t)n>=outsz) return -1;
        return 0;
    }
}

/* sign hail||app with PSK */
static int sign_if_needed(hail_ctx* ctx,
                          const char *hail_canon, const char *app, size_t app_len,
                          unsigned char out_sig[32]){
    if(ctx->psk.len==0) return 0;
    size_t hlen=strlen(hail_canon);
    unsigned char *tmp = (unsigned char*)malloc(hlen + app_len);
    if(!tmp) return -1;
    memcpy(tmp, hail_canon, hlen); memcpy(tmp+hlen, app, app_len);
    hmac_sha256((const unsigned char*)ctx->psk.key, ctx->psk.len, tmp, hlen+app_len, out_sig);
    free(tmp);
    return 32;
}

/* --------------- public API ---------------- */

hail_ctx* hail_create(const char *ip_str, uint16_t port, const char *src_id){
    hail_ctx* ctx=(hail_ctx*)calloc(1,sizeof *ctx);
    if(!ctx) return NULL;

    snprintf(ctx->declared_ip, sizeof ctx->declared_ip, "0.0.0.0");
    ctx->alias[0] = 0;
    snprintf(ctx->nodeid_path, sizeof ctx->nodeid_path, "%s", "/etc/hail_nodeid");


    if(src_id && strlen(src_id)==HAIL_ID_LEN-1) snprintf(ctx->src_id,sizeof ctx->src_id,"%s",src_id);
    else { char hex[17]; hex64(hex,rnd64()); snprintf(ctx->src_id,sizeof ctx->src_id,"%s",hex); }
    ctx->port = port?port:HAIL_DEFAULT_PORT;

    ctx->sock = socket(AF_INET,SOCK_DGRAM,0);
    if(ctx->sock<0){ free(ctx); return NULL; }

    int yes=1;
    setsockopt(ctx->sock,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof yes);
    setsockopt(ctx->sock,SOL_SOCKET,SO_BROADCAST,&yes,sizeof yes);

    memset(&ctx->bind_addr,0,sizeof ctx->bind_addr);
    ctx->bind_addr.sin_family=AF_INET;
    ctx->bind_addr.sin_port=htons(ctx->port);
    if(!ip_str) ip_str="0.0.0.0";
    if(inet_pton(AF_INET,ip_str,&ctx->bind_addr.sin_addr)!=1){ close(ctx->sock); free(ctx); return NULL; }
    if(bind(ctx->sock,(struct sockaddr*)&ctx->bind_addr,sizeof ctx->bind_addr)!=0){ close(ctx->sock); free(ctx); return NULL; }

    make_nonblock(ctx->sock);
    build_broadcast_list(ctx);
    pend_init(ctx);

    ctx->pref_unicast=1; ctx->max_app_bytes=1024; ctx->relay_ok=1;
    ctx->beacon_interval_ms=3000; ctx->expiry_seconds=HAIL_DEFAULT_EXPIRES_IN;

    for(size_t i=0;i<HAIL_REPLAY_RING;i++){ ctx->seen[i].id=0; ctx->replay[i]=0; ctx->replay_ts[i]=0; }
    return ctx;
}

void hail_set_on_message(hail_ctx *ctx, hail_on_message_fn cb){ ctx->on_msg=cb; }
void hail_set_on_delivery(hail_ctx *ctx, hail_on_delivery_fn cb){ ctx->on_delivery=cb; }

int hail_set_psk(hail_ctx *ctx, const void *psk, size_t len){
    if(len>sizeof(ctx->psk.key)) len=sizeof(ctx->psk.key);
    memcpy(ctx->psk.key, psk, len); ctx->psk.len=len; return 0;
}
void hail_require_signing(hail_ctx *ctx, int require){ ctx->psk.require=require?1:0; }

int hail_set_roles(hail_ctx *ctx, const char **roles, size_t n){
    if(n>HAIL_MAX_ROLES) n=HAIL_MAX_ROLES;
    for(size_t i=0;i<ctx->n_roles;i++){ free(ctx->roles[i]); ctx->roles[i]=NULL; }
    ctx->n_roles=0;
    for(size_t i=0;i<n;i++){ ctx->roles[i]=strdup(roles[i]); if(ctx->roles[i]) ctx->n_roles++; }
    return 0;
}
int hail_set_caps(hail_ctx *ctx, const char **caps, size_t n){
    if(n>HAIL_MAX_CAPS) n=HAIL_MAX_CAPS;
    for(size_t i=0;i<ctx->n_caps;i++){ free(ctx->caps[i]); ctx->caps[i]=NULL; }
    ctx->n_caps=0;
    for(size_t i=0;i<n;i++){ ctx->caps[i]=strdup(caps[i]); if(ctx->caps[i]) ctx->n_caps++; }
    return 0;
}
void hail_set_pref_unicast(hail_ctx *ctx, int pref){ ctx->pref_unicast=pref?1:0; }
void hail_set_max_app_bytes(hail_ctx *ctx, int n){ ctx->max_app_bytes=n; }
void hail_set_relay_ok(hail_ctx *ctx, int ok){ ctx->relay_ok=ok?1:0; }
void hail_set_beacon_interval_ms(hail_ctx *ctx, int ms){ if(ms>200) ctx->beacon_interval_ms=ms; }
void hail_set_expiry_seconds(hail_ctx *ctx, int s){ if(s>1) ctx->expiry_seconds=s; }

/* ---------------- building + sending ---------------- */

static int build_and_send(hail_ctx *ctx, const struct sockaddr_in* to,
                          const char *type, const char *correl_id,
                          int hop, int ttl, int ack_req,
                          const char *app_json, const char *force_msg_id,
                          char out_msgid[HAIL_MSGID_LEN]){
    char msgid[HAIL_MSGID_LEN];
    if(force_msg_id) snprintf(msgid, sizeof msgid, "%s", force_msg_id);
    else mk_msgid(msgid);
    if(out_msgid) snprintf(out_msgid, HAIL_MSGID_LEN, "%s", msgid);

    long long ts=(long long)time(NULL);
    char hail_canon[1024];
    char nonce_hex[HAIL_NONCE_HEXLEN+1]={0};
    const char *nonce_use=NULL;

    if(ctx->psk.len>0){
        unsigned char nb[8]; uint64_t r=rnd64(); memcpy(nb,&r,8); hex_n(nb,8,nonce_hex); nonce_hex[HAIL_NONCE_HEXLEN]=0;
        nonce_use=nonce_hex;
    }

    if(!app_json) app_json="null";
    int expires_in = ctx->expiry_seconds>0 ? ctx->expiry_seconds : HAIL_DEFAULT_EXPIRES_IN;

    if(build_canonical_hail(hail_canon, sizeof hail_canon,
                            type, msgid, correl_id ? correl_id : NULL,
                            ctx->src_id, ctx->alias, ctx->declared_ip, ctx->port, ts, hop, ttl,
                            ack_req,
                            ctx->pref_unicast,ctx->max_app_bytes,expires_in,ctx->relay_ok,
                            (const char**)ctx->roles,ctx->n_roles,
                            (const char**)ctx->caps, ctx->n_caps,
                            nonce_use)<0) return -1;

    unsigned char sig[32]; int siglen=0;
    siglen=sign_if_needed(ctx, hail_canon, app_json, strlen(app_json), sig);
    if(siglen<0) return -1;

    if(build_outer(ctx->buf, sizeof ctx->buf, hail_canon,
                   (siglen>0?sig:NULL), (siglen>0?32:0),
                   app_json, strlen(app_json))<0) return -1;

    return send_json_to(ctx, ctx->buf, to);
}



int hail_send_data_unicast_reliable_async(hail_ctx *ctx, const char *ip_str, uint16_t port,
                                          const char *app_json, int retries, int per_try_timeout_ms,
                                          char out_msg_id[HAIL_MSGID_LEN]){
    if(retries<1) retries=3;
    if(per_try_timeout_ms<50) per_try_timeout_ms=300;

    struct sockaddr_in to={0};
    to.sin_family=AF_INET; to.sin_port=htons(port?port:ctx->port);
    if(inet_pton(AF_INET,ip_str,&to.sin_addr)!=1) return -1;

    int slot = pend_alloc(ctx);
    if(slot<0) return -1;

    hail_pend_ack_t *p=&ctx->pend[slot];
    memset(p,0,sizeof *p); p->in_use=1; p->to=to;
    p->retries_left=retries; p->per_try_timeout_ms=per_try_timeout_ms;

    /* first transmit (ttl=0 => no flooding, see section 2) */
    if(build_and_send(ctx,&to,"DATA",NULL,0,0,1, app_json, NULL, p->msg_id)!=0){
        p->in_use=0; return -1;
    }
    if(out_msg_id) snprintf(out_msg_id,HAIL_MSGID_LEN,"%s",p->msg_id);
    snprintf(p->app,sizeof p->app,"%s", app_json?app_json:"null");
    p->next_deadline_ms = now_ms() + per_try_timeout_ms;
    return 0;
}


int hail_send_beacon(hail_ctx *ctx){
    int rc=0;
    struct sockaddr_in to; memset(&to,0,sizeof to);
    for(int i=0;i<ctx->bcast_count;i++){
        to=ctx->bcast_list[i];
        if(build_and_send(ctx,&to,"BEACON",NULL,0,HAIL_TTL_BEACON,0,"null",NULL,NULL)!=0) rc=-1;
    }
    return rc;
}

int hail_send_announce(hail_ctx *ctx, const char *app_json){
    int rc=0; struct sockaddr_in to;
    for(int i=0;i<ctx->bcast_count;i++){
        to=ctx->bcast_list[i];
        if(build_and_send(ctx,&to,"ANNOUNCE",NULL,0,HAIL_TTL_ANNOUNCE,0,app_json,NULL,NULL)!=0) rc=-1;
    }
    return rc;
}

int hail_send_ping(hail_ctx *ctx, const char *dst_ip, uint16_t dst_port, const char *app_json){
    struct sockaddr_in to={0};
    to.sin_family=AF_INET; to.sin_port=htons(dst_port?dst_port:ctx->port);
    if(inet_pton(AF_INET,dst_ip,&to.sin_addr)!=1) return -1;
    return build_and_send(ctx,&to,"PING",NULL,0,HAIL_TTL_PING,0,app_json,NULL,NULL);
}

int hail_send_pong(hail_ctx *ctx, const hail_meta_t *req_meta, const struct sockaddr_in *to){
    return build_and_send(ctx,to,"PONG",req_meta->msg_id,0,HAIL_TTL_PONG,0,"null",NULL,NULL);
}

int hail_send_data_broadcast(hail_ctx *ctx, int ttl, const char *app_json){
    if(ttl<0) ttl=0;
    int rc=0; struct sockaddr_in to;
    for(int i=0;i<ctx->bcast_count;i++){
        to=ctx->bcast_list[i];
        if(build_and_send(ctx,&to,"DATA",NULL,0,(ttl>0?ttl:HAIL_TTL_DATA),0,app_json,NULL,NULL)!=0) rc=-1;
    }
    return rc;
}

int hail_send_unicast(hail_ctx *ctx, const char *ip_str, uint16_t port,
                      const char *type, int hop, int ttl, int ack_req,
                      const char *app_json){
    struct sockaddr_in to={0};
    to.sin_family=AF_INET; to.sin_port=htons(port?port:ctx->port);
    if(inet_pton(AF_INET,ip_str,&to.sin_addr)!=1) return -1;
    return build_and_send(ctx,&to,type,NULL,hop,ttl,ack_req,app_json,NULL,NULL);
}

/* ---------------- RX path + forward + behaviors ---------------- */

/* Forward decl: RX handler used by await_ack */
static int handle_rx(hail_ctx *ctx, const struct sockaddr_in *from);

static uint64_t parse_hex64_8_8(const char *s){
    uint64_t v=0;
    for(int i=0;i<8;i++){ char c=s[i]; int n=(c>='0'&&c<='9')?c-'0':(c>='a'&&c<='f')?c-'a'+10:(c>='A'&&c<='F')?c-'A'+10:0; v=(v<<4)|n; }
    for(int i=9;i<17;i++){ char c=s[i]; int n=(c>='0'&&c<='9')?c-'0':(c>='a'&&c<='f')?c-'a'+10:(c>='A'&&c<='F')?c-'A'+10:0; v=(v<<4)|n; }
    return v;
}

static int verify_signature(hail_ctx* ctx, const char* whole_json){
    if(ctx->psk.len==0) return 1;

    const char* sp=json_find_key(whole_json,"sig");
    if(!sp || *sp!='\"') return ctx->psk.require ? 0 : 1;
    sp++; const char* sq=sp; while(*sq && *sq!='\"') sq++;
    size_t sig_b64_len=(size_t)(sq-sp);
    char sig_b64[128]={0};
    if(sig_b64_len>=sizeof sig_b64) return 0;
    memcpy(sig_b64,sp,sig_b64_len); sig_b64[sig_b64_len]=0;

    const char *hail=NULL, *app=NULL; size_t hlen=0, alen=0;
    if(json_find_hail_slice(whole_json,&hail,&hlen)!=0) return 0;
    if(json_find_app_slice(whole_json,&app,&alen)!=0) return 0;

    unsigned char mac[32];
    size_t total = hlen + alen;
    unsigned char *tmp=(unsigned char*)malloc(total);
    if(!tmp) return 0;
    memcpy(tmp, hail, hlen);
    memcpy(tmp+hlen, app, alen);
    hmac_sha256((const unsigned char*)ctx->psk.key, ctx->psk.len, tmp, total, mac);
    free(tmp);

    char macb64[64]={0}; b64_encode(mac,32,macb64,sizeof macb64);

    char src_id[HAIL_ID_LEN]={0}, nonce[HAIL_NONCE_HEXLEN+1]={0};
    json_get_str(whole_json,"src_id",src_id,sizeof src_id);
    if(json_get_str(whole_json,"nonce",nonce,sizeof nonce)==0){
        uint64_t key = hash_srcid_nonce(src_id, nonce);
        if(replay_seen(ctx,key)) return 0;
        replay_add(ctx,key);
    }

    return (strcmp(macb64,sig_b64)==0);
}

/* Process one received datagram (ctx->buf contains NUL-terminated JSON) */
static int handle_rx(hail_ctx *ctx, const struct sockaddr_in *from){
    /* ===== Debug stash of last RX (whole JSON + hail{} + app) ===== */
    {
        size_t blen = strnlen(ctx->buf, sizeof(ctx->buf));
        if (blen >= sizeof(ctx->last_json)) blen = sizeof(ctx->last_json) - 1;
        memcpy(ctx->last_json, ctx->buf, blen);
        ctx->last_json[blen] = 0;

        const char *hb = NULL, *ab = NULL; size_t hl = 0, al = 0;
        if (json_find_hail_slice(ctx->buf, &hb, &hl) == 0) {
            if (hl >= sizeof(ctx->last_hail)) hl = sizeof(ctx->last_hail) - 1;
            memcpy(ctx->last_hail, hb, hl);
            ctx->last_hail[hl] = 0;
        } else {
            ctx->last_hail[0] = 0;
        }
        if (json_find_app_slice(ctx->buf, &ab, &al) == 0) {
            if (al >= sizeof(ctx->last_app)) al = sizeof(ctx->last_app) - 1;
            memcpy(ctx->last_app, ab, al);
            ctx->last_app[al] = 0;
        } else {
            ctx->last_app[0] = 0;
        }
    }
    /* >>> INSERT THIS BLOCK <<< */
    const char *app_src = NULL; size_t app_len = 0;
    if (json_find_app_slice(ctx->buf, &app_src, &app_len) != 0) { app_src = "null"; app_len = 4; }
    char appbuf[HAIL_MAX_PACKET];
    if (app_len >= sizeof appbuf) app_len = sizeof appbuf - 1;
    memcpy(appbuf, app_src, app_len); appbuf[app_len] = 0;

    /* Dedup quickly by msg_id */
    char msg_id[HAIL_MSGID_LEN] = {0};
    if (json_get_str(ctx->buf, "msg_id", msg_id, sizeof msg_id) != 0) return -1;
    uint64_t mid = parse_hex64_8_8(msg_id);
    if (seen_has(ctx, mid)) return 0;
    seen_add(ctx, mid);

    /* Signature verify if configured */
    int signed_ok = verify_signature(ctx, ctx->buf);
    if (ctx->psk.len > 0 && ctx->psk.require && !signed_ok) return -1;

    /* Parse minimal meta */
    hail_meta_t meta; memset(&meta, 0, sizeof meta);
    snprintf(meta.msg_id, sizeof meta.msg_id, "%s", msg_id);
    if (json_get_str(ctx->buf, "correl_id", meta.correl_id, sizeof meta.correl_id) != 0) meta.correl_id[0] = 0;
    json_get_str(ctx->buf, "src_id", meta.src_id, sizeof meta.src_id);
    json_get_str(ctx->buf, "type",   meta.type,   sizeof meta.type);
    long long ts = 0, hop = 0, ttl = 0;
    json_get_int(ctx->buf, "ts",  &ts);   meta.ts  = (int64_t)ts;
    json_get_int(ctx->buf, "hop", &hop);  meta.hop = (int)hop;
    json_get_int(ctx->buf, "ttl", &ttl);  meta.ttl = (int)ttl;
    int ack_req = 0; json_get_bool01(ctx->buf, "ack", &ack_req); meta.ack_req = ack_req;
    meta.signed_present = (json_find_key(ctx->buf, "sig") != NULL);
    meta.signed_ok = signed_ok;
    meta.src_ip = from->sin_addr.s_addr;
    meta.src_port = ntohs(from->sin_port);

    /* --- DROP SELF PACKETS (src_id or local IP) --- */
    if (!strcmp(meta.src_id, ctx->src_id))           return 0;
    if (is_local_ip(ctx, from->sin_addr.s_addr))     return 0;

    /* Update node table (keep existing behavior) */
    {
        node_entry_t* n = node_get(ctx, meta.src_id, 1);
        if (n) {
            n->ip = from->sin_addr;
            n->port = ntohs(from->sin_port);
            n->last_seen_ts = time(NULL);
            n->last_hop = meta.hop;
            n->signed_ok = meta.signed_ok;

            int pref = 0; if (json_get_bool01(ctx->buf,"pref_unicast",&pref)==0) n->pref_unicast = pref;
            long long mab = -1; if (json_get_int(ctx->buf,"max_app_bytes",&mab)==0) n->max_app_bytes = (int)mab;
            int rok = 0; if (json_get_bool01(ctx->buf,"relay_ok",&rok)==0) n->relay_ok = rok ? 1 : 0;

            /* NEW: capture alias into node entry */
            char alias_tmp[64] = "";
            if (json_get_str(ctx->buf,"alias",alias_tmp,sizeof alias_tmp)==0) {
                snprintf(n->alias, sizeof n->alias, "%s", alias_tmp);
            } else {
                n->alias[0] = 0;
            }
        }
    }

        /* When an ACK arrives, complete any matching pending entry */
    if (!strcmp(meta.type,"ACK") && meta.correl_id[0]){
        for(int i=0;i<HAIL_MAX_PENDING_ACK;i++){
            hail_pend_ack_t* p=&ctx->pend[i];
            if(!p->in_use) continue;
            if(strcmp(p->msg_id, meta.correl_id)==0){
                if(ctx->on_delivery) ctx->on_delivery(ctx,p->msg_id,&p->to,HAIL_DELIVER_OK);
                p->in_use=0;
                break;
            }
        }
    }


    /* ACK if requested (for unicast reliability) */
    if (ack_req && strcmp(meta.type, "ACK") != 0) {
        struct sockaddr_in to = *from;
        build_and_send(ctx, &to, "ACK", meta.msg_id, 0, HAIL_TTL_PONG, 0, "null", NULL, NULL);
    }

    /* Auto PONG to PING */
    if (!strcmp(meta.type, "PING")) {
        struct sockaddr_in to = *from;
        hail_send_pong(ctx, &meta, &to);
    }

    /* TOPOQ: reply TOPOA to sender with our 1-hop neighbors */
    if (!strcmp(meta.type, "TOPOQ")) {
        time_t now = time(NULL);
        char nb[800]; size_t o = 0;
        o += snprintf(nb + o, sizeof nb - o, "{\"neighbors\":[");
        int first = 1;
        for (size_t i = 0; i < ctx->n_nodes; i++) {
            node_entry_t *e = &ctx->nodes[i];
            int active = ((now - e->last_seen_ts) <= ctx->expiry_seconds);
            if (!active) continue;
            char ipbuf[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &e->ip, ipbuf, sizeof ipbuf);
            o += snprintf(nb + o, sizeof nb - o, "%s{\"src_id\":\"%s\",\"ip\":\"%s\",\"port\":%u,\"age\":%ld}",
                          first ? "" : ",", e->id, ipbuf, (unsigned)e->port, (long)(now - e->last_seen_ts));
            first = 0;
            if (o > 700) break;
        }
        o += snprintf(nb + o, sizeof nb - o, "]}");
        struct sockaddr_in to = *from;
        build_and_send(ctx, &to, "TOPOA", meta.msg_id, 0, 0, 0, nb, NULL, NULL);
    }

    /* Forward DATA only if ttl>0 AND it's not an acked-unicast */
    if (!strcmp(meta.type, "DATA") && meta.ttl > 0 && !meta.ack_req) {
        for (int i = 0; i < ctx->bcast_count; i++) {
            build_and_send(ctx, &ctx->bcast_list[i], "DATA",
                        NULL, meta.hop + 1, meta.ttl - 1, 0,
                        appbuf, meta.msg_id, NULL);
        }
    }

    /* Deliver to host application */
    /* Deliver to host application (use stable copy) */
    {
        if (ctx->on_msg) ctx->on_msg(ctx, &meta, appbuf, strlen(appbuf), from);
    }

    return 0;
}



/* -------- reliable unicast with ACK (blocking helper) -------- */

static int await_ack(hail_ctx *ctx, const char *expect_msgid,
                     const struct sockaddr_in *to, int timeout_ms){
    (void)to;
    time_t deadline = time(NULL) + (timeout_ms+999)/1000;

    while(time(NULL) <= deadline){
        struct timeval tv;
        int remain_ms = (int)(deadline - time(NULL)) * 1000;
        if(remain_ms < 0) remain_ms = 0;
        tv.tv_sec = remain_ms/1000;
        tv.tv_usec = (remain_ms%1000)*1000;

        fd_set rfds; FD_ZERO(&rfds); FD_SET(ctx->sock,&rfds);
        int s=select(ctx->sock+1,&rfds,NULL,NULL,&tv);
        if(s<0){ if(errno==EINTR) continue; return -1; }
        if(s==0) return 1; /* timeout */

        if(FD_ISSET(ctx->sock,&rfds)){
            struct sockaddr_in from; socklen_t flen=sizeof from;
            ssize_t r=recvfrom(ctx->sock, ctx->buf, sizeof(ctx->buf)-1, 0, (struct sockaddr*)&from, &flen);
            if(r<=0) continue;
            ctx->buf[r]=0;

            handle_rx(ctx,&from);

            char type[12]={0}; if(json_get_str(ctx->buf,"type",type,sizeof type)!=0) continue;
            if(strcmp(type,"ACK")!=0) continue;
            char correl[HAIL_MSGID_LEN]={0}; if(json_get_str(ctx->buf,"correl_id",correl,sizeof correl)!=0) continue;
            if(strcmp(correl,expect_msgid)==0) return 0;
        }
    }
    return 1; /* timeout */
}

int hail_send_data_unicast_reliable(hail_ctx *ctx, const char *ip_str, uint16_t port,
                                    const char *app_json, int retries, int per_try_timeout_ms){
    if(retries<1) retries=3;
    if(per_try_timeout_ms<50) per_try_timeout_ms=300;

    struct sockaddr_in to={0};
    to.sin_family=AF_INET; to.sin_port=htons(port?port:ctx->port);
    if(inet_pton(AF_INET,ip_str,&to.sin_addr)!=1) return -1;

    char msgid[HAIL_MSGID_LEN]={0};
    if(build_and_send(ctx,&to,"DATA",NULL,0,0,1,app_json,NULL,msgid)!=0) return -1;

    for(int attempt=0; attempt<retries; ++attempt){
        int res=await_ack(ctx,msgid,&to,per_try_timeout_ms);
        if(res==0){
            if(ctx->on_delivery) ctx->on_delivery(ctx,msgid,&to,HAIL_DELIVER_OK);
            return 0;
        }
        if(attempt<retries-1){
            if(build_and_send(ctx,&to,"DATA",NULL,0,HAIL_TTL_DATA,1,app_json,msgid,NULL)!=0) break;
        }
    }
    if(ctx->on_delivery) ctx->on_delivery(ctx,msgid,&to,HAIL_DELIVER_TIMEOUT);
    return -1;
}

/* ---- updated: request topology + emit local TOPOA ---- */
int hail_request_topology(hail_ctx *ctx, int ttl){
    if(ttl<0) ttl=0;

    /* Use a single msg_id for all TOPOQ fanouts so replies correlate nicely */
    char reqid[HAIL_MSGID_LEN]={0};
    mk_msgid(reqid);

    int rc=0; struct sockaddr_in to;
    for(int i=0;i<ctx->bcast_count;i++){
        to=ctx->bcast_list[i];
        if(build_and_send(ctx,&to,"TOPOQ",NULL,0,ttl,0,"null",reqid,NULL)!=0) rc=-1;
    }

    /* Immediately emit our own view as a TOPOA */
    emit_local_topoa(ctx, reqid);
    return rc;
}

int hail_poll(hail_ctx *ctx, int timeout_ms){
    struct timeval tv, *ptv=NULL; fd_set rfds;
    if(timeout_ms>=0){ tv.tv_sec=timeout_ms/1000; tv.tv_usec=(timeout_ms%1000)*1000; ptv=&tv; }
    FD_ZERO(&rfds); FD_SET(ctx->sock,&rfds);
    int s=select(ctx->sock+1,&rfds,NULL,NULL,ptv);
    if(s<0) return errno;
    if(s==0) return 0;
    if(FD_ISSET(ctx->sock,&rfds)){
        struct sockaddr_in from; socklen_t flen=sizeof from;
        ssize_t r=recvfrom(ctx->sock, ctx->buf, sizeof(ctx->buf)-1, 0, (struct sockaddr*)&from, &flen);
        if(r>0){ ctx->buf[r]=0; handle_rx(ctx,&from); }
    }
    int64_t now = now_ms();
    int retransmitted = 0;
    for(int i=0;i<HAIL_MAX_PENDING_ACK && retransmitted<4;i++){
        hail_pend_ack_t* p=&ctx->pend[i];
        if(!p->in_use) continue;
        if(now < p->next_deadline_ms) continue;

        if(p->retries_left > 0){
            p->retries_left--;
            /* reuse same msg_id so the ACK correlates */
            if(build_and_send(ctx,&p->to,"DATA",NULL,0,0,1, p->app, p->msg_id, NULL)==0){
                p->next_deadline_ms = now + p->per_try_timeout_ms;
                retransmitted++;
            }else{
                /* give up on send error */
                if(ctx->on_delivery) ctx->on_delivery(ctx,p->msg_id,&p->to,HAIL_DELIVER_TIMEOUT);
                p->in_use=0;
            }
        }else{
            if(ctx->on_delivery) ctx->on_delivery(ctx,p->msg_id,&p->to,HAIL_DELIVER_TIMEOUT);
            p->in_use=0;
        }
    }
    return 0;
}

/* ---------------- node snapshots ---------------- */

size_t hail_nodes_snapshot(hail_ctx *ctx, hail_node_t *buf, size_t max, int include_expired){
    time_t now=time(NULL);
    size_t needed=0;
    for(size_t i=0;i<ctx->n_nodes;i++){
        node_entry_t *e=&ctx->nodes[i];
        int active = ((now - e->last_seen_ts) <= ctx->expiry_seconds);
        if(!active && !include_expired) continue;
        needed++;
    }
    if(!buf) return needed;
    size_t w=0;
    for(size_t i=0;i<ctx->n_nodes && w<max;i++){
        node_entry_t *e=&ctx->nodes[i];
        int active = ((now - e->last_seen_ts) <= ctx->expiry_seconds);
        if(!active && !include_expired) continue;
        hail_node_t *n=&buf[w++];
        memset(n,0,sizeof *n);
        snprintf(n->src_id, sizeof n->src_id, "%s", e->id);
        n->ip=e->ip; n->port=e->port; n->last_seen_ts=e->last_seen_ts; n->last_hop=e->last_hop;
        n->signed_ok=e->signed_ok; n->active=active; n->pref_unicast=e->pref_unicast;
        n->max_app_bytes=e->max_app_bytes; n->relay_ok=e->relay_ok;
        snprintf(n->alias, sizeof n->alias, "%s", e->alias);
    }
    return w;
}

int hail_node_forget(hail_ctx *ctx, const char *src_id){
    for(size_t i=0;i<ctx->n_nodes;i++){
        if(!strncmp(ctx->nodes[i].id,src_id,HAIL_ID_LEN)){
            if(i!=ctx->n_nodes-1) ctx->nodes[i]=ctx->nodes[ctx->n_nodes-1];
            ctx->n_nodes--; return 0;
        }
    }
    return -1;
}

int hail_node_is_active(hail_ctx *ctx, const char *src_id){
    time_t now=time(NULL);
    node_entry_t* e=node_get(ctx,src_id,0); if(!e) return 0;
    return ((now - e->last_seen_ts) <= ctx->expiry_seconds);
}

/* ---------------- teardown ---------------- */

void hail_destroy(hail_ctx *ctx){
    if(!ctx) return;
    if(ctx->sock>=0) close(ctx->sock);
    for(size_t i=0;i<ctx->n_roles;i++) free(ctx->roles[i]);
    for(size_t i=0;i<ctx->n_caps;i++)  free(ctx->caps[i]);
    free(ctx);
}
