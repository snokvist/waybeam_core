#ifndef HAIL_H
#define HAIL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>

/* ------------------ version ------------------ */
#define HAIL_VERSION_MAJOR 1
#define HAIL_VERSION_MINOR 0
#define HAIL_VERSION_PATCH 0
const char* hail_version(void); /* e.g., "Hail/1.0.0" */

/* ------------------ constants ------------------ */

#define HAIL_DEFAULT_PORT 47929
#define HAIL_MAX_PACKET   1200      /* max UDP payload size */

#define HAIL_MSGID_LEN    18        /* "xxxxxxxx-xxxxxxxx" (17) + NUL */
#define HAIL_ID_LEN       17        /* 64-bit hex (16) + NUL */
#define HAIL_NONCE_HEXLEN 16        /* 8 bytes -> 16 hex chars (NUL stored in buffers sized +1) */

#define HAIL_MAX_ROLES    8
#define HAIL_MAX_CAPS     16
#define HAIL_MAX_NODES    256

/* Node expires if not seen within this window unless peer suggests expires_in */
#define HAIL_DEFAULT_EXPIRES_IN 12
#define HAIL_GRACE_EXPIRED_SEC  60

/* Replay cache horizon */
#define HAIL_REPLAY_WINDOW_SEC 30
#define HAIL_REPLAY_RING        512

/* Forwarding rules (defaults) */
#define HAIL_TTL_BEACON   0
#define HAIL_TTL_ANNOUNCE 0
#define HAIL_TTL_PING     0
#define HAIL_TTL_PONG     0
#define HAIL_TTL_DATA     2

/* ------------------ types ------------------ */

typedef struct {
    char     msg_id[HAIL_MSGID_LEN];
    char     correl_id[HAIL_MSGID_LEN]; /* "" if none */
    char     src_id[HAIL_ID_LEN];
    char     type[12];                  /* "BEACON","ANNOUNCE","PING","PONG","DATA","ACK","TOPOQ","TOPOA" */
    uint32_t src_ip;                    /* network order */
    uint16_t src_port;                  /* host order */
    int64_t  ts;
    int      hop;
    int      ttl;
    int      ack_req;                   /* hail.ack == 1 */
    int      signed_present;            /* hail.sig present (root key) */
    int      signed_ok;                 /* signature verified OK */
} hail_meta_t;

typedef struct hail_ctx hail_ctx;

/* Application callback for any valid message */
typedef void (*hail_on_message_fn)(
    hail_ctx *ctx,
    const hail_meta_t *meta,
    const char *app_json, size_t app_len,
    const struct sockaddr_in *from);

/* Reliable unicast delivery result */
typedef enum {
    HAIL_DELIVER_OK = 0,
    HAIL_DELIVER_TIMEOUT = 1
} hail_delivery_result_t;

/* Optional delivery callback for reliable unicast helper */
typedef void (*hail_on_delivery_fn)(
    hail_ctx *ctx,
    const char *msg_id,                 /* original msg_id we waited for ACK on */
    const struct sockaddr_in *to,
    hail_delivery_result_t result);

/* Node snapshot */
typedef struct {
    char     src_id[HAIL_ID_LEN];
    struct in_addr ip;
    uint16_t port;
    int64_t  last_seen_ts;
    int      last_hop;
    int      signed_ok;     /* 1 if last packet verified */
    int      active;        /* computed at snapshot time */
    int      pref_unicast;  /* best-effort from last seen */
    int      max_app_bytes; /* -1 unknown */
    int      relay_ok;      /* -1 unknown, 0 false, 1 true */
    char     alias[64];
} hail_node_t;

/* ------------------ API ------------------ */

/* Create and bind. ip_str may be "0.0.0.0". port==0 -> HAIL_DEFAULT_PORT. src_id NULL -> random 64-bit hex. */
hail_ctx* hail_create(const char *ip_str, uint16_t port, const char *src_id);


/* Optional: set the IP string to advertise inside hail{} (default "0.0.0.0") */
void hail_set_declared_ip(hail_ctx *ctx, const char *ip_str);


/* ---- identity helpers ---- */
void hail_set_alias(hail_ctx *ctx, const char *alias);

/* Set path where a persistent node id (src_id) is stored. Default: /etc/hail_nodeid */
void hail_set_nodeid_path(hail_ctx *ctx, const char *path);

/* Ensure ctx->src_id is set:
 * 1) if src_id already set (e.g., via hail_create param or hail_set_src_id), keep it
 * 2) else try to load from nodeid_path
 * 3) else create a random id, write to nodeid_path, and set it.
 * Returns 0 on success, -1 on failure (e.g., cannot write file).
 */
int  hail_ensure_src_id(hail_ctx *ctx);


/* Read-only view of the current src_id (NULL if ctx==NULL). */
const char* hail_get_src_id(const hail_ctx *ctx);

/* Explicitly set src_id from hex (8..32 hex chars recommended). Returns 0 on success, -1 on bad input. */
int  hail_set_src_id(hail_ctx *ctx, const char *hex);




/* Set callbacks (optional). */
void hail_set_on_message(hail_ctx *ctx, hail_on_message_fn cb);
void hail_set_on_delivery(hail_ctx *ctx, hail_on_delivery_fn cb);

/* Security: set pre-shared key bytes; len 0 clears. */
int  hail_set_psk(hail_ctx *ctx, const void *psk, size_t len);
/* If true, drop unsigned messages when PSK is set. */
void hail_require_signing(hail_ctx *ctx, int require);

/* Advertised properties for outgoing BEACON/ANNOUNCE. */
int  hail_set_roles(hail_ctx *ctx, const char **roles, size_t n);
int  hail_set_caps(hail_ctx *ctx,  const char **caps,  size_t n);
void hail_set_pref_unicast(hail_ctx *ctx, int pref);
void hail_set_max_app_bytes(hail_ctx *ctx, int n);
void hail_set_relay_ok(hail_ctx *ctx, int ok);

/* Timers / behavior */
void hail_set_beacon_interval_ms(hail_ctx *ctx, int ms);
void hail_set_expiry_seconds(hail_ctx *ctx, int s);

/* Send helpers (JSON in app_json must be object/array/null; no leading spaces).
   Returns 0 on success (queued/sent), -1 on immediate error. */
int hail_send_beacon(hail_ctx *ctx);
int hail_send_announce(hail_ctx *ctx, const char *app_json);
int hail_send_ping(hail_ctx *ctx, const char *dst_ip, uint16_t dst_port, const char *app_json);
int hail_send_pong(hail_ctx *ctx, const hail_meta_t *req_meta, const struct sockaddr_in *to);
int hail_send_data_broadcast(hail_ctx *ctx, int ttl, const char *app_json);
int hail_send_unicast(hail_ctx *ctx, const char *ip_str, uint16_t port,
                      const char *type, int hop, int ttl, int ack_req,
                      const char *app_json);

/* Reliable unicast DATA with ACK. Retries up to 'retries' times (>=1).
   per_try_timeout_ms per attempt. Returns 0 if ACKed, -1 if timed out.
   Also triggers on_delivery callback if set. */
int hail_send_data_unicast_reliable(hail_ctx *ctx, const char *ip_str, uint16_t port,
                                    const char *app_json, int retries, int per_try_timeout_ms);

/* Non-blocking reliable unicast: returns 0 queued, -1 on error. on_delivery() will be called later. */
int hail_send_data_unicast_reliable_async(hail_ctx *ctx, const char *ip_str, uint16_t port,
                                          const char *app_json, int retries, int per_try_timeout_ms,
                                          char out_msg_id[HAIL_MSGID_LEN]);


/* Topology query: broadcast TOPOQ with TTL; receivers reply TOPOA via unicast with neighbor list. */
int hail_request_topology(hail_ctx *ctx, int ttl);

/* Fills 'out' with this instance as a synthetic node (ip=declared_ip if set, else bind). */
void   hail_self_node(hail_ctx *ctx, hail_node_t *out);

/* Snapshot including self as the first entry. Returns count like hail_nodes_snapshot. */
size_t hail_nodes_snapshot_with_self(hail_ctx *ctx, hail_node_t *buf, size_t max, int include_expired);



/* Core poll: runs receive/forward work; timeout_ms <0 block, =0 poll. Returns 0/errno. */
int hail_poll(hail_ctx *ctx, int timeout_ms);

/* Node table snapshots */
size_t hail_nodes_snapshot(hail_ctx *ctx, hail_node_t *buf, size_t max, int include_expired);
int    hail_node_forget(hail_ctx *ctx, const char *src_id);
int    hail_node_is_active(hail_ctx *ctx, const char *src_id);


/* Debug helpers: copy last received JSON/slices into user buffers (returns length copied, 0 if none). */
int  hail_last_json(hail_ctx *ctx, char *out, size_t outsz);
int  hail_last_hail(hail_ctx *ctx, char *out, size_t outsz);
int  hail_last_app(hail_ctx *ctx, char *out, size_t outsz);

/* Destroy */
void hail_destroy(hail_ctx *ctx);

/* ------------------ compile-time sanity ------------------ */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(HAIL_MSGID_LEN >= 18, "HAIL_MSGID_LEN must be >= 18");
_Static_assert(HAIL_ID_LEN   >= 17, "HAIL_ID_LEN must be >= 17");
_Static_assert(HAIL_NONCE_HEXLEN == 16, "HAIL_NONCE_HEXLEN must be 16");
#endif

#ifdef __cplusplus
}
#endif
#endif /* HAIL_H */
