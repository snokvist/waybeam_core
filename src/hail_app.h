/* BEACON role executable maps
   Examples:
   - legacy: "{to} {lane} {params.bitrate_kbps} {params.mtu}"
   - new nested (preferred):
     "{to} {lane} {params.video0.codec} {params.video0.fps} {params.video0.size} "
     "{params.video0.rcMode} {params.video0.gopSize} {params.video0.bitrate} "
     "{params.isp.exposure} {params.image.contrast} {params.image.hue} {params.image.luminance} "
     "{params.audio.enabled} {params.records.enabled}"
*/
#pragma once
#include <stddef.h>
#include <netinet/in.h>
#include "hail.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ===== Return codes (stringified into JSON) ===== */
typedef enum {
  APP_OK = 0,
  APP_NO_PATH,
  APP_TIMEOUT,
  APP_BUSY,
  APP_DENIED,
  APP_BAD_ARGS,
  APP_INTERNAL
} app_code_t;

/* ===== Minimal decoded message ===== */
typedef struct {
  int v;                              /* version (optional, default 1) */
  char id[64];                        /* optional correlation id */
  char kind[12];                      /* cmd|event|ack|err */
  char topic[24];                     /* hail|presence|beam|stats|constellation */
  char action[16];                    /* request|update|cast|stop|save|load */
  const char* data_json;              /* malloc'ed copy of "data" (never NULL; "null" if absent) */
} app_msg_t;

/* ===== Per-role “module” configuration ===== */
typedef struct {
  /* Global role list from hail.conf, e.g. "relay,video,beacon" */
  char roles_csv[256];

  /* BEACON role executable maps */
  char beacon_exec_beam_cast[256];
  char beacon_exec_beam_update[256];
  char beacon_exec_beam_stop[256];
  char beacon_exec_beam_request[256];
  char beacon_allow_lanes[128];       /* csv: "udp,rtsp,srt" — empty means allow any */
  char beacon_busy_file[128];         /* path to mark WORKING/BUSY, e.g. "/tmp/beacon_busy" */
  /* --- Relay exec hooks + lanes --- */
  char relay_exec_update[256];
  char relay_exec_start[256];
  char relay_exec_stop[256];
  char relay_exec_request[256];
  char relay_allow_lanes[128];

  /* --- Porthole exec hooks + lanes --- */
  char porthole_exec_update[256];
  char porthole_exec_stop[256];
  char porthole_exec_control[256];
  char porthole_exec_request[256];
  char porthole_allow_lanes[128];

  /* --- Constellation exec hook --- */
  char constellation_exec_sync[256];

} app_modules_t;

/* ===== Lightweight runtime state (includes de-dupe ring) ===== */
typedef enum { ST_INIT=0, ST_WORKING=1, ST_ERROR=2 } app_state_t;

#ifndef APP_RECENT_MAX
#define APP_RECENT_MAX 32
#endif

typedef struct {
  app_state_t state;
  char recent_ids[APP_RECENT_MAX][64];  /* ring buffer of recently handled ids */
  int  recent_pos;                      /* next insert position (0..APP_RECENT_MAX-1) */
} app_runtime_t;

/* ===== API ===== */

/* Parse a top-level app JSON into app_msg_t (allocates data_json).
   Returns 0 on success; -1 on parse/contract failure. */
int app_parse_message(const char* txt, app_msg_t* out);

/* Free fields allocated by parse */
void app_free_message(app_msg_t* m);

/* Check if our local roles include a given role (fallback via hail payload if cfg roles not used) */
int app_has_role(hail_ctx* h, const char* role);

/* Handle an incoming Hail DATA app payload.
   If supported for our roles, dispatch and send back an app-level ack/err.
   `from` gives us reply IP/port.
   Returns 1 if handled, 0 if ignored, -1 on internal error. */
int app_handle_rx(hail_ctx* h,
                  const hail_meta_t* meta,
                  const char* app_json, size_t app_len,
                  const struct sockaddr_in* from,
                  const app_modules_t* cfg,
                  app_runtime_t* rt);

#ifdef __cplusplus
}
#endif
