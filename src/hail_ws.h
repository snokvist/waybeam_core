// hail_ws.h
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>
#include "hail.h"

typedef struct ws_server ws_server;

/* Start/stop the WebSocket bridge */
ws_server* ws_start(const char* ip, uint16_t port, hail_ctx* hail);
void       ws_stop(ws_server* s);

/* Push async events (called from hail callbacks) */
void ws_push_rx(ws_server* s, const hail_meta_t* m, const char* app_json, size_t app_len);
void ws_push_delivery(ws_server* s, const char* msg_id, const struct sockaddr_in* to, int ok);
