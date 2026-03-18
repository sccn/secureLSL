// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#ifndef LSL_TCP_SERVER_H
#define LSL_TCP_SERVER_H

#include "lsl_esp32_types.h"
#include "lsl_stream_info.h"
#include "lsl_ring_buffer.h"
#include "lsl_security.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#define TCP_SERVER_STOPPED_BIT BIT0

typedef struct {
    struct lsl_esp32_stream_info *info;
    lsl_ring_buffer_t *ring;
    const lsl_security_config_t *security; /* NULL = disabled; must outlive server */
    TaskHandle_t accept_task;
    EventGroupHandle_t events;
    int listen_sock;
    int active_connections;
    SemaphoreHandle_t conn_mutex;
    volatile bool running;
} lsl_tcp_server_t;

/* Start the TCP data server. Listens for LSL streamfeed connections.
 * Spawns an accept task and per-connection feed tasks.
 * The chosen TCP port is written to info->v4data_port.
 * security may be NULL to disable encryption. */
lsl_esp32_err_t tcp_server_start(lsl_tcp_server_t *server, struct lsl_esp32_stream_info *info,
                                 lsl_ring_buffer_t *ring, const lsl_security_config_t *security);

/* Stop the TCP server and close all connections.
 * Returns 0 if all feed tasks exited cleanly, or the number of
 * feed tasks still running after a bounded wait (10s). If >0,
 * the caller must not free resources that feed tasks may reference. */
int tcp_server_stop(lsl_tcp_server_t *server);

#endif /* LSL_TCP_SERVER_H */
