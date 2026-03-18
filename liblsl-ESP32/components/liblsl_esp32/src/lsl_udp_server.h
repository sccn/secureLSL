// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#ifndef LSL_UDP_SERVER_H
#define LSL_UDP_SERVER_H

#include "lsl_esp32_types.h"
#include "lsl_protocol.h"
#include "lsl_stream_info.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"

#define UDP_SERVER_STOPPED_BIT BIT0

typedef struct {
    struct lsl_esp32_stream_info *info;
    TaskHandle_t task_handle;
    EventGroupHandle_t events;
    int mcast_sock;
    volatile bool running;
    /* Pre-allocated response buffer (avoids malloc per query) */
    char response_buf[LSL_ESP32_SHORTINFO_MAX + 128];
} lsl_udp_server_t;

/* Start the UDP discovery responder and time service.
 * Spawns a FreeRTOS task that listens on multicast for LSL queries. */
lsl_esp32_err_t udp_server_start(lsl_udp_server_t *server, struct lsl_esp32_stream_info *info);

/* Stop the UDP server and clean up resources.
 * Blocks until the server task has exited (up to 2 seconds). */
void udp_server_stop(lsl_udp_server_t *server);

#endif /* LSL_UDP_SERVER_H */
