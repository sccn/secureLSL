// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#ifndef LSL_INLET_H
#define LSL_INLET_H

#include "lsl_esp32_types.h"
#include "lsl_stream_info.h"
#include "lsl_security.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include <stdbool.h>

#define INLET_STOPPED_BIT BIT0
#define INLET_QUEUE_SLOTS 32

struct lsl_esp32_inlet {
    struct lsl_esp32_stream_info *info; /* owned stream info (transferred from caller) */
    int sock;                           /* TCP socket to outlet */
    QueueHandle_t sample_queue;         /* deserialized samples */
    TaskHandle_t recv_task;             /* receiver task handle */
    EventGroupHandle_t events;          /* shutdown coordination */
    size_t sample_data_size;            /* channel_count * bytes_per_channel */
    size_t queue_item_size;             /* sizeof(double) + sample_data_size */
    lsl_security_config_t security;
    lsl_security_session_t session; /* per-connection security session */
    volatile bool active;
    volatile bool connected;
    uint32_t drop_count; /* samples dropped due to queue overflow */
};

#endif /* LSL_INLET_H */
