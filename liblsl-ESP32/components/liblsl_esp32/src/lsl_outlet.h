// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#ifndef LSL_OUTLET_H
#define LSL_OUTLET_H

#include "lsl_esp32_types.h"
#include <stdbool.h>
#include "lsl_stream_info.h"
#include "lsl_ring_buffer.h"
#include "lsl_udp_server.h"
#include "lsl_tcp_server.h"
#include "lsl_security.h"

struct lsl_esp32_outlet {
    struct lsl_esp32_stream_info *info;
    lsl_ring_buffer_t ring;
    lsl_udp_server_t udp;
    lsl_tcp_server_t tcp;
    lsl_security_config_t security;
    int chunk_size;
    size_t sample_bytes; /* bytes per serialized sample (tag + ts + data) */
    volatile bool active;
};

#endif /* LSL_OUTLET_H */
