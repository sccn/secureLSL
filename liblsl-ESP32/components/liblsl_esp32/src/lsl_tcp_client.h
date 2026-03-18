// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#ifndef LSL_TCP_CLIENT_H
#define LSL_TCP_CLIENT_H

#include "lsl_esp32_types.h"
#include "lsl_stream_info.h"
#include "lsl_security.h"

/* Connect to an LSL outlet via TCP and perform the protocol handshake.
 * Returns the connected socket fd on success, -1 on failure.
 * The handshake includes: sending streamfeed request, reading response
 * headers, consuming fullinfo XML, and validating test pattern samples.
 * If security is non-NULL and enabled, sends security headers and
 * derives session key on success (written to session_out).
 * session_out must not be NULL when security is enabled. */
int tcp_client_connect(const struct lsl_esp32_stream_info *info,
                       const lsl_security_config_t *security, lsl_security_session_t *session_out);

#endif /* LSL_TCP_CLIENT_H */
