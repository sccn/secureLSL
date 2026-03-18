// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#ifndef LSL_TCP_COMMON_H
#define LSL_TCP_COMMON_H

#include "lsl_security.h"
#include <stdint.h>
#include <stddef.h>

/* Send all bytes, handling partial writes. Returns 0 on success, -1 on error. */
int tcp_send_all(int sock, const void *data, size_t len);

/* Receive exactly n bytes from socket. Returns 0 on success, -1 on error. */
int tcp_recv_exact(int sock, void *buf, size_t n);

/* Read a line (up to CRLF) from socket. CRLF is stripped.
 * Returns line length (excluding CRLF) or -1 on error. */
int tcp_recv_line(int sock, char *buf, size_t buf_len);

/* Parse "Key: Value" from a header line. Returns pointer to value or NULL. */
const char *tcp_parse_header_value(const char *line, const char *key);

/* Read one encrypted chunk: [4B BE len][8B LE nonce][ciphertext+tag].
 * Decrypts into plaintext_out. Returns plaintext length, or -1 on error. */
int tcp_recv_encrypted_chunk(int sock, lsl_security_session_t *session, uint8_t *plaintext_out,
                             size_t plaintext_max, uint8_t *ct_buf, size_t ct_buf_size);

/* Send plaintext wrapped in an encrypted chunk: [4B BE len][8B LE nonce][ciphertext+tag].
 * Returns 0 on success, -1 on error. */
int tcp_send_encrypted_chunk(int sock, lsl_security_session_t *session, const uint8_t *plaintext,
                             size_t plaintext_len, uint8_t *ct_buf, size_t ct_buf_size);

#endif /* LSL_TCP_COMMON_H */
