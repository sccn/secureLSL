// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#include "lsl_tcp_common.h"
#include "lsl_security.h"
#include "lsl_sample.h"
#include "lsl_protocol.h" /* LE compile-time check for nonce byte order */
#include "esp_log.h"

#include "lwip/sockets.h"
#include <string.h>
#include <strings.h> /* strncasecmp */

static const char *TAG = "lsl_tcp";

int tcp_send_all(int sock, const void *data, size_t len)
{
    const uint8_t *ptr = (const uint8_t *)data;
    size_t remaining = len;
    while (remaining > 0) {
        int sent = send(sock, ptr, remaining, 0);
        if (sent <= 0) {
            return -1;
        }
        ptr += sent;
        remaining -= (size_t)sent;
    }
    return 0;
}

int tcp_recv_exact(int sock, void *buf, size_t n)
{
    uint8_t *ptr = (uint8_t *)buf;
    size_t remaining = n;
    while (remaining > 0) {
        int received = recv(sock, ptr, remaining, 0);
        if (received <= 0) {
            return -1;
        }
        ptr += received;
        remaining -= (size_t)received;
    }
    return 0;
}

int tcp_recv_line(int sock, char *buf, size_t buf_len)
{
    size_t pos = 0;
    while (pos < buf_len - 1) {
        char c;
        int n = recv(sock, &c, 1, 0);
        if (n <= 0) {
            return -1;
        }
        buf[pos++] = c;
        if (pos >= 2 && buf[pos - 2] == '\r' && buf[pos - 1] == '\n') {
            buf[pos - 2] = '\0'; /* strip CRLF */
            return (int)(pos - 2);
        }
    }
    buf[pos] = '\0';
    ESP_LOGW(TAG, "Header line too long (%zu bytes), no CRLF found", pos);
    return -1;
}

const char *tcp_parse_header_value(const char *line, const char *key)
{
    size_t key_len = strlen(key);
    if (strncasecmp(line, key, key_len) != 0) {
        return NULL;
    }
    if (line[key_len] != ':') {
        return NULL;
    }
    const char *p = line + key_len + 1;
    while (*p == ' ') {
        p++;
    }
    return p;
}

/* Maximum valid encrypted payload: nonce + max_sample + auth_tag */
#define MAX_ENCRYPTED_PAYLOAD \
    (LSL_SECURITY_NONCE_WIRE_SIZE + LSL_SAMPLE_MAX_BYTES + LSL_SECURITY_AUTH_TAG_SIZE)

int tcp_recv_encrypted_chunk(int sock, lsl_security_session_t *session, uint8_t *plaintext_out,
                             size_t plaintext_max, uint8_t *ct_buf, size_t ct_buf_size)
{
    /* Read 4-byte big-endian payload length */
    uint8_t len_buf[4];
    if (tcp_recv_exact(sock, len_buf, 4) < 0) {
        ESP_LOGW(TAG, "Failed to read encrypted chunk length header");
        return -1;
    }
    uint32_t payload_len = ((uint32_t)len_buf[0] << 24) | ((uint32_t)len_buf[1] << 16) |
                           ((uint32_t)len_buf[2] << 8) | (uint32_t)len_buf[3];

    /* Must contain at least nonce + auth tag + 1 byte plaintext */
    if (payload_len < LSL_SECURITY_NONCE_WIRE_SIZE + LSL_SECURITY_AUTH_TAG_SIZE + 1) {
        ESP_LOGE(TAG, "Encrypted chunk too short: %lu bytes", (unsigned long)payload_len);
        return -1;
    }

    /* Reject obviously oversized payloads (protocol desync or malicious peer) */
    if (payload_len > MAX_ENCRYPTED_PAYLOAD) {
        ESP_LOGE(TAG, "Encrypted payload too large: %lu bytes (max %d)", (unsigned long)payload_len,
                 MAX_ENCRYPTED_PAYLOAD);
        return -1;
    }

    /* Read 8-byte little-endian nonce */
    uint64_t nonce;
    if (tcp_recv_exact(sock, &nonce, LSL_SECURITY_NONCE_WIRE_SIZE) < 0) {
        ESP_LOGW(TAG, "Failed to read encrypted chunk nonce");
        return -1;
    }

    /* Read ciphertext (payload_len - 8 bytes nonce) */
    size_t ct_len = payload_len - LSL_SECURITY_NONCE_WIRE_SIZE;
    if (ct_len > ct_buf_size) {
        ESP_LOGE(TAG, "Ciphertext too large for buffer: %zu bytes (max %zu)", ct_len, ct_buf_size);
        return -1;
    }
    if (tcp_recv_exact(sock, ct_buf, ct_len) < 0) {
        ESP_LOGW(TAG, "Failed to read encrypted chunk ciphertext (%zu bytes)", ct_len);
        return -1;
    }

    return security_decrypt(session, nonce, ct_buf, ct_len, plaintext_out, plaintext_max);
}

int tcp_send_encrypted_chunk(int sock, lsl_security_session_t *session, const uint8_t *plaintext,
                             size_t plaintext_len, uint8_t *ct_buf, size_t ct_buf_size)
{
    uint64_t nonce;
    int ct_len = security_encrypt(session, plaintext, plaintext_len, ct_buf, ct_buf_size, &nonce);
    if (ct_len < 0) {
        ESP_LOGE(TAG, "Encryption failed for %zu byte plaintext (session active=%d)", plaintext_len,
                 session ? session->active : -1);
        return -1;
    }

    /* Payload = nonce(8) + ciphertext(ct_len) */
    uint32_t payload_len = (uint32_t)(LSL_SECURITY_NONCE_WIRE_SIZE + ct_len);
    uint8_t header[4 + LSL_SECURITY_NONCE_WIRE_SIZE];

    /* 4 bytes big-endian payload length */
    header[0] = (uint8_t)(payload_len >> 24);
    header[1] = (uint8_t)(payload_len >> 16);
    header[2] = (uint8_t)(payload_len >> 8);
    header[3] = (uint8_t)(payload_len);

    /* 8 bytes little-endian nonce */
    memcpy(header + 4, &nonce, 8);

    if (tcp_send_all(sock, header, sizeof(header)) < 0) {
        return -1;
    }
    if (tcp_send_all(sock, ct_buf, (size_t)ct_len) < 0) {
        return -1;
    }
    return 0;
}
