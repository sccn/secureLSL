// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#include "lsl_tcp_client.h"
#include "lsl_tcp_common.h"
#include "lsl_protocol.h"
#include "lsl_sample.h"
#include "lsl_security.h"
#include "lsl_key_manager.h"
#include "esp_log.h"
#include "sodium.h"

#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include <stdio.h>
#include <string.h>

static const char *TAG = "lsl_tcp_client";

/* Read and discard a null-terminated string from socket (fullinfo XML).
 * Desktop liblsl sends this after response headers. */
static int consume_null_terminated(int sock, size_t max_bytes)
{
    for (size_t i = 0; i < max_bytes; i++) {
        char c;
        int n = recv(sock, &c, 1, 0);
        if (n <= 0) {
            return -1;
        }
        if (c == '\0') {
            return (int)i;
        }
    }
    ESP_LOGW(TAG, "Null-terminated string exceeded %zu bytes", max_bytes);
    return -1;
}

int tcp_client_connect(const struct lsl_esp32_stream_info *info,
                       const lsl_security_config_t *security, lsl_security_session_t *session_out)
{
    if (!info || info->v4addr[0] == '\0' || info->v4data_port == 0) {
        ESP_LOGE(TAG, "Invalid stream info for TCP connection");
        return -1;
    }

    ESP_LOGI(TAG, "Connecting to %s:%d (uid=%s)", info->v4addr, info->v4data_port, info->uid);

    /* Create TCP socket */
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        ESP_LOGE(TAG, "Failed to create socket: errno %d", errno);
        return -1;
    }

    /* Set timeouts */
    struct timeval tv = {.tv_sec = 10, .tv_usec = 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    /* Connect */
    struct sockaddr_in dest = {
        .sin_family = AF_INET,
        .sin_port = htons(info->v4data_port),
    };
    if (inet_aton(info->v4addr, &dest.sin_addr) == 0) {
        ESP_LOGE(TAG, "Invalid address: %s", info->v4addr);
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        ESP_LOGE(TAG, "Connect failed: errno %d", errno);
        close(sock);
        return -1;
    }

    /* Set TCP_NODELAY for low latency */
    int nodelay = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

    ESP_LOGI(TAG, "Connected to %s:%d", info->v4addr, info->v4data_port);

    /* Send request: request line + headers + blank line.
     * Desktop liblsl tcp_server expects at minimum the request line
     * and reads headers until a blank line. We send the standard
     * negotiation headers matching what desktop data_receiver sends. */
    int our_security_enabled = (security && security->enabled) ? 1 : 0;

    char request[768];
    int req_len;
    if (our_security_enabled) {
        char our_pubkey_b64[LSL_KEY_BASE64_SIZE];
        sodium_bin2base64(our_pubkey_b64, sizeof(our_pubkey_b64), security->public_key,
                          LSL_KEY_PUBLIC_SIZE, sodium_base64_VARIANT_ORIGINAL);
        req_len = snprintf(request, sizeof(request),
                           "LSL:streamfeed/%d %s\r\n"
                           "Native-Byte-Order: 1234\r\n"
                           "Has-Clock-Offsets: 0\r\n"
                           "Endian-Performance: 0\r\n"
                           "Has-IEEE754-Floats: 1\r\n"
                           "Supports-Subnormals: 0\r\n"
                           "Value-Size: %zu\r\n"
                           "Max-Buffer-Length: 360\r\n"
                           "Max-Chunk-Length: 0\r\n"
                           "Protocol-Version: %d\r\n"
                           "Security-Enabled: true\r\n"
                           "Security-Public-Key: %s\r\n"
                           "\r\n",
                           LSL_ESP32_PROTOCOL_VERSION, info->uid,
                           stream_info_bytes_per_channel(info->channel_format),
                           LSL_ESP32_PROTOCOL_VERSION, our_pubkey_b64);
    } else {
        req_len = snprintf(request, sizeof(request),
                           "LSL:streamfeed/%d %s\r\n"
                           "Native-Byte-Order: 1234\r\n"
                           "Has-Clock-Offsets: 0\r\n"
                           "Endian-Performance: 0\r\n"
                           "Has-IEEE754-Floats: 1\r\n"
                           "Supports-Subnormals: 0\r\n"
                           "Value-Size: %zu\r\n"
                           "Max-Buffer-Length: 360\r\n"
                           "Max-Chunk-Length: 0\r\n"
                           "Protocol-Version: %d\r\n"
                           "Security-Enabled: false\r\n"
                           "\r\n",
                           LSL_ESP32_PROTOCOL_VERSION, info->uid,
                           stream_info_bytes_per_channel(info->channel_format),
                           LSL_ESP32_PROTOCOL_VERSION);
    }
    if (req_len < 0 || (size_t)req_len >= sizeof(request)) {
        ESP_LOGE(TAG, "Request too long");
        close(sock);
        return -1;
    }

    if (tcp_send_all(sock, request, (size_t)req_len) < 0) {
        ESP_LOGE(TAG, "Failed to send request");
        close(sock);
        return -1;
    }

    /* Read response status line: "LSL/110 200 OK\r\n" */
    char line[512];
    int line_len = tcp_recv_line(sock, line, sizeof(line));
    if (line_len < 0) {
        ESP_LOGE(TAG, "Failed to read response line");
        close(sock);
        return -1;
    }

    /* Check for success */
    if (strncmp(line, "LSL/", 4) != 0 || !strstr(line, "200")) {
        ESP_LOGE(TAG, "Server rejected connection: %s", line);
        close(sock);
        return -1;
    }

    ESP_LOGI(TAG, "Response: %s", line);

    /* Read response headers until empty line */
    int server_security_enabled = 0;
    char server_pubkey_b64[LSL_KEY_BASE64_SIZE] = {0};

    while (1) {
        line_len = tcp_recv_line(sock, line, sizeof(line));
        if (line_len < 0) {
            ESP_LOGE(TAG, "Failed to read response headers");
            close(sock);
            return -1;
        }
        if (line_len == 0) {
            break; /* empty line = end of headers */
        }

        /* Parse security headers */
        const char *val = tcp_parse_header_value(line, "Security-Enabled");
        if (val) {
            server_security_enabled = (strcmp(val, "true") == 0) ? 1 : 0;
        }
        val = tcp_parse_header_value(line, "Security-Public-Key");
        if (val) {
            if (strlen(val) >= sizeof(server_pubkey_b64)) {
                ESP_LOGW(TAG, "Security-Public-Key too long, will be truncated");
            }
            strncpy(server_pubkey_b64, val, sizeof(server_pubkey_b64) - 1);
        }

        ESP_LOGD(TAG, "Response header: %s", line);
    }

    /* Security verification (client side) */
    if (our_security_enabled != server_security_enabled) {
        ESP_LOGE(TAG, "Security mismatch: client=%s, server=%s",
                 our_security_enabled ? "enabled" : "disabled",
                 server_security_enabled ? "enabled" : "disabled");
        close(sock);
        return -1;
    }

    if (our_security_enabled) {
        if (!session_out) {
            ESP_LOGE(TAG, "Security enabled but session_out is NULL (caller bug)");
            close(sock);
            return -1;
        }

        if (strlen(server_pubkey_b64) >= sizeof(server_pubkey_b64) - 1) {
            ESP_LOGW(TAG, "Security-Public-Key header may be truncated");
        }

        lsl_esp32_err_t sec_err =
            security_handshake_verify(security, server_pubkey_b64, session_out);
        if (sec_err != LSL_ESP32_OK) {
            ESP_LOGE(TAG, "Security handshake failed: %d", sec_err);
            close(sock);
            return -1;
        }

        ESP_LOGI(TAG, "Security handshake: session key derived");
    }

    /* Check if fullinfo XML follows (desktop liblsl sends it, ESP32 outlet does not).
     * Peek at the first byte: '<' means XML, 0x01/0x02 means test pattern tag.
     * Note: in encrypted mode, desktop secureLSL sends fullinfo as plaintext before
     * encrypted data begins. ESP32 outlets do not send fullinfo, so the peek is safe
     * for both encrypted and unencrypted ESP32-to-ESP32 connections. Desktop interop
     * in encrypted mode may need encrypted fullinfo handling in the future. */
    int encrypted = (session_out && session_out->active);

    uint8_t peek_byte;
    int peek_n = recv(sock, &peek_byte, 1, MSG_PEEK);
    if (peek_n <= 0) {
        ESP_LOGE(TAG, "Connection lost during handshake (peek failed: %d)", peek_n);
        close(sock);
        return -1;
    }
    if (peek_byte == '<') {
        /* Consume null-terminated fullinfo XML (always plaintext, even in encrypted mode;
         * encryption only starts after test patterns, matching desktop secureLSL) */
        int xml_bytes = consume_null_terminated(sock, LSL_ESP32_FULLINFO_MAX);
        if (xml_bytes < 0) {
            ESP_LOGE(TAG, "Failed to consume fullinfo XML, stream desynchronized");
            close(sock);
            return -1;
        }
        ESP_LOGD(TAG, "Consumed fullinfo XML (%d bytes)", xml_bytes);
    } else {
        ESP_LOGD(TAG, "No fullinfo XML (ESP32 outlet), proceeding to test patterns");
    }

    /* Receive and validate 2 test-pattern samples (always plaintext).
     * Desktop secureLSL sends test patterns unencrypted even when security
     * is enabled; encryption starts only for streaming data that follows. */
    size_t bpc = stream_info_bytes_per_channel(info->channel_format);
    size_t sample_wire_size = 1 + 8 + (size_t)info->channel_count * bpc;
    uint8_t sample_buf[LSL_SAMPLE_MAX_BYTES];

    for (int pat = 0; pat < 2; pat++) {
        int offset = (pat == 0) ? LSL_ESP32_TEST_OFFSET_1 : LSL_ESP32_TEST_OFFSET_2;

        if (tcp_recv_exact(sock, sample_buf, sample_wire_size) < 0) {
            ESP_LOGE(TAG, "Failed to receive test pattern %d", pat + 1);
            close(sock);
            return -1;
        }

        /* Deserialize */
        uint8_t channel_data[LSL_ESP32_MAX_CHANNELS * 8];
        double timestamp;
        int consumed = sample_deserialize(sample_buf, sample_wire_size, info->channel_count,
                                          info->channel_format, channel_data, sizeof(channel_data),
                                          &timestamp);
        if (consumed <= 0) {
            ESP_LOGE(TAG, "Failed to deserialize test pattern %d", pat + 1);
            close(sock);
            return -1;
        }

        /* Validate */
        if (sample_validate_test_pattern(info->channel_count, info->channel_format, offset,
                                         LSL_ESP32_TEST_TIMESTAMP, channel_data, timestamp) != 0) {
            ESP_LOGE(TAG, "Test pattern %d validation failed", pat + 1);
            close(sock);
            return -1;
        }

        ESP_LOGI(TAG, "Test pattern %d: OK", pat + 1);
    }

    /* Clear receive timeout for streaming phase.
     * Irregular or low-rate streams may have long gaps between samples;
     * a timeout would cause spurious disconnections. */
    struct timeval no_timeout = {.tv_sec = 0, .tv_usec = 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &no_timeout, sizeof(no_timeout));

    ESP_LOGI(TAG, "Handshake complete, ready to receive samples%s",
             encrypted ? " (encrypted streaming)" : "");
    return sock;
}
