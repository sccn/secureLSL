// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#include "lsl_tcp_server.h"
#include "lsl_tcp_common.h"
#include "lsl_clock.h"
#include "lsl_protocol.h"
#include "lsl_sample.h"
#include "lsl_security.h"
#include "lsl_key_manager.h"
#include "esp_log.h"
#include "sodium.h"

#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *TAG = "lsl_tcp_server";

#define TCP_ACCEPT_STACK 4096
#define TCP_ACCEPT_PRIO  6
#define TCP_FEED_STACK   8192
#define TCP_FEED_PRIO    7
#define TCP_RECV_BUF     2048
#define TCP_HEADER_MAX   1024

/* Error response strings (use sizeof-1 to avoid manual length counting) */
static const char RESP_400[] = "LSL/110 400 Bad Request\r\n\r\n";
static const char RESP_403[] = "LSL/110 403 Forbidden\r\n\r\n";
static const char RESP_404[] = "LSL/110 404 Not found\r\n\r\n";
static const char RESP_500[] = "LSL/110 500 Internal Error\r\n\r\n";

/* Context passed to each feed task */
typedef struct {
    lsl_tcp_server_t *server;
    int client_sock;
    lsl_ring_consumer_t consumer;
    lsl_security_session_t session; /* per-connection session (inactive when security disabled) */
} feed_ctx_t;

/* Handle one connected client: protocol negotiation, test patterns, streaming */
static void feed_task(void *arg)
{
    feed_ctx_t *ctx = (feed_ctx_t *)arg;
    lsl_tcp_server_t *server = ctx->server;
    int sock = ctx->client_sock;
    char line_buf[TCP_HEADER_MAX];
    uint8_t *ct_buf = NULL; /* heap-allocated if encrypted; freed in cleanup */

    ESP_LOGI(TAG, "Feed task started for client fd=%d", sock);

    /* Read request line: "LSL:streamfeed/110 <uid>\r\n" */
    int line_len = tcp_recv_line(sock, line_buf, sizeof(line_buf));
    if (line_len < 0) {
        ESP_LOGW(TAG, "Failed to read request line");
        goto cleanup;
    }

    /* Validate request */
    if (strncmp(line_buf, "LSL:streamfeed/", 15) != 0) {
        ESP_LOGW(TAG, "Invalid request: %s", line_buf);
        tcp_send_all(sock, RESP_400, sizeof(RESP_400) - 1);
        goto cleanup;
    }

    /* Check protocol version */
    int proto_ver = 0;
    char req_uid[64] = {0};
    if (sscanf(line_buf + 15, "%d %63s", &proto_ver, req_uid) < 1) {
        ESP_LOGW(TAG, "Cannot parse protocol version from: %s", line_buf);
        tcp_send_all(sock, RESP_400, sizeof(RESP_400) - 1);
        goto cleanup;
    }

    ESP_LOGI(TAG, "Request: proto=%d uid=%s", proto_ver, req_uid);

    /* Validate UID if provided */
    if (req_uid[0] != '\0' && strcmp(req_uid, server->info->uid) != 0) {
        ESP_LOGW(TAG, "UID mismatch: got '%s', expected '%s'", req_uid, server->info->uid);
        tcp_send_all(sock, RESP_404, sizeof(RESP_404) - 1);
        goto cleanup;
    }

    /* Read request headers until empty line (CRLF CRLF) */
    int client_security_enabled = 0;
    char client_pubkey_b64[LSL_KEY_BASE64_SIZE] = {0};

    while (1) {
        line_len = tcp_recv_line(sock, line_buf, sizeof(line_buf));
        if (line_len < 0) {
            goto cleanup;
        }
        if (line_len == 0) {
            break; /* empty line = end of headers */
        }

        /* Parse security headers */
        const char *val = tcp_parse_header_value(line_buf, "Security-Enabled");
        if (val) {
            client_security_enabled = (strcmp(val, "true") == 0) ? 1 : 0;
        }
        val = tcp_parse_header_value(line_buf, "Security-Public-Key");
        if (val) {
            if (strlen(val) >= sizeof(client_pubkey_b64)) {
                ESP_LOGW(TAG, "Security-Public-Key too long, will be truncated");
            }
            strncpy(client_pubkey_b64, val, sizeof(client_pubkey_b64) - 1);
        }

        ESP_LOGD(TAG, "Client header: %s", line_buf);
    }

    /* Security negotiation */
    int our_security_enabled = (server->security && server->security->enabled) ? 1 : 0;

    /* Unanimous enforcement: both must agree */
    if (our_security_enabled != client_security_enabled) {
        ESP_LOGW(TAG, "Security mismatch: server=%s, client=%s",
                 our_security_enabled ? "enabled" : "disabled",
                 client_security_enabled ? "enabled" : "disabled");
        if (tcp_send_all(sock, RESP_403, sizeof(RESP_403) - 1) < 0) {
            ESP_LOGW(TAG, "Failed to send 403 rejection");
        }
        goto cleanup;
    }

    /* If security enabled, verify public key match and derive session key */
    if (our_security_enabled) {
        if (strlen(client_pubkey_b64) >= sizeof(client_pubkey_b64) - 1) {
            ESP_LOGW(TAG, "Security-Public-Key header may be truncated");
        }

        lsl_esp32_err_t sec_err =
            security_handshake_verify(server->security, client_pubkey_b64, &ctx->session);
        if (sec_err != LSL_ESP32_OK) {
            /* Invalid key or mismatch = 403; derivation failure = 500 */
            const char *resp_err =
                (sec_err == LSL_ESP32_ERR_INVALID_ARG || sec_err == LSL_ESP32_ERR_SECURITY)
                    ? RESP_403
                    : RESP_500;
            size_t resp_err_len =
                (resp_err == RESP_403) ? sizeof(RESP_403) - 1 : sizeof(RESP_500) - 1;
            if (tcp_send_all(sock, resp_err, resp_err_len) < 0) {
                ESP_LOGW(TAG, "Failed to send rejection response");
            }
            goto cleanup;
        }

        ESP_LOGI(TAG, "Security handshake: session key derived");
    }

    /* Build response headers */
    char resp[512];
    int resp_len;
    if (our_security_enabled) {
        char our_pubkey_b64[LSL_KEY_BASE64_SIZE];
        sodium_bin2base64(our_pubkey_b64, sizeof(our_pubkey_b64), server->security->public_key,
                          LSL_KEY_PUBLIC_SIZE, sodium_base64_VARIANT_ORIGINAL);
        resp_len = snprintf(resp, sizeof(resp),
                            "LSL/110 200 OK\r\n"
                            "UID: %s\r\n"
                            "Byte-Order: 1234\r\n"
                            "Data-Protocol-Version: 110\r\n"
                            "Security-Enabled: true\r\n"
                            "Security-Public-Key: %s\r\n"
                            "\r\n",
                            server->info->uid, our_pubkey_b64);
    } else {
        resp_len = snprintf(resp, sizeof(resp),
                            "LSL/110 200 OK\r\n"
                            "UID: %s\r\n"
                            "Byte-Order: 1234\r\n"
                            "Data-Protocol-Version: 110\r\n"
                            "Security-Enabled: false\r\n"
                            "\r\n",
                            server->info->uid);
    }

    if (resp_len < 0 || (size_t)resp_len >= sizeof(resp)) {
        ESP_LOGE(TAG, "Response header truncated (need %d, have %zu)", resp_len, sizeof(resp));
        goto cleanup;
    }
    if (tcp_send_all(sock, resp, (size_t)resp_len) < 0) {
        ESP_LOGE(TAG, "Failed to send response headers");
        goto cleanup;
    }

    ESP_LOGI(TAG, "Sent response headers (%d bytes, security=%s)", resp_len,
             our_security_enabled ? "on" : "off");

    /* Note: desktop liblsl's tcp_server sends fullinfo XML after headers,
     * but the desktop inlet (data_receiver) reads it as a null-terminated
     * string before expecting test samples. However, testing shows pylsl
     * works without it (it gets stream info from the discovery response).
     * Adding it here breaks test pattern validation, so we skip it for now
     * and will investigate the exact protocol sequence if needed. */

    /* Send 2 test-pattern samples (always plaintext, matching desktop secureLSL).
     * Desktop sends test patterns unencrypted even when security is enabled;
     * encryption starts only for the streaming data that follows. */
    uint8_t sample_buf[LSL_SAMPLE_MAX_BYTES];
    int sample_len;
    /* Session state is fixed: established during handshake or never. Does not change mid-stream. */
    int encrypted = ctx->session.active;

    for (int pat = 0; pat < 2; pat++) {
        int offset = (pat == 0) ? LSL_ESP32_TEST_OFFSET_1 : LSL_ESP32_TEST_OFFSET_2;
        sample_len = sample_generate_test_pattern(
            server->info->channel_count, server->info->channel_format, offset,
            LSL_ESP32_TEST_TIMESTAMP, sample_buf, sizeof(sample_buf));
        if (sample_len <= 0) {
            ESP_LOGE(TAG, "Failed to generate test pattern %d (ret=%d)", pat + 1, sample_len);
            goto cleanup;
        }
        if (tcp_send_all(sock, sample_buf, (size_t)sample_len) < 0) {
            ESP_LOGE(TAG, "Failed to send test pattern %d", pat + 1);
            goto cleanup;
        }
    }

    ESP_LOGI(TAG, "Sent 2 test-pattern samples, starting data stream");

    /* Log stack high-water mark after handshake (most stack-intensive phase) */
    ESP_LOGD(TAG, "Feed task stack HWM: %u words free",
             (unsigned)uxTaskGetStackHighWaterMark(NULL));

    /* Allocate ciphertext buffer for streaming (only when encrypted) */
    size_t ct_size = LSL_SAMPLE_MAX_BYTES + LSL_SECURITY_AUTH_TAG_SIZE;
    ct_buf = encrypted ? malloc(ct_size) : NULL;
    if (encrypted && !ct_buf) {
        ESP_LOGE(TAG, "Failed to allocate ciphertext buffer");
        goto cleanup;
    }

    /* Initialize consumer at current ring buffer position */
    ring_buffer_consumer_init(server->ring, &ctx->consumer);

    /* Stream samples from ring buffer (encrypted if session active) */
    while (server->running) {
        size_t nbytes =
            ring_buffer_read(server->ring, &ctx->consumer, sample_buf, sizeof(sample_buf));
        if (nbytes > 0) {
            int send_ret;
            if (encrypted) {
                send_ret = tcp_send_encrypted_chunk(sock, &ctx->session, sample_buf, nbytes, ct_buf,
                                                    ct_size);
            } else {
                send_ret = tcp_send_all(sock, sample_buf, nbytes);
            }
            if (send_ret < 0) {
                ESP_LOGI(TAG, "Client disconnected (send failed)");
                break;
            }
        } else {
            /* No data available; yield briefly */
            vTaskDelay(1);
        }
    }

cleanup:
    free(ct_buf);
    security_session_clear(&ctx->session);
    close(sock);
    ESP_LOGI(TAG, "Feed task ended for client fd=%d", ctx->client_sock);

    /* Decrement connection count (mandatory; use portMAX_DELAY to prevent leak) */
    if (server->conn_mutex && xSemaphoreTake(server->conn_mutex, portMAX_DELAY) == pdTRUE) {
        server->active_connections--;
        ESP_LOGI(TAG, "Active connections: %d", server->active_connections);
        xSemaphoreGive(server->conn_mutex);
    }

    free(ctx);
    vTaskDelete(NULL);
}

static void accept_task(void *arg)
{
    lsl_tcp_server_t *server = (lsl_tcp_server_t *)arg;

    ESP_LOGI(TAG, "TCP accept task started on port %d", server->info->v4data_port);

    while (server->running) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);

        int client_sock = accept(server->listen_sock, (struct sockaddr *)&client_addr, &addr_len);
        if (client_sock < 0) {
            if (!server->running) {
                break;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            ESP_LOGE(TAG, "accept error: errno %d", errno);
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        ESP_LOGI(TAG, "New connection from %s:%d", inet_ntoa(client_addr.sin_addr),
                 ntohs(client_addr.sin_port));

        /* Check connection limit */
        int can_accept = 0;
        if (xSemaphoreTake(server->conn_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
            if (server->active_connections < LSL_ESP32_MAX_CONNECTIONS) {
                server->active_connections++;
                can_accept = 1;
            }
            xSemaphoreGive(server->conn_mutex);
        }

        if (!can_accept) {
            ESP_LOGW(TAG, "Max connections (%d) reached, rejecting", LSL_ESP32_MAX_CONNECTIONS);
            send(client_sock, "LSL/110 503 Service Unavailable\r\n\r\n", 35, 0);
            close(client_sock);
            continue;
        }

        /* Set TCP_NODELAY for low latency */
        int nodelay = 1;
        setsockopt(client_sock, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

        /* Set keepalive */
        int keepalive = 1;
        setsockopt(client_sock, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));

        /* Set receive timeout to prevent feed task from blocking forever
         * on a slow/malicious client during header parsing */
        struct timeval client_tv = {.tv_sec = 10, .tv_usec = 0};
        setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, &client_tv, sizeof(client_tv));

        /* Set send timeout to prevent feed task from blocking indefinitely
         * on a stalled client (critical for clean shutdown) */
        struct timeval send_tv = {.tv_sec = 5, .tv_usec = 0};
        setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, &send_tv, sizeof(send_tv));

        /* Spawn feed task */
        feed_ctx_t *ctx = calloc(1, sizeof(feed_ctx_t));
        if (!ctx) {
            ESP_LOGE(TAG, "Failed to allocate feed context");
            close(client_sock);
            if (xSemaphoreTake(server->conn_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
                server->active_connections--;
                xSemaphoreGive(server->conn_mutex);
            }
            continue;
        }

        ctx->server = server;
        ctx->client_sock = client_sock;

        char task_name[16];
        snprintf(task_name, sizeof(task_name), "lsl_feed_%d", server->active_connections);

        BaseType_t ret = xTaskCreatePinnedToCore(feed_task, task_name, TCP_FEED_STACK, (void *)ctx,
                                                 TCP_FEED_PRIO, NULL, 1);
        if (ret != pdPASS) {
            ESP_LOGE(TAG, "Failed to create feed task");
            close(client_sock);
            free(ctx);
            if (xSemaphoreTake(server->conn_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
                server->active_connections--;
                xSemaphoreGive(server->conn_mutex);
            }
        }
    }

    ESP_LOGI(TAG, "TCP accept task stopping");

    /* Close listen socket */
    if (server->listen_sock >= 0) {
        close(server->listen_sock);
        server->listen_sock = -1;
    }

    xEventGroupSetBits(server->events, TCP_SERVER_STOPPED_BIT);
    vTaskDelete(NULL);
}

lsl_esp32_err_t tcp_server_start(lsl_tcp_server_t *server, struct lsl_esp32_stream_info *info,
                                 lsl_ring_buffer_t *ring, const lsl_security_config_t *security)
{
    if (!server || !info || !ring) {
        return LSL_ESP32_ERR_INVALID_ARG;
    }

    memset(server, 0, sizeof(*server));
    server->info = info;
    server->ring = ring;
    server->security = security;
    server->listen_sock = -1;

    server->events = xEventGroupCreate();
    if (!server->events) {
        ESP_LOGE(TAG, "Failed to create event group");
        return LSL_ESP32_ERR_NO_MEMORY;
    }

    server->conn_mutex = xSemaphoreCreateMutex();
    if (!server->conn_mutex) {
        ESP_LOGE(TAG, "Failed to create connection mutex");
        vEventGroupDelete(server->events);
        return LSL_ESP32_ERR_NO_MEMORY;
    }

    /* Create TCP socket */
    server->listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server->listen_sock < 0) {
        ESP_LOGE(TAG, "Failed to create TCP socket: errno %d", errno);
        vSemaphoreDelete(server->conn_mutex);
        vEventGroupDelete(server->events);
        return LSL_ESP32_ERR_NETWORK;
    }

    int reuse = 1;
    setsockopt(server->listen_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    /* Try ports in range until one works */
    int port;
    for (port = LSL_ESP32_TCP_PORT_MIN; port <= LSL_ESP32_TCP_PORT_MAX; port++) {
        struct sockaddr_in bind_addr = {
            .sin_family = AF_INET,
            .sin_port = htons(port),
            .sin_addr.s_addr = htonl(INADDR_ANY),
        };
        if (bind(server->listen_sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) == 0) {
            break;
        }
    }

    if (port > LSL_ESP32_TCP_PORT_MAX) {
        ESP_LOGE(TAG, "Failed to bind to any port in range %d-%d", LSL_ESP32_TCP_PORT_MIN,
                 LSL_ESP32_TCP_PORT_MAX);
        close(server->listen_sock);
        server->listen_sock = -1;
        vSemaphoreDelete(server->conn_mutex);
        vEventGroupDelete(server->events);
        return LSL_ESP32_ERR_NETWORK;
    }

    info->v4data_port = port;
    ESP_LOGI(TAG, "TCP server bound to port %d", port);

    if (listen(server->listen_sock, LSL_ESP32_MAX_CONNECTIONS) < 0) {
        ESP_LOGE(TAG, "listen() failed: errno %d", errno);
        close(server->listen_sock);
        server->listen_sock = -1;
        vSemaphoreDelete(server->conn_mutex);
        vEventGroupDelete(server->events);
        return LSL_ESP32_ERR_NETWORK;
    }

    /* Set accept timeout (critical for clean shutdown) */
    struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
    if (setsockopt(server->listen_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        ESP_LOGE(TAG, "Failed to set SO_RCVTIMEO on listen socket: errno %d", errno);
        close(server->listen_sock);
        server->listen_sock = -1;
        vSemaphoreDelete(server->conn_mutex);
        vEventGroupDelete(server->events);
        return LSL_ESP32_ERR_NETWORK;
    }

    server->running = true;
    BaseType_t ret =
        xTaskCreatePinnedToCore(accept_task, "lsl_tcp", TCP_ACCEPT_STACK, (void *)server,
                                TCP_ACCEPT_PRIO, &server->accept_task, 1);
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create accept task");
        close(server->listen_sock);
        server->listen_sock = -1;
        server->running = false;
        vSemaphoreDelete(server->conn_mutex);
        vEventGroupDelete(server->events);
        return LSL_ESP32_ERR_NO_MEMORY;
    }

    ESP_LOGI(TAG, "TCP data server started on port %d", port);
    return LSL_ESP32_OK;
}

int tcp_server_stop(lsl_tcp_server_t *server)
{
    if (!server || !server->running) {
        return 0;
    }

    server->running = false;
    __sync_synchronize(); /* ensure visibility across cores */

    /* Wait for accept task to exit */
    if (server->events) {
        xEventGroupWaitBits(server->events, TCP_SERVER_STOPPED_BIT, pdFALSE, pdFALSE,
                            pdMS_TO_TICKS(3000));
        vEventGroupDelete(server->events);
        server->events = NULL;
    }

    /* Wait for feed tasks to exit (SO_SNDTIMEO ensures they unblock within 5s).
     * Poll active_connections with a bounded timeout. */
    int remaining = 0;
    if (server->conn_mutex) {
        for (int i = 0; i < 20; i++) { /* up to 10 seconds */
            if (xSemaphoreTake(server->conn_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
                remaining = server->active_connections;
                xSemaphoreGive(server->conn_mutex);
                if (remaining == 0) {
                    break;
                }
            }
            vTaskDelay(pdMS_TO_TICKS(500));
        }
        if (remaining == 0) {
            vSemaphoreDelete(server->conn_mutex);
            server->conn_mutex = NULL;
        }
        /* If remaining > 0, leave mutex alive for feed tasks still running */
    }

    server->accept_task = NULL;
    if (remaining > 0) {
        ESP_LOGW(TAG, "TCP server stopped with %d feed tasks still running", remaining);
    } else {
        ESP_LOGI(TAG, "TCP data server stopped");
    }
    return remaining;
}
