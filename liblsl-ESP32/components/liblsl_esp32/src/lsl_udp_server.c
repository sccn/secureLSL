// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#include "lsl_udp_server.h"
#include "lsl_clock.h"
#include "esp_log.h"

#include "lwip/sockets.h"
#include "lwip/igmp.h"
#include "lwip/netdb.h"
#include <string.h>
#include <stdio.h>

static const char *TAG = "lsl_udp_server";

#define UDP_BUF_SIZE   1500
#define UDP_TASK_STACK 4096
#define UDP_TASK_PRIO  5

/* Parse a LSL:shortinfo query and respond if this stream matches.
 * Query format: "LSL:shortinfo\r\n<query>\r\n<return-port> <query-id>\r\n"
 * Response sent via mcast_sock to sender IP on return-port. */
static void handle_shortinfo_query(lsl_udp_server_t *server, const char *buf, int len,
                                   const struct sockaddr_in *sender)
{
    const char *line1_end = strstr(buf, "\r\n");
    if (!line1_end) {
        ESP_LOGW(TAG, "Malformed shortinfo: no CRLF after header (%d bytes)", len);
        return;
    }

    const char *query_start = line1_end + 2;
    const char *line2_end = strstr(query_start, "\r\n");
    if (!line2_end) {
        ESP_LOGW(TAG, "Malformed shortinfo: no CRLF after query string");
        return;
    }

    /* Extract query string */
    size_t query_len = (size_t)(line2_end - query_start);
    char query[256];
    if (query_len >= sizeof(query)) {
        query_len = sizeof(query) - 1;
    }
    memcpy(query, query_start, query_len);
    query[query_len] = '\0';

    /* Extract return-port and query-id from third line */
    const char *line3_start = line2_end + 2;
    int return_port = 0;
    char query_id[64] = {0};
    if (sscanf(line3_start, "%d %63s", &return_port, query_id) < 2) {
        ESP_LOGW(TAG, "Malformed shortinfo query (missing port/id)");
        return;
    }

    if (return_port <= 0 || return_port > 65535) {
        ESP_LOGW(TAG, "Invalid return port: %d", return_port);
        return;
    }

    if (!stream_info_match_query(server->info, query)) {
        ESP_LOGD(TAG, "Query not matched: '%s'", query);
        return;
    }

    ESP_LOGI(TAG, "Discovery query matched: id=%s port=%d", query_id, return_port);

    /* Build response in pre-allocated buffer: "<query-id>\r\n<shortinfo-xml>" */
    int hdr_len = snprintf(server->response_buf, 128, "%s\r\n", query_id);
    if (hdr_len >= 128) {
        ESP_LOGW(TAG, "Query ID truncated in response header");
        hdr_len = 127;
    }
    int xml_len = stream_info_to_shortinfo_xml(server->info, server->response_buf + hdr_len,
                                               LSL_ESP32_SHORTINFO_MAX);
    if (xml_len < 0) {
        ESP_LOGE(TAG, "Failed to serialize shortinfo XML for query id=%s", query_id);
        return;
    }

    int total_len = hdr_len + xml_len;

    /* Send response to sender IP on return-port via existing socket */
    struct sockaddr_in dest = {
        .sin_family = AF_INET,
        .sin_port = htons(return_port),
        .sin_addr = sender->sin_addr,
    };

    int sent = sendto(server->mcast_sock, server->response_buf, total_len, 0,
                      (struct sockaddr *)&dest, sizeof(dest));
    if (sent < 0) {
        ESP_LOGE(TAG, "Failed to send discovery response: errno %d", errno);
    } else {
        ESP_LOGI(TAG, "Sent discovery response (%d bytes) to %s:%d", sent, inet_ntoa(dest.sin_addr),
                 return_port);
    }
}

/* Parse a LSL:timedata query and respond with time correction data.
 * Query format: "LSL:timedata\r\n<wave-id> <t0>\r\n"
 * Response: "<wave-id> <t0> <t1> <t2>\r\n" */
static void handle_timedata_query(lsl_udp_server_t *server, const char *buf, int len,
                                  const struct sockaddr_in *sender)
{
    double t1 = clock_get_time(); /* receive time */

    const char *line1_end = strstr(buf, "\r\n");
    if (!line1_end) {
        ESP_LOGW(TAG, "Malformed timedata: no CRLF (%d bytes)", len);
        return;
    }

    const char *line2_start = line1_end + 2;
    int wave_id = 0;
    double t0 = 0.0;
    if (sscanf(line2_start, "%d %lf", &wave_id, &t0) < 2) {
        ESP_LOGW(TAG, "Malformed timedata query");
        return;
    }

    double t2 = clock_get_time(); /* send time */

    char response[128];
    int resp_len =
        snprintf(response, sizeof(response), "%d %.10g %.10g %.10g\r\n", wave_id, t0, t1, t2);

    int sent = sendto(server->mcast_sock, response, resp_len, 0, (struct sockaddr *)sender,
                      sizeof(*sender));
    if (sent < 0) {
        ESP_LOGE(TAG, "Failed to send time response: errno %d", errno);
    } else {
        ESP_LOGD(TAG, "Time response: wave=%d t0=%.6f t1=%.6f t2=%.6f", wave_id, t0, t1, t2);
    }
}

static void udp_server_task(void *arg)
{
    lsl_udp_server_t *server = (lsl_udp_server_t *)arg;
    char *buf = malloc(UDP_BUF_SIZE);
    if (!buf) {
        ESP_LOGE(TAG, "Failed to allocate receive buffer");
        server->running = false;
        xEventGroupSetBits(server->events, UDP_SERVER_STOPPED_BIT);
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "UDP server task started on multicast %s:%d", LSL_ESP32_MULTICAST_ADDR,
             LSL_ESP32_MULTICAST_PORT);

    int consecutive_errors = 0;

    while (server->running) {
        struct sockaddr_in sender;
        socklen_t sender_len = sizeof(sender);

        int len = recvfrom(server->mcast_sock, buf, UDP_BUF_SIZE - 1, 0, (struct sockaddr *)&sender,
                           &sender_len);
        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                consecutive_errors = 0;
                continue; /* timeout, check running flag */
            }
            if (!server->running) {
                break;
            }
            consecutive_errors++;
            ESP_LOGE(TAG, "recvfrom error: errno %d (consecutive: %d)", errno, consecutive_errors);
            if (consecutive_errors >= 10) {
                ESP_LOGE(TAG, "Too many consecutive errors, stopping UDP server");
                server->running = false;
                break;
            }
            vTaskDelay(pdMS_TO_TICKS(100)); /* back off */
            continue;
        }
        consecutive_errors = 0;

        buf[len] = '\0';

        if (strncmp(buf, "LSL:shortinfo", 13) == 0) {
            handle_shortinfo_query(server, buf, len, &sender);
        } else if (strncmp(buf, "LSL:timedata", 12) == 0) {
            handle_timedata_query(server, buf, len, &sender);
        } else {
            ESP_LOGD(TAG, "Unknown UDP message from %s (%d bytes)", inet_ntoa(sender.sin_addr),
                     len);
        }
    }

    /* Task owns socket cleanup */
    if (server->mcast_sock >= 0) {
        close(server->mcast_sock);
        server->mcast_sock = -1;
    }

    free(buf);
    ESP_LOGI(TAG, "UDP server task stopped");
    xEventGroupSetBits(server->events, UDP_SERVER_STOPPED_BIT);
    vTaskDelete(NULL);
}

lsl_esp32_err_t udp_server_start(lsl_udp_server_t *server, struct lsl_esp32_stream_info *info)
{
    if (!server || !info) {
        return LSL_ESP32_ERR_INVALID_ARG;
    }

    memset(server, 0, sizeof(*server));
    server->info = info;
    server->mcast_sock = -1;

    server->events = xEventGroupCreate();
    if (!server->events) {
        ESP_LOGE(TAG, "Failed to create event group");
        return LSL_ESP32_ERR_NO_MEMORY;
    }

    /* Create UDP socket */
    server->mcast_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (server->mcast_sock < 0) {
        ESP_LOGE(TAG, "Failed to create socket: errno %d", errno);
        vEventGroupDelete(server->events);
        return LSL_ESP32_ERR_NETWORK;
    }

    /* Allow multiple LSL services on same port */
    int reuse = 1;
    if (setsockopt(server->mcast_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        ESP_LOGW(TAG, "SO_REUSEADDR failed: errno %d (non-fatal)", errno);
    }

    /* Bind to multicast port */
    struct sockaddr_in bind_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(LSL_ESP32_MULTICAST_PORT),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    if (bind(server->mcast_sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        ESP_LOGE(TAG, "Failed to bind to port %d: errno %d", LSL_ESP32_MULTICAST_PORT, errno);
        close(server->mcast_sock);
        server->mcast_sock = -1;
        vEventGroupDelete(server->events);
        return LSL_ESP32_ERR_NETWORK;
    }

    /* Join multicast group */
    struct ip_mreq mreq = {
        .imr_multiaddr.s_addr = inet_addr(LSL_ESP32_MULTICAST_ADDR),
        .imr_interface.s_addr = htonl(INADDR_ANY),
    };
    if (setsockopt(server->mcast_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        ESP_LOGE(TAG, "Failed to join multicast group %s: errno %d", LSL_ESP32_MULTICAST_ADDR,
                 errno);
        close(server->mcast_sock);
        server->mcast_sock = -1;
        vEventGroupDelete(server->events);
        return LSL_ESP32_ERR_NETWORK;
    }

    /* Set receive timeout (required for clean shutdown; task checks running flag on timeout) */
    struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
    if (setsockopt(server->mcast_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        ESP_LOGE(TAG, "SO_RCVTIMEO failed: errno %d (required for shutdown)", errno);
        close(server->mcast_sock);
        server->mcast_sock = -1;
        vEventGroupDelete(server->events);
        return LSL_ESP32_ERR_NETWORK;
    }

    /* Start task */
    server->running = true;
    BaseType_t ret =
        xTaskCreatePinnedToCore(udp_server_task, "lsl_udp", UDP_TASK_STACK, (void *)server,
                                UDP_TASK_PRIO, &server->task_handle, 1 /* core 1 = app core */);
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create UDP server task");
        close(server->mcast_sock);
        server->mcast_sock = -1;
        server->running = false;
        vEventGroupDelete(server->events);
        return LSL_ESP32_ERR_NO_MEMORY;
    }

    ESP_LOGI(TAG, "UDP discovery server started");
    return LSL_ESP32_OK;
}

void udp_server_stop(lsl_udp_server_t *server)
{
    if (!server || !server->running) {
        return;
    }

    /* Signal task to stop; the 1s recv timeout will break the loop */
    server->running = false;

    /* Wait for task to exit (up to 2 seconds) */
    if (server->events) {
        xEventGroupWaitBits(server->events, UDP_SERVER_STOPPED_BIT, pdFALSE, pdFALSE,
                            pdMS_TO_TICKS(2000));
        vEventGroupDelete(server->events);
        server->events = NULL;
    }

    server->task_handle = NULL;
    ESP_LOGI(TAG, "UDP discovery server stopped");
}
