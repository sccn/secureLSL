// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#include "lsl_resolver.h"
#include "lsl_xml_parser.h"
#include "lsl_protocol.h"
#include "lsl_clock.h"
#include "esp_log.h"
#include "esp_random.h"

#include "lwip/sockets.h"
#include "lwip/igmp.h"
#include <stdio.h>
#include <string.h>

static const char *TAG = "lsl_resolver";

#define RESOLVER_BUF_SIZE          1500
#define RESOLVER_QUERY_INTERVAL_MS 500

/* Check if a UID is already in the results (deduplication) */
static int uid_seen(const struct lsl_esp32_stream_info *results, int count, const char *uid)
{
    for (int i = 0; i < count; i++) {
        if (strcmp(results[i].uid, uid) == 0) {
            return 1;
        }
    }
    return 0;
}

static int resolver_run(const char *query, double timeout_sec,
                        struct lsl_esp32_stream_info *results, int max_results)
{
    if (!results || max_results < 1) {
        return 0;
    }

    /* Create UDP socket for sending queries and receiving responses */
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        ESP_LOGE(TAG, "Failed to create resolver socket: errno %d", errno);
        return 0;
    }

    /* Bind to ephemeral port (OS picks a free port) */
    struct sockaddr_in bind_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(0),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    if (bind(sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        ESP_LOGE(TAG, "Failed to bind resolver socket: errno %d", errno);
        close(sock);
        return 0;
    }

    /* Get the actual port that was assigned */
    struct sockaddr_in bound_addr;
    socklen_t bound_len = sizeof(bound_addr);
    if (getsockname(sock, (struct sockaddr *)&bound_addr, &bound_len) < 0) {
        ESP_LOGE(TAG, "Failed to get bound port: errno %d", errno);
        close(sock);
        return 0;
    }
    int return_port = ntohs(bound_addr.sin_port);

    /* Set receive timeout for polling */
    struct timeval tv = {.tv_sec = 0, .tv_usec = 100000}; /* 100ms */
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        ESP_LOGW(TAG, "SO_RCVTIMEO failed: errno %d (resolve may block)", errno);
    }

    /* Generate a unique query ID */
    uint32_t rand_val = esp_random();
    char query_id[16];
    snprintf(query_id, sizeof(query_id), "%lu", (unsigned long)rand_val);

    /* Build the query packet:
     * "LSL:shortinfo\r\n<query>\r\n<return-port> <query-id>\r\n" */
    char query_pkt[512];
    int query_len = snprintf(query_pkt, sizeof(query_pkt), "LSL:shortinfo\r\n%s\r\n%d %s\r\n",
                             query ? query : "", return_port, query_id);
    if (query_len < 0 || (size_t)query_len >= sizeof(query_pkt)) {
        ESP_LOGE(TAG, "Query packet too large");
        close(sock);
        return 0;
    }

    /* Multicast destination */
    struct sockaddr_in mcast_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(LSL_ESP32_MULTICAST_PORT),
        .sin_addr.s_addr = inet_addr(LSL_ESP32_MULTICAST_ADDR),
    };

    ESP_LOGI(TAG, "Resolving streams (query='%s', timeout=%.1fs, port=%d)", query ? query : "",
             timeout_sec, return_port);

    char recv_buf[RESOLVER_BUF_SIZE];

    int found = 0;
    double start_time = clock_get_time();
    double last_query_time = 0;

    while (clock_get_time() - start_time < timeout_sec && found < max_results) {
        /* Send query periodically */
        double now = clock_get_time();
        if (now - last_query_time >= RESOLVER_QUERY_INTERVAL_MS / 1000.0) {
            int sent = sendto(sock, query_pkt, query_len, 0, (struct sockaddr *)&mcast_addr,
                              sizeof(mcast_addr));
            if (sent < 0) {
                ESP_LOGW(TAG, "Failed to send discovery query: errno %d", errno);
            }
            last_query_time = now;
        }

        /* Receive responses */
        struct sockaddr_in sender;
        socklen_t sender_len = sizeof(sender);
        int len = recvfrom(sock, recv_buf, RESOLVER_BUF_SIZE - 1, 0, (struct sockaddr *)&sender,
                           &sender_len);
        if (len <= 0) {
            continue; /* timeout or error, retry */
        }
        recv_buf[len] = '\0';

        /* Parse response: "<query-id>\r\n<shortinfo-xml>" */
        const char *crlf = strstr(recv_buf, "\r\n");
        if (!crlf) {
            ESP_LOGD(TAG, "Malformed response (no CRLF)");
            continue;
        }

        /* Verify query ID matches */
        size_t id_len = (size_t)(crlf - recv_buf);
        if (id_len != strlen(query_id) || strncmp(recv_buf, query_id, id_len) != 0) {
            ESP_LOGD(TAG, "Query ID mismatch, ignoring response");
            continue;
        }

        /* Parse XML portion */
        const char *xml_start = crlf + 2;
        size_t xml_len = (size_t)(len - (xml_start - recv_buf));

        struct lsl_esp32_stream_info info;
        if (xml_parse_stream_info(xml_start, xml_len, &info) != 0) {
            ESP_LOGW(TAG, "Failed to parse discovery response XML");
            continue;
        }

        /* Use sender's IP as fallback if v4addr is empty (common for desktop outlets) */
        if (info.v4addr[0] == '\0') {
            snprintf(info.v4addr, sizeof(info.v4addr), "%s", inet_ntoa(sender.sin_addr));
            ESP_LOGD(TAG, "Using sender IP as v4addr: %s", info.v4addr);
        }

        /* Deduplicate by UID */
        if (uid_seen(results, found, info.uid)) {
            ESP_LOGD(TAG, "Duplicate stream (uid=%s), skipping", info.uid);
            continue;
        }

        /* Store result */
        memcpy(&results[found], &info, sizeof(info));
        found++;

        ESP_LOGI(TAG, "Found stream: %s (%s, %dch %s @ %.0fHz) at %s:%d", info.name, info.type,
                 info.channel_count, stream_info_format_string(info.channel_format),
                 info.nominal_srate, info.v4addr, info.v4data_port);
    }

    close(sock);

    ESP_LOGI(TAG, "Resolve complete: found %d stream(s) in %.1fs", found,
             clock_get_time() - start_time);
    return found;
}

int resolver_find(const char *prop, const char *value, double timeout_sec,
                  struct lsl_esp32_stream_info *results, int max_results)
{
    if (!prop || !value) {
        return resolver_find_all(timeout_sec, results, max_results);
    }

    /* Build query string: "prop='value'" */
    char query[256];
    int qlen = snprintf(query, sizeof(query), "%s='%s'", prop, value);
    if (qlen < 0 || (size_t)qlen >= sizeof(query)) {
        ESP_LOGE(TAG, "Query string too long (prop='%s', value truncated)", prop);
        return 0;
    }

    return resolver_run(query, timeout_sec, results, max_results);
}

int resolver_find_all(double timeout_sec, struct lsl_esp32_stream_info *results, int max_results)
{
    return resolver_run("", timeout_sec, results, max_results);
}
