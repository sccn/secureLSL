#ifndef WIFI_HELPER_H
#define WIFI_HELPER_H

#include "esp_err.h"

/* Initialize WiFi in station mode and connect to the configured AP.
 * Blocks until connected, max retries exhausted, or 30s timeout.
 * Returns ESP_OK on success, ESP_FAIL on connection failure,
 * ESP_ERR_TIMEOUT on timeout, ESP_ERR_NO_MEM on resource failure. */
esp_err_t wifi_helper_init_sta(void);

/* Get the local IPv4 address as a string (e.g., "192.168.1.50").
 * out must be at least 16 bytes. Returns ESP_OK on success. */
esp_err_t wifi_helper_get_ip_str(char *out, size_t out_len);

#endif /* WIFI_HELPER_H */
