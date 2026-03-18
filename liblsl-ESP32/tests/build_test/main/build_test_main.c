// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

/* Build test: verifies the liblsl_esp32 component compiles and links.
 * Also serves as a smoke test for core APIs: stream info, XML, and sample format. */

#include "lsl_esp32.h"
#include "lsl_protocol.h"
#include "lsl_stream_info.h"
#include "lsl_sample.h"
#include "lsl_xml_parser.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>

static const char *TAG = "build_test";

void app_main(void)
{
    /* Brief delay so serial monitor can connect */
    ESP_LOGI(TAG, "Starting in 2 seconds...");
    vTaskDelay(pdMS_TO_TICKS(2000));

    ESP_LOGI(TAG, "=== liblsl_esp32 build test ===");

    /* Clock */
    double t = lsl_esp32_local_clock();
    ESP_LOGI(TAG, "[OK] Clock: %.6f s", t);

    /* Stream info */
    lsl_esp32_stream_info_t info = lsl_esp32_create_streaminfo(
        "BuildTest", "Test", 8, 250.0, LSL_ESP32_FMT_FLOAT32, "build_test_src");

    if (!info) {
        ESP_LOGE(TAG, "[FAIL] Failed to create stream info");
        return;
    }
    ESP_LOGI(TAG, "[OK] Stream info created");

    /* XML serialization */
    char xml_buf[LSL_ESP32_SHORTINFO_MAX];
    int xml_len = stream_info_to_shortinfo_xml(info, xml_buf, sizeof(xml_buf));
    if (xml_len > 0) {
        ESP_LOGI(TAG, "[OK] shortinfo XML (%d bytes):", xml_len);
        ESP_LOGI(TAG, "%s", xml_buf);
    } else {
        ESP_LOGE(TAG, "[FAIL] shortinfo XML serialization failed");
    }

    /* Query matching */
    int match1 = stream_info_match_query(info, "name='BuildTest'");
    int match2 = stream_info_match_query(info, "type='Test'");
    int match3 = stream_info_match_query(info, "name='Wrong'");
    int match4 = stream_info_match_query(info, "");
    int match5 = stream_info_match_query(info, "name='BuildTest' and type='Test'");
    int match6 = stream_info_match_query(info, "name='BuildTest' and type='Wrong'");
    int match7 = stream_info_match_query(info, "hostname='ESP32'");
    ESP_LOGI(TAG, "[%s] Query name='BuildTest': %d", match1 ? "OK" : "FAIL", match1);
    ESP_LOGI(TAG, "[%s] Query type='Test': %d", match2 ? "OK" : "FAIL", match2);
    ESP_LOGI(TAG, "[%s] Query name='Wrong': %d", !match3 ? "OK" : "FAIL", match3);
    ESP_LOGI(TAG, "[%s] Query empty (match all): %d", match4 ? "OK" : "FAIL", match4);
    ESP_LOGI(TAG, "[%s] Query AND (both match): %d", match5 ? "OK" : "FAIL", match5);
    ESP_LOGI(TAG, "[%s] Query AND (type wrong): %d", !match6 ? "OK" : "FAIL", match6);
    ESP_LOGI(TAG, "[%s] Query hostname (not name): %d", !match7 ? "OK" : "FAIL", match7);

    /* Test pattern generation */
    uint8_t sample_buf[256];
    int sample_len =
        sample_generate_test_pattern(8, LSL_ESP32_FMT_FLOAT32, LSL_ESP32_TEST_OFFSET_1,
                                     LSL_ESP32_TEST_TIMESTAMP, sample_buf, sizeof(sample_buf));

    if (sample_len > 0) {
        ESP_LOGI(TAG, "[OK] Test pattern 1 (%d bytes): tag=0x%02x", sample_len, sample_buf[0]);
        /* Read channel values safely via memcpy (avoid strict-aliasing violation) */
        float ch[4];
        memcpy(ch, sample_buf + 1 + 8, sizeof(ch)); /* skip tag + timestamp */
        ESP_LOGI(TAG, "  ch0=%.1f ch1=%.1f ch2=%.1f ch3=%.1f", ch[0], ch[1], ch[2], ch[3]);
    } else {
        ESP_LOGE(TAG, "[FAIL] Test pattern generation failed");
    }

    int sample_len2 =
        sample_generate_test_pattern(8, LSL_ESP32_FMT_FLOAT32, LSL_ESP32_TEST_OFFSET_2,
                                     LSL_ESP32_TEST_TIMESTAMP, sample_buf, sizeof(sample_buf));

    if (sample_len2 > 0) {
        ESP_LOGI(TAG, "[OK] Test pattern 2 (%d bytes): tag=0x%02x", sample_len2, sample_buf[0]);
        float ch[4];
        memcpy(ch, sample_buf + 1 + 8, sizeof(ch));
        ESP_LOGI(TAG, "  ch0=%.1f ch1=%.1f ch2=%.1f ch3=%.1f", ch[0], ch[1], ch[2], ch[3]);
    } else {
        ESP_LOGE(TAG, "[FAIL] Test pattern 2 generation failed");
    }

    /* XML roundtrip: serialize -> parse -> compare */
    ESP_LOGI(TAG, "--- XML roundtrip test ---");
    struct lsl_esp32_stream_info parsed_info;
    int xml_parse_ok = xml_parse_stream_info(xml_buf, (size_t)xml_len, &parsed_info);
    if (xml_parse_ok == 0) {
        int name_ok = (strcmp(info->name, parsed_info.name) == 0);
        int type_ok = (strcmp(info->type, parsed_info.type) == 0);
        int ch_ok = (info->channel_count == parsed_info.channel_count);
        int fmt_ok = (info->channel_format == parsed_info.channel_format);
        int uid_ok = (strcmp(info->uid, parsed_info.uid) == 0);
        ESP_LOGI(TAG, "[%s] XML roundtrip name: %s", name_ok ? "OK" : "FAIL", parsed_info.name);
        ESP_LOGI(TAG, "[%s] XML roundtrip type: %s", type_ok ? "OK" : "FAIL", parsed_info.type);
        ESP_LOGI(TAG, "[%s] XML roundtrip channels: %d", ch_ok ? "OK" : "FAIL",
                 parsed_info.channel_count);
        ESP_LOGI(TAG, "[%s] XML roundtrip format: %d", fmt_ok ? "OK" : "FAIL",
                 parsed_info.channel_format);
        ESP_LOGI(TAG, "[%s] XML roundtrip uid: %s", uid_ok ? "OK" : "FAIL", parsed_info.uid);
    } else {
        ESP_LOGE(TAG, "[FAIL] XML parse failed");
    }

    /* Sample deserialize roundtrip */
    ESP_LOGI(TAG, "--- Sample deserialize roundtrip ---");
    /* Reuse sample_buf from test pattern 1 (offset=4) */
    sample_len =
        sample_generate_test_pattern(8, LSL_ESP32_FMT_FLOAT32, LSL_ESP32_TEST_OFFSET_1,
                                     LSL_ESP32_TEST_TIMESTAMP, sample_buf, sizeof(sample_buf));
    if (sample_len > 0) {
        float deser_channels[8];
        double deser_ts = 0.0;
        int consumed = sample_deserialize(sample_buf, (size_t)sample_len, 8, LSL_ESP32_FMT_FLOAT32,
                                          deser_channels, sizeof(deser_channels), &deser_ts);
        if (consumed > 0) {
            ESP_LOGI(TAG, "[OK] Deserialized %d bytes, ts=%.3f", consumed, deser_ts);
            ESP_LOGI(TAG, "  ch0=%.1f ch1=%.1f ch2=%.1f ch3=%.1f", deser_channels[0],
                     deser_channels[1], deser_channels[2], deser_channels[3]);

            /* Validate test pattern */
            int valid =
                sample_validate_test_pattern(8, LSL_ESP32_FMT_FLOAT32, LSL_ESP32_TEST_OFFSET_1,
                                             LSL_ESP32_TEST_TIMESTAMP, deser_channels, deser_ts);
            ESP_LOGI(TAG, "[%s] Test pattern validation", valid == 0 ? "OK" : "FAIL");
        } else {
            ESP_LOGE(TAG, "[FAIL] Sample deserialization failed");
        }
    }

    lsl_esp32_destroy_streaminfo(info);
    ESP_LOGI(TAG, "=== Build test PASSED ===");
}
