idf_component_register(
    SRCS "throughput_bench_main.c"
         "bench_outlet.c"
         "bench_inlet.c"
         "bench_monitor.c"
         "wifi_helper.c"
    INCLUDE_DIRS "."
    REQUIRES liblsl_esp32 esp_wifi esp_netif nvs_flash esp_event esp_timer
)
