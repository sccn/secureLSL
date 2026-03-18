idf_component_register(
    SRCS "secure_inlet_main.c"
         "wifi_helper.c"
    INCLUDE_DIRS "."
    REQUIRES liblsl_esp32 esp_wifi esp_netif nvs_flash esp_event
)
