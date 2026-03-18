idf_component_register(
    SRCS "src/lsl_clock.c"
         "src/lsl_stream_info.c"
         "src/lsl_sample.c"
         "src/lsl_udp_server.c"
         "src/lsl_ring_buffer.c"
         "src/lsl_tcp_server.c"
         "src/lsl_outlet.c"
         "src/lsl_xml_parser.c"
         "src/lsl_resolver.c"
         "src/lsl_esp32.c"
         "src/lsl_tcp_client.c"
         "src/lsl_inlet.c"
         "src/lsl_key_manager.c"
         "src/lsl_security.c"
         "src/lsl_tcp_common.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "src"
    REQUIRES esp_timer lwip esp_netif
    PRIV_REQUIRES nvs_flash libsodium
)
