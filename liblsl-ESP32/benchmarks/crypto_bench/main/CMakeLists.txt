idf_component_register(
    SRCS "crypto_bench_main.c"
         "bench_chacha20.c"
         "bench_ed25519.c"
         "bench_x25519.c"
         "bench_utils.c"
    INCLUDE_DIRS "."
    REQUIRES esp_timer
    PRIV_REQUIRES nvs_flash libsodium spi_flash
)
