idf_component_register(
    SRCS "build_test_main.c"
    INCLUDE_DIRS "."
    REQUIRES liblsl_esp32
    PRIV_INCLUDE_DIRS "${CMAKE_CURRENT_LIST_DIR}/../../../components/liblsl_esp32/src"
)
