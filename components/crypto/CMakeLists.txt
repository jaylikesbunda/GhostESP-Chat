idf_component_register(
    SRCS "crypto.c" "ratchet.c"
    INCLUDE_DIRS "include"
    REQUIRES mbedtls
)
