idf_component_register(
    SRCS "p2p.c" "p2p_security.c" "tofu_manager.c"
    INCLUDE_DIRS "include"
    REQUIRES lwip crypto protocol nvs_flash esp_timer audit
)
