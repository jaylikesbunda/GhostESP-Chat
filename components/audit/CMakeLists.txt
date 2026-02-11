idf_component_register(
    SRCS "audit_log.c"
    INCLUDE_DIRS "include"
    REQUIRES nvs_flash esp_timer
)
