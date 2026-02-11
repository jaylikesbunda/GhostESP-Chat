idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES nvs_flash esp_wifi esp_event esp_netif mbedtls esp_http_server esp_http_client crypto wifi network protocol p2p httpd peer_manager chat_storage
)
