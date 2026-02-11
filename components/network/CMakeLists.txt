idf_component_register(
    SRCS "public_ip.c" "upnp.c" "port_test.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_http_client esp_netif lwip
)
