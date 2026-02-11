/**
 * @file upnp.c
 * @brief UPnP IGD implementation (simplified)
 *
 * Note: This is a simplified implementation. Full UPnP IGD requires
 * SOAP/XML parsing which is complex on ESP32. This provides basic
 * SSDP discovery and status checking. For production, consider using
 * a lightweight UPnP library like miniupnpc ported to ESP-IDF.
 */

#include "upnp.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_http_client.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "public_ip.h"

static const char *TAG = "upnp";

// SSDP multicast address and port
#define SSDP_MULTICAST_ADDR "239.255.255.250"
#define SSDP_PORT 1900

// SSDP M-SEARCH request
#define SSDP_MSEARCH \
    "M-SEARCH * HTTP/1.1\r\n" \
    "HOST: 239.255.255.250:1900\r\n" \
    "MAN: \"ssdp:discover\"\r\n" \
    "MX: 2\r\n" \
    "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n" \
    "\r\n"

// State
static bool upnp_available = false;
static char gateway_location[256] = {0};
static char control_url[256] = {0};
static char service_type[128] = {0};
static bool upnp_initialized = false;
static bool control_url_resolved = false;
static bool port_mapped = false;
static uint16_t mapped_external_port = 0;

#define SOAP_BUFFER_SIZE 2048
static char soap_response_buffer[SOAP_BUFFER_SIZE];
static int soap_response_len = 0;

// Forward declarations
static int send_ssdp_discovery(int sock);
static int receive_ssdp_response(int sock, uint32_t timeout_ms);
static bool parse_location_from_response(const char *response, char *location, size_t location_size);
static int resolve_control_url(void);
static esp_err_t soap_http_event_handler(esp_http_client_event_t *evt);
static int send_soap_action(const char *action, const char *body, char *response, size_t response_size);
static bool extract_xml_value(const char *xml, const char *tag, char *value, size_t value_size);
static void build_base_url(const char *location, char *base_url, size_t base_size);

int upnp_init(void) {
    if (upnp_initialized) {
        return UPNP_OK;
    }

    upnp_initialized = true;
    ESP_LOGI(TAG, "UPnP module initialized");
    return UPNP_OK;
}

int upnp_discover_gateway(uint32_t timeout_ms) {
    if (!upnp_initialized) {
        upnp_init();
    }

    ESP_LOGI(TAG, "Discovering UPnP IGD gateway...");

    // Create UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        ESP_LOGE(TAG, "Failed to create socket");
        return UPNP_ERR_DISCOVERY_FAILED;
    }

    // Set socket timeout
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Send M-SEARCH
    int ret = send_ssdp_discovery(sock);
    if (ret != UPNP_OK) {
        close(sock);
        return ret;
    }

    // Wait for response
    ret = receive_ssdp_response(sock, timeout_ms);
    close(sock);

    if (ret == UPNP_OK) {
        upnp_available = true;
        ESP_LOGI(TAG, "UPnP gateway discovered at: %s", gateway_location);
    } else {
        upnp_available = false;
        ESP_LOGW(TAG, "No UPnP gateway found");
    }

    return ret;
}

int upnp_add_port_mapping(const upnp_mapping_t *mapping) {
    if (!upnp_initialized || !upnp_available) {
        return UPNP_ERR_NOT_SUPPORTED;
    }

    if (mapping == NULL) {
        return UPNP_ERR_INVALID_PARAM;
    }

    if (!control_url_resolved) {
        int ret = resolve_control_url();
        if (ret != UPNP_OK) {
            return ret;
        }
    }

    char local_ip[16];
    if (public_ip_get_local(local_ip) != PUBLIC_IP_OK) {
        ESP_LOGE(TAG, "Failed to get local IP for port mapping");
        return UPNP_ERR_MAPPING_FAILED;
    }

    const char *proto_str = mapping->protocol == UPNP_PROTO_TCP ? "TCP" : "UDP";

    char body[768];
    snprintf(body, sizeof(body),
        "<NewRemoteHost></NewRemoteHost>"
        "<NewExternalPort>%d</NewExternalPort>"
        "<NewProtocol>%s</NewProtocol>"
        "<NewInternalPort>%d</NewInternalPort>"
        "<NewInternalClient>%s</NewInternalClient>"
        "<NewEnabled>1</NewEnabled>"
        "<NewPortMappingDescription>%s</NewPortMappingDescription>"
        "<NewLeaseDuration>%lu</NewLeaseDuration>",
        mapping->external_port, proto_str,
        mapping->internal_port, local_ip,
        mapping->description,
        (unsigned long)mapping->lease_duration);

    char response[SOAP_BUFFER_SIZE];
    int ret = send_soap_action("AddPortMapping", body, response, sizeof(response));

    if (ret == UPNP_OK) {
        port_mapped = true;
        mapped_external_port = mapping->external_port;
        ESP_LOGI(TAG, "Port mapping added: %s %d -> %s:%d",
                 proto_str, mapping->external_port, local_ip, mapping->internal_port);
    } else {
        ESP_LOGE(TAG, "Failed to add port mapping");
    }

    return ret;
}

int upnp_delete_port_mapping(uint16_t external_port, upnp_protocol_t protocol) {
    if (!upnp_initialized || !upnp_available) {
        return UPNP_ERR_NOT_SUPPORTED;
    }

    if (!control_url_resolved) {
        int ret = resolve_control_url();
        if (ret != UPNP_OK) {
            return ret;
        }
    }

    const char *proto_str = protocol == UPNP_PROTO_TCP ? "TCP" : "UDP";

    char body[256];
    snprintf(body, sizeof(body),
        "<NewRemoteHost></NewRemoteHost>"
        "<NewExternalPort>%d</NewExternalPort>"
        "<NewProtocol>%s</NewProtocol>",
        external_port, proto_str);

    char response[SOAP_BUFFER_SIZE];
    int ret = send_soap_action("DeletePortMapping", body, response, sizeof(response));

    if (ret == UPNP_OK) {
        if (mapped_external_port == external_port) {
            port_mapped = false;
            mapped_external_port = 0;
        }
        ESP_LOGI(TAG, "Port mapping deleted: %s %d", proto_str, external_port);
    } else {
        ESP_LOGE(TAG, "Failed to delete port mapping");
    }

    return ret;
}

int upnp_get_external_ip(char *ip_str) {
    if (!upnp_initialized || !upnp_available) {
        return UPNP_ERR_NOT_SUPPORTED;
    }

    if (ip_str == NULL) {
        return UPNP_ERR_INVALID_PARAM;
    }

    if (!control_url_resolved) {
        int ret = resolve_control_url();
        if (ret != UPNP_OK) {
            return ret;
        }
    }

    char response[SOAP_BUFFER_SIZE];
    int ret = send_soap_action("GetExternalIPAddress", "", response, sizeof(response));

    if (ret == UPNP_OK) {
        char ip[16];
        if (extract_xml_value(response, "NewExternalIPAddress", ip, sizeof(ip))) {
            strncpy(ip_str, ip, 15);
            ip_str[15] = '\0';
            ESP_LOGI(TAG, "UPnP external IP: %s", ip_str);
            return UPNP_OK;
        }
        return UPNP_ERR_MAPPING_FAILED;
    }

    return ret;
}

bool upnp_is_available(void) {
    return upnp_available;
}

int upnp_get_gateway_info(char *manufacturer, char *model) {
    if (!upnp_initialized || !upnp_available) {
        return UPNP_ERR_NOT_SUPPORTED;
    }

    strcpy(manufacturer, "Unknown");
    strcpy(model, "Unknown");

    return UPNP_ERR_NOT_SUPPORTED;
}

bool upnp_is_port_mapped(void) {
    return port_mapped;
}

uint16_t upnp_get_mapped_port(void) {
    return mapped_external_port;
}

// Private functions

static int send_ssdp_discovery(int sock) {
    // Configure multicast address
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(SSDP_PORT);
    inet_pton(AF_INET, SSDP_MULTICAST_ADDR, &dest_addr.sin_addr);

    // Send M-SEARCH request
    int len = sendto(sock, SSDP_MSEARCH, strlen(SSDP_MSEARCH), 0,
                     (struct sockaddr *)&dest_addr, sizeof(dest_addr));

    if (len < 0) {
        ESP_LOGE(TAG, "Failed to send SSDP M-SEARCH");
        return UPNP_ERR_DISCOVERY_FAILED;
    }

    ESP_LOGD(TAG, "Sent SSDP M-SEARCH (%d bytes)", len);
    return UPNP_OK;
}

static int receive_ssdp_response(int sock, uint32_t timeout_ms) {
    char buffer[2048];
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);

    // Wait for responses (there may be multiple)
    int attempts = 0;
    int max_attempts = (timeout_ms / 100) + 1;

    while (attempts < max_attempts) {
        int len = recvfrom(sock, buffer, sizeof(buffer) - 1, 0,
                          (struct sockaddr *)&src_addr, &addr_len);

        if (len > 0) {
            buffer[len] = '\0';
            ESP_LOGD(TAG, "Received SSDP response (%d bytes)", len);

            // Check if this is an IGD response
            if (strstr(buffer, "InternetGatewayDevice") != NULL ||
                strstr(buffer, "WANDevice") != NULL) {

                // Extract LOCATION header
                if (parse_location_from_response(buffer, gateway_location, sizeof(gateway_location))) {
                    return UPNP_OK;
                }
            }
        } else if (len == 0) {
            break;  // Connection closed
        } else {
            // Timeout or error
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                attempts++;
                vTaskDelay(pdMS_TO_TICKS(100));
                continue;
            } else {
                ESP_LOGE(TAG, "recvfrom error: %d", errno);
                break;
            }
        }
    }

    return UPNP_ERR_DISCOVERY_FAILED;
}

static esp_err_t soap_http_event_handler(esp_http_client_event_t *evt) {
    switch (evt->event_id) {
        case HTTP_EVENT_ON_DATA:
            if (soap_response_len + evt->data_len < SOAP_BUFFER_SIZE - 1) {
                memcpy(soap_response_buffer + soap_response_len, evt->data, evt->data_len);
                soap_response_len += evt->data_len;
                soap_response_buffer[soap_response_len] = '\0';
            }
            break;
        default:
            break;
    }
    return ESP_OK;
}

static void build_base_url(const char *location, char *base_url, size_t base_size) {
    const char *p = strstr(location, "://");
    if (!p) {
        strncpy(base_url, location, base_size - 1);
        return;
    }
    p += 3;
    const char *slash = strchr(p, '/');
    size_t len = slash ? (size_t)(slash - location) : strlen(location);
    if (len >= base_size) len = base_size - 1;
    strncpy(base_url, location, len);
    base_url[len] = '\0';
}

static bool extract_xml_value(const char *xml, const char *tag, char *value, size_t value_size) {
    char open_tag[128];
    char close_tag[128];
    snprintf(open_tag, sizeof(open_tag), "<%s>", tag);
    snprintf(close_tag, sizeof(close_tag), "</%s>", tag);

    const char *start = strstr(xml, open_tag);
    if (!start) return false;
    start += strlen(open_tag);

    const char *end = strstr(start, close_tag);
    if (!end) return false;

    size_t len = (size_t)(end - start);
    if (len >= value_size) len = value_size - 1;
    strncpy(value, start, len);
    value[len] = '\0';
    return true;
}

static int resolve_control_url(void) {
    if (gateway_location[0] == '\0') {
        return UPNP_ERR_DISCOVERY_FAILED;
    }

    ESP_LOGI(TAG, "Fetching device description from: %s", gateway_location);

    soap_response_len = 0;
    memset(soap_response_buffer, 0, sizeof(soap_response_buffer));

    esp_http_client_config_t config = {
        .url = gateway_location,
        .event_handler = soap_http_event_handler,
        .timeout_ms = 10000,
        .buffer_size = SOAP_BUFFER_SIZE,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) return UPNP_ERR_MAPPING_FAILED;

    esp_err_t err = esp_http_client_perform(client);
    int status = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);

    if (err != ESP_OK || status != 200) {
        ESP_LOGE(TAG, "Failed to fetch device description (status=%d)", status);
        return UPNP_ERR_MAPPING_FAILED;
    }

    const char *wan_ip = strstr(soap_response_buffer, "WANIPConnection");
    const char *wan_ppp = strstr(soap_response_buffer, "WANPPPConnection");
    const char *svc_ptr = wan_ip ? wan_ip : wan_ppp;

    if (!svc_ptr) {
        ESP_LOGE(TAG, "No WANIPConnection or WANPPPConnection service found");
        return UPNP_ERR_NOT_SUPPORTED;
    }

    if (wan_ip) {
        strncpy(service_type, "urn:schemas-upnp-org:service:WANIPConnection:1", sizeof(service_type) - 1);
    } else {
        strncpy(service_type, "urn:schemas-upnp-org:service:WANPPPConnection:1", sizeof(service_type) - 1);
    }

    const char *ctrl_start = strstr(svc_ptr, "<controlURL>");
    if (!ctrl_start) {
        ESP_LOGE(TAG, "No controlURL found in service description");
        return UPNP_ERR_NOT_SUPPORTED;
    }
    ctrl_start += strlen("<controlURL>");

    const char *ctrl_end = strstr(ctrl_start, "</controlURL>");
    if (!ctrl_end) return UPNP_ERR_NOT_SUPPORTED;

    char relative_url[128];
    size_t len = (size_t)(ctrl_end - ctrl_start);
    if (len >= sizeof(relative_url)) len = sizeof(relative_url) - 1;
    strncpy(relative_url, ctrl_start, len);
    relative_url[len] = '\0';

    if (relative_url[0] == 'h' && strstr(relative_url, "://")) {
        strncpy(control_url, relative_url, sizeof(control_url) - 1);
    } else {
        char base_url[128];
        build_base_url(gateway_location, base_url, sizeof(base_url));
        if (relative_url[0] == '/') {
            snprintf(control_url, sizeof(control_url), "%s%s", base_url, relative_url);
        } else {
            snprintf(control_url, sizeof(control_url), "%s/%s", base_url, relative_url);
        }
    }

    control_url_resolved = true;
    ESP_LOGI(TAG, "Control URL resolved: %s", control_url);
    ESP_LOGI(TAG, "Service type: %s", service_type);
    return UPNP_OK;
}

static int send_soap_action(const char *action, const char *body, char *response, size_t response_size) {
    if (!control_url_resolved || control_url[0] == '\0') {
        return UPNP_ERR_NOT_SUPPORTED;
    }

    char soap_body[1024];
    snprintf(soap_body, sizeof(soap_body),
        "<?xml version=\"1.0\"?>"
        "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\""
        " s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
        "<s:Body>"
        "<u:%s xmlns:u=\"%s\">"
        "%s"
        "</u:%s>"
        "</s:Body>"
        "</s:Envelope>",
        action, service_type, body, action);

    char soap_action_header[256];
    snprintf(soap_action_header, sizeof(soap_action_header), "\"%s#%s\"", service_type, action);

    soap_response_len = 0;
    memset(soap_response_buffer, 0, sizeof(soap_response_buffer));

    esp_http_client_config_t config = {
        .url = control_url,
        .method = HTTP_METHOD_POST,
        .event_handler = soap_http_event_handler,
        .timeout_ms = 10000,
        .buffer_size = SOAP_BUFFER_SIZE,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) return UPNP_ERR_MAPPING_FAILED;

    esp_http_client_set_header(client, "Content-Type", "text/xml; charset=\"utf-8\"");
    esp_http_client_set_header(client, "SOAPAction", soap_action_header);
    esp_http_client_set_post_field(client, soap_body, strlen(soap_body));

    esp_err_t err = esp_http_client_perform(client);
    int status = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "SOAP request failed: %s", esp_err_to_name(err));
        return UPNP_ERR_MAPPING_FAILED;
    }

    if (status >= 200 && status < 300) {
        if (response && response_size > 0) {
            size_t copy_len = soap_response_len < (int)(response_size - 1) ? soap_response_len : (int)(response_size - 1);
            memcpy(response, soap_response_buffer, copy_len);
            response[copy_len] = '\0';
        }
        return UPNP_OK;
    }

    ESP_LOGE(TAG, "SOAP %s failed with HTTP %d", action, status);
    ESP_LOGD(TAG, "Response: %s", soap_response_buffer);
    return UPNP_ERR_MAPPING_FAILED;
}

static bool parse_location_from_response(const char *response, char *location, size_t location_size) {
    // Find "LOCATION:" header (case insensitive)
    const char *loc_start = strcasestr(response, "LOCATION:");
    if (loc_start == NULL) {
        loc_start = strcasestr(response, "Location:");
    }

    if (loc_start == NULL) {
        return false;
    }

    // Skip to value
    loc_start += strlen("LOCATION:");
    while (*loc_start == ' ' || *loc_start == '\t') {
        loc_start++;
    }

    // Find end of line
    const char *loc_end = strstr(loc_start, "\r\n");
    if (loc_end == NULL) {
        loc_end = strstr(loc_start, "\n");
    }
    if (loc_end == NULL) {
        loc_end = loc_start + strlen(loc_start);
    }

    // Copy to output
    size_t len = loc_end - loc_start;
    if (len >= location_size) {
        len = location_size - 1;
    }

    strncpy(location, loc_start, len);
    location[len] = '\0';

    return true;
}
