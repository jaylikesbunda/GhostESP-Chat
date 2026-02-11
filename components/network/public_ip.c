/**
 * @file public_ip.c
 * @brief Public IP discovery implementation
 */

#include "public_ip.h"
#include <string.h>
#include <ctype.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/timers.h"
#include "esp_log.h"
#include "esp_http_client.h"
#include "esp_netif.h"

static const char *TAG = "public_ip";

// Service URLs
static const char *SERVICE_URLS[] = {
    [PUBLIC_IP_SERVICE_IPIFY] = "http://api.ipify.org",
    [PUBLIC_IP_SERVICE_AMAZONAWS] = "http://checkip.amazonaws.com",
    [PUBLIC_IP_SERVICE_ICANHAZIP] = "http://icanhazip.com",
    [PUBLIC_IP_SERVICE_WTFISMYIP] = "http://wtfismyip.com/text",
};

// State
static char cached_public_ip[PUBLIC_IP_MAX_LEN] = {0};
static TimerHandle_t monitor_timer = NULL;
static public_ip_callback_t monitor_callback = NULL;
static void *monitor_user_data = NULL;

// HTTP response buffer
#define HTTP_RESPONSE_BUFFER_SIZE 256
static char http_response_buffer[HTTP_RESPONSE_BUFFER_SIZE];
static int http_response_len = 0;

// Forward declarations
static esp_err_t http_event_handler(esp_http_client_event_t *evt);
static bool is_valid_ipv4(const char *ip);
static void trim_string(char *str);
static void monitor_timer_callback(TimerHandle_t timer);

int public_ip_discover(char *ip_str, public_ip_service_t service) {
    if (ip_str == NULL) {
        return PUBLIC_IP_ERR_INVALID_PARAM;
    }

    // Validate service index
    if (service >= sizeof(SERVICE_URLS) / sizeof(SERVICE_URLS[0])) {
        service = PUBLIC_IP_SERVICE_IPIFY;
    }

    const char *url = SERVICE_URLS[service];
    ESP_LOGI(TAG, "Discovering public IP from: %s", url);

    // Reset buffer
    http_response_len = 0;
    memset(http_response_buffer, 0, sizeof(http_response_buffer));

    // Configure HTTP client
    esp_http_client_config_t config = {
        .url = url,
        .event_handler = http_event_handler,
        .timeout_ms = 10000,
        .buffer_size = HTTP_RESPONSE_BUFFER_SIZE,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL) {
        ESP_LOGE(TAG, "Failed to initialize HTTP client");
        return PUBLIC_IP_ERR_HTTP_FAILED;
    }

    // Perform GET request
    esp_err_t err = esp_http_client_perform(client);
    int status_code = esp_http_client_get_status_code(client);

    esp_http_client_cleanup(client);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "HTTP request failed: %s", esp_err_to_name(err));
        return PUBLIC_IP_ERR_HTTP_FAILED;
    }

    if (status_code != 200) {
        ESP_LOGE(TAG, "HTTP request returned status: %d", status_code);
        return PUBLIC_IP_ERR_HTTP_FAILED;
    }

    // Parse IP from response
    trim_string(http_response_buffer);

    if (!is_valid_ipv4(http_response_buffer)) {
        ESP_LOGE(TAG, "Invalid IP address in response: %s", http_response_buffer);
        return PUBLIC_IP_ERR_PARSE_FAILED;
    }

    strncpy(ip_str, http_response_buffer, PUBLIC_IP_MAX_LEN - 1);
    ip_str[PUBLIC_IP_MAX_LEN - 1] = '\0';

    // Cache the result
    strncpy(cached_public_ip, ip_str, PUBLIC_IP_MAX_LEN - 1);

    ESP_LOGI(TAG, "Public IP discovered: %s", ip_str);
    return PUBLIC_IP_OK;
}

int public_ip_discover_auto(char *ip_str) {
    if (ip_str == NULL) {
        return PUBLIC_IP_ERR_INVALID_PARAM;
    }

    // Try all services in order
    for (int i = 0; i < sizeof(SERVICE_URLS) / sizeof(SERVICE_URLS[0]); i++) {
        int ret = public_ip_discover(ip_str, (public_ip_service_t)i);
        if (ret == PUBLIC_IP_OK) {
            return PUBLIC_IP_OK;
        }
        ESP_LOGW(TAG, "Service %d failed, trying next...", i);
        vTaskDelay(pdMS_TO_TICKS(1000));  // Brief delay between attempts
    }

    ESP_LOGE(TAG, "All IP discovery services failed");
    return PUBLIC_IP_ERR_HTTP_FAILED;
}

int public_ip_monitor_start(public_ip_callback_t callback, void *user_data, uint32_t interval_sec) {
    if (callback == NULL || interval_sec < 60) {
        return PUBLIC_IP_ERR_INVALID_PARAM;
    }

    // Stop existing monitor
    if (monitor_timer != NULL) {
        public_ip_monitor_stop();
    }

    monitor_callback = callback;
    monitor_user_data = user_data;

    // Create timer
    monitor_timer = xTimerCreate(
        "ip_monitor",
        pdMS_TO_TICKS(interval_sec * 1000),
        pdTRUE,  // Auto-reload
        NULL,
        monitor_timer_callback
    );

    if (monitor_timer == NULL) {
        ESP_LOGE(TAG, "Failed to create monitor timer");
        return PUBLIC_IP_ERR_HTTP_FAILED;
    }

    // Start timer
    xTimerStart(monitor_timer, 0);

    // Do initial discovery
    char ip[PUBLIC_IP_MAX_LEN];
    if (public_ip_discover_auto(ip) == PUBLIC_IP_OK) {
        callback(ip, user_data);
    }

    ESP_LOGI(TAG, "IP monitoring started (interval: %lu seconds)", interval_sec);
    return PUBLIC_IP_OK;
}

void public_ip_monitor_stop(void) {
    if (monitor_timer != NULL) {
        xTimerStop(monitor_timer, 0);
        xTimerDelete(monitor_timer, 0);
        monitor_timer = NULL;
        ESP_LOGI(TAG, "IP monitoring stopped");
    }
}

int public_ip_get_cached(char *ip_str) {
    if (ip_str == NULL) {
        return PUBLIC_IP_ERR_INVALID_PARAM;
    }

    if (cached_public_ip[0] == '\0') {
        return PUBLIC_IP_ERR_NOT_CONNECTED;
    }

    strncpy(ip_str, cached_public_ip, PUBLIC_IP_MAX_LEN - 1);
    ip_str[PUBLIC_IP_MAX_LEN - 1] = '\0';
    return PUBLIC_IP_OK;
}

int public_ip_get_local(char *ip_str) {
    if (ip_str == NULL) {
        return PUBLIC_IP_ERR_INVALID_PARAM;
    }

    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (netif == NULL) {
        return PUBLIC_IP_ERR_NOT_CONNECTED;
    }

    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(netif, &ip_info) != ESP_OK) {
        return PUBLIC_IP_ERR_NOT_CONNECTED;
    }

    sprintf(ip_str, IPSTR, IP2STR(&ip_info.ip));
    return PUBLIC_IP_OK;
}

// Private functions

static esp_err_t http_event_handler(esp_http_client_event_t *evt) {
    switch (evt->event_id) {
        case HTTP_EVENT_ON_DATA:
            // Append data to buffer
            if (http_response_len + evt->data_len < HTTP_RESPONSE_BUFFER_SIZE - 1) {
                memcpy(http_response_buffer + http_response_len, evt->data, evt->data_len);
                http_response_len += evt->data_len;
                http_response_buffer[http_response_len] = '\0';
            }
            break;

        case HTTP_EVENT_ERROR:
            ESP_LOGD(TAG, "HTTP_EVENT_ERROR");
            break;

        case HTTP_EVENT_ON_CONNECTED:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_CONNECTED");
            break;

        case HTTP_EVENT_HEADER_SENT:
            ESP_LOGD(TAG, "HTTP_EVENT_HEADER_SENT");
            break;

        case HTTP_EVENT_ON_HEADER:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_HEADER: %s: %s", evt->header_key, evt->header_value);
            break;

        case HTTP_EVENT_ON_FINISH:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_FINISH");
            break;

        case HTTP_EVENT_DISCONNECTED:
            ESP_LOGD(TAG, "HTTP_EVENT_DISCONNECTED");
            break;

        default:
            break;
    }
    return ESP_OK;
}

static bool is_valid_ipv4(const char *ip) {
    if (ip == NULL || *ip == '\0') {
        return false;
    }

    int dots = 0;
    int digits = 0;
    int value = 0;

    for (const char *p = ip; *p != '\0'; p++) {
        if (*p == '.') {
            if (digits == 0 || digits > 3 || value > 255) {
                return false;
            }
            dots++;
            digits = 0;
            value = 0;
        } else if (isdigit((unsigned char)*p)) {
            value = value * 10 + (*p - '0');
            digits++;
            if (value > 255) {
                return false;
            }
        } else {
            return false;  // Invalid character
        }
    }

    // Check final octet
    if (digits == 0 || digits > 3 || value > 255 || dots != 3) {
        return false;
    }

    return true;
}

static void trim_string(char *str) {
    if (str == NULL) {
        return;
    }

    // Trim leading whitespace
    char *start = str;
    while (*start && isspace((unsigned char)*start)) {
        start++;
    }

    // Trim trailing whitespace
    char *end = start + strlen(start) - 1;
    while (end > start && isspace((unsigned char)*end)) {
        end--;
    }
    *(end + 1) = '\0';

    // Move trimmed string to beginning
    if (start != str) {
        memmove(str, start, strlen(start) + 1);
    }
}

static void monitor_timer_callback(TimerHandle_t timer) {
    char current_ip[PUBLIC_IP_MAX_LEN];
    char previous_ip[PUBLIC_IP_MAX_LEN];

    // Get cached IP
    strncpy(previous_ip, cached_public_ip, PUBLIC_IP_MAX_LEN);

    // Discover current IP
    if (public_ip_discover_auto(current_ip) == PUBLIC_IP_OK) {
        // Check if IP changed
        if (strcmp(current_ip, previous_ip) != 0) {
            ESP_LOGI(TAG, "Public IP changed: %s -> %s", previous_ip, current_ip);
            if (monitor_callback != NULL) {
                monitor_callback(current_ip, monitor_user_data);
            }
        }
    } else {
        ESP_LOGW(TAG, "Failed to refresh public IP");
    }
}
