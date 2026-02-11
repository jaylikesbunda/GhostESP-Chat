/**
 * @file wifi_manager.c
 * @brief WiFi connection manager implementation
 */

#include "wifi_manager.h"
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "nvs_flash.h"
#include "nvs.h"

static const char *TAG = "wifi_mgr";

// Event group bits
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

// NVS keys
#define NVS_NAMESPACE "wifi"
#define NVS_KEY_SSID "ssid"
#define NVS_KEY_PASS "password"

// Maximum retry attempts
#define MAX_RETRY_ATTEMPTS 5

// State management
static wifi_state_t current_state = WIFI_STATE_IDLE;
static EventGroupHandle_t wifi_event_group = NULL;
static wifi_event_cb_t event_callback = NULL;
static void *callback_user_data = NULL;
static int retry_count = 0;
static esp_netif_t *sta_netif = NULL;
static esp_netif_t *ap_netif = NULL;
static bool wifi_initialized = false;
static bool ap_mode_active = false;

// Forward declarations
static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data);
static void update_state(wifi_state_t new_state);

int wifi_manager_init(void) {
    if (wifi_initialized) {
        return WIFI_OK;
    }

    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // Create event group
    wifi_event_group = xEventGroupCreate();
    if (wifi_event_group == NULL) {
        ESP_LOGE(TAG, "Failed to create event group");
        return WIFI_ERR_NOT_INITIALIZED;
    }

    // Initialize TCP/IP stack
    ESP_ERROR_CHECK(esp_netif_init());

    // Create default event loop
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    // Create default WiFi station
    sta_netif = esp_netif_create_default_wifi_sta();

    // Initialize WiFi with default config
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    // Register event handlers
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT,
        ESP_EVENT_ANY_ID,
        &wifi_event_handler,
        NULL,
        NULL
    ));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT,
        IP_EVENT_STA_GOT_IP,
        &wifi_event_handler,
        NULL,
        NULL
    ));

    // Set WiFi mode to station
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));

    // Start WiFi
    ESP_ERROR_CHECK(esp_wifi_start());

    wifi_initialized = true;
    update_state(WIFI_STATE_IDLE);
    ESP_LOGI(TAG, "WiFi manager initialized");
    return WIFI_OK;
}

int wifi_manager_connect(const char *ssid, const char *password, bool save_credentials) {
    if (!wifi_initialized) {
        return WIFI_ERR_NOT_INITIALIZED;
    }

    if (ssid == NULL || password == NULL) {
        return WIFI_ERR_INVALID_PARAM;
    }

    if (strlen(ssid) > 32 || strlen(password) > 64) {
        return WIFI_ERR_INVALID_PARAM;
    }

    // Configure WiFi
    wifi_config_t wifi_config = {0};
    strncpy((char *)wifi_config.sta.ssid, ssid, sizeof(wifi_config.sta.ssid) - 1);
    strncpy((char *)wifi_config.sta.password, password, sizeof(wifi_config.sta.password) - 1);
    wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    wifi_config.sta.pmf_cfg.capable = true;
    wifi_config.sta.pmf_cfg.required = false;

    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));

    // Save credentials if requested
    if (save_credentials) {
        nvs_handle_t nvs_handle;
        esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs_handle);
        if (err == ESP_OK) {
            nvs_set_str(nvs_handle, NVS_KEY_SSID, ssid);
            nvs_set_str(nvs_handle, NVS_KEY_PASS, password);
            nvs_commit(nvs_handle);
            nvs_close(nvs_handle);
            ESP_LOGI(TAG, "Credentials saved to NVS");
        } else {
            ESP_LOGW(TAG, "Failed to save credentials: %s", esp_err_to_name(err));
        }
    }

    // Reset retry counter
    retry_count = 0;

    // Clear event bits
    xEventGroupClearBits(wifi_event_group, WIFI_CONNECTED_BIT | WIFI_FAIL_BIT);

    // Connect
    update_state(WIFI_STATE_CONNECTING);
    ESP_ERROR_CHECK(esp_wifi_connect());

    ESP_LOGI(TAG, "Connecting to SSID: %s", ssid);
    return WIFI_OK;
}

int wifi_manager_disconnect(void) {
    if (!wifi_initialized) {
        return WIFI_ERR_NOT_INITIALIZED;
    }

    ESP_ERROR_CHECK(esp_wifi_disconnect());
    update_state(WIFI_STATE_DISCONNECTED);
    ESP_LOGI(TAG, "Disconnected from WiFi");
    return WIFI_OK;
}

wifi_state_t wifi_manager_get_state(void) {
    return current_state;
}

int wifi_manager_get_ip(char *ip_str) {
    if (!wifi_initialized || ip_str == NULL) {
        return WIFI_ERR_INVALID_PARAM;
    }

    if (current_state != WIFI_STATE_CONNECTED) {
        return WIFI_ERR_CONNECT_FAILED;
    }

    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(sta_netif, &ip_info) == ESP_OK) {
        sprintf(ip_str, IPSTR, IP2STR(&ip_info.ip));
        return WIFI_OK;
    }

    return WIFI_ERR_CONNECT_FAILED;
}

void wifi_manager_register_callback(wifi_event_cb_t callback, void *user_data) {
    event_callback = callback;
    callback_user_data = user_data;
}

int wifi_manager_auto_connect(void) {
    if (!wifi_initialized) {
        return WIFI_ERR_NOT_INITIALIZED;
    }

    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGI(TAG, "No saved credentials found");
        return WIFI_ERR_NVS_FAILED;
    }

    char ssid[33] = {0};
    char password[65] = {0};
    size_t ssid_len = sizeof(ssid);
    size_t pass_len = sizeof(password);

    err = nvs_get_str(nvs_handle, NVS_KEY_SSID, ssid, &ssid_len);
    if (err != ESP_OK) {
        nvs_close(nvs_handle);
        return WIFI_ERR_NVS_FAILED;
    }

    err = nvs_get_str(nvs_handle, NVS_KEY_PASS, password, &pass_len);
    if (err != ESP_OK) {
        nvs_close(nvs_handle);
        return WIFI_ERR_NVS_FAILED;
    }

    nvs_close(nvs_handle);

    ESP_LOGI(TAG, "Auto-connecting to saved network: %s", ssid);
    return wifi_manager_connect(ssid, password, false);
}

int wifi_manager_clear_credentials(void) {
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK) {
        return WIFI_ERR_NVS_FAILED;
    }

    nvs_erase_key(nvs_handle, NVS_KEY_SSID);
    nvs_erase_key(nvs_handle, NVS_KEY_PASS);
    nvs_commit(nvs_handle);
    nvs_close(nvs_handle);

    ESP_LOGI(TAG, "Cleared saved credentials");
    return WIFI_OK;
}

bool wifi_manager_has_saved_credentials(void) {
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs_handle);
    if (err != ESP_OK) return false;

    char ssid[33] = {0};
    size_t ssid_len = sizeof(ssid);
    err = nvs_get_str(nvs_handle, NVS_KEY_SSID, ssid, &ssid_len);
    nvs_close(nvs_handle);

    return (err == ESP_OK && ssid[0] != '\0');
}

int wifi_manager_start_ap(const char *ssid, const char *password) {
    if (ssid == NULL) return WIFI_ERR_INVALID_PARAM;

    if (!wifi_initialized) {
        wifi_event_group = xEventGroupCreate();
        ESP_ERROR_CHECK(esp_netif_init());
        ESP_ERROR_CHECK(esp_event_loop_create_default());

        wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
        ESP_ERROR_CHECK(esp_wifi_init(&cfg));

        wifi_initialized = true;
    } else {
        esp_wifi_stop();
    }

    if (!ap_netif) {
        ap_netif = esp_netif_create_default_wifi_ap();
    }
    if (!sta_netif) {
        sta_netif = esp_netif_create_default_wifi_sta();
    }

    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, NULL));

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));

    wifi_config_t ap_config = {0};
    strncpy((char *)ap_config.ap.ssid, ssid, sizeof(ap_config.ap.ssid) - 1);
    ap_config.ap.ssid_len = strlen(ssid);
    ap_config.ap.max_connection = 4;
    ap_config.ap.channel = 1;

    if (password && strlen(password) >= 8) {
        strncpy((char *)ap_config.ap.password, password, sizeof(ap_config.ap.password) - 1);
        ap_config.ap.authmode = WIFI_AUTH_WPA2_PSK;
    } else {
        ap_config.ap.authmode = WIFI_AUTH_OPEN;
    }

    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ap_mode_active = true;
    ESP_LOGI(TAG, "AP started: %s", ssid);
    return WIFI_OK;
}

int wifi_manager_stop_ap(void) {
    if (!ap_mode_active) return WIFI_OK;

    esp_wifi_stop();
    ap_mode_active = false;

    if (!sta_netif) {
        sta_netif = esp_netif_create_default_wifi_sta();
    }

    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, NULL));

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "AP stopped, switched to STA mode");
    return WIFI_OK;
}

int8_t wifi_manager_get_rssi(void) {
    if (current_state != WIFI_STATE_CONNECTED) {
        return 0;
    }

    wifi_ap_record_t ap_info;
    if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) {
        return ap_info.rssi;
    }

    return 0;
}

// Private functions

static void update_state(wifi_state_t new_state) {
    if (current_state != new_state) {
        current_state = new_state;
        ESP_LOGI(TAG, "State changed to: %d", new_state);

        // Notify callback
        if (event_callback != NULL) {
            event_callback(new_state, callback_user_data);
        }
    }
}

static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data) {
    if (event_base == WIFI_EVENT) {
        switch (event_id) {
            case WIFI_EVENT_STA_START:
                ESP_LOGI(TAG, "WiFi started");
                break;

            case WIFI_EVENT_STA_CONNECTED:
                ESP_LOGI(TAG, "Connected to AP");
                break;

            case WIFI_EVENT_STA_DISCONNECTED: {
                wifi_event_sta_disconnected_t *event = (wifi_event_sta_disconnected_t *)event_data;
                ESP_LOGI(TAG, "Disconnected from AP (reason: %d)", event->reason);

                if (retry_count < MAX_RETRY_ATTEMPTS) {
                    retry_count++;
                    ESP_LOGI(TAG, "Retry connecting (%d/%d)", retry_count, MAX_RETRY_ATTEMPTS);
                    esp_wifi_connect();
                    update_state(WIFI_STATE_CONNECTING);
                } else {
                    ESP_LOGE(TAG, "Failed to connect after %d attempts", MAX_RETRY_ATTEMPTS);
                    xEventGroupSetBits(wifi_event_group, WIFI_FAIL_BIT);
                    update_state(WIFI_STATE_ERROR);
                }
                break;
            }

            default:
                break;
        }
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&event->ip_info.ip));
        retry_count = 0;
        xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
        update_state(WIFI_STATE_CONNECTED);
    }
}
