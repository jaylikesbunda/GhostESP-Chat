/**
 * @file wifi_manager.h
 * @brief WiFi connection manager for GhostESP
 */

#ifndef GHOST_WIFI_MANAGER_H
#define GHOST_WIFI_MANAGER_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// WiFi connection states
typedef enum {
    WIFI_STATE_IDLE,
    WIFI_STATE_CONNECTING,
    WIFI_STATE_CONNECTED,
    WIFI_STATE_DISCONNECTED,
    WIFI_STATE_ERROR
} wifi_state_t;

// WiFi event callback
typedef void (*wifi_event_cb_t)(wifi_state_t state, void *user_data);

// Error codes
#define WIFI_OK 0
#define WIFI_ERR_INVALID_PARAM -1
#define WIFI_ERR_NOT_INITIALIZED -2
#define WIFI_ERR_CONNECT_FAILED -3
#define WIFI_ERR_NVS_FAILED -4

/**
 * @brief Initialize WiFi manager
 *
 * @return WIFI_OK on success, error code otherwise
 */
int wifi_manager_init(void);

/**
 * @brief Connect to WiFi access point
 *
 * @param ssid WiFi SSID (max 32 chars)
 * @param password WiFi password (max 64 chars)
 * @param save_credentials Save credentials to NVS for auto-reconnect
 * @return WIFI_OK on success, error code otherwise
 */
int wifi_manager_connect(const char *ssid, const char *password, bool save_credentials);

/**
 * @brief Disconnect from WiFi
 *
 * @return WIFI_OK on success, error code otherwise
 */
int wifi_manager_disconnect(void);

/**
 * @brief Get current WiFi connection state
 *
 * @return Current WiFi state
 */
wifi_state_t wifi_manager_get_state(void);

/**
 * @brief Get local IP address
 *
 * @param ip_str Output buffer for IP string (min 16 bytes)
 * @return WIFI_OK on success, error code otherwise
 */
int wifi_manager_get_ip(char *ip_str);

/**
 * @brief Register event callback
 *
 * @param callback Callback function
 * @param user_data User data passed to callback
 */
void wifi_manager_register_callback(wifi_event_cb_t callback, void *user_data);

/**
 * @brief Load saved credentials from NVS and auto-connect
 *
 * @return WIFI_OK if credentials loaded and connection initiated, error otherwise
 */
int wifi_manager_auto_connect(void);

/**
 * @brief Clear saved credentials from NVS
 *
 * @return WIFI_OK on success, error code otherwise
 */
int wifi_manager_clear_credentials(void);

/**
 * @brief Check if WiFi credentials are saved in NVS
 *
 * @return true if credentials exist, false otherwise
 */
bool wifi_manager_has_saved_credentials(void);

/**
 * @brief Start WiFi in AP mode for setup
 *
 * @param ssid AP SSID
 * @param password AP password (NULL for open)
 * @return WIFI_OK on success, error code otherwise
 */
int wifi_manager_start_ap(const char *ssid, const char *password);

/**
 * @brief Stop AP mode and switch back to STA
 *
 * @return WIFI_OK on success, error code otherwise
 */
int wifi_manager_stop_ap(void);

/**
 * @brief Get WiFi signal strength (RSSI)
 *
 * @return RSSI value in dBm, or 0 if not connected
 */
int8_t wifi_manager_get_rssi(void);

#ifdef __cplusplus
}
#endif

#endif // GHOST_WIFI_MANAGER_H
