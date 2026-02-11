/**
 * @file public_ip.h
 * @brief Public IP discovery for GhostESP
 *
 * Discovers the device's public IP address by querying external services.
 */

#ifndef GHOST_PUBLIC_IP_H
#define GHOST_PUBLIC_IP_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Maximum IP string length (IPv4: "xxx.xxx.xxx.xxx\0")
#define PUBLIC_IP_MAX_LEN 16

// Error codes
#define PUBLIC_IP_OK 0
#define PUBLIC_IP_ERR_INVALID_PARAM -1
#define PUBLIC_IP_ERR_NOT_CONNECTED -2
#define PUBLIC_IP_ERR_HTTP_FAILED -3
#define PUBLIC_IP_ERR_PARSE_FAILED -4
#define PUBLIC_IP_ERR_TIMEOUT -5

/**
 * @brief Public IP discovery services
 */
typedef enum {
    PUBLIC_IP_SERVICE_IPIFY,        // https://api.ipify.org
    PUBLIC_IP_SERVICE_AMAZONAWS,    // https://checkip.amazonaws.com
    PUBLIC_IP_SERVICE_ICANHAZIP,    // https://icanhazip.com
    PUBLIC_IP_SERVICE_WTFISMYIP,    // https://wtfismyip.com/text
} public_ip_service_t;

/**
 * @brief Callback for IP discovery completion
 *
 * @param ip_address Discovered public IP (NULL on failure)
 * @param user_data User data passed during registration
 */
typedef void (*public_ip_callback_t)(const char *ip_address, void *user_data);

/**
 * @brief Discover public IP address synchronously
 *
 * Queries an external service to discover the device's public IP address.
 * Tries multiple services if the first one fails.
 *
 * @param ip_str Output buffer for IP string (min PUBLIC_IP_MAX_LEN bytes)
 * @param service Service to use (or use default if invalid)
 * @return PUBLIC_IP_OK on success, error code otherwise
 */
int public_ip_discover(char *ip_str, public_ip_service_t service);

/**
 * @brief Discover public IP with automatic fallback
 *
 * Tries multiple services in order until one succeeds.
 *
 * @param ip_str Output buffer for IP string
 * @return PUBLIC_IP_OK on success, error code otherwise
 */
int public_ip_discover_auto(char *ip_str);

/**
 * @brief Start automatic IP monitoring
 *
 * Periodically checks for IP changes and calls callback when changed.
 *
 * @param callback Callback function
 * @param user_data User data for callback
 * @param interval_sec Check interval in seconds (min 60, recommended 300)
 * @return PUBLIC_IP_OK on success, error code otherwise
 */
int public_ip_monitor_start(public_ip_callback_t callback, void *user_data, uint32_t interval_sec);

/**
 * @brief Stop IP monitoring
 */
void public_ip_monitor_stop(void);

/**
 * @brief Get the last discovered public IP
 *
 * @param ip_str Output buffer for IP string
 * @return PUBLIC_IP_OK if IP available, error otherwise
 */
int public_ip_get_cached(char *ip_str);

/**
 * @brief Get local IP address (private network)
 *
 * @param ip_str Output buffer for IP string
 * @return PUBLIC_IP_OK on success, error code otherwise
 */
int public_ip_get_local(char *ip_str);

#ifdef __cplusplus
}
#endif

#endif // GHOST_PUBLIC_IP_H
