/**
 * @file upnp.h
 * @brief UPnP IGD (Internet Gateway Device) port mapping for GhostESP
 *
 * Implements automatic port forwarding using UPnP protocol.
 */

#ifndef GHOST_UPNP_H
#define GHOST_UPNP_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Error codes
#define UPNP_OK 0
#define UPNP_ERR_INVALID_PARAM -1
#define UPNP_ERR_NOT_SUPPORTED -2
#define UPNP_ERR_DISCOVERY_FAILED -3
#define UPNP_ERR_MAPPING_FAILED -4
#define UPNP_ERR_DELETE_FAILED -5
#define UPNP_ERR_TIMEOUT -6

// Protocol types
typedef enum {
    UPNP_PROTO_TCP,
    UPNP_PROTO_UDP
} upnp_protocol_t;

/**
 * @brief Port mapping information
 */
typedef struct {
    uint16_t external_port;        // External port on router
    uint16_t internal_port;        // Internal port on device
    upnp_protocol_t protocol;      // TCP or UDP
    uint32_t lease_duration;       // Lease time in seconds (0 = permanent)
    char description[64];          // Description for the mapping
} upnp_mapping_t;

/**
 * @brief Initialize UPnP module
 *
 * @return UPNP_OK on success, error code otherwise
 */
int upnp_init(void);

/**
 * @brief Discover UPnP IGD gateway on network
 *
 * Sends SSDP M-SEARCH multicast to discover router with UPnP support.
 *
 * @param timeout_ms Discovery timeout in milliseconds
 * @return UPNP_OK if gateway found, error otherwise
 */
int upnp_discover_gateway(uint32_t timeout_ms);

/**
 * @brief Add port mapping
 *
 * Creates a port forwarding rule on the router.
 *
 * @param mapping Port mapping configuration
 * @return UPNP_OK on success, error code otherwise
 */
int upnp_add_port_mapping(const upnp_mapping_t *mapping);

/**
 * @brief Delete port mapping
 *
 * Removes a port forwarding rule from the router.
 *
 * @param external_port External port to remove
 * @param protocol Protocol (TCP/UDP)
 * @return UPNP_OK on success, error code otherwise
 */
int upnp_delete_port_mapping(uint16_t external_port, upnp_protocol_t protocol);

/**
 * @brief Get external (public) IP address from gateway
 *
 * @param ip_str Output buffer for IP string (min 16 bytes)
 * @return UPNP_OK on success, error code otherwise
 */
int upnp_get_external_ip(char *ip_str);

/**
 * @brief Check if UPnP is supported by the gateway
 *
 * @return true if UPnP available, false otherwise
 */
bool upnp_is_available(void);

/**
 * @brief Check if a port mapping is currently active
 *
 * @return true if port mapped via UPnP, false otherwise
 */
bool upnp_is_port_mapped(void);

/**
 * @brief Get the currently mapped external port
 *
 * @return Mapped port number, or 0 if none
 */
uint16_t upnp_get_mapped_port(void);

/**
 * @brief Get gateway information
 *
 * @param manufacturer Output buffer (min 64 bytes)
 * @param model Output buffer (min 64 bytes)
 * @return UPNP_OK on success, error code otherwise
 */
int upnp_get_gateway_info(char *manufacturer, char *model);

#ifdef __cplusplus
}
#endif

#endif // GHOST_UPNP_H
