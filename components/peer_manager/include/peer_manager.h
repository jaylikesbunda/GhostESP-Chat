#ifndef PEER_MANAGER_H
#define PEER_MANAGER_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Maximum values
 */
#define PEER_MAX_PEERS 10
#define PEER_MAX_NAME_LEN 32
#define PEER_MAX_IP_LEN 16
#define PEER_PUBLIC_KEY_LEN 32

/**
 * Peer status
 */
typedef enum {
    PEER_STATUS_OFFLINE = 0,
    PEER_STATUS_ONLINE = 1
} peer_status_t;

/**
 * Peer information structure
 */
typedef struct {
    char id[16];                        // Unique peer ID
    char name[PEER_MAX_NAME_LEN];       // Display name
    char ip[PEER_MAX_IP_LEN];           // IP address
    uint16_t port;                      // Port number
    uint8_t public_key[PEER_PUBLIC_KEY_LEN];  // X25519 public key
    peer_status_t status;               // Online/offline status
    uint32_t last_seen;                 // Unix timestamp
    bool trusted;                       // TOFU trust flag
} peer_info_t;

/**
 * Return codes
 */
#define PEER_OK 0
#define PEER_ERR_INVALID_ARG -1
#define PEER_ERR_NOT_FOUND -2
#define PEER_ERR_FULL -3
#define PEER_ERR_STORAGE -4
#define PEER_ERR_EXISTS -5

/**
 * Initialize peer manager
 *
 * Loads peer list from NVS storage
 *
 * @return PEER_OK on success, error code otherwise
 */
int peer_manager_init(void);

/**
 * Add a new peer
 *
 * @param name Display name for peer
 * @param ip IP address
 * @param port Port number
 * @param public_key X25519 public key (32 bytes)
 * @param peer_id Output: generated peer ID (can be NULL)
 * @return PEER_OK on success, error code otherwise
 */
int peer_manager_add(const char *name, const char *ip, uint16_t port,
                    const uint8_t public_key[PEER_PUBLIC_KEY_LEN],
                    char peer_id[16]);

/**
 * Remove a peer by ID
 *
 * @param peer_id Peer ID to remove
 * @return PEER_OK on success, error code otherwise
 */
int peer_manager_remove(const char *peer_id);

/**
 * Get peer information by ID
 *
 * @param peer_id Peer ID
 * @param info Output peer information
 * @return PEER_OK on success, error code otherwise
 */
int peer_manager_get(const char *peer_id, peer_info_t *info);

/**
 * Get all peers
 *
 * @param peers Output array of peer info
 * @param max_peers Maximum number of peers to return
 * @param count Output: actual number of peers returned
 * @return PEER_OK on success, error code otherwise
 */
int peer_manager_get_all(peer_info_t *peers, int max_peers, int *count);

/**
 * Update peer status (online/offline)
 *
 * @param peer_id Peer ID
 * @param status New status
 * @return PEER_OK on success, error code otherwise
 */
int peer_manager_set_status(const char *peer_id, peer_status_t status);

/**
 * Update peer last seen timestamp
 *
 * @param peer_id Peer ID
 * @param timestamp Unix timestamp
 * @return PEER_OK on success, error code otherwise
 */
int peer_manager_set_last_seen(const char *peer_id, uint32_t timestamp);

/**
 * Mark peer as trusted (TOFU)
 *
 * @param peer_id Peer ID
 * @param trusted Trust flag
 * @return PEER_OK on success, error code otherwise
 */
int peer_manager_set_trusted(const char *peer_id, bool trusted);

/**
 * Get number of stored peers
 *
 * @return Number of peers
 */
int peer_manager_count(void);

/**
 * Clear all peers from storage
 *
 * @return PEER_OK on success, error code otherwise
 */
int peer_manager_clear_all(void);

/**
 * Save peer list to NVS
 *
 * @return PEER_OK on success, error code otherwise
 */
int peer_manager_save(void);

#ifdef __cplusplus
}
#endif

#endif // PEER_MANAGER_H
