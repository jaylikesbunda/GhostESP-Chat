/**
 * @file p2p.h
 * @brief P2P connection management for GhostESP
 *
 * Handles direct peer-to-peer TCP connections with encrypted messaging.
 */

#ifndef GHOST_P2P_H
#define GHOST_P2P_H

#include <stdint.h>
#include <stdbool.h>
#include "crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

// Default P2P port
#define P2P_DEFAULT_PORT 8000
#define P2P_MAX_CONNECTIONS 10

// Error codes
#define P2P_OK 0
#define P2P_ERR_INVALID_PARAM -1
#define P2P_ERR_NOT_INITIALIZED -2
#define P2P_ERR_SOCKET_FAILED -3
#define P2P_ERR_CONNECT_FAILED -4
#define P2P_ERR_HANDSHAKE_FAILED -5
#define P2P_ERR_SEND_FAILED -6
#define P2P_ERR_RECEIVE_FAILED -7
#define P2P_ERR_TIMEOUT -8
#define P2P_ERR_DISCONNECTED -9

// Connection state
typedef enum {
    P2P_STATE_IDLE,
    P2P_STATE_CONNECTING,
    P2P_STATE_HANDSHAKING,
    P2P_STATE_CONNECTED,
    P2P_STATE_DISCONNECTED,
    P2P_STATE_ERROR
} p2p_state_t;

// Connection handle (opaque)
typedef struct p2p_connection p2p_connection_t;

/**
 * @brief Message received callback
 *
 * @param conn Connection handle
 * @param message Decrypted message text
 * @param message_len Length of message
 * @param user_data User data
 */
typedef void (*p2p_message_cb_t)(p2p_connection_t *conn, const char *message,
                                  size_t message_len, void *user_data);

/**
 * @brief Connection state change callback
 *
 * @param conn Connection handle
 * @param state New state
 * @param user_data User data
 */
typedef void (*p2p_state_cb_t)(p2p_connection_t *conn, p2p_state_t state, void *user_data);

/**
 * @brief Initialize P2P subsystem
 *
 * @param listen_port Port to listen on for incoming connections
 * @return P2P_OK on success, error code otherwise
 */
int p2p_init(uint16_t listen_port);

/**
 * @brief Shutdown P2P subsystem
 */
void p2p_shutdown(void);

/**
 * @brief Connect to a peer
 *
 * Initiates outgoing connection and performs ECDH handshake.
 *
 * @param peer_ip Peer IP address
 * @param peer_port Peer port
 * @param peer_public_key Peer's public key (32 bytes, for verification)
 * @param conn Output connection handle
 * @return P2P_OK on success, error code otherwise
 */
int p2p_connect(const char *peer_ip, uint16_t peer_port,
               const uint8_t peer_public_key[32], p2p_connection_t **conn);

/**
 * @brief Send encrypted message to peer
 *
 * @param conn Connection handle
 * @param message Message text
 * @param message_len Message length
 * @return P2P_OK on success, error code otherwise
 */
int p2p_send_message(p2p_connection_t *conn, const char *message, size_t message_len);

/**
 * @brief Disconnect from peer
 *
 * Sends disconnect message and closes connection cleanly.
 *
 * @param conn Connection handle
 * @return P2P_OK on success, error code otherwise
 */
int p2p_disconnect(p2p_connection_t *conn);

/**
 * @brief Get connection state
 *
 * @param conn Connection handle
 * @return Current connection state
 */
p2p_state_t p2p_get_state(p2p_connection_t *conn);

/**
 * @brief Register message callback
 *
 * @param conn Connection handle
 * @param callback Callback function
 * @param user_data User data for callback
 */
void p2p_register_message_callback(p2p_connection_t *conn, p2p_message_cb_t callback, void *user_data);

/**
 * @brief Register state change callback
 *
 * @param conn Connection handle
 * @param callback Callback function
 * @param user_data User data for callback
 */
void p2p_register_state_callback(p2p_connection_t *conn, p2p_state_cb_t callback, void *user_data);

/**
 * @brief Get peer information
 *
 * @param conn Connection handle
 * @param peer_ip Output buffer for peer IP (min 16 bytes)
 * @param peer_port Output peer port
 * @return P2P_OK on success, error code otherwise
 */
int p2p_get_peer_info(p2p_connection_t *conn, char *peer_ip, uint16_t *peer_port);

/**
 * @brief Get local keypair for this connection
 *
 * @param conn Connection handle
 * @param keypair Output keypair structure
 * @return P2P_OK on success, error code otherwise
 */
int p2p_get_local_keypair(p2p_connection_t *conn, crypto_keypair_t *keypair);

/**
 * @brief Get peer's public key
 *
 * @param conn Connection handle
 * @param public_key Output buffer (32 bytes)
 * @return P2P_OK on success, error code otherwise
 */
int p2p_get_peer_public_key(p2p_connection_t *conn, uint8_t public_key[32]);

/**
 * @brief Send heartbeat (keep-alive)
 *
 * @param conn Connection handle
 * @return P2P_OK on success, error code otherwise
 */
int p2p_send_heartbeat(p2p_connection_t *conn);

/**
 * @brief Get device's public key (device-level identity)
 *
 * @param public_key Output buffer (32 bytes)
 * @return P2P_OK on success, error code otherwise
 */
int p2p_get_device_public_key(uint8_t public_key[32]);

typedef void (*p2p_global_message_cb_t)(const char *peer_ip, uint16_t peer_port,
                                         const char *message, size_t message_len);

void p2p_set_global_message_callback(p2p_global_message_cb_t callback);

p2p_connection_t *p2p_find_connection(const char *peer_ip, uint16_t peer_port);

int p2p_find_or_connect(const char *peer_ip, uint16_t peer_port,
                        const uint8_t peer_public_key[32], p2p_connection_t **conn);

#ifdef __cplusplus
}
#endif

#endif // GHOST_P2P_H
