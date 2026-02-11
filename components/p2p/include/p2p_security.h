/**
 * @file p2p_security.h
 * @brief Security enhancements for P2P handshake
 *
 * Provides TOFU (Trust On First Use) and fingerprint verification
 * to prevent MITM attacks during handshake.
 */

#ifndef GHOST_P2P_SECURITY_H
#define GHOST_P2P_SECURITY_H

#include <stdint.h>
#include <stdbool.h>
#include "crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

// Security status codes
#define P2P_SEC_OK                  0
#define P2P_SEC_ERR_INVALID_PARAM  -1
#define P2P_SEC_ERR_UNTRUSTED      -2
#define P2P_SEC_ERR_MISMATCH       -3
#define P2P_SEC_ERR_STORAGE        -4

// Fingerprint display format
#define P2P_FINGERPRINT_HEX_LEN 64  // 32 bytes * 2 hex chars
#define P2P_FINGERPRINT_DISPLAY_LEN 80  // "XX:XX:XX..." format

/**
 * @brief Peer trust status
 */
typedef enum {
    P2P_TRUST_UNKNOWN = 0,     // Never seen before
    P2P_TRUST_FIRST_USE,       // First connection (TOFU)
    P2P_TRUST_VERIFIED,        // Manually verified by user
    P2P_TRUST_PINNED,          // Key pinned, verify on each connection
    P2P_TRUST_REJECTED         // Explicitly untrusted
} p2p_trust_status_t;

/**
 * @brief Peer security context
 */
typedef struct {
    char peer_id[32];
    uint8_t public_key[32];
    uint8_t fingerprint[32];
    p2p_trust_status_t trust_status;
    uint32_t first_seen;
    uint32_t last_seen;
    uint32_t connection_count;
} p2p_peer_security_t;

/**
 * @brief Initialize P2P security module
 *
 * @return P2P_SEC_OK on success
 */
int p2p_security_init(void);

/**
 * @brief Format fingerprint for display
 *
 * @param fingerprint Raw fingerprint (32 bytes)
 * @param output Formatted string output
 * @param output_len Length of output buffer
 * @return P2P_SEC_OK on success
 */
int p2p_security_format_fingerprint(const uint8_t fingerprint[32],
                                    char *output, size_t output_len);

/**
 * @brief Verify peer's public key (TOFU + pinning)
 *
 * Implements Trust On First Use:
 * - First connection: Accept and store key
 * - Subsequent connections: Verify key matches stored value
 *
 * @param peer_id Peer identifier
 * @param public_key Peer's public key
 * @param trust_status Output trust status
 * @return P2P_SEC_OK if trusted, error code otherwise
 */
int p2p_security_verify_peer(const char *peer_id,
                              const uint8_t public_key[32],
                              p2p_trust_status_t *trust_status);

/**
 * @brief Get peer security information
 *
 * @param peer_id Peer identifier
 * @param security Output security context
 * @return P2P_SEC_OK on success
 */
int p2p_security_get_peer(const char *peer_id, p2p_peer_security_t *security);

/**
 * @brief Manually mark peer as verified
 *
 * User has verified fingerprint out-of-band (QR code, etc.)
 *
 * @param peer_id Peer identifier
 * @return P2P_SEC_OK on success
 */
int p2p_security_mark_verified(const char *peer_id);

/**
 * @brief Manually reject peer
 *
 * Mark peer as untrusted, reject future connections
 *
 * @param peer_id Peer identifier
 * @return P2P_SEC_OK on success
 */
int p2p_security_mark_rejected(const char *peer_id);

/**
 * @brief Check if peer key changed (possible MITM)
 *
 * @param peer_id Peer identifier
 * @param public_key New public key
 * @return true if key changed, false if same or first use
 */
bool p2p_security_key_changed(const char *peer_id, const uint8_t public_key[32]);

/**
 * @brief Remove peer from trust store
 *
 * @param peer_id Peer identifier
 * @return P2P_SEC_OK on success
 */
int p2p_security_forget_peer(const char *peer_id);

/**
 * @brief Get all trusted peers
 *
 * @param peers Output array
 * @param max_peers Maximum peers to return
 * @param count Number of peers returned
 * @return P2P_SEC_OK on success
 */
int p2p_security_list_peers(p2p_peer_security_t *peers, int max_peers, int *count);

#ifdef __cplusplus
}
#endif

#endif // GHOST_P2P_SECURITY_H
