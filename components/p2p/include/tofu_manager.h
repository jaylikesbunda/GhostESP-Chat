/**
 * @file tofu_manager.h
 * @brief Trust-On-First-Use Manager with User Confirmation
 *
 * Manages pending peer connections requiring user approval
 */

#ifndef TOFU_MANAGER_H
#define TOFU_MANAGER_H

#include <stdint.h>
#include <stdbool.h>
#include "p2p_security.h"

#ifdef __cplusplus
extern "C" {
#endif

// Return codes
#define TOFU_OK                 0
#define TOFU_ERR_INVALID_PARAM -1
#define TOFU_ERR_NOT_FOUND     -2
#define TOFU_ERR_FULL          -3
#define TOFU_ERR_TIMEOUT       -4

// Maximum pending requests
#define TOFU_MAX_PENDING 10

// Timeout for pending requests (seconds)
#define TOFU_REQUEST_TIMEOUT 300  // 5 minutes

/**
 * @brief TOFU request status
 */
typedef enum {
    TOFU_STATUS_PENDING = 0,
    TOFU_STATUS_APPROVED,
    TOFU_STATUS_REJECTED,
    TOFU_STATUS_TIMEOUT
} tofu_status_t;

/**
 * @brief Callback for TOFU decision notifications
 */
typedef void (*tofu_decision_cb_t)(const char *request_id, tofu_status_t status, void *user_data);

/**
 * @brief TOFU request structure
 */
typedef struct {
    char request_id[16];                // Unique request ID
    char peer_id[32];                   // Peer identifier
    char peer_ip[16];                   // Peer IP address
    uint16_t peer_port;                 // Peer port
    uint8_t public_key[32];             // Peer's public key
    uint8_t fingerprint[32];            // Key fingerprint
    char fingerprint_display[80];       // Formatted fingerprint
    uint32_t timestamp;                 // Request timestamp
    tofu_status_t status;               // Current status
    tofu_decision_cb_t callback;        // Decision callback
    void *user_data;                    // Callback user data
} tofu_request_t;

/**
 * @brief Initialize TOFU manager
 *
 * @return TOFU_OK on success
 */
int tofu_manager_init(void);

/**
 * @brief Create new TOFU request for user approval
 *
 * @param peer_id Peer identifier
 * @param peer_ip Peer IP address
 * @param peer_port Peer port
 * @param public_key Peer's public key
 * @param callback Decision callback (optional)
 * @param user_data User data for callback
 * @param request_id Output request ID
 * @return TOFU_OK on success
 */
int tofu_create_request(const char *peer_id,
                        const char *peer_ip,
                        uint16_t peer_port,
                        const uint8_t public_key[32],
                        tofu_decision_cb_t callback,
                        void *user_data,
                        char *request_id);

/**
 * @brief Approve TOFU request
 *
 * @param request_id Request ID
 * @return TOFU_OK on success
 */
int tofu_approve(const char *request_id);

/**
 * @brief Reject TOFU request
 *
 * @param request_id Request ID
 * @return TOFU_OK on success
 */
int tofu_reject(const char *request_id);

/**
 * @brief Get pending TOFU request
 *
 * @param request_id Request ID
 * @param request Output request structure
 * @return TOFU_OK on success
 */
int tofu_get_request(const char *request_id, tofu_request_t *request);

/**
 * @brief Get all pending TOFU requests
 *
 * @param requests Output array
 * @param max_requests Maximum requests to return
 * @param count Number of pending requests
 * @return TOFU_OK on success
 */
int tofu_get_pending_requests(tofu_request_t *requests,
                              int max_requests,
                              int *count);

/**
 * @brief Wait for user decision on TOFU request
 *
 * Blocks until user approves/rejects or timeout occurs
 *
 * @param request_id Request ID
 * @param timeout_ms Timeout in milliseconds (0 = no timeout)
 * @return TOFU_STATUS_APPROVED, TOFU_STATUS_REJECTED, or TOFU_STATUS_TIMEOUT
 */
tofu_status_t tofu_wait_for_decision(const char *request_id, uint32_t timeout_ms);

/**
 * @brief Cancel pending TOFU request
 *
 * @param request_id Request ID
 * @return TOFU_OK on success
 */
int tofu_cancel_request(const char *request_id);

/**
 * @brief Clean up expired TOFU requests
 *
 * @return Number of requests cleaned up
 */
int tofu_cleanup_expired(void);

/**
 * @brief Get number of pending requests
 *
 * @return Number of pending requests
 */
int tofu_get_pending_count(void);

#ifdef __cplusplus
}
#endif

#endif // TOFU_MANAGER_H
