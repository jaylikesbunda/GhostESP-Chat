/**
 * @file audit_log.h
 * @brief Comprehensive audit logging for security events
 *
 * Provides tamper-resistant logging of security-critical events
 * with persistent storage in NVS flash.
 */

#ifndef AUDIT_LOG_H
#define AUDIT_LOG_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

// Return codes
#define AUDIT_OK                 0
#define AUDIT_ERR_INVALID_PARAM -1
#define AUDIT_ERR_STORAGE       -2
#define AUDIT_ERR_FULL          -3

// Maximum log entry sizes
#define AUDIT_MAX_ENTRY_LEN     256
#define AUDIT_MAX_ENTRIES       100
#define AUDIT_PEER_ID_LEN       32
#define AUDIT_IP_LEN            16

/**
 * @brief Audit event types
 */
typedef enum {
    // Connection events
    AUDIT_EVENT_CONNECTION_ATTEMPT = 1,
    AUDIT_EVENT_CONNECTION_SUCCESS,
    AUDIT_EVENT_CONNECTION_FAILED,
    AUDIT_EVENT_CONNECTION_CLOSED,

    // Handshake events
    AUDIT_EVENT_HANDSHAKE_INIT,
    AUDIT_EVENT_HANDSHAKE_SUCCESS,
    AUDIT_EVENT_HANDSHAKE_FAILED,

    // Security events
    AUDIT_EVENT_TOFU_NEW_PEER,
    AUDIT_EVENT_TOFU_ACCEPTED,
    AUDIT_EVENT_TOFU_REJECTED,
    AUDIT_EVENT_KEY_CHANGED_DETECTED,
    AUDIT_EVENT_KEY_VERIFIED,
    AUDIT_EVENT_AUTH_FAILED,
    AUDIT_EVENT_REPLAY_DETECTED,

    // Crypto events
    AUDIT_EVENT_ENCRYPTION_FAILED,
    AUDIT_EVENT_DECRYPTION_FAILED,
    AUDIT_EVENT_KEY_DERIVATION,
    AUDIT_EVENT_KEY_ROTATION,

    // Configuration events
    AUDIT_EVENT_CONFIG_CHANGED,
    AUDIT_EVENT_PEER_ADDED,
    AUDIT_EVENT_PEER_REMOVED,
    AUDIT_EVENT_TRUST_UPDATED,

    // System events
    AUDIT_EVENT_SYSTEM_BOOT,
    AUDIT_EVENT_SYSTEM_SHUTDOWN,
    AUDIT_EVENT_NVS_ERROR,
    AUDIT_EVENT_MEMORY_ERROR,

    // Attack detection
    AUDIT_EVENT_DOS_DETECTED,
    AUDIT_EVENT_INVALID_MESSAGE,
    AUDIT_EVENT_RATE_LIMIT_EXCEEDED
} audit_event_type_t;

/**
 * @brief Audit event severity
 */
typedef enum {
    AUDIT_SEVERITY_INFO = 0,
    AUDIT_SEVERITY_WARNING,
    AUDIT_SEVERITY_ERROR,
    AUDIT_SEVERITY_CRITICAL
} audit_severity_t;

/**
 * @brief Audit log entry
 */
typedef struct {
    uint32_t id;                        // Sequential entry ID
    uint32_t timestamp;                 // Unix timestamp (seconds since boot)
    audit_event_type_t event_type;      // Event type
    audit_severity_t severity;          // Severity level
    char peer_id[AUDIT_PEER_ID_LEN];    // Peer ID (if applicable)
    char ip_address[AUDIT_IP_LEN];      // IP address (if applicable)
    uint16_t port;                      // Port (if applicable)
    char details[AUDIT_MAX_ENTRY_LEN];  // Event details/message
    uint8_t checksum;                   // Simple integrity check
} audit_entry_t;

/**
 * @brief Initialize audit logging system
 *
 * @return AUDIT_OK on success
 */
int audit_init(void);

/**
 * @brief Log a security event
 *
 * @param event_type Type of event
 * @param severity Severity level
 * @param peer_id Peer ID (NULL if not applicable)
 * @param ip_address IP address (NULL if not applicable)
 * @param port Port number (0 if not applicable)
 * @param format Printf-style format string for details
 * @param ... Variable arguments for format string
 * @return AUDIT_OK on success
 */
int audit_log(audit_event_type_t event_type,
              audit_severity_t severity,
              const char *peer_id,
              const char *ip_address,
              uint16_t port,
              const char *format, ...);

/**
 * @brief Get audit log entries
 *
 * @param entries Output array for entries
 * @param max_entries Maximum entries to retrieve
 * @param offset Starting offset (for pagination)
 * @param count Number of entries retrieved
 * @return AUDIT_OK on success
 */
int audit_get_entries(audit_entry_t *entries,
                      int max_entries,
                      int offset,
                      int *count);

/**
 * @brief Get total number of log entries
 *
 * @return Number of entries
 */
int audit_get_count(void);

/**
 * @brief Search audit logs for specific event type
 *
 * @param event_type Event type to search for
 * @param entries Output array
 * @param max_entries Maximum entries to return
 * @param count Number of matching entries found
 * @return AUDIT_OK on success
 */
int audit_search_by_type(audit_event_type_t event_type,
                         audit_entry_t *entries,
                         int max_entries,
                         int *count);

/**
 * @brief Search audit logs by peer ID
 *
 * @param peer_id Peer ID to search for
 * @param entries Output array
 * @param max_entries Maximum entries to return
 * @param count Number of matching entries found
 * @return AUDIT_OK on success
 */
int audit_search_by_peer(const char *peer_id,
                         audit_entry_t *entries,
                         int max_entries,
                         int *count);

/**
 * @brief Clear audit logs (requires confirmation)
 *
 * WARNING: This erases all audit history
 *
 * @param confirmation Must be 0xDEADBEEF to proceed
 * @return AUDIT_OK on success
 */
int audit_clear_logs(uint32_t confirmation);

/**
 * @brief Get event type name string
 *
 * @param event_type Event type
 * @return Human-readable event name
 */
const char* audit_get_event_name(audit_event_type_t event_type);

/**
 * @brief Get severity name string
 *
 * @param severity Severity level
 * @return Human-readable severity name
 */
const char* audit_get_severity_name(audit_severity_t severity);

/**
 * @brief Export audit logs as JSON
 *
 * @param buffer Output buffer
 * @param buffer_size Size of buffer
 * @param offset Starting entry offset
 * @param limit Maximum entries to export
 * @return Number of bytes written, or negative on error
 */
int audit_export_json(char *buffer, size_t buffer_size, int offset, int limit);

/**
 * @brief Verify audit log integrity
 *
 * Checks for missing entries or corrupted checksums
 *
 * @return AUDIT_OK if integrity verified, error code otherwise
 */
int audit_verify_integrity(void);

#ifdef __cplusplus
}
#endif

#endif // AUDIT_LOG_H
