/**
 * @file chat_storage.h
 * @brief Persistent chat history storage using NVS
 *
 * Stores recent chat messages in NVS flash for persistence across reboots.
 * Design considerations:
 * - Circular buffer per peer (oldest messages overwritten)
 * - Configurable max messages per peer
 * - Efficient storage with minimal overhead
 */

#ifndef CHAT_STORAGE_H
#define CHAT_STORAGE_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

// Configuration
#define CHAT_MAX_MESSAGE_LENGTH 256     // Max chars per message
#define CHAT_MAX_MESSAGES_PER_PEER 20   // Circular buffer size
#define CHAT_PEER_ID_LENGTH 32          // Peer identifier length

// Error codes
#define CHAT_STORAGE_OK 0
#define CHAT_STORAGE_ERR_INIT -1
#define CHAT_STORAGE_ERR_INVALID_PARAM -2
#define CHAT_STORAGE_ERR_NOT_FOUND -3
#define CHAT_STORAGE_ERR_FULL -4
#define CHAT_STORAGE_ERR_NVS -5

/**
 * @brief Chat message direction
 */
typedef enum {
    CHAT_DIR_SENT = 0,
    CHAT_DIR_RECEIVED = 1
} chat_direction_t;

/**
 * @brief Stored chat message
 */
typedef struct {
    uint32_t timestamp;                         // Unix timestamp
    chat_direction_t direction;                 // Sent or received
    char message[CHAT_MAX_MESSAGE_LENGTH];      // Message text
} chat_message_t;

/**
 * @brief Chat history for a peer
 */
typedef struct {
    char peer_id[CHAT_PEER_ID_LENGTH];          // Peer identifier (IP or public key hash)
    uint16_t count;                              // Number of messages stored
    uint16_t head;                               // Circular buffer head index
    chat_message_t messages[CHAT_MAX_MESSAGES_PER_PEER];
} chat_history_t;

/**
 * @brief Initialize chat storage
 *
 * @return CHAT_STORAGE_OK on success, error code otherwise
 */
int chat_storage_init(void);

/**
 * @brief Add a message to chat history
 *
 * Automatically handles circular buffer wrapping.
 *
 * @param peer_id Peer identifier (e.g., IP address or key fingerprint)
 * @param message Message text (will be truncated if too long)
 * @param direction Message direction (sent/received)
 * @return CHAT_STORAGE_OK on success, error code otherwise
 */
int chat_storage_add_message(const char *peer_id, const char *message,
                              chat_direction_t direction);

/**
 * @brief Retrieve chat history for a peer
 *
 * Returns messages in chronological order (oldest first).
 *
 * @param peer_id Peer identifier
 * @param history Output buffer for chat history
 * @return CHAT_STORAGE_OK on success, error code otherwise
 */
int chat_storage_get_history(const char *peer_id, chat_history_t *history);

/**
 * @brief Delete chat history for a peer
 *
 * @param peer_id Peer identifier
 * @return CHAT_STORAGE_OK on success, error code otherwise
 */
int chat_storage_delete_history(const char *peer_id);

/**
 * @brief Clear all chat history
 *
 * @return CHAT_STORAGE_OK on success, error code otherwise
 */
int chat_storage_clear_all(void);

/**
 * @brief Get list of peers with stored chat history
 *
 * @param peer_ids Output buffer for peer IDs
 * @param max_peers Maximum number of peer IDs to return
 * @param count Output: actual number of peers found
 * @return CHAT_STORAGE_OK on success, error code otherwise
 */
int chat_storage_list_peers(char peer_ids[][CHAT_PEER_ID_LENGTH],
                            uint16_t max_peers, uint16_t *count);

/**
 * @brief Get storage statistics
 *
 * @param total_peers Output: number of peers with history
 * @param total_messages Output: total messages across all peers
 * @param nvs_used_bytes Output: approximate NVS bytes used
 * @return CHAT_STORAGE_OK on success, error code otherwise
 */
int chat_storage_get_stats(uint16_t *total_peers, uint32_t *total_messages,
                           size_t *nvs_used_bytes);

#ifdef __cplusplus
}
#endif

#endif // CHAT_STORAGE_H
