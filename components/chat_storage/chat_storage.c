/**
 * @file chat_storage.c
 * @brief Implementation of persistent chat history storage
 */

#include "chat_storage.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"

static const char *TAG = "chat_storage";
static const char *NVS_NAMESPACE = "chat";

// NVS keys are limited to 15 chars, we'll use format: "h_<8-char-hash>"
#define NVS_KEY_PREFIX "h_"
#define NVS_KEY_INDEX "peers"  // Stores list of peer hashes
#define MAX_STORED_PEERS 10    // Limit to prevent NVS exhaustion

/**
 * @brief Generate a short hash from peer_id for NVS key
 */
static void generate_peer_hash(const char *peer_id, char *hash_out, size_t hash_len) {
    // Simple hash: take first 8 chars or hash of peer_id
    uint32_t hash = 0;
    for (int i = 0; peer_id[i] != '\0'; i++) {
        hash = hash * 31 + (uint8_t)peer_id[i];
    }
    snprintf(hash_out, hash_len, "%s%08lx", NVS_KEY_PREFIX, hash);
}

int chat_storage_init(void) {
    ESP_LOGI(TAG, "Initializing chat storage");

    // NVS should already be initialized by main, but check anyway
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS namespace: %s", esp_err_to_name(err));
        return CHAT_STORAGE_ERR_NVS;
    }

    nvs_close(handle);
    ESP_LOGI(TAG, "Chat storage initialized");
    return CHAT_STORAGE_OK;
}

int chat_storage_add_message(const char *peer_id, const char *message,
                              chat_direction_t direction) {
    if (!peer_id || !message) {
        return CHAT_STORAGE_ERR_INVALID_PARAM;
    }

    ESP_LOGD(TAG, "Adding message for peer: %s", peer_id);

    // Generate NVS key from peer_id
    char nvs_key[16];
    generate_peer_hash(peer_id, nvs_key, sizeof(nvs_key));

    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
        return CHAT_STORAGE_ERR_NVS;
    }

    // Allocate history on heap to avoid stack overflow (structure is ~5.3KB)
    chat_history_t *history = (chat_history_t *)malloc(sizeof(chat_history_t));
    if (!history) {
        ESP_LOGE(TAG, "Failed to allocate memory for chat history");
        nvs_close(handle);
        return CHAT_STORAGE_ERR_NVS;
    }
    memset(history, 0, sizeof(chat_history_t));

    // Load existing history or create new
    size_t required_size = sizeof(chat_history_t);
    err = nvs_get_blob(handle, nvs_key, history, &required_size);

    if (err == ESP_ERR_NVS_NOT_FOUND) {
        // New peer, initialize history
        strncpy(history->peer_id, peer_id, CHAT_PEER_ID_LENGTH - 1);
        history->peer_id[CHAT_PEER_ID_LENGTH - 1] = '\0';
        history->count = 0;
        history->head = 0;
        ESP_LOGI(TAG, "Creating new chat history for: %s", peer_id);
    } else if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to read chat history: %s", esp_err_to_name(err));
        free(history);
        nvs_close(handle);
        return CHAT_STORAGE_ERR_NVS;
    }

    // Add new message to circular buffer
    chat_message_t *msg = &history->messages[history->head];
    msg->timestamp = (uint32_t)time(NULL);
    msg->direction = direction;

    // Truncate long messages for storage (full message is sent over P2P)
    size_t msg_len = strlen(message);
    if (msg_len >= CHAT_MAX_MESSAGE_LENGTH) {
        strncpy(msg->message, message, CHAT_MAX_MESSAGE_LENGTH - 4);
        msg->message[CHAT_MAX_MESSAGE_LENGTH - 4] = '.';
        msg->message[CHAT_MAX_MESSAGE_LENGTH - 3] = '.';
        msg->message[CHAT_MAX_MESSAGE_LENGTH - 2] = '.';
        msg->message[CHAT_MAX_MESSAGE_LENGTH - 1] = '\0';
        ESP_LOGD(TAG, "Message truncated from %zu to %d chars for storage", msg_len, CHAT_MAX_MESSAGE_LENGTH - 4);
    } else {
        strncpy(msg->message, message, CHAT_MAX_MESSAGE_LENGTH - 1);
        msg->message[CHAT_MAX_MESSAGE_LENGTH - 1] = '\0';
    }
    msg->message[CHAT_MAX_MESSAGE_LENGTH - 1] = '\0';

    // Update circular buffer pointers
    history->head = (history->head + 1) % CHAT_MAX_MESSAGES_PER_PEER;
    if (history->count < CHAT_MAX_MESSAGES_PER_PEER) {
        history->count++;
    }

    // Save updated history
    err = nvs_set_blob(handle, nvs_key, history, sizeof(chat_history_t));
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to save chat history: %s", esp_err_to_name(err));
        free(history);
        nvs_close(handle);
        return CHAT_STORAGE_ERR_NVS;
    }

    err = nvs_commit(handle);
    nvs_close(handle);

    if (err != ESP_OK) {
        free(history);
        ESP_LOGE(TAG, "Failed to commit NVS: %s", esp_err_to_name(err));
        return CHAT_STORAGE_ERR_NVS;
    }

    ESP_LOGD(TAG, "Message saved (%d/%d messages)", history->count, CHAT_MAX_MESSAGES_PER_PEER);
    free(history);
    return CHAT_STORAGE_OK;
}

int chat_storage_get_history(const char *peer_id, chat_history_t *history) {
    if (!peer_id || !history) {
        return CHAT_STORAGE_ERR_INVALID_PARAM;
    }

    char nvs_key[16];
    generate_peer_hash(peer_id, nvs_key, sizeof(nvs_key));

    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
        return CHAT_STORAGE_ERR_NVS;
    }

    size_t required_size = sizeof(chat_history_t);
    err = nvs_get_blob(handle, nvs_key, history, &required_size);
    nvs_close(handle);

    if (err == ESP_ERR_NVS_NOT_FOUND) {
        ESP_LOGD(TAG, "No chat history found for: %s", peer_id);
        return CHAT_STORAGE_ERR_NOT_FOUND;
    } else if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to read chat history: %s", esp_err_to_name(err));
        return CHAT_STORAGE_ERR_NVS;
    }

    ESP_LOGD(TAG, "Retrieved %d messages for peer: %s", history->count, peer_id);
    return CHAT_STORAGE_OK;
}

int chat_storage_delete_history(const char *peer_id) {
    if (!peer_id) {
        return CHAT_STORAGE_ERR_INVALID_PARAM;
    }

    char nvs_key[16];
    generate_peer_hash(peer_id, nvs_key, sizeof(nvs_key));

    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        return CHAT_STORAGE_ERR_NVS;
    }

    err = nvs_erase_key(handle, nvs_key);
    if (err != ESP_OK && err != ESP_ERR_NVS_NOT_FOUND) {
        ESP_LOGE(TAG, "Failed to delete chat history: %s", esp_err_to_name(err));
        nvs_close(handle);
        return CHAT_STORAGE_ERR_NVS;
    }

    nvs_commit(handle);
    nvs_close(handle);

    ESP_LOGI(TAG, "Deleted chat history for: %s", peer_id);
    return CHAT_STORAGE_OK;
}

int chat_storage_clear_all(void) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        return CHAT_STORAGE_ERR_NVS;
    }

    err = nvs_erase_all(handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to clear all chat history: %s", esp_err_to_name(err));
        nvs_close(handle);
        return CHAT_STORAGE_ERR_NVS;
    }

    nvs_commit(handle);
    nvs_close(handle);

    ESP_LOGI(TAG, "Cleared all chat history");
    return CHAT_STORAGE_OK;
}

int chat_storage_list_peers(char peer_ids[][CHAT_PEER_ID_LENGTH],
                            uint16_t max_peers, uint16_t *count) {
    if (!peer_ids || !count) {
        return CHAT_STORAGE_ERR_INVALID_PARAM;
    }

    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &handle);
    if (err != ESP_OK) {
        return CHAT_STORAGE_ERR_NVS;
    }

    *count = 0;

    // Allocate history on heap to avoid stack overflow
    chat_history_t *history = (chat_history_t *)malloc(sizeof(chat_history_t));
    if (!history) {
        nvs_close(handle);
        return CHAT_STORAGE_ERR_NVS;
    }

    nvs_iterator_t it = NULL;
    err = nvs_entry_find("nvs", NVS_NAMESPACE, NVS_TYPE_BLOB, &it);

    while (err == ESP_OK && *count < max_peers) {
        nvs_entry_info_t info;
        nvs_entry_info(it, &info);

        // Check if this is a chat history entry (starts with NVS_KEY_PREFIX)
        if (strncmp(info.key, NVS_KEY_PREFIX, strlen(NVS_KEY_PREFIX)) == 0) {
            // Load the history to get the actual peer_id
            size_t required_size = sizeof(chat_history_t);
            esp_err_t read_err = nvs_get_blob(handle, info.key, history, &required_size);

            if (read_err == ESP_OK) {
                strncpy(peer_ids[*count], history->peer_id, CHAT_PEER_ID_LENGTH);
                (*count)++;
            }
        }

        err = nvs_entry_next(&it);
    }

    free(history);

    if (it) {
        nvs_release_iterator(it);
    }
    nvs_close(handle);

    ESP_LOGD(TAG, "Found %d peers with chat history", *count);
    return CHAT_STORAGE_OK;
}

int chat_storage_get_stats(uint16_t *total_peers, uint32_t *total_messages,
                           size_t *nvs_used_bytes) {
    if (!total_peers || !total_messages || !nvs_used_bytes) {
        return CHAT_STORAGE_ERR_INVALID_PARAM;
    }

    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &handle);
    if (err != ESP_OK) {
        return CHAT_STORAGE_ERR_NVS;
    }

    *total_peers = 0;
    *total_messages = 0;
    *nvs_used_bytes = 0;

    // Allocate history on heap to avoid stack overflow
    chat_history_t *history = (chat_history_t *)malloc(sizeof(chat_history_t));
    if (!history) {
        nvs_close(handle);
        return CHAT_STORAGE_ERR_NVS;
    }

    nvs_iterator_t it = NULL;
    err = nvs_entry_find("nvs", NVS_NAMESPACE, NVS_TYPE_BLOB, &it);

    while (err == ESP_OK) {
        nvs_entry_info_t info;
        nvs_entry_info(it, &info);

        if (strncmp(info.key, NVS_KEY_PREFIX, strlen(NVS_KEY_PREFIX)) == 0) {
            size_t required_size = sizeof(chat_history_t);
            esp_err_t read_err = nvs_get_blob(handle, info.key, history, &required_size);

            if (read_err == ESP_OK) {
                (*total_peers)++;
                *total_messages += history->count;
                *nvs_used_bytes += sizeof(chat_history_t);
            }
        }

        err = nvs_entry_next(&it);
    }

    if (it) {
        nvs_release_iterator(it);
    }
    nvs_close(handle);
    free(history);

    ESP_LOGI(TAG, "Stats: %d peers, %d messages, %d bytes used",
             *total_peers, *total_messages, *nvs_used_bytes);
    return CHAT_STORAGE_OK;
}
