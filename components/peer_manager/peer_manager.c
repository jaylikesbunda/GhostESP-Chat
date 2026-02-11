#include "peer_manager.h"
#include <string.h>
#include <stdio.h>
#include <esp_log.h>
#include <nvs_flash.h>
#include <nvs.h>

static const char *TAG = "peer_mgr";

// NVS namespace
#define NVS_NAMESPACE "ghost_peers"

// In-memory peer list
static peer_info_t peers[PEER_MAX_PEERS];
static int peer_count = 0;
static bool initialized = false;

/**
 * Generate unique peer ID from name
 */
static void generate_peer_id(const char *name, char id[16]) {
    // Simple ID: first 12 chars of name + counter
    static int id_counter = 0;
    snprintf(id, 16, "peer_%d", id_counter++);
}

/**
 * Find peer index by ID
 */
static int find_peer_index(const char *peer_id) {
    for (int i = 0; i < peer_count; i++) {
        if (strcmp(peers[i].id, peer_id) == 0) {
            return i;
        }
    }
    return -1;
}

/**
 * Load peers from NVS
 */
static int load_from_nvs(void) {
    nvs_handle_t handle;
    esp_err_t err;

    err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &handle);
    if (err != ESP_OK) {
        if (err == ESP_ERR_NVS_NOT_FOUND) {
            ESP_LOGI(TAG, "No saved peers found");
            return PEER_OK;
        }
        ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
        return PEER_ERR_STORAGE;
    }

    // Read peer count
    uint32_t count = 0;
    err = nvs_get_u32(handle, "count", &count);
    if (err != ESP_OK || count == 0) {
        nvs_close(handle);
        return PEER_OK;
    }

    // Read each peer
    for (uint32_t i = 0; i < count && i < PEER_MAX_PEERS; i++) {
        char key[16];
        snprintf(key, sizeof(key), "peer_%lu", (unsigned long)i);

        size_t required_size = sizeof(peer_info_t);
        err = nvs_get_blob(handle, key, &peers[i], &required_size);
        if (err == ESP_OK) {
            peer_count++;
        }
    }

    nvs_close(handle);
    ESP_LOGI(TAG, "Loaded %d peers from NVS", peer_count);
    return PEER_OK;
}

/**
 * Initialize peer manager
 */
int peer_manager_init(void) {
    if (initialized) {
        ESP_LOGW(TAG, "Peer manager already initialized");
        return PEER_OK;
    }

    ESP_LOGI(TAG, "Initializing peer manager");

    memset(peers, 0, sizeof(peers));
    peer_count = 0;

    // Load from NVS
    int ret = load_from_nvs();
    if (ret != PEER_OK) {
        ESP_LOGW(TAG, "Failed to load peers from NVS, starting fresh");
    }

    initialized = true;
    ESP_LOGI(TAG, "Peer manager initialized with %d peers", peer_count);
    return PEER_OK;
}

/**
 * Save peers to NVS
 */
int peer_manager_save(void) {
    nvs_handle_t handle;
    esp_err_t err;

    err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS for writing: %s", esp_err_to_name(err));
        return PEER_ERR_STORAGE;
    }

    // Save peer count
    err = nvs_set_u32(handle, "count", peer_count);
    if (err != ESP_OK) {
        nvs_close(handle);
        return PEER_ERR_STORAGE;
    }

    // Save each peer
    for (int i = 0; i < peer_count; i++) {
        char key[16];
        snprintf(key, sizeof(key), "peer_%d", i);

        err = nvs_set_blob(handle, key, &peers[i], sizeof(peer_info_t));
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "Failed to save peer %d", i);
        }
    }

    // Commit
    err = nvs_commit(handle);
    nvs_close(handle);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to commit NVS: %s", esp_err_to_name(err));
        return PEER_ERR_STORAGE;
    }

    ESP_LOGI(TAG, "Saved %d peers to NVS", peer_count);
    return PEER_OK;
}

/**
 * Add a new peer
 */
int peer_manager_add(const char *name, const char *ip, uint16_t port,
                    const uint8_t public_key[PEER_PUBLIC_KEY_LEN],
                    char peer_id[16]) {
    if (!initialized) {
        return PEER_ERR_INVALID_ARG;
    }

    if (!name || !ip || !public_key) {
        return PEER_ERR_INVALID_ARG;
    }

    if (peer_count >= PEER_MAX_PEERS) {
        ESP_LOGE(TAG, "Peer list full (%d/%d)", peer_count, PEER_MAX_PEERS);
        return PEER_ERR_FULL;
    }

    // Generate unique ID
    char new_id[16];
    generate_peer_id(name, new_id);

    // Add to list
    peer_info_t *peer = &peers[peer_count];
    memset(peer, 0, sizeof(peer_info_t));

    strncpy(peer->id, new_id, sizeof(peer->id) - 1);
    strncpy(peer->name, name, sizeof(peer->name) - 1);
    strncpy(peer->ip, ip, sizeof(peer->ip) - 1);
    peer->port = port;
    memcpy(peer->public_key, public_key, PEER_PUBLIC_KEY_LEN);
    peer->status = PEER_STATUS_OFFLINE;
    peer->last_seen = 0;
    peer->trusted = false;

    peer_count++;

    // Return ID
    if (peer_id) {
        strncpy(peer_id, new_id, 16);
    }

    // Save to NVS
    peer_manager_save();

    ESP_LOGI(TAG, "Added peer: %s (%s:%d)", name, ip, port);
    return PEER_OK;
}

/**
 * Remove a peer
 */
int peer_manager_remove(const char *peer_id) {
    if (!initialized || !peer_id) {
        return PEER_ERR_INVALID_ARG;
    }

    int index = find_peer_index(peer_id);
    if (index < 0) {
        return PEER_ERR_NOT_FOUND;
    }

    // Shift remaining peers
    for (int i = index; i < peer_count - 1; i++) {
        peers[i] = peers[i + 1];
    }
    peer_count--;

    // Clear last entry
    memset(&peers[peer_count], 0, sizeof(peer_info_t));

    // Save to NVS
    peer_manager_save();

    ESP_LOGI(TAG, "Removed peer: %s", peer_id);
    return PEER_OK;
}

/**
 * Get peer information
 */
int peer_manager_get(const char *peer_id, peer_info_t *info) {
    if (!initialized || !peer_id || !info) {
        return PEER_ERR_INVALID_ARG;
    }

    int index = find_peer_index(peer_id);
    if (index < 0) {
        return PEER_ERR_NOT_FOUND;
    }

    memcpy(info, &peers[index], sizeof(peer_info_t));
    return PEER_OK;
}

/**
 * Get all peers
 */
int peer_manager_get_all(peer_info_t *output_peers, int max_peers, int *count) {
    if (!initialized || !output_peers || !count) {
        return PEER_ERR_INVALID_ARG;
    }

    int copy_count = (peer_count < max_peers) ? peer_count : max_peers;

    for (int i = 0; i < copy_count; i++) {
        memcpy(&output_peers[i], &peers[i], sizeof(peer_info_t));
    }

    *count = copy_count;
    return PEER_OK;
}

/**
 * Update peer status
 */
int peer_manager_set_status(const char *peer_id, peer_status_t status) {
    if (!initialized || !peer_id) {
        return PEER_ERR_INVALID_ARG;
    }

    int index = find_peer_index(peer_id);
    if (index < 0) {
        return PEER_ERR_NOT_FOUND;
    }

    peers[index].status = status;
    return PEER_OK;  // Don't save to NVS for status updates
}

/**
 * Update last seen timestamp
 */
int peer_manager_set_last_seen(const char *peer_id, uint32_t timestamp) {
    if (!initialized || !peer_id) {
        return PEER_ERR_INVALID_ARG;
    }

    int index = find_peer_index(peer_id);
    if (index < 0) {
        return PEER_ERR_NOT_FOUND;
    }

    peers[index].last_seen = timestamp;
    return PEER_OK;  // Don't save to NVS for timestamp updates
}

/**
 * Mark peer as trusted
 */
int peer_manager_set_trusted(const char *peer_id, bool trusted) {
    if (!initialized || !peer_id) {
        return PEER_ERR_INVALID_ARG;
    }

    int index = find_peer_index(peer_id);
    if (index < 0) {
        return PEER_ERR_NOT_FOUND;
    }

    peers[index].trusted = trusted;

    // Save trust changes to NVS
    peer_manager_save();

    ESP_LOGI(TAG, "Peer %s trust: %s", peer_id, trusted ? "trusted" : "untrusted");
    return PEER_OK;
}

/**
 * Get peer count
 */
int peer_manager_count(void) {
    return peer_count;
}

/**
 * Clear all peers
 */
int peer_manager_clear_all(void) {
    if (!initialized) {
        return PEER_ERR_INVALID_ARG;
    }

    memset(peers, 0, sizeof(peers));
    peer_count = 0;

    // Clear NVS
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err == ESP_OK) {
        nvs_erase_all(handle);
        nvs_commit(handle);
        nvs_close(handle);
    }

    ESP_LOGI(TAG, "Cleared all peers");
    return PEER_OK;
}
