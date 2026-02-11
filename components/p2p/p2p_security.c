/**
 * @file p2p_security.c
 * @brief P2P security implementation with TOFU
 */

#include "p2p_security.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "nvs.h"

static const char *TAG = "p2p_sec";

// NVS namespace for security data
#define NVS_SECURITY_NAMESPACE "ghost_sec"
#define MAX_STORED_PEERS 32

// In-memory peer security database
static p2p_peer_security_t peers[MAX_STORED_PEERS];
static int peer_count = 0;
static bool initialized = false;

// Forward declarations
static int load_from_nvs(void);
static int save_to_nvs(void);
static int find_peer_index(const char *peer_id);
static uint32_t get_timestamp(void);

int p2p_security_init(void) {
    if (initialized) {
        return P2P_SEC_OK;
    }

    ESP_LOGI(TAG, "Initializing P2P security module");

    memset(peers, 0, sizeof(peers));
    peer_count = 0;

    // Load trusted peers from NVS
    int ret = load_from_nvs();
    if (ret != P2P_SEC_OK) {
        ESP_LOGW(TAG, "Failed to load security data, starting fresh");
    }

    initialized = true;
    ESP_LOGI(TAG, "P2P security initialized with %d known peers", peer_count);
    return P2P_SEC_OK;
}

int p2p_security_format_fingerprint(const uint8_t fingerprint[32],
                                    char *output, size_t output_len) {
    if (fingerprint == NULL || output == NULL || output_len < P2P_FINGERPRINT_DISPLAY_LEN) {
        return P2P_SEC_ERR_INVALID_PARAM;
    }

    // Format as: XX:XX:XX:XX:XX:XX:XX:XX (first 8 bytes for brevity)
    snprintf(output, output_len,
             "%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
             fingerprint[0], fingerprint[1], fingerprint[2], fingerprint[3],
             fingerprint[4], fingerprint[5], fingerprint[6], fingerprint[7]);

    return P2P_SEC_OK;
}

int p2p_security_verify_peer(const char *peer_id,
                              const uint8_t public_key[32],
                              p2p_trust_status_t *trust_status) {
    if (!initialized || peer_id == NULL || public_key == NULL || trust_status == NULL) {
        return P2P_SEC_ERR_INVALID_PARAM;
    }

    // Compute fingerprint
    uint8_t fingerprint[32];
    if (crypto_fingerprint(fingerprint, public_key) != CRYPTO_OK) {
        ESP_LOGE(TAG, "Failed to compute fingerprint");
        return P2P_SEC_ERR_INVALID_PARAM;
    }

    // Look for existing peer
    int index = find_peer_index(peer_id);

    if (index < 0) {
        // TOFU: First time seeing this peer
        if (peer_count >= MAX_STORED_PEERS) {
            ESP_LOGE(TAG, "Peer trust store full");
            return P2P_SEC_ERR_STORAGE;
        }

        // Add new peer
        p2p_peer_security_t *peer = &peers[peer_count];
        strncpy(peer->peer_id, peer_id, sizeof(peer->peer_id) - 1);
        memcpy(peer->public_key, public_key, 32);
        memcpy(peer->fingerprint, fingerprint, 32);
        peer->trust_status = P2P_TRUST_FIRST_USE;
        peer->first_seen = get_timestamp();
        peer->last_seen = peer->first_seen;
        peer->connection_count = 1;

        peer_count++;
        save_to_nvs();

        *trust_status = P2P_TRUST_FIRST_USE;

        char fp_str[P2P_FINGERPRINT_DISPLAY_LEN];
        p2p_security_format_fingerprint(fingerprint, fp_str, sizeof(fp_str));
        ESP_LOGW(TAG, "TOFU: First connection from %s", peer_id);
        ESP_LOGW(TAG, "Fingerprint: %s", fp_str);
        ESP_LOGW(TAG, "Please verify this fingerprint with peer out-of-band!");

        return P2P_SEC_OK;
    }

    // Existing peer - verify key matches
    p2p_peer_security_t *peer = &peers[index];

    if (memcmp(peer->public_key, public_key, 32) != 0) {
        // KEY CHANGED - Possible MITM attack!
        char old_fp[P2P_FINGERPRINT_DISPLAY_LEN];
        char new_fp[P2P_FINGERPRINT_DISPLAY_LEN];
        p2p_security_format_fingerprint(peer->fingerprint, old_fp, sizeof(old_fp));
        p2p_security_format_fingerprint(fingerprint, new_fp, sizeof(new_fp));

        ESP_LOGE(TAG, "⚠️  SECURITY ALERT: Peer key changed!");
        ESP_LOGE(TAG, "Peer ID: %s", peer_id);
        ESP_LOGE(TAG, "Old fingerprint: %s", old_fp);
        ESP_LOGE(TAG, "New fingerprint: %s", new_fp);
        ESP_LOGE(TAG, "⚠️  Possible MITM attack! Connection rejected.");

        *trust_status = P2P_TRUST_REJECTED;
        return P2P_SEC_ERR_MISMATCH;
    }

    // Key matches - update stats
    peer->last_seen = get_timestamp();
    peer->connection_count++;

    *trust_status = peer->trust_status;

    // Don't save on every connection (performance)
    if (peer->connection_count % 10 == 0) {
        save_to_nvs();
    }

    ESP_LOGI(TAG, "Peer %s verified (connections: %lu, status: %d)",
             peer_id, peer->connection_count, peer->trust_status);

    return P2P_SEC_OK;
}

int p2p_security_get_peer(const char *peer_id, p2p_peer_security_t *security) {
    if (!initialized || peer_id == NULL || security == NULL) {
        return P2P_SEC_ERR_INVALID_PARAM;
    }

    int index = find_peer_index(peer_id);
    if (index < 0) {
        return P2P_SEC_ERR_INVALID_PARAM;
    }

    memcpy(security, &peers[index], sizeof(p2p_peer_security_t));
    return P2P_SEC_OK;
}

int p2p_security_mark_verified(const char *peer_id) {
    if (!initialized || peer_id == NULL) {
        return P2P_SEC_ERR_INVALID_PARAM;
    }

    int index = find_peer_index(peer_id);
    if (index < 0) {
        return P2P_SEC_ERR_INVALID_PARAM;
    }

    peers[index].trust_status = P2P_TRUST_VERIFIED;
    save_to_nvs();

    ESP_LOGI(TAG, "Peer %s marked as verified", peer_id);
    return P2P_SEC_OK;
}

int p2p_security_mark_rejected(const char *peer_id) {
    if (!initialized || peer_id == NULL) {
        return P2P_SEC_ERR_INVALID_PARAM;
    }

    int index = find_peer_index(peer_id);
    if (index < 0) {
        return P2P_SEC_ERR_INVALID_PARAM;
    }

    peers[index].trust_status = P2P_TRUST_REJECTED;
    save_to_nvs();

    ESP_LOGW(TAG, "Peer %s marked as REJECTED", peer_id);
    return P2P_SEC_OK;
}

bool p2p_security_key_changed(const char *peer_id, const uint8_t public_key[32]) {
    if (!initialized || peer_id == NULL || public_key == NULL) {
        return false;
    }

    int index = find_peer_index(peer_id);
    if (index < 0) {
        return false;  // New peer, no change
    }

    return (memcmp(peers[index].public_key, public_key, 32) != 0);
}

int p2p_security_forget_peer(const char *peer_id) {
    if (!initialized || peer_id == NULL) {
        return P2P_SEC_ERR_INVALID_PARAM;
    }

    int index = find_peer_index(peer_id);
    if (index < 0) {
        return P2P_SEC_ERR_INVALID_PARAM;
    }

    // Shift remaining peers
    for (int i = index; i < peer_count - 1; i++) {
        peers[i] = peers[i + 1];
    }
    peer_count--;

    memset(&peers[peer_count], 0, sizeof(p2p_peer_security_t));
    save_to_nvs();

    ESP_LOGI(TAG, "Forgot peer %s", peer_id);
    return P2P_SEC_OK;
}

int p2p_security_list_peers(p2p_peer_security_t *output, int max_peers, int *count) {
    if (!initialized || output == NULL || count == NULL) {
        return P2P_SEC_ERR_INVALID_PARAM;
    }

    int copy_count = (peer_count < max_peers) ? peer_count : max_peers;

    for (int i = 0; i < copy_count; i++) {
        memcpy(&output[i], &peers[i], sizeof(p2p_peer_security_t));
    }

    *count = copy_count;
    return P2P_SEC_OK;
}

// Private functions

static int find_peer_index(const char *peer_id) {
    for (int i = 0; i < peer_count; i++) {
        if (strcmp(peers[i].peer_id, peer_id) == 0) {
            return i;
        }
    }
    return -1;
}

static uint32_t get_timestamp(void) {
    return (uint32_t)(esp_timer_get_time() / 1000000);  // Seconds since boot
}

static int load_from_nvs(void) {
    nvs_handle_t handle;
    esp_err_t err;

    err = nvs_open(NVS_SECURITY_NAMESPACE, NVS_READONLY, &handle);
    if (err != ESP_OK) {
        if (err == ESP_ERR_NVS_NOT_FOUND) {
            ESP_LOGI(TAG, "No saved security data");
            return P2P_SEC_OK;
        }
        ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
        return P2P_SEC_ERR_STORAGE;
    }

    // Read peer count
    uint32_t count = 0;
    err = nvs_get_u32(handle, "peer_count", &count);
    if (err != ESP_OK || count == 0) {
        nvs_close(handle);
        return P2P_SEC_OK;
    }

    // Read each peer
    for (uint32_t i = 0; i < count && i < MAX_STORED_PEERS; i++) {
        char key[16];
        snprintf(key, sizeof(key), "peer_%lu", i);

        size_t required_size = sizeof(p2p_peer_security_t);
        err = nvs_get_blob(handle, key, &peers[i], &required_size);
        if (err == ESP_OK) {
            peer_count++;
        }
    }

    nvs_close(handle);
    ESP_LOGI(TAG, "Loaded %d peers from NVS", peer_count);
    return P2P_SEC_OK;
}

static int save_to_nvs(void) {
    nvs_handle_t handle;
    esp_err_t err;

    err = nvs_open(NVS_SECURITY_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS for writing: %s", esp_err_to_name(err));
        return P2P_SEC_ERR_STORAGE;
    }

    // Save peer count
    err = nvs_set_u32(handle, "peer_count", peer_count);
    if (err != ESP_OK) {
        nvs_close(handle);
        return P2P_SEC_ERR_STORAGE;
    }

    // Save each peer
    for (int i = 0; i < peer_count; i++) {
        char key[16];
        snprintf(key, sizeof(key), "peer_%d", i);

        err = nvs_set_blob(handle, key, &peers[i], sizeof(p2p_peer_security_t));
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "Failed to save peer %d", i);
        }
    }

    // Commit
    err = nvs_commit(handle);
    nvs_close(handle);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to commit NVS: %s", esp_err_to_name(err));
        return P2P_SEC_ERR_STORAGE;
    }

    return P2P_SEC_OK;
}
