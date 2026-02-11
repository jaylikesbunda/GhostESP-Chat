/**
 * @file audit_log.c
 * @brief Audit logging implementation with NVS persistence
 */

#include "audit_log.h"
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "audit";

// NVS namespace for audit logs
#define NVS_AUDIT_NAMESPACE "audit"
#define NVS_KEY_COUNT "log_count"
#define NVS_KEY_NEXT_ID "next_id"

// In-memory circular buffer for recent entries
#define AUDIT_BUFFER_SIZE 50
static audit_entry_t audit_buffer[AUDIT_BUFFER_SIZE];
static int buffer_head = 0;
static int buffer_count = 0;
static uint32_t next_entry_id = 1;

// Thread safety
static SemaphoreHandle_t audit_mutex = NULL;
static bool initialized = false;

// Forward declarations
static uint8_t calculate_checksum(const audit_entry_t *entry);
static int save_entry_to_nvs(const audit_entry_t *entry);
static int load_entries_from_nvs(void);
static uint32_t get_timestamp(void);

int audit_init(void) {
    if (initialized) {
        return AUDIT_OK;
    }

    ESP_LOGI(TAG, "Initializing audit logging system");

    // Create mutex
    audit_mutex = xSemaphoreCreateMutex();
    if (audit_mutex == NULL) {
        ESP_LOGE(TAG, "Failed to create mutex");
        return AUDIT_ERR_STORAGE;
    }

    // Initialize buffer
    memset(audit_buffer, 0, sizeof(audit_buffer));
    buffer_head = 0;
    buffer_count = 0;

    // Load saved entry count and next ID from NVS
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_AUDIT_NAMESPACE, NVS_READONLY, &handle);
    if (err == ESP_OK) {
        uint32_t count = 0;
        nvs_get_u32(handle, NVS_KEY_COUNT, &count);

        uint32_t id = 1;
        nvs_get_u32(handle, NVS_KEY_NEXT_ID, &id);
        next_entry_id = id;

        nvs_close(handle);
        ESP_LOGI(TAG, "Loaded audit state: %lu entries, next ID: %lu", count, next_entry_id);
    } else {
        ESP_LOGI(TAG, "No previous audit data found");
    }

    // Load recent entries into buffer
    load_entries_from_nvs();

    initialized = true;

    // Log system boot
    audit_log(AUDIT_EVENT_SYSTEM_BOOT, AUDIT_SEVERITY_INFO,
              NULL, NULL, 0, "System boot complete");

    ESP_LOGI(TAG, "Audit logging initialized");
    return AUDIT_OK;
}

int audit_log(audit_event_type_t event_type,
              audit_severity_t severity,
              const char *peer_id,
              const char *ip_address,
              uint16_t port,
              const char *format, ...) {
    if (!initialized) {
        return AUDIT_ERR_INVALID_PARAM;
    }

    xSemaphoreTake(audit_mutex, portMAX_DELAY);

    // Create new entry
    audit_entry_t entry;
    memset(&entry, 0, sizeof(entry));

    entry.id = next_entry_id++;
    entry.timestamp = get_timestamp();
    entry.event_type = event_type;
    entry.severity = severity;
    entry.port = port;

    // Copy peer ID if provided
    if (peer_id != NULL) {
        strncpy(entry.peer_id, peer_id, AUDIT_PEER_ID_LEN - 1);
    }

    // Copy IP address if provided
    if (ip_address != NULL) {
        strncpy(entry.ip_address, ip_address, AUDIT_IP_LEN - 1);
    }

    // Format details message
    if (format != NULL) {
        va_list args;
        va_start(args, format);
        vsnprintf(entry.details, AUDIT_MAX_ENTRY_LEN, format, args);
        va_end(args);
    }

    // Calculate checksum
    entry.checksum = calculate_checksum(&entry);

    // Add to circular buffer
    audit_buffer[buffer_head] = entry;
    buffer_head = (buffer_head + 1) % AUDIT_BUFFER_SIZE;
    if (buffer_count < AUDIT_BUFFER_SIZE) {
        buffer_count++;
    }

    // Save to NVS (async in background would be better for production)
    save_entry_to_nvs(&entry);

    // Log to console based on severity
    const char *event_name = audit_get_event_name(event_type);
    const char *severity_name = audit_get_severity_name(severity);

    switch (severity) {
        case AUDIT_SEVERITY_CRITICAL:
            ESP_LOGE(TAG, "[%s] %s: %s (peer: %s, ip: %s:%d)",
                     severity_name, event_name, entry.details,
                     peer_id ? peer_id : "N/A",
                     ip_address ? ip_address : "N/A", port);
            break;
        case AUDIT_SEVERITY_ERROR:
            ESP_LOGE(TAG, "[%s] %s: %s", severity_name, event_name, entry.details);
            break;
        case AUDIT_SEVERITY_WARNING:
            ESP_LOGW(TAG, "[%s] %s: %s", severity_name, event_name, entry.details);
            break;
        default:
            ESP_LOGI(TAG, "[%s] %s: %s", severity_name, event_name, entry.details);
            break;
    }

    xSemaphoreGive(audit_mutex);
    return AUDIT_OK;
}

int audit_get_entries(audit_entry_t *entries,
                      int max_entries,
                      int offset,
                      int *count) {
    if (!initialized || entries == NULL || count == NULL) {
        return AUDIT_ERR_INVALID_PARAM;
    }

    xSemaphoreTake(audit_mutex, portMAX_DELAY);

    int available = buffer_count - offset;
    if (available < 0) {
        *count = 0;
        xSemaphoreGive(audit_mutex);
        return AUDIT_OK;
    }

    int to_copy = (available < max_entries) ? available : max_entries;
    *count = to_copy;

    // Copy from circular buffer
    int start_idx = (buffer_head - buffer_count + offset + AUDIT_BUFFER_SIZE) % AUDIT_BUFFER_SIZE;

    for (int i = 0; i < to_copy; i++) {
        int idx = (start_idx + i) % AUDIT_BUFFER_SIZE;
        memcpy(&entries[i], &audit_buffer[idx], sizeof(audit_entry_t));
    }

    xSemaphoreGive(audit_mutex);
    return AUDIT_OK;
}

int audit_get_count(void) {
    if (!initialized) {
        return 0;
    }
    return buffer_count;
}

int audit_search_by_type(audit_event_type_t event_type,
                         audit_entry_t *entries,
                         int max_entries,
                         int *count) {
    if (!initialized || entries == NULL || count == NULL) {
        return AUDIT_ERR_INVALID_PARAM;
    }

    xSemaphoreTake(audit_mutex, portMAX_DELAY);

    int found = 0;
    int start_idx = (buffer_head - buffer_count + AUDIT_BUFFER_SIZE) % AUDIT_BUFFER_SIZE;

    for (int i = 0; i < buffer_count && found < max_entries; i++) {
        int idx = (start_idx + i) % AUDIT_BUFFER_SIZE;
        if (audit_buffer[idx].event_type == event_type) {
            memcpy(&entries[found], &audit_buffer[idx], sizeof(audit_entry_t));
            found++;
        }
    }

    *count = found;
    xSemaphoreGive(audit_mutex);
    return AUDIT_OK;
}

int audit_search_by_peer(const char *peer_id,
                         audit_entry_t *entries,
                         int max_entries,
                         int *count) {
    if (!initialized || peer_id == NULL || entries == NULL || count == NULL) {
        return AUDIT_ERR_INVALID_PARAM;
    }

    xSemaphoreTake(audit_mutex, portMAX_DELAY);

    int found = 0;
    int start_idx = (buffer_head - buffer_count + AUDIT_BUFFER_SIZE) % AUDIT_BUFFER_SIZE;

    for (int i = 0; i < buffer_count && found < max_entries; i++) {
        int idx = (start_idx + i) % AUDIT_BUFFER_SIZE;
        if (strcmp(audit_buffer[idx].peer_id, peer_id) == 0) {
            memcpy(&entries[found], &audit_buffer[idx], sizeof(audit_entry_t));
            found++;
        }
    }

    *count = found;
    xSemaphoreGive(audit_mutex);
    return AUDIT_OK;
}

int audit_clear_logs(uint32_t confirmation) {
    if (!initialized) {
        return AUDIT_ERR_INVALID_PARAM;
    }

    if (confirmation != 0xDEADBEEF) {
        ESP_LOGE(TAG, "Invalid confirmation code for log clearing");
        return AUDIT_ERR_INVALID_PARAM;
    }

    audit_log(AUDIT_EVENT_CONFIG_CHANGED, AUDIT_SEVERITY_WARNING,
              NULL, NULL, 0, "Audit logs cleared");

    xSemaphoreTake(audit_mutex, portMAX_DELAY);

    // Clear buffer
    memset(audit_buffer, 0, sizeof(audit_buffer));
    buffer_head = 0;
    buffer_count = 0;
    next_entry_id = 1;

    // Clear NVS
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_AUDIT_NAMESPACE, NVS_READWRITE, &handle);
    if (err == ESP_OK) {
        nvs_erase_all(handle);
        nvs_commit(handle);
        nvs_close(handle);
    }

    xSemaphoreGive(audit_mutex);

    ESP_LOGW(TAG, "All audit logs cleared");
    return AUDIT_OK;
}

const char* audit_get_event_name(audit_event_type_t event_type) {
    switch (event_type) {
        case AUDIT_EVENT_CONNECTION_ATTEMPT: return "CONNECTION_ATTEMPT";
        case AUDIT_EVENT_CONNECTION_SUCCESS: return "CONNECTION_SUCCESS";
        case AUDIT_EVENT_CONNECTION_FAILED: return "CONNECTION_FAILED";
        case AUDIT_EVENT_CONNECTION_CLOSED: return "CONNECTION_CLOSED";
        case AUDIT_EVENT_HANDSHAKE_INIT: return "HANDSHAKE_INIT";
        case AUDIT_EVENT_HANDSHAKE_SUCCESS: return "HANDSHAKE_SUCCESS";
        case AUDIT_EVENT_HANDSHAKE_FAILED: return "HANDSHAKE_FAILED";
        case AUDIT_EVENT_TOFU_NEW_PEER: return "TOFU_NEW_PEER";
        case AUDIT_EVENT_TOFU_ACCEPTED: return "TOFU_ACCEPTED";
        case AUDIT_EVENT_TOFU_REJECTED: return "TOFU_REJECTED";
        case AUDIT_EVENT_KEY_CHANGED_DETECTED: return "KEY_CHANGED_DETECTED";
        case AUDIT_EVENT_KEY_VERIFIED: return "KEY_VERIFIED";
        case AUDIT_EVENT_AUTH_FAILED: return "AUTH_FAILED";
        case AUDIT_EVENT_REPLAY_DETECTED: return "REPLAY_DETECTED";
        case AUDIT_EVENT_ENCRYPTION_FAILED: return "ENCRYPTION_FAILED";
        case AUDIT_EVENT_DECRYPTION_FAILED: return "DECRYPTION_FAILED";
        case AUDIT_EVENT_KEY_DERIVATION: return "KEY_DERIVATION";
        case AUDIT_EVENT_KEY_ROTATION: return "KEY_ROTATION";
        case AUDIT_EVENT_CONFIG_CHANGED: return "CONFIG_CHANGED";
        case AUDIT_EVENT_PEER_ADDED: return "PEER_ADDED";
        case AUDIT_EVENT_PEER_REMOVED: return "PEER_REMOVED";
        case AUDIT_EVENT_TRUST_UPDATED: return "TRUST_UPDATED";
        case AUDIT_EVENT_SYSTEM_BOOT: return "SYSTEM_BOOT";
        case AUDIT_EVENT_SYSTEM_SHUTDOWN: return "SYSTEM_SHUTDOWN";
        case AUDIT_EVENT_NVS_ERROR: return "NVS_ERROR";
        case AUDIT_EVENT_MEMORY_ERROR: return "MEMORY_ERROR";
        case AUDIT_EVENT_DOS_DETECTED: return "DOS_DETECTED";
        case AUDIT_EVENT_INVALID_MESSAGE: return "INVALID_MESSAGE";
        case AUDIT_EVENT_RATE_LIMIT_EXCEEDED: return "RATE_LIMIT_EXCEEDED";
        default: return "UNKNOWN_EVENT";
    }
}

const char* audit_get_severity_name(audit_severity_t severity) {
    switch (severity) {
        case AUDIT_SEVERITY_INFO: return "INFO";
        case AUDIT_SEVERITY_WARNING: return "WARNING";
        case AUDIT_SEVERITY_ERROR: return "ERROR";
        case AUDIT_SEVERITY_CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

int audit_export_json(char *buffer, size_t buffer_size, int offset, int limit) {
    if (!initialized || buffer == NULL) {
        return AUDIT_ERR_INVALID_PARAM;
    }

    xSemaphoreTake(audit_mutex, portMAX_DELAY);

    char *ptr = buffer;
    size_t remaining = buffer_size;
    int written;

    // Start JSON array
    written = snprintf(ptr, remaining, "{\"entries\":[");
    if (written < 0 || written >= remaining) goto overflow;
    ptr += written;
    remaining -= written;

    int entries_to_export = (limit < buffer_count - offset) ? limit : (buffer_count - offset);
    int start_idx = (buffer_head - buffer_count + offset + AUDIT_BUFFER_SIZE) % AUDIT_BUFFER_SIZE;

    for (int i = 0; i < entries_to_export; i++) {
        int idx = (start_idx + i) % AUDIT_BUFFER_SIZE;
        audit_entry_t *entry = &audit_buffer[idx];

        written = snprintf(ptr, remaining,
            "%s{\"id\":%lu,\"timestamp\":%lu,\"event\":\"%s\",\"severity\":\"%s\","
            "\"peer_id\":\"%s\",\"ip\":\"%s\",\"port\":%u,\"details\":\"%s\"}",
            (i > 0 ? "," : ""),
            entry->id, entry->timestamp,
            audit_get_event_name(entry->event_type),
            audit_get_severity_name(entry->severity),
            entry->peer_id[0] ? entry->peer_id : "",
            entry->ip_address[0] ? entry->ip_address : "",
            entry->port,
            entry->details);

        if (written < 0 || written >= remaining) goto overflow;
        ptr += written;
        remaining -= written;
    }

    // Close JSON
    written = snprintf(ptr, remaining, "],\"total\":%d,\"offset\":%d,\"limit\":%d}",
                      buffer_count, offset, limit);
    if (written < 0 || written >= remaining) goto overflow;
    ptr += written;

    xSemaphoreGive(audit_mutex);
    return (ptr - buffer);

overflow:
    xSemaphoreGive(audit_mutex);
    ESP_LOGE(TAG, "JSON export buffer overflow");
    return AUDIT_ERR_INVALID_PARAM;
}

int audit_verify_integrity(void) {
    if (!initialized) {
        return AUDIT_ERR_INVALID_PARAM;
    }

    xSemaphoreTake(audit_mutex, portMAX_DELAY);

    int corrupted = 0;
    int start_idx = (buffer_head - buffer_count + AUDIT_BUFFER_SIZE) % AUDIT_BUFFER_SIZE;

    for (int i = 0; i < buffer_count; i++) {
        int idx = (start_idx + i) % AUDIT_BUFFER_SIZE;
        audit_entry_t *entry = &audit_buffer[idx];

        uint8_t expected = calculate_checksum(entry);
        if (entry->checksum != expected) {
            ESP_LOGE(TAG, "Corrupted entry detected: ID=%lu", entry->id);
            corrupted++;
        }
    }

    xSemaphoreGive(audit_mutex);

    if (corrupted > 0) {
        ESP_LOGE(TAG, "Integrity check failed: %d corrupted entries", corrupted);
        return AUDIT_ERR_STORAGE;
    }

    ESP_LOGI(TAG, "Integrity check passed: %d entries verified", buffer_count);
    return AUDIT_OK;
}

// Private functions

static uint8_t calculate_checksum(const audit_entry_t *entry) {
    // Simple XOR checksum (for production, use CRC32 or HMAC)
    uint8_t checksum = 0;
    const uint8_t *ptr = (const uint8_t *)entry;

    // Checksum everything except the checksum field itself
    for (size_t i = 0; i < offsetof(audit_entry_t, checksum); i++) {
        checksum ^= ptr[i];
    }

    return checksum;
}

static int save_entry_to_nvs(const audit_entry_t *entry) {
    nvs_handle_t handle;
    esp_err_t err;

    err = nvs_open(NVS_AUDIT_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS for audit: %s", esp_err_to_name(err));
        return AUDIT_ERR_STORAGE;
    }

    // Save entry with ID as key
    char key[16];
    snprintf(key, sizeof(key), "e_%lu", entry->id);

    err = nvs_set_blob(handle, key, entry, sizeof(audit_entry_t));
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to save audit entry: %s", esp_err_to_name(err));
        nvs_close(handle);
        return AUDIT_ERR_STORAGE;
    }

    // Update count and next ID
    nvs_set_u32(handle, NVS_KEY_NEXT_ID, next_entry_id);

    err = nvs_commit(handle);
    nvs_close(handle);

    return (err == ESP_OK) ? AUDIT_OK : AUDIT_ERR_STORAGE;
}

static int load_entries_from_nvs(void) {
    // For simplicity, just load metadata
    // In production, implement pagination to load entries on demand
    ESP_LOGI(TAG, "Audit entries stored in NVS, loading on demand");
    return AUDIT_OK;
}

static uint32_t get_timestamp(void) {
    return (uint32_t)(esp_timer_get_time() / 1000000);  // Seconds since boot
}
