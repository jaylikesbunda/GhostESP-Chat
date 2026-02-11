/**
 * @file tofu_manager.c
 * @brief TOFU manager implementation
 */

#include "tofu_manager.h"
#include "crypto.h"
#include "audit_log.h"
#include <string.h>
#include <stdio.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/event_groups.h"

static const char *TAG = "tofu";

// Pending requests storage
static tofu_request_t pending_requests[TOFU_MAX_PENDING];
static int pending_count = 0;
static bool initialized = false;

// Thread safety
static SemaphoreHandle_t tofu_mutex = NULL;
static EventGroupHandle_t decision_events[TOFU_MAX_PENDING];

// Forward declarations
static int find_request_index(const char *request_id);
static void generate_request_id(char *request_id);
static uint32_t get_timestamp(void);
static void notify_decision(tofu_request_t *request);

int tofu_manager_init(void) {
    if (initialized) {
        return TOFU_OK;
    }

    ESP_LOGI(TAG, "Initializing TOFU manager");

    // Create mutex
    tofu_mutex = xSemaphoreCreateMutex();
    if (tofu_mutex == NULL) {
        ESP_LOGE(TAG, "Failed to create mutex");
        return TOFU_ERR_INVALID_PARAM;
    }

    // Create event groups for decision notifications
    for (int i = 0; i < TOFU_MAX_PENDING; i++) {
        decision_events[i] = xEventGroupCreate();
        if (decision_events[i] == NULL) {
            ESP_LOGE(TAG, "Failed to create event group %d", i);
            return TOFU_ERR_INVALID_PARAM;
        }
    }

    // Initialize pending requests
    memset(pending_requests, 0, sizeof(pending_requests));
    pending_count = 0;

    initialized = true;
    ESP_LOGI(TAG, "TOFU manager initialized");
    return TOFU_OK;
}

int tofu_create_request(const char *peer_id,
                        const char *peer_ip,
                        uint16_t peer_port,
                        const uint8_t public_key[32],
                        tofu_decision_cb_t callback,
                        void *user_data,
                        char *request_id) {
    if (!initialized || peer_id == NULL || public_key == NULL || request_id == NULL) {
        return TOFU_ERR_INVALID_PARAM;
    }

    xSemaphoreTake(tofu_mutex, portMAX_DELAY);

    // Check if we have space
    if (pending_count >= TOFU_MAX_PENDING) {
        xSemaphoreGive(tofu_mutex);
        ESP_LOGE(TAG, "TOFU request queue full");
        return TOFU_ERR_FULL;
    }

    // Find free slot
    int slot = -1;
    for (int i = 0; i < TOFU_MAX_PENDING; i++) {
        if (pending_requests[i].status == TOFU_STATUS_TIMEOUT ||
            pending_requests[i].request_id[0] == '\0') {
            slot = i;
            break;
        }
    }

    if (slot < 0) {
        xSemaphoreGive(tofu_mutex);
        return TOFU_ERR_FULL;
    }

    // Create new request
    tofu_request_t *req = &pending_requests[slot];
    memset(req, 0, sizeof(tofu_request_t));

    generate_request_id(req->request_id);
    strncpy(req->peer_id, peer_id, sizeof(req->peer_id) - 1);
    if (peer_ip != NULL) {
        strncpy(req->peer_ip, peer_ip, sizeof(req->peer_ip) - 1);
    }
    req->peer_port = peer_port;
    memcpy(req->public_key, public_key, 32);

    // Compute and format fingerprint
    crypto_fingerprint(req->fingerprint, public_key);
    p2p_security_format_fingerprint(req->fingerprint,
                                   req->fingerprint_display,
                                   sizeof(req->fingerprint_display));

    req->timestamp = get_timestamp();
    req->status = TOFU_STATUS_PENDING;
    req->callback = callback;
    req->user_data = user_data;

    // Clear event group for this slot
    xEventGroupClearBits(decision_events[slot], 0xFFFFFF);

    pending_count++;
    strcpy(request_id, req->request_id);

    xSemaphoreGive(tofu_mutex);

    // Log audit event
    audit_log(AUDIT_EVENT_TOFU_NEW_PEER, AUDIT_SEVERITY_WARNING,
              peer_id, peer_ip, peer_port,
              "New peer requires approval - Fingerprint: %s",
              req->fingerprint_display);

    ESP_LOGW(TAG, "🔐 TOFU Request Created");
    ESP_LOGW(TAG, "  Request ID: %s", req->request_id);
    ESP_LOGW(TAG, "  Peer: %s (%s:%d)", peer_id,
             peer_ip ? peer_ip : "unknown", peer_port);
    ESP_LOGW(TAG, "  Fingerprint: %s", req->fingerprint_display);
    ESP_LOGW(TAG, "  ⚠️  USER APPROVAL REQUIRED");

    return TOFU_OK;
}

int tofu_approve(const char *request_id) {
    if (!initialized || request_id == NULL) {
        return TOFU_ERR_INVALID_PARAM;
    }

    xSemaphoreTake(tofu_mutex, portMAX_DELAY);

    int idx = find_request_index(request_id);
    if (idx < 0) {
        xSemaphoreGive(tofu_mutex);
        return TOFU_ERR_NOT_FOUND;
    }

    tofu_request_t *req = &pending_requests[idx];
    req->status = TOFU_STATUS_APPROVED;

    // Add to security trust store
    p2p_security_verify_peer(req->peer_id, req->public_key, &(p2p_trust_status_t){0});
    p2p_security_mark_verified(req->peer_id);

    // Log audit event
    audit_log(AUDIT_EVENT_TOFU_ACCEPTED, AUDIT_SEVERITY_INFO,
              req->peer_id, req->peer_ip, req->peer_port,
              "User approved TOFU request");

    ESP_LOGI(TAG, "✅ TOFU Request APPROVED: %s (peer: %s)",
             request_id, req->peer_id);

    // Notify waiters
    xEventGroupSetBits(decision_events[idx], 0x01);
    notify_decision(req);

    xSemaphoreGive(tofu_mutex);
    return TOFU_OK;
}

int tofu_reject(const char *request_id) {
    if (!initialized || request_id == NULL) {
        return TOFU_ERR_INVALID_PARAM;
    }

    xSemaphoreTake(tofu_mutex, portMAX_DELAY);

    int idx = find_request_index(request_id);
    if (idx < 0) {
        xSemaphoreGive(tofu_mutex);
        return TOFU_ERR_NOT_FOUND;
    }

    tofu_request_t *req = &pending_requests[idx];
    req->status = TOFU_STATUS_REJECTED;

    // Mark as rejected in security store
    p2p_security_mark_rejected(req->peer_id);

    // Log audit event
    audit_log(AUDIT_EVENT_TOFU_REJECTED, AUDIT_SEVERITY_WARNING,
              req->peer_id, req->peer_ip, req->peer_port,
              "User rejected TOFU request");

    ESP_LOGW(TAG, "❌ TOFU Request REJECTED: %s (peer: %s)",
             request_id, req->peer_id);

    // Notify waiters
    xEventGroupSetBits(decision_events[idx], 0x02);
    notify_decision(req);

    xSemaphoreGive(tofu_mutex);
    return TOFU_OK;
}

int tofu_get_request(const char *request_id, tofu_request_t *request) {
    if (!initialized || request_id == NULL || request == NULL) {
        return TOFU_ERR_INVALID_PARAM;
    }

    xSemaphoreTake(tofu_mutex, portMAX_DELAY);

    int idx = find_request_index(request_id);
    if (idx < 0) {
        xSemaphoreGive(tofu_mutex);
        return TOFU_ERR_NOT_FOUND;
    }

    memcpy(request, &pending_requests[idx], sizeof(tofu_request_t));

    xSemaphoreGive(tofu_mutex);
    return TOFU_OK;
}

int tofu_get_pending_requests(tofu_request_t *requests,
                              int max_requests,
                              int *count) {
    if (!initialized || requests == NULL || count == NULL) {
        return TOFU_ERR_INVALID_PARAM;
    }

    xSemaphoreTake(tofu_mutex, portMAX_DELAY);

    int found = 0;
    for (int i = 0; i < TOFU_MAX_PENDING && found < max_requests; i++) {
        if (pending_requests[i].status == TOFU_STATUS_PENDING &&
            pending_requests[i].request_id[0] != '\0') {
            memcpy(&requests[found], &pending_requests[i], sizeof(tofu_request_t));
            found++;
        }
    }

    *count = found;

    xSemaphoreGive(tofu_mutex);
    return TOFU_OK;
}

tofu_status_t tofu_wait_for_decision(const char *request_id, uint32_t timeout_ms) {
    if (!initialized || request_id == NULL) {
        return TOFU_STATUS_TIMEOUT;
    }

    xSemaphoreTake(tofu_mutex, portMAX_DELAY);

    int idx = find_request_index(request_id);
    if (idx < 0) {
        xSemaphoreGive(tofu_mutex);
        return TOFU_STATUS_TIMEOUT;
    }

    // Check if already decided
    if (pending_requests[idx].status != TOFU_STATUS_PENDING) {
        tofu_status_t status = pending_requests[idx].status;
        xSemaphoreGive(tofu_mutex);
        return status;
    }

    xSemaphoreGive(tofu_mutex);

    // Wait for decision event
    TickType_t ticks = (timeout_ms == 0) ? portMAX_DELAY : pdMS_TO_TICKS(timeout_ms);
    EventBits_t bits = xEventGroupWaitBits(decision_events[idx],
                                           0x03,  // Approved or rejected
                                           pdFALSE,
                                           pdFALSE,
                                           ticks);

    if (bits & 0x01) {
        return TOFU_STATUS_APPROVED;
    } else if (bits & 0x02) {
        return TOFU_STATUS_REJECTED;
    }

    // Timeout
    ESP_LOGW(TAG, "⏱️  TOFU request timed out: %s", request_id);
    return TOFU_STATUS_TIMEOUT;
}

int tofu_cancel_request(const char *request_id) {
    if (!initialized || request_id == NULL) {
        return TOFU_ERR_INVALID_PARAM;
    }

    xSemaphoreTake(tofu_mutex, portMAX_DELAY);

    int idx = find_request_index(request_id);
    if (idx < 0) {
        xSemaphoreGive(tofu_mutex);
        return TOFU_ERR_NOT_FOUND;
    }

    memset(&pending_requests[idx], 0, sizeof(tofu_request_t));
    pending_count--;

    xSemaphoreGive(tofu_mutex);

    ESP_LOGI(TAG, "TOFU request cancelled: %s", request_id);
    return TOFU_OK;
}

int tofu_cleanup_expired(void) {
    if (!initialized) {
        return 0;
    }

    xSemaphoreTake(tofu_mutex, portMAX_DELAY);

    uint32_t now = get_timestamp();
    int cleaned = 0;

    for (int i = 0; i < TOFU_MAX_PENDING; i++) {
        tofu_request_t *req = &pending_requests[i];
        if (req->status == TOFU_STATUS_PENDING &&
            req->request_id[0] != '\0' &&
            (now - req->timestamp) > TOFU_REQUEST_TIMEOUT) {

            ESP_LOGW(TAG, "TOFU request expired: %s (peer: %s)",
                     req->request_id, req->peer_id);

            req->status = TOFU_STATUS_TIMEOUT;
            xEventGroupSetBits(decision_events[i], 0x04);
            cleaned++;
        }
    }

    xSemaphoreGive(tofu_mutex);

    if (cleaned > 0) {
        ESP_LOGI(TAG, "Cleaned up %d expired TOFU requests", cleaned);
    }

    return cleaned;
}

int tofu_get_pending_count(void) {
    if (!initialized) {
        return 0;
    }

    int count = 0;
    xSemaphoreTake(tofu_mutex, portMAX_DELAY);

    for (int i = 0; i < TOFU_MAX_PENDING; i++) {
        if (pending_requests[i].status == TOFU_STATUS_PENDING &&
            pending_requests[i].request_id[0] != '\0') {
            count++;
        }
    }

    xSemaphoreGive(tofu_mutex);
    return count;
}

// Private functions

static int find_request_index(const char *request_id) {
    for (int i = 0; i < TOFU_MAX_PENDING; i++) {
        if (strcmp(pending_requests[i].request_id, request_id) == 0) {
            return i;
        }
    }
    return -1;
}

static void generate_request_id(char *request_id) {
    // Generate random 8-character ID
    uint32_t rand1 = esp_random();
    uint32_t rand2 = esp_random();
    snprintf(request_id, 16, "%08lx", rand1);
}

static uint32_t get_timestamp(void) {
    return (uint32_t)(esp_timer_get_time() / 1000000);
}

static void notify_decision(tofu_request_t *request) {
    if (request->callback != NULL) {
        request->callback(request->request_id, request->status, request->user_data);
    }
}
