/**
 * @file main.c
 * @brief GhostESP: Chat - P2P E2E Encrypted Chat on ESP32
 * @note A spin-off of GhostESP: Revival firmware
 */

#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"

#include "crypto.h"
#include "wifi_manager.h"
#include "public_ip.h"
#include "upnp.h"
#include "port_test.h"
#include "p2p.h"
#include "message.h"
#include "http_server.h"
#include "peer_manager.h"
#include "chat_storage.h"

static const char *TAG = "main";

#define GHOST_P2P_PORT 8000


/**
 * Initialize P2P services, peer manager, and HTTP server
 */
static void init_services_task(void *pvParameters) {
    port_test_stop_listener();
    vTaskDelay(pdMS_TO_TICKS(500));

    if (p2p_init(GHOST_P2P_PORT) != P2P_OK) {
        ESP_LOGE(TAG, "P2P initialization failed");
        vTaskDelete(NULL);
        return;
    }

    vTaskDelay(pdMS_TO_TICKS(2000));

    char local_ip[16];
    if (public_ip_get_local(local_ip) == PUBLIC_IP_OK) {
        ESP_LOGI(TAG, "Ready: %s:%d", local_ip, GHOST_P2P_PORT);
    }

    if (peer_manager_init() == PEER_OK) {
        ESP_LOGI(TAG, "Peer manager initialized: %d peers", peer_manager_count());
    }

    vTaskDelay(pdMS_TO_TICKS(500));

    if (http_server_init() == ESP_OK) {
        ESP_LOGI(TAG, "HTTP server ready: http://%s", local_ip);
    }

    vTaskDelete(NULL);
}

/**
 * Initialize network services including public IP discovery, UPnP, and port testing
 */
static void init_network_task(void *pvParameters) {
    char public_ip[PUBLIC_IP_MAX_LEN];
    char local_ip[PUBLIC_IP_MAX_LEN];

    if (public_ip_discover_auto(public_ip) == PUBLIC_IP_OK) {
        ESP_LOGI(TAG, "Public IP: %s", public_ip);
    }

    vTaskDelay(pdMS_TO_TICKS(1000));

    if (public_ip_get_local(local_ip) == PUBLIC_IP_OK) {
        ESP_LOGI(TAG, "Local IP: %s", local_ip);
    }

    vTaskDelay(pdMS_TO_TICKS(1000));

    upnp_init();
    if (upnp_discover_gateway(5000) == UPNP_OK) {
        upnp_mapping_t mapping = {
            .external_port = GHOST_P2P_PORT,
            .internal_port = GHOST_P2P_PORT,
            .protocol = UPNP_PROTO_TCP,
            .lease_duration = 0,
            .description = "GhostESP: Chat"
        };

        if (upnp_add_port_mapping(&mapping) == UPNP_OK) {
            ESP_LOGI(TAG, "UPnP mapped: %d -> %s:%d", GHOST_P2P_PORT, local_ip, GHOST_P2P_PORT);
        }
    }

    vTaskDelay(pdMS_TO_TICKS(1000));

    if (port_test_start_listener(GHOST_P2P_PORT) == PORT_TEST_OK) {
        ESP_LOGI(TAG, "TCP listener ready: port %d", GHOST_P2P_PORT);
    }

    vTaskDelay(pdMS_TO_TICKS(2000));
    xTaskCreate(init_services_task, "init_services", 16384, NULL, 5, NULL);

    vTaskDelete(NULL);
}

static void wifi_event_cb(wifi_state_t state, void *user_data) {
    switch (state) {
        case WIFI_STATE_CONNECTING:
            ESP_LOGI(TAG, "WiFi connecting...");
            break;
        case WIFI_STATE_CONNECTED: {
            char ip[16];
            if (wifi_manager_get_ip(ip) == WIFI_OK) {
                ESP_LOGI(TAG, "WiFi connected: %s (RSSI: %d dBm)", ip, wifi_manager_get_rssi());
            }
            vTaskDelay(pdMS_TO_TICKS(2000));
            xTaskCreate(init_network_task, "init_network", 16384, NULL, 5, NULL);
            break;
        }
        case WIFI_STATE_DISCONNECTED:
            ESP_LOGI(TAG, "WiFi disconnected");
            break;
        case WIFI_STATE_ERROR:
            ESP_LOGE(TAG, "WiFi error");
            break;
        default:
            break;
    }
}

/**
 * Validate cryptographic implementation on boot
 * Tests ECDH key exchange and ChaCha20-Poly1305 encryption/decryption
 * to ensure the crypto subsystem is functioning correctly
 */
static void validate_crypto(void) {
    crypto_keypair_t keypair_a, keypair_b;

    if (crypto_generate_keypair(&keypair_a) != CRYPTO_OK) return;
    if (crypto_generate_keypair(&keypair_b) != CRYPTO_OK) return;

    uint8_t shared_secret_a[CRYPTO_KEY_SIZE];
    uint8_t shared_secret_b[CRYPTO_KEY_SIZE];

    if (crypto_compute_shared_secret(shared_secret_a, keypair_a.private_key, keypair_b.public_key) != CRYPTO_OK) return;
    if (crypto_compute_shared_secret(shared_secret_b, keypair_b.private_key, keypair_a.public_key) != CRYPTO_OK) return;

    if (memcmp(shared_secret_a, shared_secret_b, CRYPTO_KEY_SIZE) != 0) {
        ESP_LOGE(TAG, "ECDH failed");
        return;
    }

    crypto_session_t session;
    if (crypto_derive_session_keys(&session, shared_secret_a, NULL, 0, NULL, 0) != CRYPTO_OK) return;

    const char *test_message = "Hello from GhostESP: Chat!";
    uint8_t ciphertext[256];
    uint8_t plaintext[256];
    size_t ciphertext_len, plaintext_len;

    if (crypto_encrypt_message(
            ciphertext, &ciphertext_len,
            (const uint8_t *)test_message, strlen(test_message),
            session.tx_key, 0, NULL, 0) != CRYPTO_OK) return;

    if (crypto_decrypt_message(
            plaintext, &plaintext_len,
            ciphertext, ciphertext_len,
            session.tx_key, 0, NULL, 0) != CRYPTO_OK) return;

    plaintext[plaintext_len] = '\0';
    if (strcmp(test_message, (const char *)plaintext) != 0) {
        ESP_LOGE(TAG, "Decryption failed");
        return;
    }

    ESP_LOGI(TAG, "Crypto tests passed");
}

void app_main(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    if (crypto_init() != CRYPTO_OK) {
        ESP_LOGE(TAG, "Crypto init failed");
        return;
    }

    if (chat_storage_init() != CHAT_STORAGE_OK) {
        ESP_LOGE(TAG, "Chat storage init failed");
    } else {
        uint16_t total_peers;
        uint32_t total_messages;
        size_t nvs_bytes;
        if (chat_storage_get_stats(&total_peers, &total_messages, &nvs_bytes) == CHAT_STORAGE_OK) {
            ESP_LOGI(TAG, "Chat storage: %d peers, %d messages, %d bytes used",
                     total_peers, total_messages, nvs_bytes);
        }
    }

    // Validate crypto implementation on boot (recommended for security)
    vTaskDelay(pdMS_TO_TICKS(1000));
    validate_crypto();

    if (!wifi_manager_has_saved_credentials()) {
        ESP_LOGI(TAG, "No WiFi credentials found, starting setup wizard");

        if (wifi_manager_start_ap("GhostESP:Chat-Setup", NULL) != WIFI_OK) {
            ESP_LOGE(TAG, "Failed to start setup AP");
            return;
        }

        if (http_server_init_setup_mode() != ESP_OK) {
            ESP_LOGE(TAG, "Failed to start setup server");
            return;
        }

        ESP_LOGI(TAG, "Connect to 'GhostESP:Chat-Setup' WiFi and open http://192.168.4.1");

        while (1) {
            vTaskDelay(pdMS_TO_TICKS(1000));
        }
    }

    ESP_LOGI(TAG, "WiFi credentials found, connecting...");

    vTaskDelay(pdMS_TO_TICKS(2000));
    if (wifi_manager_init() != WIFI_OK) {
        ESP_LOGE(TAG, "WiFi init failed");
        return;
    }

    wifi_manager_register_callback(wifi_event_cb, NULL);

    if (wifi_manager_auto_connect() != WIFI_OK) {
        ESP_LOGW(TAG, "Auto-connect failed, restarting setup");
        wifi_manager_clear_credentials();
        esp_restart();
    }

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(10000));
        if (wifi_manager_get_state() == WIFI_STATE_CONNECTED) {
            ESP_LOGI(TAG, "WiFi RSSI: %d dBm", wifi_manager_get_rssi());
        }
    }
}
