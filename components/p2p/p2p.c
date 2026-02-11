/**
 * @file p2p.c
 * @brief P2P connection implementation
 */

#include "p2p.h"
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "message.h"
#include "ratchet.h"

static const char *TAG = "p2p";

#define HANDSHAKE_BUF_SIZE (MSG_HEADER_SIZE + 32 + 16)

// Connection structure
struct p2p_connection {
    int socket;
    p2p_state_t state;
    crypto_keypair_t local_keypair;
    uint8_t peer_public_key[32];
    ratchet_state_t ratchet;  // Double Ratchet state (replaces simple session)
    bool is_initiator;         // True if we initiated the connection
    uint32_t tx_counter;
    uint32_t rx_counter;
    char peer_ip[16];
    uint16_t peer_port;
    TaskHandle_t rx_task;
    SemaphoreHandle_t mutex;
    p2p_message_cb_t message_callback;
    void *message_user_data;
    p2p_state_cb_t state_callback;
    void *state_user_data;
    bool running;
};

// Global state
static bool p2p_initialized = false;
static uint16_t listen_port = P2P_DEFAULT_PORT;
static int listen_socket = -1;
static TaskHandle_t accept_task_handle = NULL;
static crypto_keypair_t device_keypair;

static p2p_connection_t *conn_registry[P2P_MAX_CONNECTIONS] = {0};
static SemaphoreHandle_t registry_mutex = NULL;
static p2p_global_message_cb_t global_message_cb = NULL;

// Forward declarations
static void accept_task(void *pvParameters);
static void rx_task(void *pvParameters);
static int perform_handshake_initiator(p2p_connection_t *conn);
static int perform_handshake_responder(p2p_connection_t *conn);
static void update_state(p2p_connection_t *conn, p2p_state_t new_state);

int p2p_init(uint16_t port) {
    if (p2p_initialized) {
        return P2P_OK;
    }

    listen_port = port;

    // Generate device-level keypair for identification
    if (crypto_generate_keypair(&device_keypair) != CRYPTO_OK) {
        ESP_LOGE(TAG, "Failed to generate device keypair");
        return P2P_ERR_HANDSHAKE_FAILED;
    }
    ESP_LOGI(TAG, "Device keypair generated");

    // Create listen socket
    listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_socket < 0) {
        ESP_LOGE(TAG, "Failed to create listen socket");
        return P2P_ERR_SOCKET_FAILED;
    }

    // Set socket options
    int opt = 1;
    setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Bind
    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind_addr.sin_port = htons(port);

    if (bind(listen_socket, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        ESP_LOGE(TAG, "Failed to bind to port %d", port);
        close(listen_socket);
        return P2P_ERR_SOCKET_FAILED;
    }

    // Listen
    if (listen(listen_socket, 5) < 0) {
        ESP_LOGE(TAG, "Failed to listen");
        close(listen_socket);
        return P2P_ERR_SOCKET_FAILED;
    }

    // Create accept task
    xTaskCreate(accept_task, "p2p_accept", 8192, NULL, 5, &accept_task_handle);

    if (registry_mutex == NULL) {
        registry_mutex = xSemaphoreCreateMutex();
    }

    p2p_initialized = true;
    ESP_LOGI(TAG, "P2P initialized, listening on port %d", port);
    return P2P_OK;
}

static void registry_add(p2p_connection_t *conn) {
    xSemaphoreTake(registry_mutex, portMAX_DELAY);
    for (int i = 0; i < P2P_MAX_CONNECTIONS; i++) {
        if (conn_registry[i] == NULL) {
            conn_registry[i] = conn;
            break;
        }
    }
    xSemaphoreGive(registry_mutex);
}

static void registry_remove(p2p_connection_t *conn) {
    xSemaphoreTake(registry_mutex, portMAX_DELAY);
    for (int i = 0; i < P2P_MAX_CONNECTIONS; i++) {
        if (conn_registry[i] == conn) {
            conn_registry[i] = NULL;
            break;
        }
    }
    xSemaphoreGive(registry_mutex);
}

void p2p_set_global_message_callback(p2p_global_message_cb_t callback) {
    global_message_cb = callback;
}

p2p_connection_t *p2p_find_connection(const char *peer_ip, uint16_t peer_port) {
    if (!registry_mutex) return NULL;
    xSemaphoreTake(registry_mutex, portMAX_DELAY);
    p2p_connection_t *found = NULL;
    for (int i = 0; i < P2P_MAX_CONNECTIONS; i++) {
        p2p_connection_t *c = conn_registry[i];
        if (c && c->state == P2P_STATE_CONNECTED &&
            strcmp(c->peer_ip, peer_ip) == 0 && c->peer_port == peer_port) {
            found = c;
            break;
        }
    }
    xSemaphoreGive(registry_mutex);
    return found;
}

int p2p_find_or_connect(const char *peer_ip, uint16_t peer_port,
                        const uint8_t peer_public_key[32], p2p_connection_t **conn) {
    p2p_connection_t *existing = p2p_find_connection(peer_ip, peer_port);
    if (existing) {
        *conn = existing;
        return P2P_OK;
    }
    return p2p_connect(peer_ip, peer_port, peer_public_key, conn);
}

void p2p_shutdown(void) {
    if (!p2p_initialized) {
        return;
    }

    p2p_initialized = false;

    if (listen_socket >= 0) {
        close(listen_socket);
        listen_socket = -1;
    }

    if (accept_task_handle != NULL) {
        vTaskDelete(accept_task_handle);
        accept_task_handle = NULL;
    }

    ESP_LOGI(TAG, "P2P shut down");
}

int p2p_connect(const char *peer_ip, uint16_t peer_port,
               const uint8_t peer_public_key[32], p2p_connection_t **conn) {
    if (!p2p_initialized || peer_ip == NULL || conn == NULL) {
        return P2P_ERR_INVALID_PARAM;
    }

    // Allocate connection structure
    p2p_connection_t *new_conn = calloc(1, sizeof(p2p_connection_t));
    if (new_conn == NULL) {
        return P2P_ERR_SOCKET_FAILED;
    }

    new_conn->mutex = xSemaphoreCreateMutex();
    new_conn->state = P2P_STATE_IDLE;
    new_conn->tx_counter = 0;
    new_conn->rx_counter = 0;
    strncpy(new_conn->peer_ip, peer_ip, sizeof(new_conn->peer_ip) - 1);
    new_conn->peer_port = peer_port;

    if (peer_public_key != NULL) {
        memcpy(new_conn->peer_public_key, peer_public_key, 32);
    }

    // Generate local keypair
    if (crypto_generate_keypair(&new_conn->local_keypair) != CRYPTO_OK) {
        ESP_LOGE(TAG, "Failed to generate keypair");
        vSemaphoreDelete(new_conn->mutex);
        free(new_conn);
        return P2P_ERR_HANDSHAKE_FAILED;
    }

    ESP_LOGI(TAG, "Connecting to %s:%d", peer_ip, peer_port);
    update_state(new_conn, P2P_STATE_CONNECTING);

    // Create socket
    new_conn->socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (new_conn->socket < 0) {
        ESP_LOGE(TAG, "Failed to create socket");
        vSemaphoreDelete(new_conn->mutex);
        free(new_conn);
        return P2P_ERR_SOCKET_FAILED;
    }

    // Connect
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(peer_port);
    inet_pton(AF_INET, peer_ip, &dest_addr.sin_addr);

    if (connect(new_conn->socket, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        ESP_LOGE(TAG, "Connect failed: %d", errno);
        close(new_conn->socket);
        vSemaphoreDelete(new_conn->mutex);
        free(new_conn);
        return P2P_ERR_CONNECT_FAILED;
    }

    ESP_LOGI(TAG, "TCP connection established");

    // Perform handshake
    update_state(new_conn, P2P_STATE_HANDSHAKING);
    int ret = perform_handshake_initiator(new_conn);
    if (ret != P2P_OK) {
        close(new_conn->socket);
        vSemaphoreDelete(new_conn->mutex);
        free(new_conn);
        return ret;
    }

    new_conn->running = true;
    xTaskCreate(rx_task, "p2p_rx", 8192, new_conn, 5, &new_conn->rx_task);

    update_state(new_conn, P2P_STATE_CONNECTED);
    registry_add(new_conn);
    ESP_LOGI(TAG, "P2P connection established and encrypted");

    *conn = new_conn;
    return P2P_OK;
}

int p2p_send_message(p2p_connection_t *conn, const char *message, size_t message_len) {
    if (conn == NULL || message == NULL) {
        return P2P_ERR_INVALID_PARAM;
    }

    if (conn->state != P2P_STATE_CONNECTED) {
        return P2P_ERR_DISCONNECTED;
    }

    xSemaphoreTake(conn->mutex, portMAX_DELAY);

    // Allocate buffer for ratchet message
    uint8_t *buffer = malloc(MSG_MAX_RATCHET_MESSAGE_SIZE);
    if (!buffer) {
        xSemaphoreGive(conn->mutex);
        return P2P_ERR_SEND_FAILED;
    }

    // Encrypt with Double Ratchet
    size_t buffer_len;
    int ret = message_ratchet_encrypt(&conn->ratchet, (const uint8_t*)message, message_len,
                                     buffer, MSG_MAX_RATCHET_MESSAGE_SIZE, &buffer_len);
    if (ret != MSG_OK) {
        ESP_LOGE(TAG, "Ratchet encryption failed: %d", ret);
        free(buffer);
        xSemaphoreGive(conn->mutex);
        return P2P_ERR_SEND_FAILED;
    }

    // Send encrypted message
    ssize_t sent = send(conn->socket, buffer, buffer_len, 0);
    free(buffer);
    if (sent < 0) {
        ESP_LOGE(TAG, "Send failed: %d", errno);
        xSemaphoreGive(conn->mutex);
        return P2P_ERR_SEND_FAILED;
    }

    conn->tx_counter++;
    xSemaphoreGive(conn->mutex);

    ESP_LOGD(TAG, "Sent ratchet-encrypted message (%zu bytes)", buffer_len);
    return P2P_OK;
}

int p2p_disconnect(p2p_connection_t *conn) {
    if (conn == NULL) {
        return P2P_ERR_INVALID_PARAM;
    }

    conn->running = false;

    // Send disconnect message
    if (conn->state == P2P_STATE_CONNECTED) {
        message_t *msg = malloc(sizeof(message_t));
        if (msg) {
            message_create_disconnect(msg, conn->tx_counter);
            uint8_t buf[HANDSHAKE_BUF_SIZE];
            size_t buf_len;
            if (message_serialize(msg, buf, sizeof(buf), &buf_len) == MSG_OK) {
                send(conn->socket, buf, buf_len, 0);
            }
            free(msg);
        }
    }

    registry_remove(conn);

    if (conn->socket >= 0) {
        close(conn->socket);
        conn->socket = -1;
    }

    // Wait for RX task
    if (conn->rx_task != NULL) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    update_state(conn, P2P_STATE_DISCONNECTED);

    // Cleanup
    vSemaphoreDelete(conn->mutex);
    free(conn);

    ESP_LOGI(TAG, "Disconnected");
    return P2P_OK;
}

p2p_state_t p2p_get_state(p2p_connection_t *conn) {
    return conn ? conn->state : P2P_STATE_IDLE;
}

void p2p_register_message_callback(p2p_connection_t *conn, p2p_message_cb_t callback, void *user_data) {
    if (conn != NULL) {
        conn->message_callback = callback;
        conn->message_user_data = user_data;
    }
}

void p2p_register_state_callback(p2p_connection_t *conn, p2p_state_cb_t callback, void *user_data) {
    if (conn != NULL) {
        conn->state_callback = callback;
        conn->state_user_data = user_data;
    }
}

int p2p_get_peer_info(p2p_connection_t *conn, char *peer_ip, uint16_t *peer_port) {
    if (conn == NULL || peer_ip == NULL || peer_port == NULL) {
        return P2P_ERR_INVALID_PARAM;
    }

    strncpy(peer_ip, conn->peer_ip, 16);
    *peer_port = conn->peer_port;
    return P2P_OK;
}

int p2p_get_local_keypair(p2p_connection_t *conn, crypto_keypair_t *keypair) {
    if (conn == NULL || keypair == NULL) {
        return P2P_ERR_INVALID_PARAM;
    }

    memcpy(keypair, &conn->local_keypair, sizeof(crypto_keypair_t));
    return P2P_OK;
}

int p2p_get_peer_public_key(p2p_connection_t *conn, uint8_t public_key[32]) {
    if (conn == NULL || public_key == NULL) {
        return P2P_ERR_INVALID_PARAM;
    }

    memcpy(public_key, conn->peer_public_key, 32);
    return P2P_OK;
}

int p2p_send_heartbeat(p2p_connection_t *conn) {
    if (conn == NULL || conn->state != P2P_STATE_CONNECTED) {
        return P2P_ERR_INVALID_PARAM;
    }

    message_t *msg = malloc(sizeof(message_t));
    if (!msg) return P2P_ERR_SEND_FAILED;

    message_create_heartbeat(msg, conn->tx_counter);

    uint8_t buf[HANDSHAKE_BUF_SIZE];
    size_t buf_len;
    message_serialize(msg, buf, sizeof(buf), &buf_len);
    free(msg);

    send(conn->socket, buf, buf_len, 0);
    conn->tx_counter++;

    return P2P_OK;
}

// Private functions

static void update_state(p2p_connection_t *conn, p2p_state_t new_state) {
    if (conn->state != new_state) {
        conn->state = new_state;
        if (conn->state_callback != NULL) {
            conn->state_callback(conn, new_state, conn->state_user_data);
        }
    }
}

static int perform_handshake_initiator(p2p_connection_t *conn) {
    message_t *msg = malloc(sizeof(message_t));
    if (!msg) return P2P_ERR_HANDSHAKE_FAILED;

    message_create_handshake_init(msg, conn->local_keypair.public_key, 0);

    uint8_t buffer[HANDSHAKE_BUF_SIZE];
    size_t buffer_len;
    message_serialize(msg, buffer, sizeof(buffer), &buffer_len);

    if (send(conn->socket, buffer, buffer_len, 0) < 0) {
        ESP_LOGE(TAG, "Failed to send handshake init");
        free(msg);
        return P2P_ERR_HANDSHAKE_FAILED;
    }

    ESP_LOGI(TAG, "Sent HANDSHAKE_INIT");

    ssize_t received = recv(conn->socket, buffer, sizeof(buffer), 0);
    if (received <= 0) {
        ESP_LOGE(TAG, "Failed to receive handshake ack");
        free(msg);
        return P2P_ERR_HANDSHAKE_FAILED;
    }

    if (message_deserialize(buffer, received, msg) != MSG_OK) {
        ESP_LOGE(TAG, "Failed to parse handshake ack");
        free(msg);
        return P2P_ERR_HANDSHAKE_FAILED;
    }

    if (msg->type != MSG_TYPE_HANDSHAKE_ACK || msg->length != 32) {
        ESP_LOGE(TAG, "Invalid handshake ack");
        free(msg);
        return P2P_ERR_HANDSHAKE_FAILED;
    }

    memcpy(conn->peer_public_key, msg->payload, 32);
    free(msg);
    ESP_LOGI(TAG, "Received HANDSHAKE_ACK with peer public key");

    uint8_t shared_secret[32];
    if (crypto_compute_shared_secret(shared_secret, conn->local_keypair.private_key,
                                     conn->peer_public_key) != CRYPTO_OK) {
        ESP_LOGE(TAG, "Failed to compute shared secret");
        return P2P_ERR_HANDSHAKE_FAILED;
    }

    // Initialize Double Ratchet as Alice (initiator)
    conn->is_initiator = true;
    if (ratchet_init_alice(&conn->ratchet, shared_secret, conn->peer_public_key) != RATCHET_OK) {
        ESP_LOGE(TAG, "Failed to initialize Double Ratchet");
        crypto_zero_memory(shared_secret, 32);
        return P2P_ERR_HANDSHAKE_FAILED;
    }

    crypto_zero_memory(shared_secret, 32);
    ESP_LOGI(TAG, "Handshake complete, Double Ratchet initialized (Alice)");
    return P2P_OK;
}

static int perform_handshake_responder(p2p_connection_t *conn) {
    message_t *msg = malloc(sizeof(message_t));
    if (!msg) return P2P_ERR_HANDSHAKE_FAILED;

    uint8_t buffer[HANDSHAKE_BUF_SIZE];

    ssize_t received = recv(conn->socket, buffer, sizeof(buffer), 0);
    if (received <= 0) {
        ESP_LOGE(TAG, "Failed to receive handshake init");
        free(msg);
        return P2P_ERR_HANDSHAKE_FAILED;
    }

    if (message_deserialize(buffer, received, msg) != MSG_OK) {
        ESP_LOGE(TAG, "Failed to parse handshake init");
        free(msg);
        return P2P_ERR_HANDSHAKE_FAILED;
    }

    if (msg->type != MSG_TYPE_HANDSHAKE_INIT || msg->length != 32) {
        ESP_LOGE(TAG, "Invalid handshake init");
        free(msg);
        return P2P_ERR_HANDSHAKE_FAILED;
    }

    memcpy(conn->peer_public_key, msg->payload, 32);
    ESP_LOGI(TAG, "Received HANDSHAKE_INIT with peer public key");

    message_create_handshake_ack(msg, conn->local_keypair.public_key, 0);

    size_t buffer_len;
    message_serialize(msg, buffer, sizeof(buffer), &buffer_len);
    free(msg);

    if (send(conn->socket, buffer, buffer_len, 0) < 0) {
        ESP_LOGE(TAG, "Failed to send handshake ack");
        return P2P_ERR_HANDSHAKE_FAILED;
    }

    ESP_LOGI(TAG, "Sent HANDSHAKE_ACK");

    uint8_t shared_secret[32];
    if (crypto_compute_shared_secret(shared_secret, conn->local_keypair.private_key,
                                     conn->peer_public_key) != CRYPTO_OK) {
        ESP_LOGE(TAG, "Failed to compute shared secret");
        return P2P_ERR_HANDSHAKE_FAILED;
    }

    // Initialize Double Ratchet as Bob (responder)
    conn->is_initiator = false;
    if (ratchet_init_bob(&conn->ratchet, shared_secret, &conn->local_keypair) != RATCHET_OK) {
        ESP_LOGE(TAG, "Failed to initialize Double Ratchet");
        crypto_zero_memory(shared_secret, 32);
        return P2P_ERR_HANDSHAKE_FAILED;
    }

    crypto_zero_memory(shared_secret, 32);
    ESP_LOGI(TAG, "Handshake complete (responder), Double Ratchet initialized (Bob)");
    return P2P_OK;
}

/**
 * @brief Read exact number of bytes from socket
 *
 * TCP is a stream protocol - recv() may return less data than requested.
 * This function keeps reading until we have exactly the requested amount.
 */
static int recv_exact(int socket, uint8_t *buffer, size_t length, bool *running) {
    size_t total_received = 0;

    while (total_received < length && *running) {
        ssize_t received = recv(socket, buffer + total_received,
                               length - total_received, 0);

        if (received < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                vTaskDelay(pdMS_TO_TICKS(10));
                continue;
            }
            ESP_LOGE(TAG, "recv_exact error: %d", errno);
            return -1;
        } else if (received == 0) {
            ESP_LOGI(TAG, "Peer closed connection during recv_exact");
            return 0;
        }

        total_received += received;
    }

    return total_received;
}

static void rx_task(void *pvParameters) {
    p2p_connection_t *conn = (p2p_connection_t *)pvParameters;
    uint8_t *buffer = malloc(MSG_MAX_RATCHET_MESSAGE_SIZE);
    if (!buffer) {
        ESP_LOGE(TAG, "RX task: failed to allocate buffer");
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "RX task started");

    while (conn->running && conn->socket >= 0) {
        // Step 1: Read the message header (7 bytes: Type + Counter + Length)
        int received = recv_exact(conn->socket, buffer, MSG_HEADER_SIZE, &conn->running);

        if (received <= 0) {
            if (received == 0) {
                ESP_LOGI(TAG, "Peer closed connection");
            }
            break;
        }

        if (received < MSG_HEADER_SIZE) {
            ESP_LOGW(TAG, "Incomplete header received: %d bytes", received);
            continue;
        }

        // Parse header
        uint8_t msg_type = buffer[0];
        // uint32_t counter = (buffer[1] << 24) | (buffer[2] << 16) | (buffer[3] << 8) | buffer[4];
        uint16_t payload_len = (buffer[5] << 8) | buffer[6];

        ESP_LOGI(TAG, "RX: type=0x%02x, payload_len=%u", msg_type, payload_len);

        // Validate payload length
        if (payload_len > MSG_MAX_PAYLOAD_SIZE + MSG_RATCHET_HEADER_SIZE + CRYPTO_TAG_SIZE) {
            ESP_LOGE(TAG, "Invalid payload length: %u", payload_len);
            break;
        }

        // Step 2: Read the payload based on the length field
        if (payload_len > 0) {
            received = recv_exact(conn->socket, buffer + MSG_HEADER_SIZE,
                                 payload_len, &conn->running);

            if (received <= 0) {
                ESP_LOGE(TAG, "Failed to receive payload");
                break;
            }

            if (received < payload_len) {
                ESP_LOGW(TAG, "Incomplete payload: expected %u, got %d", payload_len, received);
                continue;
            }
        }

        // Total message size
        size_t total_msg_size = MSG_HEADER_SIZE + payload_len;

        ESP_LOGI(TAG, "RX: Complete message received, total_size=%zu", total_msg_size);

        if (msg_type == MSG_TYPE_RATCHET_MSG) {
            // Decrypt with Double Ratchet
            uint8_t plaintext[MSG_MAX_PAYLOAD_SIZE];
            size_t plaintext_len;

            int ret = message_ratchet_decrypt(&conn->ratchet, buffer, total_msg_size,
                                             plaintext, sizeof(plaintext), &plaintext_len);
            if (ret == MSG_OK) {
                plaintext[plaintext_len] = '\0';  // Null-terminate for text messages

                ESP_LOGI(TAG, "RX: Decrypted plaintext_len=%zu", plaintext_len);

                // Invoke callbacks
                if (conn->message_callback != NULL) {
                    conn->message_callback(conn, (char *)plaintext, plaintext_len, conn->message_user_data);
                }
                if (global_message_cb != NULL) {
                    global_message_cb(conn->peer_ip, conn->peer_port, (char *)plaintext, plaintext_len);
                }
            } else {
                ESP_LOGW(TAG, "Failed to decrypt ratchet message: %d", ret);
            }
        } else if (msg_type == MSG_TYPE_DISCONNECT) {
            ESP_LOGI(TAG, "Peer requested disconnect");
            break;
        } else {
            ESP_LOGW(TAG, "Unknown message type: 0x%02x", msg_type);
        }

        vTaskDelay(pdMS_TO_TICKS(1));
    }

    free(buffer);
    update_state(conn, P2P_STATE_DISCONNECTED);
    ESP_LOGI(TAG, "RX task exiting");
    vTaskDelete(NULL);
}

static void accept_task(void *pvParameters) {
    ESP_LOGI(TAG, "Accept task started");

    while (p2p_initialized && listen_socket >= 0) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);

        // Set timeout for accept
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        setsockopt(listen_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        int client_sock = accept(listen_socket, (struct sockaddr *)&client_addr, &addr_len);
        if (client_sock >= 0) {
            char client_ip[16];
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
            uint16_t client_port = ntohs(client_addr.sin_port);
            ESP_LOGI(TAG, "Incoming connection from %s:%d", client_ip, client_port);

            // Allocate connection structure
            p2p_connection_t *conn = calloc(1, sizeof(p2p_connection_t));
            if (conn == NULL) {
                ESP_LOGE(TAG, "Failed to allocate connection structure");
                close(client_sock);
                continue;
            }

            conn->socket = client_sock;
            conn->mutex = xSemaphoreCreateMutex();
            conn->state = P2P_STATE_IDLE;
            conn->tx_counter = 0;
            conn->rx_counter = 0;
            strncpy(conn->peer_ip, client_ip, sizeof(conn->peer_ip) - 1);
            conn->peer_port = client_port;

            // Generate local keypair
            if (crypto_generate_keypair(&conn->local_keypair) != CRYPTO_OK) {
                ESP_LOGE(TAG, "Failed to generate keypair");
                close(client_sock);
                vSemaphoreDelete(conn->mutex);
                free(conn);
                continue;
            }

            // Perform handshake as responder
            update_state(conn, P2P_STATE_HANDSHAKING);
            int ret = perform_handshake_responder(conn);
            if (ret != P2P_OK) {
                ESP_LOGE(TAG, "Handshake failed");
                close(client_sock);
                vSemaphoreDelete(conn->mutex);
                free(conn);
                continue;
            }

            conn->running = true;
            xTaskCreate(rx_task, "p2p_rx_in", 8192, conn, 5, &conn->rx_task);

            update_state(conn, P2P_STATE_CONNECTED);
            registry_add(conn);
            ESP_LOGI(TAG, "Incoming P2P connection established and encrypted");
        }

        vTaskDelay(pdMS_TO_TICKS(100));
    }

    ESP_LOGI(TAG, "Accept task exiting");
    vTaskDelete(NULL);
}

int p2p_get_device_public_key(uint8_t public_key[32]) {
    if (!p2p_initialized || public_key == NULL) {
        return P2P_ERR_NOT_INITIALIZED;
    }

    memcpy(public_key, device_keypair.public_key, 32);
    return P2P_OK;
}
