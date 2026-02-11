#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include <esp_http_server.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * HTTP Server Configuration
 */
#define HTTP_SERVER_PORT 80
#define MAX_WEBSOCKET_CLIENTS 5

/**
 * WebSocket message types for client<->server communication
 */
typedef enum {
    WS_MSG_CHAT = 1,          // Chat message to peer
    WS_MSG_STATUS = 2,        // Connection status update
    WS_MSG_PEER_LIST = 3,     // Peer list update
    WS_MSG_SYSTEM = 4,        // System notification
    WS_MSG_ERROR = 5          // Error message
} ws_msg_type_t;

/**
 * Initialize HTTP server
 *
 * @return ESP_OK on success, error code otherwise
 */
int http_server_init(void);

/**
 * Initialize HTTP server in setup mode (AP captive portal)
 * Only serves the setup wizard and WiFi config endpoints.
 *
 * @return ESP_OK on success, error code otherwise
 */
int http_server_init_setup_mode(void);

/**
 * Stop HTTP server
 */
void http_server_stop(void);

/**
 * Check if HTTP server is running
 *
 * @return true if running, false otherwise
 */
bool http_server_is_running(void);

/**
 * Broadcast message to all connected WebSocket clients
 *
 * @param msg_type Message type
 * @param data JSON data string
 * @param len Length of data
 * @return Number of clients message was sent to
 */
int http_server_ws_broadcast(ws_msg_type_t msg_type, const char *data, size_t len);

/**
 * Send message to specific WebSocket client
 *
 * @param fd File descriptor of client
 * @param msg_type Message type
 * @param data JSON data string
 * @param len Length of data
 * @return ESP_OK on success, error code otherwise
 */
int http_server_ws_send(int fd, ws_msg_type_t msg_type, const char *data, size_t len);

/**
 * Get number of connected WebSocket clients
 *
 * @return Number of connected clients
 */
int http_server_ws_client_count(void);

#ifdef __cplusplus
}
#endif

#endif // HTTP_SERVER_H
