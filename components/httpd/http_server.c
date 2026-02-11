#include "http_server.h"
#include "wifi_manager.h"
#include "peer_manager.h"
#include "public_ip.h"
#include "upnp.h"
#include "qrcode_gen.h"
#include "tofu_manager.h"
#include "audit_log.h"
#include "p2p.h"
#include "p2p_security.h"
#include "chat_storage.h"
#include <esp_log.h>
#include <esp_timer.h>
#include <esp_wifi.h>
#include <esp_system.h>
#include <esp_netif.h>
#include <nvs.h>
#include <esp_vfs.h>
#include <esp_http_server.h>
#include <string.h>
#include <sys/param.h>
#include <cJSON.h>
#include <mbedtls/base64.h>
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"

static const char *TAG = "http_server";

static httpd_handle_t server = NULL;

static int ws_clients[MAX_WEBSOCKET_CLIENTS] = {0};
static int ws_client_count = 0;

// Message ID generation counter for deduplication
static uint32_t message_id_counter = 0;

typedef struct {
    char peer_id[16];
    char *text;  // Dynamically allocated
} p2p_send_req_t;

static QueueHandle_t p2p_send_queue = NULL;
static TaskHandle_t p2p_send_task_handle = NULL;

static void p2p_send_task(void *pvParameters) {
    p2p_send_req_t req;
    while (1) {
        if (xQueueReceive(p2p_send_queue, &req, portMAX_DELAY) == pdTRUE) {
            peer_info_t peer;
            if (peer_manager_get(req.peer_id, &peer) == PEER_OK) {
                p2p_connection_t *conn = NULL;
                int ret = p2p_find_or_connect(peer.ip, peer.port, peer.public_key, &conn);
                if (ret == P2P_OK && conn) {
                    ret = p2p_send_message(conn, req.text, strlen(req.text));
                    if (ret == P2P_OK) {
                        ESP_LOGI(TAG, "Message sent to peer %s", req.peer_id);

                        // Store sent message in persistent storage
                        if (chat_storage_add_message(peer.ip, req.text, CHAT_DIR_SENT) != CHAT_STORAGE_OK) {
                            ESP_LOGW(TAG, "Failed to store sent message to %s", peer.ip);
                        }
                    } else {
                        ESP_LOGE(TAG, "P2P send failed: %d", ret);
                    }
                } else {
                    ESP_LOGE(TAG, "Failed to connect to peer %s: %d", req.peer_id, ret);
                }
            } else {
                ESP_LOGW(TAG, "Peer %s not found", req.peer_id);
            }

            // Free the dynamically allocated text
            free(req.text);
        }
    }
}

static void queue_p2p_send(const char *peer_id, const char *text) {
    if (!p2p_send_queue) return;

    p2p_send_req_t req = {0};
    strncpy(req.peer_id, peer_id, sizeof(req.peer_id) - 1);

    // Dynamically allocate memory for the text
    req.text = strdup(text);
    if (!req.text) {
        ESP_LOGE(TAG, "Failed to allocate memory for P2P message");
        return;
    }

    if (xQueueSend(p2p_send_queue, &req, pdMS_TO_TICKS(100)) != pdTRUE) {
        ESP_LOGW(TAG, "P2P send queue full");
        free(req.text);  // Free if queue send failed
    }
}

// Forward declarations
static esp_err_t index_handler(httpd_req_t *req);
static esp_err_t app_js_handler(httpd_req_t *req);
static esp_err_t setup_handler(httpd_req_t *req);
static esp_err_t api_wifi_scan_handler(httpd_req_t *req);
static esp_err_t api_wifi_connect_handler(httpd_req_t *req);
static esp_err_t api_setup_complete_handler(httpd_req_t *req);
static esp_err_t api_info_handler(httpd_req_t *req);
static esp_err_t api_peers_handler(httpd_req_t *req);
static esp_err_t api_send_handler(httpd_req_t *req);
static esp_err_t ws_handler(httpd_req_t *req);
static void ws_async_send(void *arg);

// Security/TOFU handlers
static esp_err_t api_tofu_pending_handler(httpd_req_t *req);
static esp_err_t api_tofu_approve_handler(httpd_req_t *req);
static esp_err_t api_tofu_reject_handler(httpd_req_t *req);
static esp_err_t api_qrcode_handler(httpd_req_t *req);
static esp_err_t api_audit_log_handler(httpd_req_t *req);
static esp_err_t api_security_status_handler(httpd_req_t *req);

/**
 * Add WebSocket client to tracking list
 */
static bool add_ws_client(int fd) {
    for (int i = 0; i < MAX_WEBSOCKET_CLIENTS; i++) {
        if (ws_clients[i] == 0) {
            ws_clients[i] = fd;
            ws_client_count++;
            ESP_LOGI(TAG, "WebSocket client %d connected (total: %d)", fd, ws_client_count);
            return true;
        }
    }
    ESP_LOGW(TAG, "WebSocket client limit reached");
    return false;
}

/**
 * Remove WebSocket client from tracking list
 */
static void remove_ws_client(int fd) {
    for (int i = 0; i < MAX_WEBSOCKET_CLIENTS; i++) {
        if (ws_clients[i] == fd) {
            ws_clients[i] = 0;
            ws_client_count--;
            ESP_LOGI(TAG, "WebSocket client %d disconnected (total: %d)", fd, ws_client_count);
            return;
        }
    }
}

/**
 * Check if fd is a tracked WebSocket client
 */
static bool is_ws_client(int fd) {
    for (int i = 0; i < MAX_WEBSOCKET_CLIENTS; i++) {
        if (ws_clients[i] == fd) {
            return true;
        }
    }
    return false;
}

/**
 * WebSocket async send structure
 */
typedef struct {
    httpd_handle_t hd;
    int fd;
    char *payload;
    size_t len;
} ws_async_msg_t;

/**
 * Async send task to avoid blocking
 */
static void ws_async_send(void *arg) {
    ws_async_msg_t *msg = (ws_async_msg_t *)arg;

    if (msg && msg->payload) {
        httpd_ws_frame_t ws_pkt;
        memset(&ws_pkt, 0, sizeof(httpd_ws_frame_t));
        ws_pkt.payload = (uint8_t *)msg->payload;
        ws_pkt.len = msg->len;
        ws_pkt.type = HTTPD_WS_TYPE_TEXT;

        esp_err_t ret = httpd_ws_send_frame_async(msg->hd, msg->fd, &ws_pkt);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "WebSocket send failed: %s", esp_err_to_name(ret));
            // Client might be disconnected
            remove_ws_client(msg->fd);
        }

        free(msg->payload);
        free(msg);
    }
}

/**
 * Send WebSocket message to specific client
 */
int http_server_ws_send(int fd, ws_msg_type_t msg_type, const char *data, size_t len) {
    if (server == NULL || !is_ws_client(fd)) {
        return ESP_ERR_INVALID_STATE;
    }

    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "type", msg_type);
    cJSON *parsed = data ? cJSON_Parse(data) : NULL;
    if (parsed) {
        cJSON_AddItemToObject(root, "data", parsed);
    } else {
        cJSON_AddStringToObject(root, "data", data ? data : "");
    }
    cJSON_AddNumberToObject(root, "timestamp", esp_timer_get_time() / 1000000);

    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    if (!json_str) {
        return ESP_ERR_NO_MEM;
    }

    // Create async message
    ws_async_msg_t *msg = malloc(sizeof(ws_async_msg_t));
    if (!msg) {
        free(json_str);
        return ESP_ERR_NO_MEM;
    }

    msg->hd = server;
    msg->fd = fd;
    msg->payload = json_str;
    msg->len = strlen(json_str);

    // Send asynchronously
    if (httpd_queue_work(server, ws_async_send, msg) != ESP_OK) {
        free(json_str);
        free(msg);
        return ESP_FAIL;
    }

    return ESP_OK;
}

/**
 * Broadcast to all connected WebSocket clients
 */
int http_server_ws_broadcast(ws_msg_type_t msg_type, const char *data, size_t len) {
    int sent_count = 0;

    for (int i = 0; i < MAX_WEBSOCKET_CLIENTS; i++) {
        if (ws_clients[i] != 0) {
            if (http_server_ws_send(ws_clients[i], msg_type, data, len) == ESP_OK) {
                sent_count++;
            }
        }
    }

    return sent_count;
}

/**
 * Get WebSocket client count
 */
int http_server_ws_client_count(void) {
    return ws_client_count;
}

/**
 * WebSocket handler
 */
static esp_err_t ws_handler(httpd_req_t *req) {
    if (req->method == HTTP_GET) {
        // New WebSocket connection
        ESP_LOGI(TAG, "WebSocket handshake from fd %d", httpd_req_to_sockfd(req));

        if (!add_ws_client(httpd_req_to_sockfd(req))) {
            return ESP_FAIL;
        }

        return ESP_OK;
    }

    // WebSocket frame received
    httpd_ws_frame_t ws_pkt;
    memset(&ws_pkt, 0, sizeof(httpd_ws_frame_t));
    ws_pkt.type = HTTPD_WS_TYPE_TEXT;

    // Get frame length
    esp_err_t ret = httpd_ws_recv_frame(req, &ws_pkt, 0);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to get WebSocket frame length: %s", esp_err_to_name(ret));
        return ret;
    }

    if (ws_pkt.len) {
        // Allocate buffer
        uint8_t *buf = calloc(1, ws_pkt.len + 1);
        if (!buf) {
            ESP_LOGE(TAG, "Failed to allocate WebSocket buffer");
            return ESP_ERR_NO_MEM;
        }

        ws_pkt.payload = buf;

        // Receive frame
        ret = httpd_ws_recv_frame(req, &ws_pkt, ws_pkt.len);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to receive WebSocket frame: %s", esp_err_to_name(ret));
            free(buf);
            return ret;
        }

        ESP_LOGI(TAG, "WebSocket frame: type=%d, len=%d", ws_pkt.type, ws_pkt.len);

        // Handle different frame types
        if (ws_pkt.type == HTTPD_WS_TYPE_TEXT) {
            ESP_LOGI(TAG, "Received: %s", ws_pkt.payload);

            // Parse JSON message
            cJSON *root = cJSON_Parse((char *)ws_pkt.payload);
            if (root) {
                cJSON *type = cJSON_GetObjectItem(root, "type");
                cJSON *data = cJSON_GetObjectItem(root, "data");

                if (type && data) {
                    int msg_type = type->valueint;
                    char *msg_data = cJSON_PrintUnformatted(data);

                    ESP_LOGI(TAG, "Message type: %d, data: %s", msg_type, msg_data);

                    if (msg_type == WS_MSG_CHAT) {
                        cJSON *peer_id = cJSON_GetObjectItem(data, "peer_id");
                        cJSON *text = cJSON_GetObjectItem(data, "text");
                        if (cJSON_IsString(peer_id) && cJSON_IsString(text)) {
                            queue_p2p_send(peer_id->valuestring, text->valuestring);
                        }
                    } else {
                        http_server_ws_broadcast(msg_type, msg_data, strlen(msg_data));
                    }

                    free(msg_data);
                }

                cJSON_Delete(root);
            }
        } else if (ws_pkt.type == HTTPD_WS_TYPE_CLOSE) {
            ESP_LOGI(TAG, "WebSocket client closed");
            remove_ws_client(httpd_req_to_sockfd(req));
        }

        free(buf);
    }

    return ESP_OK;
}

/**
 * Serve index.html (gzipped)
 */
static esp_err_t index_handler(httpd_req_t *req) {
    #include "www/index.html.gz.h"

    httpd_resp_set_type(req, "text/html");
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache, must-revalidate");
    httpd_resp_send(req, (const char *)index_html_gz, index_html_gz_len);

    return ESP_OK;
}

/**
 * Handler for app.js (gzipped)
 * GET /app.js
 */
static esp_err_t app_js_handler(httpd_req_t *req) {
    #include "www/app.js.gz.h"

    httpd_resp_set_type(req, "application/javascript");
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache, must-revalidate");
    httpd_resp_send(req, (const char *)app_js_gz, app_js_gz_len);

    return ESP_OK;
}

/**
 * API: Get device info
 * GET /api/info
 */
static esp_err_t api_info_handler(httpd_req_t *req) {
    cJSON *root = cJSON_CreateObject();

    cJSON_AddStringToObject(root, "device_id", "ESP32-GhostChat");
    cJSON_AddStringToObject(root, "version", "1.0.0-phase4");

    // Get local IP
    char local_ip[PUBLIC_IP_MAX_LEN] = "0.0.0.0";
    public_ip_get_local(local_ip);
    cJSON_AddStringToObject(root, "local_ip", local_ip);

    // Get public IP (might be cached or fail)
    char public_ip[PUBLIC_IP_MAX_LEN] = "Unknown";
    public_ip_discover_auto(public_ip);
    cJSON_AddStringToObject(root, "public_ip", public_ip);

    // Port
    cJSON_AddNumberToObject(root, "port", 8000);

    // UPnP / NAT status
    cJSON_AddBoolToObject(root, "upnp_available", upnp_is_available());
    cJSON_AddBoolToObject(root, "port_mapped", upnp_is_port_mapped());
    cJSON_AddNumberToObject(root, "mapped_port", upnp_get_mapped_port());

    if (upnp_is_port_mapped() && public_ip[0] != '\0' && strcmp(public_ip, "Unknown") != 0) {
        char external_addr[32];
        snprintf(external_addr, sizeof(external_addr), "%s:%d", public_ip, upnp_get_mapped_port());
        cJSON_AddStringToObject(root, "external_address", external_addr);
    } else {
        cJSON_AddStringToObject(root, "external_address", "Not available");
    }

    // WebSocket clients
    cJSON_AddNumberToObject(root, "ws_clients", ws_client_count);

    // Get device public key and encode as Base64
    uint8_t pubkey[32];
    char pubkey_b64[64];
    if (p2p_get_device_public_key(pubkey) == P2P_OK) {
        size_t olen;
        mbedtls_base64_encode((unsigned char*)pubkey_b64, sizeof(pubkey_b64), &olen, pubkey, 32);
        pubkey_b64[olen] = '\0';
        cJSON_AddStringToObject(root, "public_key", pubkey_b64);
    } else {
        cJSON_AddStringToObject(root, "public_key", "Not available");
    }

    char *json_str = cJSON_Print(root);
    cJSON_Delete(root);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json_str);

    free(json_str);
    return ESP_OK;
}

/**
 * API: Get peer list
 * GET /api/peers
 */
static esp_err_t api_peers_handler(httpd_req_t *req) {
    cJSON *root = cJSON_CreateArray();

    // Get peers from peer manager
    peer_info_t peers[PEER_MAX_PEERS];
    int count = 0;

    if (peer_manager_get_all(peers, PEER_MAX_PEERS, &count) == PEER_OK) {
        for (int i = 0; i < count; i++) {
            cJSON *peer = cJSON_CreateObject();
            cJSON_AddStringToObject(peer, "id", peers[i].id);
            cJSON_AddStringToObject(peer, "name", peers[i].name);
            cJSON_AddStringToObject(peer, "ip", peers[i].ip);
            cJSON_AddNumberToObject(peer, "port", peers[i].port);
            cJSON_AddBoolToObject(peer, "online", peers[i].status == PEER_STATUS_ONLINE);
            cJSON_AddBoolToObject(peer, "trusted", peers[i].trusted);
            cJSON_AddNumberToObject(peer, "last_seen", peers[i].last_seen);
            cJSON_AddItemToArray(root, peer);
        }
    }

    char *json_str = cJSON_Print(root);
    cJSON_Delete(root);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json_str);

    free(json_str);
    return ESP_OK;
}

/**
 * API: Add peer
 * POST /api/peer/add
 */
static esp_err_t api_peer_add_handler(httpd_req_t *req) {
    char buf[512];
    int ret, remaining = req->content_len;

    if (remaining >= sizeof(buf)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Request too large");
        return ESP_FAIL;
    }

    // Read request body
    ret = httpd_req_recv(req, buf, MIN(remaining, sizeof(buf)));
    if (ret <= 0) {
        if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
            httpd_resp_send_408(req);
        }
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    // Parse JSON
    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    cJSON *name = cJSON_GetObjectItem(root, "name");
    cJSON *ip = cJSON_GetObjectItem(root, "ip");
    cJSON *port = cJSON_GetObjectItem(root, "port");
    cJSON *public_key_b64 = cJSON_GetObjectItem(root, "public_key");

    if (!cJSON_IsString(name) || !cJSON_IsString(ip) ||
        !cJSON_IsNumber(port) || !cJSON_IsString(public_key_b64)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing required fields");
        return ESP_FAIL;
    }

    // Decode base64 public key
    uint8_t public_key[PEER_PUBLIC_KEY_LEN];
    size_t olen = 0;
    int decode_ret = mbedtls_base64_decode(public_key, sizeof(public_key), &olen,
                                           (const uint8_t *)public_key_b64->valuestring,
                                           strlen(public_key_b64->valuestring));

    if (decode_ret != 0 || olen != PEER_PUBLIC_KEY_LEN) {
        ESP_LOGW(TAG, "Invalid public key, using zeros");
        memset(public_key, 0, PEER_PUBLIC_KEY_LEN);
    }

    // Add peer
    char peer_id[16];
    int result = peer_manager_add(name->valuestring, ip->valuestring,
                                   port->valueint, public_key, peer_id);

    cJSON_Delete(root);

    // Build response
    cJSON *response = cJSON_CreateObject();

    if (result == PEER_OK) {
        cJSON_AddBoolToObject(response, "success", true);
        cJSON_AddStringToObject(response, "peer_id", peer_id);
        cJSON_AddStringToObject(response, "message", "Peer added successfully");
    } else {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "error", "Failed to add peer");
    }

    char *json_str = cJSON_Print(response);
    cJSON_Delete(response);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json_str);

    free(json_str);
    return ESP_OK;
}

static esp_err_t api_peer_delete_handler(httpd_req_t *req) {
    char buf[128];
    int ret, remaining = req->content_len;

    if (remaining >= (int)sizeof(buf)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Request too large");
        return ESP_FAIL;
    }

    ret = httpd_req_recv(req, buf, MIN(remaining, sizeof(buf)));
    if (ret <= 0) {
        if (ret == HTTPD_SOCK_ERR_TIMEOUT) httpd_resp_send_408(req);
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    cJSON *peer_id = cJSON_GetObjectItem(root, "peer_id");
    if (!cJSON_IsString(peer_id)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing peer_id");
        return ESP_FAIL;
    }

    int result = peer_manager_remove(peer_id->valuestring);
    cJSON_Delete(root);

    cJSON *response = cJSON_CreateObject();
    cJSON_AddBoolToObject(response, "success", result == PEER_OK);

    char *json_str = cJSON_Print(response);
    cJSON_Delete(response);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json_str);
    free(json_str);
    return ESP_OK;
}

/**
 * API: Send message
 * POST /api/send
 */
static esp_err_t api_send_handler(httpd_req_t *req) {
    char buf[512];
    int ret, remaining = req->content_len;

    if (remaining >= sizeof(buf)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Message too large");
        return ESP_FAIL;
    }

    // Read request body
    ret = httpd_req_recv(req, buf, MIN(remaining, sizeof(buf)));
    if (ret <= 0) {
        if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
            httpd_resp_send_408(req);
        }
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    ESP_LOGI(TAG, "Send request: %s", buf);

    cJSON *root = cJSON_Parse(buf);
    if (root) {
        cJSON *peer_id = cJSON_GetObjectItem(root, "peer_id");
        cJSON *text = cJSON_GetObjectItem(root, "text");
        if (cJSON_IsString(peer_id) && cJSON_IsString(text)) {
            queue_p2p_send(peer_id->valuestring, text->valuestring);
        }
        cJSON_Delete(root);
    }

    // Send success response
    cJSON *response = cJSON_CreateObject();
    cJSON_AddBoolToObject(response, "success", true);
    cJSON_AddStringToObject(response, "message", "Message sent");

    char *json_str = cJSON_Print(response);
    cJSON_Delete(response);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json_str);

    free(json_str);
    return ESP_OK;
}

/**
 * API: Get pending TOFU requests
 * GET /api/tofu/pending
 */
static esp_err_t api_tofu_pending_handler(httpd_req_t *req) {
    tofu_request_t requests[TOFU_MAX_PENDING];
    int count = 0;

    tofu_get_pending_requests(requests, TOFU_MAX_PENDING, &count);

    cJSON *root = cJSON_CreateObject();
    cJSON *array = cJSON_CreateArray();

    for (int i = 0; i < count; i++) {
        cJSON *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "request_id", requests[i].request_id);
        cJSON_AddStringToObject(item, "peer_id", requests[i].peer_id);
        cJSON_AddStringToObject(item, "peer_ip", requests[i].peer_ip);
        cJSON_AddNumberToObject(item, "peer_port", requests[i].peer_port);
        cJSON_AddStringToObject(item, "fingerprint", requests[i].fingerprint_display);
        cJSON_AddNumberToObject(item, "timestamp", requests[i].timestamp);
        cJSON_AddItemToArray(array, item);
    }

    cJSON_AddItemToObject(root, "requests", array);
    cJSON_AddNumberToObject(root, "count", count);

    char *json_str = cJSON_Print(root);
    cJSON_Delete(root);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json_str);

    free(json_str);
    return ESP_OK;
}

/**
 * API: Approve TOFU request
 * POST /api/tofu/approve
 * Body: {"request_id": "..."}
 */
static esp_err_t api_tofu_approve_handler(httpd_req_t *req) {
    char buf[128];
    int ret = httpd_req_recv(req, buf, MIN(req->content_len, sizeof(buf) - 1));
    if (ret <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid request");
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    cJSON *request_id = cJSON_GetObjectItem(root, "request_id");
    if (!cJSON_IsString(request_id)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing request_id");
        return ESP_FAIL;
    }

    int result = tofu_approve(request_id->valuestring);
    cJSON_Delete(root);

    cJSON *response = cJSON_CreateObject();
    cJSON_AddBoolToObject(response, "success", result == TOFU_OK);
    if (result == TOFU_OK) {
        cJSON_AddStringToObject(response, "message", "TOFU request approved");
    } else {
        cJSON_AddStringToObject(response, "error", "Failed to approve request");
    }

    char *json_str = cJSON_Print(response);
    cJSON_Delete(response);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json_str);

    free(json_str);
    return ESP_OK;
}

/**
 * API: Reject TOFU request
 * POST /api/tofu/reject
 * Body: {"request_id": "..."}
 */
static esp_err_t api_tofu_reject_handler(httpd_req_t *req) {
    char buf[128];
    int ret = httpd_req_recv(req, buf, MIN(req->content_len, sizeof(buf) - 1));
    if (ret <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid request");
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    cJSON *request_id = cJSON_GetObjectItem(root, "request_id");
    if (!cJSON_IsString(request_id)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing request_id");
        return ESP_FAIL;
    }

    int result = tofu_reject(request_id->valuestring);
    cJSON_Delete(root);

    cJSON *response = cJSON_CreateObject();
    cJSON_AddBoolToObject(response, "success", result == TOFU_OK);
    if (result == TOFU_OK) {
        cJSON_AddStringToObject(response, "message", "TOFU request rejected");
    } else {
        cJSON_AddStringToObject(response, "error", "Failed to reject request");
    }

    char *json_str = cJSON_Print(response);
    cJSON_Delete(response);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json_str);

    free(json_str);
    return ESP_OK;
}

/**
 * API: Get QR code for fingerprint verification
 * GET /api/qrcode?peer_id=xxx
 */
static esp_err_t api_qrcode_handler(httpd_req_t *req) {
    // Extract peer_id from query string
    char query[128];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing query");
        return ESP_FAIL;
    }

    char peer_id[32];
    if (httpd_query_key_value(query, "peer_id", peer_id, sizeof(peer_id)) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing peer_id");
        return ESP_FAIL;
    }

    // Get peer security info
    p2p_peer_security_t security;
    if (p2p_security_get_peer(peer_id, &security) != P2P_SEC_OK) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Peer not found");
        return ESP_FAIL;
    }

    // Format fingerprint for QR code
    char fp_display[P2P_FINGERPRINT_DISPLAY_LEN];
    p2p_security_format_fingerprint(security.fingerprint, fp_display, sizeof(fp_display));

    // Create QR code data (format: ghostesp://verify/PEER_ID/FINGERPRINT)
    char qr_data[256];
    snprintf(qr_data, sizeof(qr_data), "ghostesp://verify/%s/%s", peer_id, fp_display);

    // Generate QR code
    qrcode_t qr;
    if (qrcode_generate_text(&qr, qr_data, QR_ECC_MEDIUM) != 0) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "QR generation failed");
        return ESP_FAIL;
    }

    // Render as SVG
    char svg_buffer[8192];
    int svg_len = qrcode_render_svg(&qr, svg_buffer, sizeof(svg_buffer), 4);

    qrcode_free(&qr);

    if (svg_len < 0) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "SVG render failed");
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "image/svg+xml");
    httpd_resp_send(req, svg_buffer, svg_len);

    return ESP_OK;
}

/**
 * API: Get audit log
 * GET /api/audit?offset=0&limit=50
 */
static esp_err_t api_audit_log_handler(httpd_req_t *req) {
    int offset = 0;
    int limit = 50;

    // Parse query parameters
    char query[64];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
        char param[16];
        if (httpd_query_key_value(query, "offset", param, sizeof(param)) == ESP_OK) {
            offset = atoi(param);
        }
        if (httpd_query_key_value(query, "limit", param, sizeof(param)) == ESP_OK) {
            limit = atoi(param);
            if (limit > 100) limit = 100;  // Cap at 100
        }
    }

    // Export audit log as JSON
    char *json_buffer = malloc(16384);
    if (!json_buffer) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Out of memory");
        return ESP_FAIL;
    }

    int result = audit_export_json(json_buffer, 16384, offset, limit);
    if (result < 0) {
        free(json_buffer);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Export failed");
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json_buffer);

    free(json_buffer);
    return ESP_OK;
}

/**
 * API: Get security status
 * GET /api/security/status
 */
static esp_err_t api_security_status_handler(httpd_req_t *req) {
    cJSON *root = cJSON_CreateObject();

    // TOFU stats
    int pending_tofu = tofu_get_pending_count();
    cJSON_AddNumberToObject(root, "pending_tofu_requests", pending_tofu);

    // Audit log stats
    int audit_count = audit_get_count();
    cJSON_AddNumberToObject(root, "audit_entries", audit_count);

    // Verify audit integrity
    int integrity_ok = (audit_verify_integrity() == AUDIT_OK);
    cJSON_AddBoolToObject(root, "audit_integrity_ok", integrity_ok);

    // Security features status
    cJSON *features = cJSON_CreateObject();
#ifdef CONFIG_SECURE_BOOT_V2_ENABLED
    cJSON_AddBoolToObject(features, "secure_boot", true);
#else
    cJSON_AddBoolToObject(features, "secure_boot", false);
#endif

#ifdef CONFIG_SECURE_FLASH_ENC_ENABLED
    cJSON_AddBoolToObject(features, "flash_encryption", true);
#else
    cJSON_AddBoolToObject(features, "flash_encryption", false);
#endif

    cJSON_AddBoolToObject(features, "tofu_enabled", true);
    cJSON_AddBoolToObject(features, "audit_logging", true);
    cJSON_AddBoolToObject(features, "double_ratchet", true);  // Signal Protocol Double Ratchet enabled

    cJSON_AddItemToObject(root, "features", features);

    char *json_str = cJSON_Print(root);
    cJSON_Delete(root);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json_str);

    free(json_str);
    return ESP_OK;
}

static esp_err_t api_chat_history_handler(httpd_req_t *req) {
    char query[128];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing query string");
        return ESP_OK;
    }

    char peer_ip[32];
    if (httpd_query_key_value(query, "peer", peer_ip, sizeof(peer_ip)) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing peer parameter");
        return ESP_OK;
    }

    // Allocate history on heap to avoid stack overflow (structure is ~5.3KB)
    chat_history_t *history = (chat_history_t *)malloc(sizeof(chat_history_t));
    if (!history) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Out of memory");
        return ESP_OK;
    }

    int ret = chat_storage_get_history(peer_ip, history);

    if (ret == CHAT_STORAGE_ERR_NOT_FOUND) {
        free(history);
        const char *empty_json = "{\"messages\":[],\"count\":0}";
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, empty_json);
        return ESP_OK;
    } else if (ret != CHAT_STORAGE_OK) {
        free(history);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Storage error");
        return ESP_OK;
    }

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "peer", peer_ip);
    cJSON_AddNumberToObject(root, "count", history->count);

    cJSON *messages_array = cJSON_CreateArray();

    int start = (history->count < CHAT_MAX_MESSAGES_PER_PEER) ? 0 : history->head;
    for (int i = 0; i < history->count; i++) {
        int idx = (start + i) % CHAT_MAX_MESSAGES_PER_PEER;
        chat_message_t *msg = &history->messages[idx];

        cJSON *msg_obj = cJSON_CreateObject();
        cJSON_AddNumberToObject(msg_obj, "timestamp", msg->timestamp);
        cJSON_AddStringToObject(msg_obj, "direction",
                                msg->direction == CHAT_DIR_SENT ? "sent" : "received");
        cJSON_AddStringToObject(msg_obj, "message", msg->message);

        cJSON_AddItemToArray(messages_array, msg_obj);
    }

    cJSON_AddItemToObject(root, "messages", messages_array);
    free(history);

    char *json_str = cJSON_Print(root);
    cJSON_Delete(root);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json_str);

    free(json_str);
    return ESP_OK;
}

static esp_err_t api_chat_list_peers_handler(httpd_req_t *req) {
    char peer_ids[10][CHAT_PEER_ID_LENGTH];
    uint16_t count;

    int ret = chat_storage_list_peers(peer_ids, 10, &count);
    if (ret != CHAT_STORAGE_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Storage error");
        return ESP_OK;
    }

    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "count", count);

    cJSON *peers_array = cJSON_CreateArray();
    for (int i = 0; i < count; i++) {
        cJSON_AddItemToArray(peers_array, cJSON_CreateString(peer_ids[i]));
    }
    cJSON_AddItemToObject(root, "peers", peers_array);

    char *json_str = cJSON_Print(root);
    cJSON_Delete(root);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json_str);

    free(json_str);
    return ESP_OK;
}

static esp_err_t api_chat_delete_handler(httpd_req_t *req) {
    char query[128];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing query string");
        return ESP_OK;
    }

    char peer_ip[32];
    if (httpd_query_key_value(query, "peer", peer_ip, sizeof(peer_ip)) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing peer parameter");
        return ESP_OK;
    }

    int ret = chat_storage_delete_history(peer_ip);
    if (ret != CHAT_STORAGE_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Delete failed");
        return ESP_OK;
    }

    const char *success_json = "{\"status\":\"deleted\"}";
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, success_json);
    return ESP_OK;
}

static void on_p2p_message_received(const char *peer_ip, uint16_t peer_port,
                                     const char *message, size_t message_len) {
    ESP_LOGI(TAG, "P2P message from %s:%d: %.*s", peer_ip, peer_port, (int)message_len, message);

    // Store message in persistent storage
    if (chat_storage_add_message(peer_ip, message, CHAT_DIR_RECEIVED) != CHAT_STORAGE_OK) {
        ESP_LOGW(TAG, "Failed to store received message from %s", peer_ip);
    }

    peer_info_t all_peers[PEER_MAX_PEERS];
    int count = 0;
    peer_manager_get_all(all_peers, PEER_MAX_PEERS, &count);

    const char *peer_id = NULL;
    const char *sender = NULL;
    for (int i = 0; i < count; i++) {
        if (strcmp(all_peers[i].ip, peer_ip) == 0) {
            peer_id = all_peers[i].id;
            sender = all_peers[i].name;
            break;
        }
    }

    // Generate unique message ID for deduplication
    message_id_counter++;
    uint64_t timestamp = esp_timer_get_time() / 1000;  // milliseconds
    char msg_id[32];
    snprintf(msg_id, sizeof(msg_id), "%llu-%lu", timestamp, message_id_counter);

    cJSON *data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "msg_id", msg_id);
    cJSON_AddStringToObject(data, "peer_id", peer_id ? peer_id : "unknown");
    cJSON_AddStringToObject(data, "sender", sender ? sender : peer_ip);
    cJSON_AddStringToObject(data, "text", message);
    cJSON_AddNumberToObject(data, "timestamp", timestamp);

    char *data_str = cJSON_PrintUnformatted(data);
    cJSON_Delete(data);

    if (data_str) {
        http_server_ws_broadcast(WS_MSG_CHAT, data_str, strlen(data_str));
        free(data_str);
    }
}

static esp_err_t setup_handler(httpd_req_t *req) {
    #include "www/setup.html.gz.h"

    httpd_resp_set_type(req, "text/html");
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache, must-revalidate");
    httpd_resp_send(req, (const char *)setup_html_gz, setup_html_gz_len);
    return ESP_OK;
}

static esp_err_t api_wifi_scan_handler(httpd_req_t *req) {
    wifi_ap_record_t ap_records[20];
    uint16_t ap_count = 20;

    esp_wifi_set_mode(WIFI_MODE_APSTA);

    wifi_scan_config_t scan_config = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = false,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time.active.min = 100,
        .scan_time.active.max = 300,
    };

    esp_err_t err = esp_wifi_scan_start(&scan_config, true);
    if (err != ESP_OK) {
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "[]");
        return ESP_OK;
    }

    esp_wifi_scan_get_ap_num(&ap_count);
    if (ap_count > 20) ap_count = 20;
    esp_wifi_scan_get_ap_records(&ap_count, ap_records);

    cJSON *root = cJSON_CreateArray();
    for (int i = 0; i < ap_count; i++) {
        if (ap_records[i].ssid[0] == '\0') continue;

        bool duplicate = false;
        for (int j = 0; j < i; j++) {
            if (strcmp((char *)ap_records[j].ssid, (char *)ap_records[i].ssid) == 0) {
                duplicate = true;
                break;
            }
        }
        if (duplicate) continue;

        cJSON *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "ssid", (char *)ap_records[i].ssid);
        cJSON_AddNumberToObject(item, "rssi", ap_records[i].rssi);
        cJSON_AddBoolToObject(item, "secure", ap_records[i].authmode != WIFI_AUTH_OPEN);
        cJSON_AddItemToArray(root, item);
    }

    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json_str);
    free(json_str);
    return ESP_OK;
}

static esp_err_t api_wifi_connect_handler(httpd_req_t *req) {
    char buf[256];
    int ret = httpd_req_recv(req, buf, MIN(req->content_len, sizeof(buf) - 1));
    if (ret <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid request");
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    cJSON *ssid = cJSON_GetObjectItem(root, "ssid");
    cJSON *password = cJSON_GetObjectItem(root, "password");

    if (!cJSON_IsString(ssid)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing ssid");
        return ESP_FAIL;
    }

    const char *pass_str = cJSON_IsString(password) ? password->valuestring : "";

    esp_wifi_set_mode(WIFI_MODE_APSTA);

    wifi_config_t sta_config = {0};
    strncpy((char *)sta_config.sta.ssid, ssid->valuestring, sizeof(sta_config.sta.ssid) - 1);
    strncpy((char *)sta_config.sta.password, pass_str, sizeof(sta_config.sta.password) - 1);
    sta_config.sta.threshold.authmode = strlen(pass_str) > 0 ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;

    esp_wifi_set_config(WIFI_IF_STA, &sta_config);
    esp_wifi_connect();

    bool connected = false;
    char ip_str[16] = {0};

    for (int i = 0; i < 30; i++) {
        vTaskDelay(pdMS_TO_TICKS(500));
        esp_netif_t *sta_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
        if (sta_netif) {
            esp_netif_ip_info_t ip_info;
            if (esp_netif_get_ip_info(sta_netif, &ip_info) == ESP_OK && ip_info.ip.addr != 0) {
                snprintf(ip_str, sizeof(ip_str), IPSTR, IP2STR(&ip_info.ip));
                connected = true;
                break;
            }
        }
    }

    if (connected) {
        nvs_handle_t nvs_handle;
        if (nvs_open("wifi", NVS_READWRITE, &nvs_handle) == ESP_OK) {
            nvs_set_str(nvs_handle, "ssid", ssid->valuestring);
            nvs_set_str(nvs_handle, "password", pass_str);
            nvs_commit(nvs_handle);
            nvs_close(nvs_handle);
        }
    }

    cJSON *response = cJSON_CreateObject();
    if (connected) {
        cJSON_AddBoolToObject(response, "success", true);
        cJSON_AddStringToObject(response, "ip", ip_str);
    } else {
        esp_wifi_disconnect();
        esp_wifi_set_mode(WIFI_MODE_AP);
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "error", "Connection failed. Check credentials.");
    }

    cJSON_Delete(root);
    char *json_str = cJSON_PrintUnformatted(response);
    cJSON_Delete(response);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json_str);
    free(json_str);
    return ESP_OK;
}

static esp_err_t api_setup_complete_handler(httpd_req_t *req) {
    cJSON *response = cJSON_CreateObject();
    cJSON_AddBoolToObject(response, "success", true);

    char *json_str = cJSON_PrintUnformatted(response);
    cJSON_Delete(response);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json_str);
    free(json_str);

    vTaskDelay(pdMS_TO_TICKS(1000));
    esp_restart();
    return ESP_OK;
}

int http_server_init(void) {
    if (server != NULL) {
        ESP_LOGW(TAG, "HTTP server already running");
        return ESP_OK;
    }

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = HTTP_SERVER_PORT;
    config.max_open_sockets = 20;  // Increased to support multiple browser tabs/devices
    config.max_uri_handlers = 20;  // Increased from default 8 to support all endpoints + static files
    config.lru_purge_enable = true;

    ESP_LOGI(TAG, "Starting HTTP server on port %d", config.server_port);

    if (httpd_start(&server, &config) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start HTTP server");
        return ESP_FAIL;
    }

    // Register URI handlers
    httpd_uri_t index_uri = {
        .uri = "/",
        .method = HTTP_GET,
        .handler = index_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(server, &index_uri);

    httpd_uri_t app_js_uri = {
        .uri = "/app.js",
        .method = HTTP_GET,
        .handler = app_js_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(server, &app_js_uri);

    httpd_uri_t api_info_uri = {
        .uri = "/api/info",
        .method = HTTP_GET,
        .handler = api_info_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(server, &api_info_uri);

    httpd_uri_t api_peers_uri = {
        .uri = "/api/peers",
        .method = HTTP_GET,
        .handler = api_peers_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(server, &api_peers_uri);

    httpd_uri_t api_peer_add_uri = {
        .uri = "/api/peer/add",
        .method = HTTP_POST,
        .handler = api_peer_add_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(server, &api_peer_add_uri);

    httpd_uri_t api_peer_delete_uri = {
        .uri = "/api/peer/delete",
        .method = HTTP_POST,
        .handler = api_peer_delete_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(server, &api_peer_delete_uri);

    httpd_uri_t api_send_uri = {
        .uri = "/api/send",
        .method = HTTP_POST,
        .handler = api_send_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(server, &api_send_uri);

    // WebSocket handler
    httpd_uri_t ws_uri = {
        .uri = "/ws",
        .method = HTTP_GET,
        .handler = ws_handler,
        .user_ctx = NULL,
        .is_websocket = true
    };
    httpd_register_uri_handler(server, &ws_uri);

    // Security/TOFU endpoints
    httpd_uri_t tofu_pending_uri = {
        .uri = "/api/tofu/pending",
        .method = HTTP_GET,
        .handler = api_tofu_pending_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(server, &tofu_pending_uri);

    httpd_uri_t tofu_approve_uri = {
        .uri = "/api/tofu/approve",
        .method = HTTP_POST,
        .handler = api_tofu_approve_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(server, &tofu_approve_uri);

    httpd_uri_t tofu_reject_uri = {
        .uri = "/api/tofu/reject",
        .method = HTTP_POST,
        .handler = api_tofu_reject_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(server, &tofu_reject_uri);

    httpd_uri_t qrcode_uri = {
        .uri = "/api/qrcode",
        .method = HTTP_GET,
        .handler = api_qrcode_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(server, &qrcode_uri);

    httpd_uri_t audit_uri = {
        .uri = "/api/audit",
        .method = HTTP_GET,
        .handler = api_audit_log_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(server, &audit_uri);

    httpd_uri_t security_status_uri = {
        .uri = "/api/security/status",
        .method = HTTP_GET,
        .handler = api_security_status_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(server, &security_status_uri);

    httpd_uri_t chat_history_uri = {
        .uri = "/api/chat/history",
        .method = HTTP_GET,
        .handler = api_chat_history_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(server, &chat_history_uri);

    httpd_uri_t chat_list_peers_uri = {
        .uri = "/api/chat/peers",
        .method = HTTP_GET,
        .handler = api_chat_list_peers_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(server, &chat_list_peers_uri);

    httpd_uri_t chat_delete_uri = {
        .uri = "/api/chat/delete",
        .method = HTTP_DELETE,
        .handler = api_chat_delete_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(server, &chat_delete_uri);

    p2p_set_global_message_callback(on_p2p_message_received);

    p2p_send_queue = xQueueCreate(8, sizeof(p2p_send_req_t));
    xTaskCreate(p2p_send_task, "p2p_send", 8192, NULL, 5, &p2p_send_task_handle);

    ESP_LOGI(TAG, "HTTP server started successfully with security endpoints");
    return ESP_OK;
}

/**
 * Stop HTTP server
 */
void http_server_stop(void) {
    if (server) {
        ESP_LOGI(TAG, "Stopping HTTP server");
        httpd_stop(server);
        server = NULL;
        ws_client_count = 0;
        memset(ws_clients, 0, sizeof(ws_clients));
    }
}

/**
 * Check if server is running
 */
bool http_server_is_running(void) {
    return (server != NULL);
}

int http_server_init_setup_mode(void) {
    if (server != NULL) {
        ESP_LOGW(TAG, "HTTP server already running");
        return ESP_OK;
    }

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = HTTP_SERVER_PORT;
    config.max_open_sockets = 4;
    config.max_uri_handlers = 8;
    config.stack_size = 8192;
    config.lru_purge_enable = true;

    ESP_LOGI(TAG, "Starting setup HTTP server on port %d", config.server_port);

    if (httpd_start(&server, &config) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start HTTP server");
        return ESP_FAIL;
    }

    httpd_uri_t setup_uri = {
        .uri = "/",
        .method = HTTP_GET,
        .handler = setup_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(server, &setup_uri);

    httpd_uri_t wifi_scan_uri = {
        .uri = "/api/wifi/scan",
        .method = HTTP_GET,
        .handler = api_wifi_scan_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(server, &wifi_scan_uri);

    httpd_uri_t wifi_connect_uri = {
        .uri = "/api/wifi/connect",
        .method = HTTP_POST,
        .handler = api_wifi_connect_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(server, &wifi_connect_uri);

    httpd_uri_t setup_complete_uri = {
        .uri = "/api/setup/complete",
        .method = HTTP_POST,
        .handler = api_setup_complete_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(server, &setup_complete_uri);

    ESP_LOGI(TAG, "Setup mode HTTP server started");
    return ESP_OK;
}
