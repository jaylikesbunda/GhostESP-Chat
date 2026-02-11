/**
 * @file port_test.c
 * @brief Port connectivity tester implementation
 */

#include "port_test.h"
#include <string.h>
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"

static const char *TAG = "port_test";

// State
static int listener_socket = -1;
static uint16_t listener_port = 0;
static TaskHandle_t listener_task_handle = NULL;
static bool listener_running = false;

// Forward declarations
static void listener_task(void *pvParameters);

int port_test_start_listener(uint16_t port) {
    if (port == 0) {
        return PORT_TEST_ERR_INVALID_PARAM;
    }

    // Stop existing listener
    if (listener_running) {
        port_test_stop_listener();
    }

    // Create TCP socket
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        ESP_LOGE(TAG, "Failed to create socket: %d", errno);
        return PORT_TEST_ERR_SOCKET_FAILED;
    }

    // Set socket options
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Bind to port
    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind_addr.sin_port = htons(port);

    if (bind(sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        ESP_LOGE(TAG, "Failed to bind to port %d: %d", port, errno);
        close(sock);
        return PORT_TEST_ERR_BIND_FAILED;
    }

    // Listen
    if (listen(sock, 5) < 0) {
        ESP_LOGE(TAG, "Failed to listen on port %d: %d", port, errno);
        close(sock);
        return PORT_TEST_ERR_LISTEN_FAILED;
    }

    listener_socket = sock;
    listener_port = port;
    listener_running = true;

    // Create listener task
    xTaskCreate(listener_task, "port_listener", 4096, NULL, 5, &listener_task_handle);

    ESP_LOGI(TAG, "TCP listener started on port %d", port);
    return PORT_TEST_OK;
}

void port_test_stop_listener(void) {
    if (!listener_running) {
        return;
    }

    listener_running = false;

    // Close socket
    if (listener_socket >= 0) {
        close(listener_socket);
        listener_socket = -1;
    }

    // Wait for task to exit
    if (listener_task_handle != NULL) {
        vTaskDelay(pdMS_TO_TICKS(100));
        listener_task_handle = NULL;
    }

    listener_port = 0;
    ESP_LOGI(TAG, "TCP listener stopped");
}

bool port_test_is_listening(void) {
    return listener_running;
}

uint16_t port_test_get_port(void) {
    return listener_port;
}

port_status_t port_test_check_external(const char *public_ip, uint16_t port, uint32_t timeout_ms) {
    // This would require an external service to probe the port from outside
    // Services like https://portchecker.co/ offer this, but require HTTP API integration
    //
    // For now, return UNKNOWN status with a log message

    ESP_LOGW(TAG, "External port check not implemented");
    ESP_LOGW(TAG, "To test port %d manually:", port);
    ESP_LOGW(TAG, "1. Visit https://www.yougetsignal.com/tools/open-ports/");
    ESP_LOGW(TAG, "2. Enter your public IP: %s", public_ip);
    ESP_LOGW(TAG, "3. Enter port: %d", port);
    ESP_LOGW(TAG, "4. Click 'Check'");

    return PORT_STATUS_UNKNOWN;
}

int port_test_generate_instructions(const char *local_ip, uint16_t port,
                                    char *buffer, size_t buffer_size) {
    if (local_ip == NULL || buffer == NULL || buffer_size == 0) {
        return PORT_TEST_ERR_INVALID_PARAM;
    }

    int written = snprintf(buffer, buffer_size,
        "Port Forwarding Setup Instructions\n"
        "===================================\n\n"
        "To make your GhostESP accessible from the internet, you need to\n"
        "configure port forwarding on your router.\n\n"
        "Step 1: Access Your Router\n"
        "--------------------------\n"
        "1. Open a web browser\n"
        "2. Navigate to your router's admin page (common addresses):\n"
        "   - http://192.168.1.1\n"
        "   - http://192.168.0.1\n"
        "   - http://10.0.0.1\n"
        "3. Log in with your router credentials\n\n"
        "Step 2: Find Port Forwarding Settings\n"
        "-------------------------------------\n"
        "Look for one of these menu items:\n"
        "- Port Forwarding\n"
        "- Virtual Server\n"
        "- NAT Forwarding\n"
        "- Applications & Gaming\n\n"
        "Step 3: Add Port Forwarding Rule\n"
        "--------------------------------\n"
        "Service Name:    GhostESP Chat\n"
        "External Port:   %d\n"
        "Internal IP:     %s\n"
        "Internal Port:   %d\n"
        "Protocol:        TCP\n"
        "Status:          Enabled\n\n"
        "Step 4: Save and Test\n"
        "--------------------\n"
        "1. Save the configuration\n"
        "2. Router may reboot (wait 1-2 minutes)\n"
        "3. Test connectivity using the 'Test Connection' button\n\n"
        "Troubleshooting:\n"
        "---------------\n"
        "- If port test fails, verify the rule was saved correctly\n"
        "- Check if your ISP uses carrier-grade NAT (CGNAT)\n"
        "- Try enabling UPnP/IGD on your router\n"
        "- Consider using DMZ mode (less secure, but works)\n\n"
        "Security Note: Only forward the ports you need!\n",
        port, local_ip, port
    );

    if (written < 0 || (size_t)written >= buffer_size) {
        return PORT_TEST_ERR_INVALID_PARAM;
    }

    return PORT_TEST_OK;
}

// Private functions

static void listener_task(void *pvParameters) {
    ESP_LOGI(TAG, "Listener task started");

    while (listener_running && listener_socket >= 0) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);

        // Set timeout for accept
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        setsockopt(listener_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        // Accept connections
        int client_sock = accept(listener_socket, (struct sockaddr *)&client_addr, &addr_len);

        if (client_sock >= 0) {
            char client_ip[16];
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
            ESP_LOGI(TAG, "Connection received from %s:%d",
                     client_ip, ntohs(client_addr.sin_port));

            // Send a simple response
            const char *response = "GhostESP P2P Chat\r\nPort is open!\r\n";
            send(client_sock, response, strlen(response), 0);

            // Close connection
            close(client_sock);
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            // Real error (not timeout)
            if (listener_running) {
                ESP_LOGE(TAG, "Accept failed: %d", errno);
            }
        }

        vTaskDelay(pdMS_TO_TICKS(100));
    }

    ESP_LOGI(TAG, "Listener task exiting");
    vTaskDelete(NULL);
}
