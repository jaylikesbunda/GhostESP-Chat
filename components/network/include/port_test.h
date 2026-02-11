/**
 * @file port_test.h
 * @brief Port connectivity tester for GhostESP
 *
 * Tests if a port is accessible from the internet.
 */

#ifndef GHOST_PORT_TEST_H
#define GHOST_PORT_TEST_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Error codes
#define PORT_TEST_OK 0
#define PORT_TEST_ERR_INVALID_PARAM -1
#define PORT_TEST_ERR_SOCKET_FAILED -2
#define PORT_TEST_ERR_BIND_FAILED -3
#define PORT_TEST_ERR_LISTEN_FAILED -4
#define PORT_TEST_ERR_TIMEOUT -5
#define PORT_TEST_ERR_CLOSED -6

// Test result
typedef enum {
    PORT_STATUS_UNKNOWN,
    PORT_STATUS_OPEN,       // Port is accessible from internet
    PORT_STATUS_CLOSED,     // Port is not accessible
    PORT_STATUS_FILTERED,   // Port may be filtered by firewall
} port_status_t;

/**
 * @brief Start TCP listener on specified port
 *
 * Opens a TCP socket and listens for connections to test port accessibility.
 *
 * @param port Port number to listen on
 * @return PORT_TEST_OK on success, error code otherwise
 */
int port_test_start_listener(uint16_t port);

/**
 * @brief Stop TCP listener
 */
void port_test_stop_listener(void);

/**
 * @brief Check if listener is running
 *
 * @return true if listening, false otherwise
 */
bool port_test_is_listening(void);

/**
 * @brief Get current listening port
 *
 * @return Port number, or 0 if not listening
 */
uint16_t port_test_get_port(void);

/**
 * @brief Test port connectivity using external service (placeholder)
 *
 * In a full implementation, this would use an external service
 * like portchecker.io to test if the port is accessible.
 *
 * For now, this is a placeholder that returns UNKNOWN status.
 *
 * @param public_ip Public IP address to test
 * @param port Port number to test
 * @param timeout_ms Timeout in milliseconds
 * @return Port status
 */
port_status_t port_test_check_external(const char *public_ip, uint16_t port, uint32_t timeout_ms);

/**
 * @brief Generate port forwarding instructions
 *
 * Creates human-readable instructions for manual port forwarding.
 *
 * @param local_ip Local IP address (e.g., 192.168.1.100)
 * @param port Port to forward
 * @param buffer Output buffer for instructions
 * @param buffer_size Size of output buffer
 * @return PORT_TEST_OK on success, error code otherwise
 */
int port_test_generate_instructions(const char *local_ip, uint16_t port,
                                    char *buffer, size_t buffer_size);

#ifdef __cplusplus
}
#endif

#endif // GHOST_PORT_TEST_H
