/**
 * @file input_validation.h
 * @brief Input validation and sanitization for GhostESP
 *
 * Prevents buffer overflows, injection attacks, and malformed input
 */

#ifndef GHOST_INPUT_VALIDATION_H
#define GHOST_INPUT_VALIDATION_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Validation result codes
#define VALIDATE_OK                 0
#define VALIDATE_ERR_NULL          -1
#define VALIDATE_ERR_TOO_LONG      -2
#define VALIDATE_ERR_TOO_SHORT     -3
#define VALIDATE_ERR_INVALID_CHAR  -4
#define VALIDATE_ERR_INVALID_FORMAT -5
#define VALIDATE_ERR_OUT_OF_RANGE  -6

// Constraints
#define MAX_PEER_NAME_LEN 64
#define MAX_IP_LEN 45  // IPv6 max length
#define MAX_URL_LEN 256
#define MAX_MESSAGE_LEN 4096
#define MIN_PORT 1
#define MAX_PORT 65535

/**
 * @brief Validate IPv4 address
 *
 * @param ip IP address string
 * @return VALIDATE_OK if valid, error code otherwise
 */
int validate_ipv4(const char *ip);

/**
 * @brief Validate IPv6 address
 *
 * @param ip IP address string
 * @return VALIDATE_OK if valid, error code otherwise
 */
int validate_ipv6(const char *ip);

/**
 * @brief Validate IP address (v4 or v6)
 *
 * @param ip IP address string
 * @return VALIDATE_OK if valid, error code otherwise
 */
int validate_ip(const char *ip);

/**
 * @brief Validate port number
 *
 * @param port Port number
 * @return VALIDATE_OK if valid, error code otherwise
 */
int validate_port(uint16_t port);

/**
 * @brief Validate peer name
 *
 * Allows alphanumeric, space, dash, underscore
 * Length: 1-64 characters
 *
 * @param name Peer name string
 * @return VALIDATE_OK if valid, error code otherwise
 */
int validate_peer_name(const char *name);

/**
 * @brief Validate text message content
 *
 * Checks for length and dangerous characters
 *
 * @param message Message string
 * @param max_len Maximum allowed length
 * @return VALIDATE_OK if valid, error code otherwise
 */
int validate_message(const char *message, size_t max_len);

/**
 * @brief Validate URL
 *
 * Basic URL validation (http/https)
 *
 * @param url URL string
 * @return VALIDATE_OK if valid, error code otherwise
 */
int validate_url(const char *url);

/**
 * @brief Validate public key (base64 or hex)
 *
 * @param key Key string
 * @param expected_len Expected decoded length in bytes
 * @return VALIDATE_OK if valid, error code otherwise
 */
int validate_public_key(const char *key, size_t expected_len);

/**
 * @brief Sanitize string for safe display
 *
 * Removes control characters, limits length
 *
 * @param input Input string
 * @param output Output buffer
 * @param output_len Output buffer size
 * @return VALIDATE_OK on success
 */
int sanitize_string(const char *input, char *output, size_t output_len);

/**
 * @brief Validate buffer bounds
 *
 * @param buffer Buffer pointer
 * @param buffer_size Total buffer size
 * @param offset Current offset
 * @param required Required bytes
 * @return true if operation is safe, false otherwise
 */
bool validate_buffer_bounds(const void *buffer, size_t buffer_size,
                            size_t offset, size_t required);

/**
 * @brief Safe string copy with bounds checking
 *
 * @param dest Destination buffer
 * @param dest_size Destination size
 * @param src Source string
 * @return Number of bytes copied (excluding null terminator)
 */
size_t safe_string_copy(char *dest, size_t dest_size, const char *src);

/**
 * @brief Safe memory copy with bounds checking
 *
 * @param dest Destination buffer
 * @param dest_size Destination size
 * @param src Source buffer
 * @param src_size Source size
 * @return Number of bytes copied, or 0 on error
 */
size_t safe_memory_copy(void *dest, size_t dest_size,
                        const void *src, size_t src_size);

#ifdef __cplusplus
}
#endif

#endif // GHOST_INPUT_VALIDATION_H
