/**
 * @file input_validation.c
 * @brief Input validation implementation
 */

#include "input_validation.h"
#include <string.h>
#include <ctype.h>
#include <esp_log.h>

static const char *TAG = "validation";

int validate_ipv4(const char *ip) {
    if (ip == NULL || *ip == '\0') {
        return VALIDATE_ERR_NULL;
    }

    if (strlen(ip) > 15) {  // Max IPv4: "255.255.255.255"
        return VALIDATE_ERR_TOO_LONG;
    }

    int dots = 0;
    int digits = 0;
    int value = 0;

    for (const char *p = ip; *p != '\0'; p++) {
        if (*p == '.') {
            if (digits == 0 || digits > 3 || value > 255) {
                return VALIDATE_ERR_INVALID_FORMAT;
            }
            dots++;
            digits = 0;
            value = 0;
        } else if (isdigit((unsigned char)*p)) {
            value = value * 10 + (*p - '0');
            digits++;
            if (value > 255) {
                return VALIDATE_ERR_OUT_OF_RANGE;
            }
        } else {
            return VALIDATE_ERR_INVALID_CHAR;
        }
    }

    // Check final octet
    if (digits == 0 || digits > 3 || value > 255 || dots != 3) {
        return VALIDATE_ERR_INVALID_FORMAT;
    }

    return VALIDATE_OK;
}

int validate_ipv6(const char *ip) {
    if (ip == NULL || *ip == '\0') {
        return VALIDATE_ERR_NULL;
    }

    size_t len = strlen(ip);
    if (len > MAX_IP_LEN || len < 2) {
        return VALIDATE_ERR_TOO_LONG;
    }

    // Basic IPv6 validation (simplified)
    int colons = 0;
    bool has_double_colon = false;

    for (size_t i = 0; i < len; i++) {
        char c = ip[i];
        if (c == ':') {
            colons++;
            if (i > 0 && ip[i-1] == ':') {
                if (has_double_colon) {
                    return VALIDATE_ERR_INVALID_FORMAT;  // Multiple ::
                }
                has_double_colon = true;
            }
        } else if (!isxdigit((unsigned char)c) && c != '.') {
            return VALIDATE_ERR_INVALID_CHAR;
        }
    }

    // IPv6 must have colons
    if (colons < 2) {
        return VALIDATE_ERR_INVALID_FORMAT;
    }

    return VALIDATE_OK;
}

int validate_ip(const char *ip) {
    // Try IPv4 first
    int ret = validate_ipv4(ip);
    if (ret == VALIDATE_OK) {
        return VALIDATE_OK;
    }

    // Try IPv6
    return validate_ipv6(ip);
}

int validate_port(uint16_t port) {
    if (port < MIN_PORT || port > MAX_PORT) {
        return VALIDATE_ERR_OUT_OF_RANGE;
    }
    return VALIDATE_OK;
}

int validate_peer_name(const char *name) {
    if (name == NULL || *name == '\0') {
        return VALIDATE_ERR_NULL;
    }

    size_t len = strlen(name);
    if (len > MAX_PEER_NAME_LEN) {
        return VALIDATE_ERR_TOO_LONG;
    }

    if (len == 0) {
        return VALIDATE_ERR_TOO_SHORT;
    }

    // Allow: alphanumeric, space, dash, underscore
    for (size_t i = 0; i < len; i++) {
        char c = name[i];
        if (!isalnum((unsigned char)c) && c != ' ' && c != '-' && c != '_') {
            ESP_LOGW(TAG, "Invalid character in name: 0x%02x at position %d", c, i);
            return VALIDATE_ERR_INVALID_CHAR;
        }
    }

    return VALIDATE_OK;
}

int validate_message(const char *message, size_t max_len) {
    if (message == NULL) {
        return VALIDATE_ERR_NULL;
    }

    size_t len = strlen(message);
    if (len > max_len) {
        return VALIDATE_ERR_TOO_LONG;
    }

    // Check for control characters (except newline, tab)
    for (size_t i = 0; i < len; i++) {
        unsigned char c = message[i];
        if (iscntrl(c) && c != '\n' && c != '\t' && c != '\r') {
            ESP_LOGW(TAG, "Invalid control character in message: 0x%02x", c);
            return VALIDATE_ERR_INVALID_CHAR;
        }
    }

    return VALIDATE_OK;
}

int validate_url(const char *url) {
    if (url == NULL || *url == '\0') {
        return VALIDATE_ERR_NULL;
    }

    size_t len = strlen(url);
    if (len > MAX_URL_LEN) {
        return VALIDATE_ERR_TOO_LONG;
    }

    // Must start with http:// or https://
    if (strncmp(url, "http://", 7) != 0 && strncmp(url, "https://", 8) != 0) {
        return VALIDATE_ERR_INVALID_FORMAT;
    }

    // Basic character validation
    for (size_t i = 0; i < len; i++) {
        unsigned char c = url[i];
        if (iscntrl(c)) {
            return VALIDATE_ERR_INVALID_CHAR;
        }
    }

    return VALIDATE_OK;
}

int validate_public_key(const char *key, size_t expected_len) {
    if (key == NULL || *key == '\0') {
        return VALIDATE_ERR_NULL;
    }

    size_t len = strlen(key);

    // Base64 encoded: expected_len * 4/3 (rounded up)
    size_t min_base64_len = (expected_len * 4 + 2) / 3;
    size_t max_base64_len = min_base64_len + 4;  // Padding tolerance

    // Hex encoded: expected_len * 2
    size_t hex_len = expected_len * 2;

    if (len < min_base64_len && len != hex_len) {
        return VALIDATE_ERR_TOO_SHORT;
    }

    if (len > max_base64_len && len != hex_len) {
        return VALIDATE_ERR_TOO_LONG;
    }

    // Check for valid base64 or hex characters
    bool is_hex = true;
    bool is_base64 = true;

    for (size_t i = 0; i < len; i++) {
        char c = key[i];

        if (!isxdigit((unsigned char)c)) {
            is_hex = false;
        }

        if (!isalnum((unsigned char)c) && c != '+' && c != '/' && c != '=') {
            is_base64 = false;
        }
    }

    if (!is_hex && !is_base64) {
        return VALIDATE_ERR_INVALID_CHAR;
    }

    return VALIDATE_OK;
}

int sanitize_string(const char *input, char *output, size_t output_len) {
    if (input == NULL || output == NULL || output_len == 0) {
        return VALIDATE_ERR_NULL;
    }

    size_t in_len = strlen(input);
    size_t out_idx = 0;

    for (size_t i = 0; i < in_len && out_idx < output_len - 1; i++) {
        unsigned char c = input[i];

        // Keep printable characters and common whitespace
        if (isprint(c) || c == '\n' || c == '\t') {
            output[out_idx++] = c;
        } else {
            // Replace control characters with space
            output[out_idx++] = ' ';
        }
    }

    output[out_idx] = '\0';
    return VALIDATE_OK;
}

bool validate_buffer_bounds(const void *buffer, size_t buffer_size,
                            size_t offset, size_t required) {
    if (buffer == NULL) {
        return false;
    }

    // Check for overflow
    if (offset > buffer_size) {
        return false;
    }

    if (required > buffer_size - offset) {
        return false;
    }

    return true;
}

size_t safe_string_copy(char *dest, size_t dest_size, const char *src) {
    if (dest == NULL || src == NULL || dest_size == 0) {
        return 0;
    }

    size_t i;
    for (i = 0; i < dest_size - 1 && src[i] != '\0'; i++) {
        dest[i] = src[i];
    }
    dest[i] = '\0';

    return i;
}

size_t safe_memory_copy(void *dest, size_t dest_size,
                        const void *src, size_t src_size) {
    if (dest == NULL || src == NULL || dest_size == 0 || src_size == 0) {
        return 0;
    }

    size_t copy_size = (src_size < dest_size) ? src_size : dest_size;
    memcpy(dest, src, copy_size);

    return copy_size;
}
