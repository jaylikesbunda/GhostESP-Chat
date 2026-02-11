/**
 * @file message.c
 * @brief Binary message protocol implementation
 */

#include "message.h"
#include <string.h>
#include "esp_log.h"

static const char *TAG = "message";

int message_serialize(const message_t *msg, uint8_t *buffer, size_t buffer_size, size_t *bytes_written) {
    if (msg == NULL || buffer == NULL || bytes_written == NULL) {
        return MSG_ERR_INVALID_PARAM;
    }

    if (!message_is_valid_type(msg->type)) {
        return MSG_ERR_INVALID_TYPE;
    }

    size_t required_size = MSG_HEADER_SIZE + msg->length;
    if (buffer_size < required_size) {
        return MSG_ERR_TOO_LARGE;
    }

    // Serialize header
    buffer[0] = msg->type;
    buffer[1] = (msg->counter >> 24) & 0xFF;
    buffer[2] = (msg->counter >> 16) & 0xFF;
    buffer[3] = (msg->counter >> 8) & 0xFF;
    buffer[4] = msg->counter & 0xFF;
    buffer[5] = (msg->length >> 8) & 0xFF;
    buffer[6] = msg->length & 0xFF;

    // Copy payload
    if (msg->length > 0) {
        memcpy(buffer + MSG_HEADER_SIZE, msg->payload, msg->length);
    }

    *bytes_written = required_size;
    return MSG_OK;
}

int message_deserialize(const uint8_t *buffer, size_t buffer_size, message_t *msg) {
    if (buffer == NULL || msg == NULL) {
        return MSG_ERR_INVALID_PARAM;
    }

    if (buffer_size < MSG_HEADER_SIZE) {
        return MSG_ERR_DESERIALIZE_FAILED;
    }

    // Parse header
    msg->type = buffer[0];
    msg->counter = ((uint32_t)buffer[1] << 24) |
                  ((uint32_t)buffer[2] << 16) |
                  ((uint32_t)buffer[3] << 8) |
                  (uint32_t)buffer[4];
    msg->length = ((uint16_t)buffer[5] << 8) | (uint16_t)buffer[6];

    if (!message_is_valid_type(msg->type)) {
        return MSG_ERR_INVALID_TYPE;
    }

    if (msg->length > MSG_MAX_PAYLOAD_SIZE) {
        return MSG_ERR_TOO_LARGE;
    }

    if (buffer_size < MSG_HEADER_SIZE + msg->length) {
        return MSG_ERR_DESERIALIZE_FAILED;
    }

    // Copy payload
    if (msg->length > 0) {
        memcpy(msg->payload, buffer + MSG_HEADER_SIZE, msg->length);
    }

    return MSG_OK;
}

int message_encrypt(const message_t *msg, const uint8_t key[CRYPTO_KEY_SIZE],
                   uint8_t *buffer, size_t buffer_size, size_t *bytes_written) {
    if (msg == NULL || key == NULL || buffer == NULL || bytes_written == NULL) {
        return MSG_ERR_INVALID_PARAM;
    }

    uint8_t *plaintext = malloc(MSG_MAX_MESSAGE_SIZE);
    if (!plaintext) return MSG_ERR_SERIALIZE_FAILED;
    size_t plaintext_len;

    int ret = message_serialize(msg, plaintext, MSG_MAX_MESSAGE_SIZE, &plaintext_len);
    if (ret != MSG_OK) {
        free(plaintext);
        return ret;
    }

    buffer[0] = (msg->counter >> 24) & 0xFF;
    buffer[1] = (msg->counter >> 16) & 0xFF;
    buffer[2] = (msg->counter >> 8) & 0xFF;
    buffer[3] = msg->counter & 0xFF;

    size_t ciphertext_len;
    ret = crypto_encrypt_message(
        buffer + 4, &ciphertext_len,
        plaintext, plaintext_len,
        key, msg->counter,
        NULL, 0
    );
    free(plaintext);

    if (ret != CRYPTO_OK) {
        ESP_LOGE(TAG, "Encryption failed: %d", ret);
        return MSG_ERR_SERIALIZE_FAILED;
    }

    *bytes_written = 4 + ciphertext_len;
    return MSG_OK;
}

int message_decrypt(const uint8_t *buffer, size_t buffer_size,
                   const uint8_t key[CRYPTO_KEY_SIZE], message_t *msg) {
    if (buffer == NULL || key == NULL || msg == NULL) {
        return MSG_ERR_INVALID_PARAM;
    }

    if (buffer_size < 4 + CRYPTO_TAG_SIZE) {
        return MSG_ERR_INVALID_PARAM;
    }

    uint32_t counter = ((uint32_t)buffer[0] << 24) |
                       ((uint32_t)buffer[1] << 16) |
                       ((uint32_t)buffer[2] << 8) |
                       (uint32_t)buffer[3];

    uint8_t *plaintext = malloc(MSG_MAX_MESSAGE_SIZE);
    if (!plaintext) return MSG_ERR_DESERIALIZE_FAILED;
    size_t plaintext_len;

    int ret = crypto_decrypt_message(
        plaintext, &plaintext_len,
        buffer + 4, buffer_size - 4,
        key, counter,
        NULL, 0
    );

    if (ret == CRYPTO_ERR_AUTH_FAILED) {
        free(plaintext);
        ESP_LOGE(TAG, "Authentication failed - message tampered or wrong key");
        return MSG_ERR_DESERIALIZE_FAILED;
    } else if (ret != CRYPTO_OK) {
        free(plaintext);
        ESP_LOGE(TAG, "Decryption failed: %d", ret);
        return MSG_ERR_DESERIALIZE_FAILED;
    }

    ret = message_deserialize(plaintext, plaintext_len, msg);
    free(plaintext);
    return ret;
}

int message_create_handshake_init(message_t *msg, const uint8_t public_key[32], uint32_t counter) {
    if (msg == NULL || public_key == NULL) {
        return MSG_ERR_INVALID_PARAM;
    }

    msg->type = MSG_TYPE_HANDSHAKE_INIT;
    msg->counter = counter;
    msg->length = 32;
    memcpy(msg->payload, public_key, 32);

    return MSG_OK;
}

int message_create_handshake_ack(message_t *msg, const uint8_t public_key[32], uint32_t counter) {
    if (msg == NULL || public_key == NULL) {
        return MSG_ERR_INVALID_PARAM;
    }

    msg->type = MSG_TYPE_HANDSHAKE_ACK;
    msg->counter = counter;
    msg->length = 32;
    memcpy(msg->payload, public_key, 32);

    return MSG_OK;
}

int message_create_text(message_t *msg, const char *text, uint32_t counter) {
    if (msg == NULL || text == NULL) {
        return MSG_ERR_INVALID_PARAM;
    }

    size_t text_len = strlen(text);
    if (text_len > MSG_MAX_PAYLOAD_SIZE) {
        return MSG_ERR_TOO_LARGE;
    }

    msg->type = MSG_TYPE_ENCRYPTED_MSG;
    msg->counter = counter;
    msg->length = text_len;
    memcpy(msg->payload, text, text_len);

    return MSG_OK;
}

int message_create_heartbeat(message_t *msg, uint32_t counter) {
    if (msg == NULL) {
        return MSG_ERR_INVALID_PARAM;
    }

    msg->type = MSG_TYPE_HEARTBEAT;
    msg->counter = counter;
    msg->length = 0;

    return MSG_OK;
}

int message_create_disconnect(message_t *msg, uint32_t counter) {
    if (msg == NULL) {
        return MSG_ERR_INVALID_PARAM;
    }

    msg->type = MSG_TYPE_DISCONNECT;
    msg->counter = counter;
    msg->length = 0;

    return MSG_OK;
}

bool message_is_valid_type(uint8_t type) {
    return (type >= MSG_TYPE_HANDSHAKE_INIT && type <= MSG_TYPE_RATCHET_MSG);
}

int message_encrypt_ex(const message_t *msg, const crypto_session_t *session,
                       uint8_t *buffer, size_t buffer_size, size_t *bytes_written) {
    if (msg == NULL || session == NULL || buffer == NULL || bytes_written == NULL) {
        return MSG_ERR_INVALID_PARAM;
    }

    // First serialize to temporary buffer
    uint8_t plaintext[MSG_MAX_MESSAGE_SIZE];
    size_t plaintext_len;

    int ret = message_serialize(msg, plaintext, sizeof(plaintext), &plaintext_len);
    if (ret != MSG_OK) {
        return ret;
    }

    // Encrypt using session_id and counter
    size_t ciphertext_len;
    ret = crypto_encrypt_message_ex(
        buffer, &ciphertext_len,
        plaintext, plaintext_len,
        session->tx_key,
        session->session_id,
        msg->counter,
        NULL, 0
    );

    if (ret != CRYPTO_OK) {
        ESP_LOGE(TAG, "Encryption failed: %d", ret);
        return MSG_ERR_SERIALIZE_FAILED;
    }

    *bytes_written = ciphertext_len;
    return MSG_OK;
}

int message_decrypt_ex(const uint8_t *buffer, size_t buffer_size,
                       crypto_session_t *session, message_t *msg) {
    if (buffer == NULL || session == NULL || msg == NULL) {
        return MSG_ERR_INVALID_PARAM;
    }

    // SECURITY FIX: First decrypt a small header to extract the counter
    // We need to parse the encrypted data structure to get the counter
    // For now, try to decrypt and extract counter from the decrypted message

    // Temporary buffer for decryption
    uint8_t plaintext[MSG_MAX_MESSAGE_SIZE];
    size_t plaintext_len;

    // Try decryption with expected counter (session->rx_counter)
    int ret = crypto_decrypt_message_ex(
        plaintext, &plaintext_len,
        buffer, buffer_size,
        session->rx_key,
        session->session_id,
        session->rx_counter,
        NULL, 0
    );

    // If decryption fails, it might be due to counter mismatch
    // Try a window of counters (replay protection with tolerance)
    if (ret == CRYPTO_ERR_AUTH_FAILED) {
        // Try next few counters in case of packet reordering
        for (uint32_t i = 1; i <= 10; i++) {
            ret = crypto_decrypt_message_ex(
                plaintext, &plaintext_len,
                buffer, buffer_size,
                session->rx_key,
                session->session_id,
                session->rx_counter + i,
                NULL, 0
            );

            if (ret == CRYPTO_OK) {
                ESP_LOGW(TAG, "Message decrypted with counter skew: +%lu", i);
                session->rx_counter += i;
                break;
            }
        }
    }

    if (ret != CRYPTO_OK) {
        if (ret == CRYPTO_ERR_AUTH_FAILED) {
            ESP_LOGE(TAG, "Authentication failed - message tampered or wrong key");
        } else {
            ESP_LOGE(TAG, "Decryption failed: %d", ret);
        }
        return MSG_ERR_DESERIALIZE_FAILED;
    }

    // Deserialize the decrypted message
    ret = message_deserialize(plaintext, plaintext_len, msg);
    if (ret != MSG_OK) {
        return ret;
    }

    // REPLAY PROTECTION: Validate counter
    if (msg->counter < session->rx_counter_max) {
        ESP_LOGW(TAG, "Replay attack detected! Counter %lu < max %lu",
                 msg->counter, session->rx_counter_max);
        return MSG_ERR_DESERIALIZE_FAILED;
    }

    // Update max seen counter
    if (msg->counter > session->rx_counter_max) {
        session->rx_counter_max = msg->counter;
    }

    // Advance expected counter
    session->rx_counter = msg->counter + 1;

    return MSG_OK;
}

int message_ratchet_encrypt(ratchet_state_t *ratchet,
                            const uint8_t *plaintext,
                            size_t plaintext_len,
                            uint8_t *buffer,
                            size_t buffer_size,
                            size_t *bytes_written) {
    if (ratchet == NULL || plaintext == NULL || buffer == NULL || bytes_written == NULL) {
        return MSG_ERR_INVALID_PARAM;
    }

    if (plaintext_len > MSG_MAX_PAYLOAD_SIZE) {
        return MSG_ERR_TOO_LARGE;
    }

    // Need space for: Type(1) + Counter(4) + Length(2) + RatchetHeader(40) + Ciphertext + Tag(16)
    size_t required_size = MSG_HEADER_SIZE + MSG_RATCHET_HEADER_SIZE + plaintext_len + CRYPTO_TAG_SIZE;
    if (buffer_size < required_size) {
        return MSG_ERR_TOO_LARGE;
    }

    // Get ratchet header
    ratchet_header_t ratchet_header;
    if (ratchet_get_send_header(ratchet, &ratchet_header) != RATCHET_OK) {
        ESP_LOGE(TAG, "Failed to get ratchet send header");
        return MSG_ERR_SERIALIZE_FAILED;
    }

    // Encrypt with ratchet
    uint8_t ciphertext[MSG_MAX_PAYLOAD_SIZE + CRYPTO_TAG_SIZE];
    size_t ciphertext_len;

    int ret = ratchet_encrypt(ratchet, plaintext, plaintext_len,
                             &ratchet_header, ciphertext,
                             sizeof(ciphertext), &ciphertext_len);
    if (ret != RATCHET_OK) {
        ESP_LOGE(TAG, "Ratchet encryption failed: %d", ret);
        return MSG_ERR_SERIALIZE_FAILED;
    }

    // Build message: [Type][Counter][Length][RatchetHeader][Ciphertext+Tag]
    size_t offset = 0;

    // Message type
    buffer[offset++] = MSG_TYPE_RATCHET_MSG;

    // Counter (use ratchet counter)
    buffer[offset++] = (ratchet_header.n >> 24) & 0xFF;
    buffer[offset++] = (ratchet_header.n >> 16) & 0xFF;
    buffer[offset++] = (ratchet_header.n >> 8) & 0xFF;
    buffer[offset++] = ratchet_header.n & 0xFF;

    // Payload length (ratchet header + ciphertext)
    uint16_t payload_len = MSG_RATCHET_HEADER_SIZE + ciphertext_len;
    buffer[offset++] = (payload_len >> 8) & 0xFF;
    buffer[offset++] = payload_len & 0xFF;

    // Ratchet header (40 bytes: DH public key + pn + n)
    memcpy(buffer + offset, ratchet_header.dh_public, CRYPTO_PUBLIC_KEY_SIZE);
    offset += CRYPTO_PUBLIC_KEY_SIZE;

    buffer[offset++] = (ratchet_header.pn >> 24) & 0xFF;
    buffer[offset++] = (ratchet_header.pn >> 16) & 0xFF;
    buffer[offset++] = (ratchet_header.pn >> 8) & 0xFF;
    buffer[offset++] = ratchet_header.pn & 0xFF;

    buffer[offset++] = (ratchet_header.n >> 24) & 0xFF;
    buffer[offset++] = (ratchet_header.n >> 16) & 0xFF;
    buffer[offset++] = (ratchet_header.n >> 8) & 0xFF;
    buffer[offset++] = ratchet_header.n & 0xFF;

    // Ciphertext + auth tag
    memcpy(buffer + offset, ciphertext, ciphertext_len);
    offset += ciphertext_len;

    *bytes_written = offset;

    ESP_LOGD(TAG, "Ratchet message encrypted: %zu bytes", offset);
    return MSG_OK;
}

int message_ratchet_decrypt(ratchet_state_t *ratchet,
                            const uint8_t *buffer,
                            size_t buffer_size,
                            uint8_t *plaintext,
                            size_t plaintext_size,
                            size_t *plaintext_len) {
    if (ratchet == NULL || buffer == NULL || plaintext == NULL || plaintext_len == NULL) {
        return MSG_ERR_INVALID_PARAM;
    }

    if (buffer_size < MSG_HEADER_SIZE + MSG_RATCHET_HEADER_SIZE + CRYPTO_TAG_SIZE) {
        return MSG_ERR_DESERIALIZE_FAILED;
    }

    size_t offset = 0;

    // Parse message type
    uint8_t type = buffer[offset++];
    if (type != MSG_TYPE_RATCHET_MSG) {
        ESP_LOGE(TAG, "Invalid ratchet message type: 0x%02x", type);
        return MSG_ERR_INVALID_TYPE;
    }

    // Parse counter (not used for decryption, ratchet handles it)
    offset += 4;

    // Parse payload length
    uint16_t payload_len = ((uint16_t)buffer[offset] << 8) | buffer[offset + 1];
    offset += 2;

    if (buffer_size < MSG_HEADER_SIZE + payload_len) {
        return MSG_ERR_DESERIALIZE_FAILED;
    }

    // Parse ratchet header (40 bytes)
    ratchet_header_t ratchet_header;
    memcpy(ratchet_header.dh_public, buffer + offset, CRYPTO_PUBLIC_KEY_SIZE);
    offset += CRYPTO_PUBLIC_KEY_SIZE;

    ratchet_header.pn = ((uint32_t)buffer[offset] << 24) |
                        ((uint32_t)buffer[offset + 1] << 16) |
                        ((uint32_t)buffer[offset + 2] << 8) |
                        buffer[offset + 3];
    offset += 4;

    ratchet_header.n = ((uint32_t)buffer[offset] << 24) |
                       ((uint32_t)buffer[offset + 1] << 16) |
                       ((uint32_t)buffer[offset + 2] << 8) |
                       buffer[offset + 3];
    offset += 4;

    // Remaining bytes are ciphertext + tag
    size_t ciphertext_len = payload_len - MSG_RATCHET_HEADER_SIZE;
    const uint8_t *ciphertext = buffer + offset;

    // Decrypt with ratchet
    int ret = ratchet_decrypt(ratchet, &ratchet_header,
                             ciphertext, ciphertext_len,
                             plaintext, plaintext_size, plaintext_len);
    if (ret != RATCHET_OK) {
        ESP_LOGE(TAG, "Ratchet decryption failed: %d", ret);
        return MSG_ERR_DESERIALIZE_FAILED;
    }

    ESP_LOGD(TAG, "Ratchet message decrypted: %zu bytes", *plaintext_len);
    return MSG_OK;
}
