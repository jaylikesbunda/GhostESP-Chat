/**
 * @file message.h
 * @brief Binary message protocol for GhostESP P2P communication
 *
 * Message Format (binary):
 * ┌──────────┬──────────┬──────────┬──────────────┬─────────────┐
 * │  Type    │  Counter │  Length  │  Ciphertext  │  Auth Tag   │
 * │ (1 byte) │ (4 bytes)│ (2 bytes)│  (N bytes)   │  (16 bytes) │
 * └──────────┴──────────┴──────────┴──────────────┴─────────────┘
 */

#ifndef GHOST_MESSAGE_H
#define GHOST_MESSAGE_H

#include <stdint.h>
#include <stddef.h>
#include "crypto.h"
#include "ratchet.h"

#ifdef __cplusplus
extern "C" {
#endif

// Message types
#define MSG_TYPE_HANDSHAKE_INIT  0x01  // Contains sender's public key
#define MSG_TYPE_HANDSHAKE_ACK   0x02  // Contains sender's public key
#define MSG_TYPE_ENCRYPTED_MSG   0x03  // Encrypted chat message (deprecated - use RATCHET_MSG)
#define MSG_TYPE_HEARTBEAT       0x04  // Keep-alive ping
#define MSG_TYPE_DISCONNECT      0x05  // Clean disconnect
#define MSG_TYPE_RATCHET_MSG     0x06  // Double Ratchet encrypted message

// Message constraints
#define MSG_HEADER_SIZE 7               // Type(1) + Counter(4) + Length(2)
#define MSG_MAX_PAYLOAD_SIZE 4096       // Maximum plaintext payload
#define MSG_MAX_MESSAGE_SIZE (MSG_HEADER_SIZE + MSG_MAX_PAYLOAD_SIZE + CRYPTO_TAG_SIZE)
#define MSG_RATCHET_HEADER_SIZE 40      // DH_PUBLIC(32) + PN(4) + N(4)
#define MSG_MAX_RATCHET_MESSAGE_SIZE (MSG_HEADER_SIZE + MSG_RATCHET_HEADER_SIZE + MSG_MAX_PAYLOAD_SIZE + CRYPTO_TAG_SIZE)

// Error codes
#define MSG_OK 0
#define MSG_ERR_INVALID_PARAM -1
#define MSG_ERR_TOO_LARGE -2
#define MSG_ERR_INVALID_TYPE -3
#define MSG_ERR_SERIALIZE_FAILED -4
#define MSG_ERR_DESERIALIZE_FAILED -5

/**
 * @brief Message structure
 */
typedef struct {
    uint8_t type;                       // Message type
    uint32_t counter;                   // Message counter (for nonce/replay protection)
    uint16_t length;                    // Payload length
    uint8_t payload[MSG_MAX_PAYLOAD_SIZE]; // Payload data
} message_t;

/**
 * @brief Serialize a message into wire format (unencrypted)
 *
 * Used for handshake messages (public key exchange).
 *
 * @param msg Message to serialize
 * @param buffer Output buffer
 * @param buffer_size Size of output buffer
 * @param bytes_written Number of bytes written
 * @return MSG_OK on success, error code otherwise
 */
int message_serialize(const message_t *msg, uint8_t *buffer, size_t buffer_size, size_t *bytes_written);

/**
 * @brief Deserialize a message from wire format (unencrypted)
 *
 * @param buffer Input buffer
 * @param buffer_size Size of input buffer
 * @param msg Output message structure
 * @return MSG_OK on success, error code otherwise
 */
int message_deserialize(const uint8_t *buffer, size_t buffer_size, message_t *msg);

/**
 * @brief Serialize and encrypt a message
 *
 * Creates encrypted wire format suitable for sending over network.
 *
 * @param msg Message to encrypt
 * @param key Encryption key
 * @param buffer Output buffer
 * @param buffer_size Size of output buffer
 * @param bytes_written Number of bytes written (includes auth tag)
 * @return MSG_OK on success, error code otherwise
 */
int message_encrypt(const message_t *msg, const uint8_t key[CRYPTO_KEY_SIZE],
                   uint8_t *buffer, size_t buffer_size, size_t *bytes_written);

/**
 * @brief Decrypt and deserialize a message
 *
 * Verifies authentication tag and decrypts message payload.
 *
 * @param buffer Input encrypted buffer
 * @param buffer_size Size of input buffer
 * @param key Decryption key
 * @param msg Output message structure
 * @return MSG_OK on success, error code otherwise (MSG_ERR_AUTH_FAILED if tampered)
 */
int message_decrypt(const uint8_t *buffer, size_t buffer_size,
                   const uint8_t key[CRYPTO_KEY_SIZE], message_t *msg);

/**
 * @brief Serialize and encrypt a message with session ID (RECOMMENDED)
 *
 * @param msg Message to encrypt
 * @param session Session with keys and session_id
 * @param buffer Output buffer
 * @param buffer_size Size of output buffer
 * @param bytes_written Number of bytes written (includes auth tag)
 * @return MSG_OK on success, error code otherwise
 */
int message_encrypt_ex(const message_t *msg, const crypto_session_t *session,
                       uint8_t *buffer, size_t buffer_size, size_t *bytes_written);

/**
 * @brief Decrypt and validate message with replay protection (RECOMMENDED)
 *
 * @param buffer Input encrypted buffer
 * @param buffer_size Size of input buffer
 * @param session Session with keys and counter tracking
 * @param msg Output message structure
 * @return MSG_OK on success, error code otherwise
 */
int message_decrypt_ex(const uint8_t *buffer, size_t buffer_size,
                       crypto_session_t *session, message_t *msg);

/**
 * @brief Create a handshake init message
 *
 * Contains sender's public key for ECDH.
 *
 * @param msg Output message
 * @param public_key Sender's public key (32 bytes)
 * @param counter Message counter
 * @return MSG_OK on success, error code otherwise
 */
int message_create_handshake_init(message_t *msg, const uint8_t public_key[32], uint32_t counter);

/**
 * @brief Create a handshake ack message
 *
 * @param msg Output message
 * @param public_key Sender's public key (32 bytes)
 * @param counter Message counter
 * @return MSG_OK on success, error code otherwise
 */
int message_create_handshake_ack(message_t *msg, const uint8_t public_key[32], uint32_t counter);

/**
 * @brief Create an encrypted text message
 *
 * @param msg Output message
 * @param text Text content
 * @param counter Message counter
 * @return MSG_OK on success, error code otherwise
 */
int message_create_text(message_t *msg, const char *text, uint32_t counter);

/**
 * @brief Create a heartbeat message
 *
 * @param msg Output message
 * @param counter Message counter
 * @return MSG_OK on success, error code otherwise
 */
int message_create_heartbeat(message_t *msg, uint32_t counter);

/**
 * @brief Create a disconnect message
 *
 * @param msg Output message
 * @param counter Message counter
 * @return MSG_OK on success, error code otherwise
 */
int message_create_disconnect(message_t *msg, uint32_t counter);

/**
 * @brief Validate message type
 *
 * @param type Message type to validate
 * @return true if valid, false otherwise
 */
bool message_is_valid_type(uint8_t type);

/**
 * @brief Encrypt a message with Double Ratchet
 *
 * @param ratchet Ratchet state
 * @param plaintext Plaintext data
 * @param plaintext_len Length of plaintext
 * @param buffer Output buffer
 * @param buffer_size Size of output buffer
 * @param bytes_written Number of bytes written
 * @return MSG_OK on success, error code otherwise
 */
int message_ratchet_encrypt(ratchet_state_t *ratchet,
                            const uint8_t *plaintext,
                            size_t plaintext_len,
                            uint8_t *buffer,
                            size_t buffer_size,
                            size_t *bytes_written);

/**
 * @brief Decrypt a message with Double Ratchet
 *
 * @param ratchet Ratchet state
 * @param buffer Input buffer
 * @param buffer_size Size of input buffer
 * @param plaintext Output plaintext buffer
 * @param plaintext_size Size of plaintext buffer
 * @param plaintext_len Output plaintext length
 * @return MSG_OK on success, error code otherwise
 */
int message_ratchet_decrypt(ratchet_state_t *ratchet,
                            const uint8_t *buffer,
                            size_t buffer_size,
                            uint8_t *plaintext,
                            size_t plaintext_size,
                            size_t *plaintext_len);

#ifdef __cplusplus
}
#endif

#endif // GHOST_MESSAGE_H
