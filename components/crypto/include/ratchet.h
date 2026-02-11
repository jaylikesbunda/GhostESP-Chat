/**
 * @file ratchet.h
 * @brief Double Ratchet Algorithm for Forward Secrecy
 *
 * Implements Signal Protocol's Double Ratchet for perfect forward secrecy
 * and post-compromise security.
 *
 * References:
 * - https://signal.org/docs/specifications/doubleratchet/
 * - WhatsApp Security Whitepaper
 */

#ifndef RATCHET_H
#define RATCHET_H

#include <stdint.h>
#include <stdbool.h>
#include "crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

// Return codes
#define RATCHET_OK                  0
#define RATCHET_ERR_INVALID_PARAM  -1
#define RATCHET_ERR_STATE          -2
#define RATCHET_ERR_DECRYPT        -3
#define RATCHET_ERR_TOO_MANY_SKIPPED -4

// Configuration
#define RATCHET_MAX_SKIP 100  // Maximum message keys to skip (prevent DoS)
#define RATCHET_MAX_SKIPPED_KEYS 200  // Maximum skipped keys to store

/**
 * @brief Ratchet state for one direction (sending or receiving)
 */
typedef struct {
    uint8_t chain_key[CRYPTO_KEY_SIZE];   // Chain key (CK)
    uint8_t message_key[CRYPTO_KEY_SIZE]; // Current message key (MK)
    uint32_t counter;                      // Message counter (N)
} ratchet_chain_t;

/**
 * @brief Skipped message key for out-of-order delivery
 */
typedef struct {
    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];  // DH ratchet public key
    uint32_t counter;                              // Message counter
    uint8_t message_key[CRYPTO_KEY_SIZE];        // Saved message key
    bool used;                                     // Whether key has been used
} skipped_key_t;

/**
 * @brief Double Ratchet state
 */
typedef struct {
    // DH Ratchet keys
    crypto_keypair_t dh_self;                     // Our current DH keypair
    uint8_t dh_remote[CRYPTO_PUBLIC_KEY_SIZE];    // Remote's current DH public key

    // Root chain
    uint8_t root_key[CRYPTO_KEY_SIZE];            // Root key (RK)

    // Sending and receiving chains
    ratchet_chain_t send_chain;                   // Sending chain
    ratchet_chain_t recv_chain;                   // Receiving chain

    // State tracking
    uint32_t pn;                                  // Previous chain length
    uint32_t send_counter;                        // Sending counter
    uint32_t recv_counter;                        // Receiving counter

    // Skipped message keys (for out-of-order delivery)
    skipped_key_t skipped_keys[RATCHET_MAX_SKIPPED_KEYS];
    int skipped_key_count;

    // Session info
    uint8_t session_id[8];                        // Unique session identifier
    bool initialized;                             // Whether ratchet is initialized
} ratchet_state_t;

/**
 * @brief Ratchet header sent with each message
 */
typedef struct {
    uint8_t dh_public[CRYPTO_PUBLIC_KEY_SIZE];   // Current DH public key
    uint32_t pn;                                  // Previous chain length
    uint32_t n;                                   // Message counter
} ratchet_header_t;

/**
 * @brief Initialize ratchet as Alice (initiator)
 *
 * @param state Ratchet state to initialize
 * @param shared_secret Initial shared secret from handshake
 * @param remote_public_key Bob's public key
 * @return RATCHET_OK on success
 */
int ratchet_init_alice(ratchet_state_t *state,
                       const uint8_t shared_secret[CRYPTO_KEY_SIZE],
                       const uint8_t remote_public_key[CRYPTO_PUBLIC_KEY_SIZE]);

/**
 * @brief Initialize ratchet as Bob (responder)
 *
 * @param state Ratchet state to initialize
 * @param shared_secret Initial shared secret from handshake
 * @param our_keypair Our DH keypair
 * @return RATCHET_OK on success
 */
int ratchet_init_bob(ratchet_state_t *state,
                     const uint8_t shared_secret[CRYPTO_KEY_SIZE],
                     const crypto_keypair_t *our_keypair);

/**
 * @brief Encrypt message with ratchet
 *
 * @param state Ratchet state
 * @param plaintext Plaintext data
 * @param plaintext_len Length of plaintext
 * @param header Output ratchet header
 * @param ciphertext Output ciphertext buffer
 * @param ciphertext_size Size of ciphertext buffer
 * @param ciphertext_len Output ciphertext length
 * @return RATCHET_OK on success
 */
int ratchet_encrypt(ratchet_state_t *state,
                    const uint8_t *plaintext,
                    size_t plaintext_len,
                    ratchet_header_t *header,
                    uint8_t *ciphertext,
                    size_t ciphertext_size,
                    size_t *ciphertext_len);

/**
 * @brief Decrypt message with ratchet
 *
 * @param state Ratchet state
 * @param header Ratchet header from message
 * @param ciphertext Ciphertext data
 * @param ciphertext_len Length of ciphertext
 * @param plaintext Output plaintext buffer
 * @param plaintext_size Size of plaintext buffer
 * @param plaintext_len Output plaintext length
 * @return RATCHET_OK on success
 */
int ratchet_decrypt(ratchet_state_t *state,
                    const ratchet_header_t *header,
                    const uint8_t *ciphertext,
                    size_t ciphertext_len,
                    uint8_t *plaintext,
                    size_t plaintext_size,
                    size_t *plaintext_len);

/**
 * @brief Perform DH ratchet step (key rotation)
 *
 * Called when receiving a message with a new DH public key
 *
 * @param state Ratchet state
 * @param remote_public_key New remote public key
 * @return RATCHET_OK on success
 */
int ratchet_dh_step(ratchet_state_t *state,
                    const uint8_t remote_public_key[CRYPTO_PUBLIC_KEY_SIZE]);

/**
 * @brief Get current sending header
 *
 * @param state Ratchet state
 * @param header Output header
 * @return RATCHET_OK on success
 */
int ratchet_get_send_header(const ratchet_state_t *state, ratchet_header_t *header);

/**
 * @brief Serialize ratchet state for storage
 *
 * @param state Ratchet state
 * @param buffer Output buffer
 * @param buffer_size Size of buffer
 * @param written Output bytes written
 * @return RATCHET_OK on success
 */
int ratchet_serialize(const ratchet_state_t *state,
                      uint8_t *buffer,
                      size_t buffer_size,
                      size_t *written);

/**
 * @brief Deserialize ratchet state from storage
 *
 * @param state Output ratchet state
 * @param buffer Input buffer
 * @param buffer_size Size of buffer
 * @return RATCHET_OK on success
 */
int ratchet_deserialize(ratchet_state_t *state,
                        const uint8_t *buffer,
                        size_t buffer_size);

/**
 * @brief Clean up ratchet state and zero sensitive data
 *
 * @param state Ratchet state to clean
 */
void ratchet_cleanup(ratchet_state_t *state);

/**
 * @brief Get ratchet statistics
 *
 * @param state Ratchet state
 * @param send_count Output send counter
 * @param recv_count Output receive counter
 * @param skipped_count Output skipped keys count
 */
void ratchet_get_stats(const ratchet_state_t *state,
                       uint32_t *send_count,
                       uint32_t *recv_count,
                       int *skipped_count);

#ifdef __cplusplus
}
#endif

#endif // RATCHET_H
