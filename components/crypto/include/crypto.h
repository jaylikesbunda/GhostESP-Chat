/**
 * @file crypto.h
 * @brief Crypto for GhostESP Chat
 *
 * Implements X25519 (Curve25519) key exchange and ChaCha20-Poly1305 AEAD encryption
 * for end-to-end encrypted peer-to-peer communication.
 */

#ifndef GHOST_CRYPTO_H
#define GHOST_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Key sizes
#define CRYPTO_KEY_SIZE 32          // X25519 and ChaCha20 use 32-byte keys
#define CRYPTO_NONCE_SIZE 12        // ChaCha20-Poly1305 nonce
#define CRYPTO_TAG_SIZE 16          // Poly1305 authentication tag
#define CRYPTO_PUBLIC_KEY_SIZE 32   // X25519 public key
#define CRYPTO_PRIVATE_KEY_SIZE 32  // X25519 private key

// Error codes
#define CRYPTO_OK 0
#define CRYPTO_ERR_INVALID_PARAM -1
#define CRYPTO_ERR_KEYGEN_FAILED -2
#define CRYPTO_ERR_DH_FAILED -3
#define CRYPTO_ERR_KDF_FAILED -4
#define CRYPTO_ERR_ENCRYPT_FAILED -5
#define CRYPTO_ERR_DECRYPT_FAILED -6
#define CRYPTO_ERR_AUTH_FAILED -7

/**
 * @brief Keypair structure for X25519
 */
typedef struct {
    uint8_t private_key[CRYPTO_PRIVATE_KEY_SIZE];
    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];
} crypto_keypair_t;

/**
 * @brief Session keys derived from shared secret
 */
typedef struct {
    uint8_t tx_key[CRYPTO_KEY_SIZE];  // Transmit encryption key
    uint8_t rx_key[CRYPTO_KEY_SIZE];  // Receive encryption key
    uint8_t session_id[8];             // Unique session identifier for nonce
    uint32_t tx_counter;               // Transmit message counter
    uint32_t rx_counter;               // Receive message counter
    uint32_t rx_counter_max;           // Maximum seen counter (replay protection)
} crypto_session_t;

/**
 * @brief Initialize the crypto module
 *
 * Must be called before any other crypto operations.
 *
 * @return CRYPTO_OK on success, error code otherwise
 */
int crypto_init(void);

/**
 * @brief Generate an X25519 keypair
 *
 * @param keypair Pointer to keypair structure to fill
 * @return CRYPTO_OK on success, error code otherwise
 */
int crypto_generate_keypair(crypto_keypair_t *keypair);

/**
 * @brief Compute shared secret using ECDH with X25519
 *
 * @param shared_secret Output buffer for shared secret (32 bytes)
 * @param our_private Our private key
 * @param their_public Their public key
 * @return CRYPTO_OK on success, error code otherwise
 */
int crypto_compute_shared_secret(
    uint8_t shared_secret[CRYPTO_KEY_SIZE],
    const uint8_t our_private[CRYPTO_PRIVATE_KEY_SIZE],
    const uint8_t their_public[CRYPTO_PUBLIC_KEY_SIZE]
);

/**
 * @brief Derive session keys from shared secret using HKDF-SHA256
 *
 * @param session Output session keys structure
 * @param shared_secret Input shared secret (32 bytes)
 * @param salt Optional salt (can be NULL)
 * @param salt_len Length of salt
 * @param info Optional context info (can be NULL)
 * @param info_len Length of info
 * @return CRYPTO_OK on success, error code otherwise
 */
int crypto_derive_session_keys(
    crypto_session_t *session,
    const uint8_t shared_secret[CRYPTO_KEY_SIZE],
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t *info,
    size_t info_len
);

/**
 * @brief Encrypt a message using ChaCha20-Poly1305
 *
 * @param ciphertext Output buffer (must be >= plaintext_len + CRYPTO_TAG_SIZE)
 * @param ciphertext_len Output length of ciphertext + tag
 * @param plaintext Input plaintext message
 * @param plaintext_len Length of plaintext
 * @param key Encryption key (32 bytes)
 * @param counter Message counter (used as part of nonce)
 * @param aad Additional authenticated data (can be NULL)
 * @param aad_len Length of AAD
 * @return CRYPTO_OK on success, error code otherwise
 */
int crypto_encrypt_message(
    uint8_t *ciphertext,
    size_t *ciphertext_len,
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t key[CRYPTO_KEY_SIZE],
    uint32_t counter,
    const uint8_t *aad,
    size_t aad_len
);

/**
 * @brief Encrypt a message with explicit session ID (RECOMMENDED)
 *
 * @param ciphertext Output buffer (must be >= plaintext_len + CRYPTO_TAG_SIZE)
 * @param ciphertext_len Output length of ciphertext + tag
 * @param plaintext Input plaintext message
 * @param plaintext_len Length of plaintext
 * @param key Encryption key (32 bytes)
 * @param session_id Session identifier (8 bytes)
 * @param counter Message counter (used as part of nonce)
 * @param aad Additional authenticated data (can be NULL)
 * @param aad_len Length of AAD
 * @return CRYPTO_OK on success, error code otherwise
 */
int crypto_encrypt_message_ex(
    uint8_t *ciphertext,
    size_t *ciphertext_len,
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t key[CRYPTO_KEY_SIZE],
    const uint8_t session_id[8],
    uint32_t counter,
    const uint8_t *aad,
    size_t aad_len
);

/**
 * @brief Decrypt a message using ChaCha20-Poly1305
 *
 * @param plaintext Output buffer (must be >= ciphertext_len - CRYPTO_TAG_SIZE)
 * @param plaintext_len Output length of plaintext
 * @param ciphertext Input ciphertext + tag
 * @param ciphertext_len Length of ciphertext + tag
 * @param key Decryption key (32 bytes)
 * @param counter Message counter (used as part of nonce)
 * @param aad Additional authenticated data (can be NULL)
 * @param aad_len Length of AAD
 * @return CRYPTO_OK on success, CRYPTO_ERR_AUTH_FAILED if authentication fails
 */
int crypto_decrypt_message(
    uint8_t *plaintext,
    size_t *plaintext_len,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t key[CRYPTO_KEY_SIZE],
    uint32_t counter,
    const uint8_t *aad,
    size_t aad_len
);

/**
 * @brief Decrypt a message with explicit session ID (RECOMMENDED)
 *
 * @param plaintext Output buffer (must be >= ciphertext_len - CRYPTO_TAG_SIZE)
 * @param plaintext_len Output length of plaintext
 * @param ciphertext Input ciphertext + tag
 * @param ciphertext_len Length of ciphertext + tag
 * @param key Decryption key (32 bytes)
 * @param session_id Session identifier (8 bytes)
 * @param counter Message counter (used as part of nonce)
 * @param aad Additional authenticated data (can be NULL)
 * @param aad_len Length of AAD
 * @return CRYPTO_OK on success, CRYPTO_ERR_AUTH_FAILED if authentication fails
 */
int crypto_decrypt_message_ex(
    uint8_t *plaintext,
    size_t *plaintext_len,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t key[CRYPTO_KEY_SIZE],
    const uint8_t session_id[8],
    uint32_t counter,
    const uint8_t *aad,
    size_t aad_len
);

/**
 * @brief Compute SHA256 fingerprint of a public key
 *
 * @param fingerprint Output buffer (32 bytes)
 * @param public_key Input public key (32 bytes)
 * @return CRYPTO_OK on success, error code otherwise
 */
int crypto_fingerprint(
    uint8_t fingerprint[32],
    const uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE]
);

/**
 * @brief Securely zero memory
 *
 * @param ptr Pointer to memory
 * @param len Length to zero
 */
void crypto_zero_memory(void *ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif // GHOST_CRYPTO_H
