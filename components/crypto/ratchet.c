/**
 * @file ratchet.c
 * @brief Double Ratchet implementation
 */

#include "ratchet.h"
#include <string.h>
#include "esp_log.h"
#include "esp_random.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"

static const char *TAG = "ratchet";

// KDF constants
static const uint8_t KDF_RK_INFO[] = "RatchetRootKey";
static const uint8_t KDF_CK_INFO[] = "RatchetChainKey";

// Forward declarations
static int kdf_rk(const uint8_t root_key[CRYPTO_KEY_SIZE],
                  const uint8_t dh_output[CRYPTO_KEY_SIZE],
                  uint8_t new_root_key[CRYPTO_KEY_SIZE],
                  uint8_t new_chain_key[CRYPTO_KEY_SIZE]);

static int kdf_ck(const uint8_t chain_key[CRYPTO_KEY_SIZE],
                  uint8_t new_chain_key[CRYPTO_KEY_SIZE],
                  uint8_t message_key[CRYPTO_KEY_SIZE]);

static int try_skipped_message_keys(ratchet_state_t *state,
                                    const ratchet_header_t *header,
                                    const uint8_t *ciphertext,
                                    size_t ciphertext_len,
                                    uint8_t *plaintext,
                                    size_t plaintext_size,
                                    size_t *plaintext_len);

static int skip_message_keys(ratchet_state_t *state, uint32_t until);

static void store_skipped_key(ratchet_state_t *state,
                              const uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE],
                              uint32_t counter,
                              const uint8_t message_key[CRYPTO_KEY_SIZE]);

int ratchet_init_alice(ratchet_state_t *state,
                       const uint8_t shared_secret[CRYPTO_KEY_SIZE],
                       const uint8_t remote_public_key[CRYPTO_PUBLIC_KEY_SIZE]) {
    if (state == NULL || shared_secret == NULL || remote_public_key == NULL) {
        return RATCHET_ERR_INVALID_PARAM;
    }

    memset(state, 0, sizeof(ratchet_state_t));

    // Generate our DH keypair
    if (crypto_generate_keypair(&state->dh_self) != CRYPTO_OK) {
        ESP_LOGE(TAG, "Failed to generate DH keypair");
        return RATCHET_ERR_STATE;
    }

    // Store remote public key
    memcpy(state->dh_remote, remote_public_key, CRYPTO_PUBLIC_KEY_SIZE);

    // Initialize root key from shared secret
    memcpy(state->root_key, shared_secret, CRYPTO_KEY_SIZE);

    // Perform initial DH ratchet
    uint8_t dh_output[CRYPTO_KEY_SIZE];
    if (crypto_compute_shared_secret(dh_output,
                                    state->dh_self.private_key,
                                    remote_public_key) != CRYPTO_OK) {
        ESP_LOGE(TAG, "Failed to compute initial DH");
        return RATCHET_ERR_STATE;
    }

    // Derive initial sending chain
    if (kdf_rk(state->root_key, dh_output,
              state->root_key, state->send_chain.chain_key) != RATCHET_OK) {
        ESP_LOGE(TAG, "Failed to derive initial chain");
        crypto_zero_memory(dh_output, sizeof(dh_output));
        return RATCHET_ERR_STATE;
    }

    crypto_zero_memory(dh_output, sizeof(dh_output));

    // Derive session ID from shared secret (both sides must have same session_id)
    memcpy(state->session_id, shared_secret, 8);

    state->send_counter = 0;
    state->recv_counter = 0;
    state->pn = 0;
    state->initialized = true;

    ESP_LOGI(TAG, "Ratchet initialized (Alice/initiator)");
    return RATCHET_OK;
}

int ratchet_init_bob(ratchet_state_t *state,
                     const uint8_t shared_secret[CRYPTO_KEY_SIZE],
                     const crypto_keypair_t *our_keypair) {
    if (state == NULL || shared_secret == NULL || our_keypair == NULL) {
        return RATCHET_ERR_INVALID_PARAM;
    }

    memset(state, 0, sizeof(ratchet_state_t));

    // Copy our DH keypair
    memcpy(&state->dh_self, our_keypair, sizeof(crypto_keypair_t));

    // Initialize root key from shared secret
    memcpy(state->root_key, shared_secret, CRYPTO_KEY_SIZE);

    // Derive session ID from shared secret (both sides must have same session_id)
    memcpy(state->session_id, shared_secret, 8);

    state->send_counter = 0;
    state->recv_counter = 0;
    state->pn = 0;
    state->initialized = true;

    ESP_LOGI(TAG, "Ratchet initialized (Bob/responder)");
    return RATCHET_OK;
}

int ratchet_encrypt(ratchet_state_t *state,
                    const uint8_t *plaintext,
                    size_t plaintext_len,
                    ratchet_header_t *header,
                    uint8_t *ciphertext,
                    size_t ciphertext_size,
                    size_t *ciphertext_len) {
    if (!state->initialized || plaintext == NULL || header == NULL ||
        ciphertext == NULL || ciphertext_len == NULL) {
        return RATCHET_ERR_INVALID_PARAM;
    }

    // Derive message key from sending chain
    uint8_t message_key[CRYPTO_KEY_SIZE];
    if (kdf_ck(state->send_chain.chain_key,
              state->send_chain.chain_key,
              message_key) != RATCHET_OK) {
        return RATCHET_ERR_STATE;
    }

    // Create header
    memcpy(header->dh_public, state->dh_self.public_key, CRYPTO_PUBLIC_KEY_SIZE);
    header->pn = state->pn;
    header->n = state->send_counter;

    // Encrypt message (use header->n for consistency with decrypt)
    int ret = crypto_encrypt_message_ex(ciphertext, ciphertext_len,
                                       plaintext, plaintext_len,
                                       message_key,
                                       state->session_id,
                                       header->n,
                                       (uint8_t*)header, sizeof(ratchet_header_t));

    crypto_zero_memory(message_key, sizeof(message_key));

    if (ret != CRYPTO_OK) {
        ESP_LOGE(TAG, "Encryption failed");
        return RATCHET_ERR_STATE;
    }

    state->send_counter++;

    ESP_LOGD(TAG, "Ratchet encrypt: counter=%lu", state->send_counter - 1);
    return RATCHET_OK;
}

int ratchet_decrypt(ratchet_state_t *state,
                    const ratchet_header_t *header,
                    const uint8_t *ciphertext,
                    size_t ciphertext_len,
                    uint8_t *plaintext,
                    size_t plaintext_size,
                    size_t *plaintext_len) {
    if (!state->initialized || header == NULL || ciphertext == NULL ||
        plaintext == NULL || plaintext_len == NULL) {
        return RATCHET_ERR_INVALID_PARAM;
    }

    // Try skipped message keys first (for out-of-order delivery)
    int ret = try_skipped_message_keys(state, header, ciphertext, ciphertext_len,
                                      plaintext, plaintext_size, plaintext_len);
    if (ret == RATCHET_OK) {
        ESP_LOGI(TAG, "Decrypted with skipped key");
        return RATCHET_OK;
    }

    // Check if we need to perform DH ratchet
    if (memcmp(header->dh_public, state->dh_remote, CRYPTO_PUBLIC_KEY_SIZE) != 0) {
        ESP_LOGI(TAG, "Performing DH ratchet step");

        // Skip message keys from old chain
        if (skip_message_keys(state, header->pn) != RATCHET_OK) {
            ESP_LOGE(TAG, "Failed to skip message keys");
            return RATCHET_ERR_STATE;
        }

        // Perform DH ratchet
        if (ratchet_dh_step(state, header->dh_public) != RATCHET_OK) {
            ESP_LOGE(TAG, "DH ratchet step failed");
            return RATCHET_ERR_STATE;
        }
    }

    // Skip message keys up to current message
    if (skip_message_keys(state, header->n) != RATCHET_OK) {
        ESP_LOGE(TAG, "Failed to skip to current message");
        return RATCHET_ERR_STATE;
    }

    // Derive message key
    uint8_t message_key[CRYPTO_KEY_SIZE];
    if (kdf_ck(state->recv_chain.chain_key,
              state->recv_chain.chain_key,
              message_key) != RATCHET_OK) {
        return RATCHET_ERR_STATE;
    }

    // Decrypt message
    ret = crypto_decrypt_message_ex(plaintext, plaintext_len,
                                   ciphertext, ciphertext_len,
                                   message_key,
                                   state->session_id,
                                   header->n,
                                   (uint8_t*)header, sizeof(ratchet_header_t));

    crypto_zero_memory(message_key, sizeof(message_key));

    if (ret != CRYPTO_OK) {
        ESP_LOGE(TAG, "Decryption failed");
        return RATCHET_ERR_DECRYPT;
    }

    state->recv_counter = header->n + 1;

    ESP_LOGD(TAG, "Ratchet decrypt: counter=%lu", header->n);
    return RATCHET_OK;
}

int ratchet_dh_step(ratchet_state_t *state,
                    const uint8_t remote_public_key[CRYPTO_PUBLIC_KEY_SIZE]) {
    if (!state->initialized || remote_public_key == NULL) {
        return RATCHET_ERR_INVALID_PARAM;
    }

    // Save previous chain length
    state->pn = state->send_counter;

    // Update remote public key
    memcpy(state->dh_remote, remote_public_key, CRYPTO_PUBLIC_KEY_SIZE);

    // Compute DH output for receiving chain
    uint8_t dh_output[CRYPTO_KEY_SIZE];
    if (crypto_compute_shared_secret(dh_output,
                                    state->dh_self.private_key,
                                    remote_public_key) != CRYPTO_OK) {
        return RATCHET_ERR_STATE;
    }

    // Derive receiving chain key
    if (kdf_rk(state->root_key, dh_output,
              state->root_key, state->recv_chain.chain_key) != RATCHET_OK) {
        crypto_zero_memory(dh_output, sizeof(dh_output));
        return RATCHET_ERR_STATE;
    }

    state->recv_counter = 0;

    // Generate new DH keypair
    if (crypto_generate_keypair(&state->dh_self) != CRYPTO_OK) {
        crypto_zero_memory(dh_output, sizeof(dh_output));
        return RATCHET_ERR_STATE;
    }

    // Compute DH output for sending chain
    if (crypto_compute_shared_secret(dh_output,
                                    state->dh_self.private_key,
                                    remote_public_key) != CRYPTO_OK) {
        return RATCHET_ERR_STATE;
    }

    // Derive sending chain key
    if (kdf_rk(state->root_key, dh_output,
              state->root_key, state->send_chain.chain_key) != RATCHET_OK) {
        crypto_zero_memory(dh_output, sizeof(dh_output));
        return RATCHET_ERR_STATE;
    }

    crypto_zero_memory(dh_output, sizeof(dh_output));

    state->send_counter = 0;

    ESP_LOGI(TAG, "DH ratchet step complete");
    return RATCHET_OK;
}

int ratchet_get_send_header(const ratchet_state_t *state, ratchet_header_t *header) {
    if (state == NULL || header == NULL || !state->initialized) {
        return RATCHET_ERR_INVALID_PARAM;
    }

    // Copy current DH public key
    memcpy(header->dh_public, state->dh_self.public_key, CRYPTO_PUBLIC_KEY_SIZE);
    
    // Set previous chain length and current message counter
    header->pn = state->pn;
    header->n = state->send_counter;

    return RATCHET_OK;
}

void ratchet_cleanup(ratchet_state_t *state) {
    if (state != NULL) {
        crypto_zero_memory(state, sizeof(ratchet_state_t));
    }
}

void ratchet_get_stats(const ratchet_state_t *state,
                       uint32_t *send_count,
                       uint32_t *recv_count,
                       int *skipped_count) {
    if (state == NULL) return;

    if (send_count) *send_count = state->send_counter;
    if (recv_count) *recv_count = state->recv_counter;
    if (skipped_count) *skipped_count = state->skipped_key_count;
}

// Private functions

static int kdf_rk(const uint8_t root_key[CRYPTO_KEY_SIZE],
                  const uint8_t dh_output[CRYPTO_KEY_SIZE],
                  uint8_t new_root_key[CRYPTO_KEY_SIZE],
                  uint8_t new_chain_key[CRYPTO_KEY_SIZE]) {
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md == NULL) return RATCHET_ERR_STATE;

    uint8_t output[CRYPTO_KEY_SIZE * 2];

    int ret = mbedtls_hkdf(md,
                          root_key, CRYPTO_KEY_SIZE,
                          dh_output, CRYPTO_KEY_SIZE,
                          KDF_RK_INFO, sizeof(KDF_RK_INFO) - 1,
                          output, sizeof(output));

    if (ret != 0) {
        ESP_LOGE(TAG, "KDF_RK failed: -0x%04x", -ret);
        return RATCHET_ERR_STATE;
    }

    memcpy(new_root_key, output, CRYPTO_KEY_SIZE);
    memcpy(new_chain_key, output + CRYPTO_KEY_SIZE, CRYPTO_KEY_SIZE);

    crypto_zero_memory(output, sizeof(output));
    return RATCHET_OK;
}

static int kdf_ck(const uint8_t chain_key[CRYPTO_KEY_SIZE],
                  uint8_t new_chain_key[CRYPTO_KEY_SIZE],
                  uint8_t message_key[CRYPTO_KEY_SIZE]) {
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md == NULL) return RATCHET_ERR_STATE;

    uint8_t output[CRYPTO_KEY_SIZE * 2];

    int ret = mbedtls_hkdf(md,
                          NULL, 0,  // No salt
                          chain_key, CRYPTO_KEY_SIZE,
                          KDF_CK_INFO, sizeof(KDF_CK_INFO) - 1,
                          output, sizeof(output));

    if (ret != 0) {
        ESP_LOGE(TAG, "KDF_CK failed: -0x%04x", -ret);
        return RATCHET_ERR_STATE;
    }

    memcpy(new_chain_key, output, CRYPTO_KEY_SIZE);
    memcpy(message_key, output + CRYPTO_KEY_SIZE, CRYPTO_KEY_SIZE);

    crypto_zero_memory(output, sizeof(output));
    return RATCHET_OK;
}

static int try_skipped_message_keys(ratchet_state_t *state,
                                    const ratchet_header_t *header,
                                    const uint8_t *ciphertext,
                                    size_t ciphertext_len,
                                    uint8_t *plaintext,
                                    size_t plaintext_size,
                                    size_t *plaintext_len) {
    for (int i = 0; i < state->skipped_key_count; i++) {
        skipped_key_t *sk = &state->skipped_keys[i];

        if (!sk->used &&
            memcmp(sk->public_key, header->dh_public, CRYPTO_PUBLIC_KEY_SIZE) == 0 &&
            sk->counter == header->n) {

            int ret = crypto_decrypt_message_ex(plaintext, plaintext_len,
                                               ciphertext, ciphertext_len,
                                               sk->message_key,
                                               state->session_id,
                                               header->n,
                                               (uint8_t*)header, sizeof(ratchet_header_t));

            if (ret == CRYPTO_OK) {
                sk->used = true;
                crypto_zero_memory(sk->message_key, CRYPTO_KEY_SIZE);
                return RATCHET_OK;
            }
        }
    }

    return RATCHET_ERR_DECRYPT;
}

static int skip_message_keys(ratchet_state_t *state, uint32_t until) {
    if (state->recv_counter + RATCHET_MAX_SKIP < until) {
        ESP_LOGE(TAG, "Too many skipped keys: %lu", until - state->recv_counter);
        return RATCHET_ERR_TOO_MANY_SKIPPED;
    }

    while (state->recv_counter < until) {
        uint8_t message_key[CRYPTO_KEY_SIZE];

        if (kdf_ck(state->recv_chain.chain_key,
                  state->recv_chain.chain_key,
                  message_key) != RATCHET_OK) {
            return RATCHET_ERR_STATE;
        }

        store_skipped_key(state, state->dh_remote, state->recv_counter, message_key);
        crypto_zero_memory(message_key, sizeof(message_key));

        state->recv_counter++;
    }

    return RATCHET_OK;
}

static void store_skipped_key(ratchet_state_t *state,
                              const uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE],
                              uint32_t counter,
                              const uint8_t message_key[CRYPTO_KEY_SIZE]) {
    if (state->skipped_key_count >= RATCHET_MAX_SKIPPED_KEYS) {
        // Find oldest used key to replace
        for (int i = 0; i < RATCHET_MAX_SKIPPED_KEYS; i++) {
            if (state->skipped_keys[i].used) {
                crypto_zero_memory(&state->skipped_keys[i], sizeof(skipped_key_t));
                state->skipped_key_count--;
                break;
            }
        }

        if (state->skipped_key_count >= RATCHET_MAX_SKIPPED_KEYS) {
            ESP_LOGW(TAG, "Skipped key storage full, dropping oldest");
            crypto_zero_memory(&state->skipped_keys[0], sizeof(skipped_key_t));
            memmove(&state->skipped_keys[0], &state->skipped_keys[1],
                   (RATCHET_MAX_SKIPPED_KEYS - 1) * sizeof(skipped_key_t));
            state->skipped_key_count--;
        }
    }

    skipped_key_t *sk = &state->skipped_keys[state->skipped_key_count];
    memcpy(sk->public_key, public_key, CRYPTO_PUBLIC_KEY_SIZE);
    sk->counter = counter;
    memcpy(sk->message_key, message_key, CRYPTO_KEY_SIZE);
    sk->used = false;

    state->skipped_key_count++;
}
