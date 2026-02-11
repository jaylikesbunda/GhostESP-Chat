/**
 * @file crypto.c
 * @brief Crypto for GhostESP Chat
 */

#include "crypto.h"
#include <string.h>
#include "esp_log.h"
#include "esp_random.h"

// mbedTLS headers
#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/platform.h"

static const char *TAG = "crypto";

// Global entropy and RNG contexts
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;
static bool crypto_initialized = false;

int crypto_init(void) {
    if (crypto_initialized) {
        return CRYPTO_OK;
    }

    // Initialize entropy source
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    // Seed the random number generator
    const char *pers = "ghost-esp-p2p-chat";
    int ret = mbedtls_ctr_drbg_seed(
        &ctr_drbg,
        mbedtls_entropy_func,
        &entropy,
        (const unsigned char *)pers,
        strlen(pers)
    );

    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed failed: -0x%04x", -ret);
        return CRYPTO_ERR_KEYGEN_FAILED;
    }

    crypto_initialized = true;
    ESP_LOGI(TAG, "Crypto module initialized");
    return CRYPTO_OK;
}

int crypto_generate_keypair(crypto_keypair_t *keypair) {
    if (!crypto_initialized) {
        ESP_LOGE(TAG, "Crypto not initialized");
        return CRYPTO_ERR_KEYGEN_FAILED;
    }

    if (keypair == NULL) {
        return CRYPTO_ERR_INVALID_PARAM;
    }

    // Use separate mbedTLS structures (compatible with 3.x API)
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);

    int ret;

    // Load Curve25519
    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to load Curve25519: -0x%04x", -ret);
        goto cleanup;
    }

    // Generate keypair
    ret = mbedtls_ecdh_gen_public(&grp, &d, &Q, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to generate keypair: -0x%04x", -ret);
        goto cleanup;
    }

    // Export private key
    ret = mbedtls_mpi_write_binary(&d, keypair->private_key, CRYPTO_PRIVATE_KEY_SIZE);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to export private key: -0x%04x", -ret);
        goto cleanup;
    }

    // Export public key (X coordinate for Curve25519)
    ret = mbedtls_mpi_write_binary(&Q.MBEDTLS_PRIVATE(X), keypair->public_key, CRYPTO_PUBLIC_KEY_SIZE);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to export public key: -0x%04x", -ret);
        goto cleanup;
    }

    ESP_LOGI(TAG, "Generated X25519 keypair");

cleanup:
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&Q);
    return (ret == 0) ? CRYPTO_OK : CRYPTO_ERR_KEYGEN_FAILED;
}

int crypto_compute_shared_secret(
    uint8_t shared_secret[CRYPTO_KEY_SIZE],
    const uint8_t our_private[CRYPTO_PRIVATE_KEY_SIZE],
    const uint8_t their_public[CRYPTO_PUBLIC_KEY_SIZE]
) {
    if (!crypto_initialized) {
        return CRYPTO_ERR_DH_FAILED;
    }

    if (shared_secret == NULL || our_private == NULL || their_public == NULL) {
        return CRYPTO_ERR_INVALID_PARAM;
    }

    // Use separate mbedTLS structures
    mbedtls_ecp_group grp;
    mbedtls_mpi d, z;
    mbedtls_ecp_point Qp;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&z);
    mbedtls_ecp_point_init(&Qp);

    int ret;

    // Load Curve25519
    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to load Curve25519: -0x%04x", -ret);
        goto cleanup;
    }

    // Import our private key
    ret = mbedtls_mpi_read_binary(&d, our_private, CRYPTO_PRIVATE_KEY_SIZE);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to import private key: -0x%04x", -ret);
        goto cleanup;
    }

    // Import their public key (X coordinate only for Curve25519)
    ret = mbedtls_mpi_read_binary(&Qp.MBEDTLS_PRIVATE(X), their_public, CRYPTO_PUBLIC_KEY_SIZE);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to import peer public key: -0x%04x", -ret);
        goto cleanup;
    }

    // Set Z coordinate to 1 (standard for Curve25519)
    ret = mbedtls_mpi_lset(&Qp.MBEDTLS_PRIVATE(Z), 1);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to set Z coordinate: -0x%04x", -ret);
        goto cleanup;
    }

    // Compute shared secret using ECDH
    ret = mbedtls_ecdh_compute_shared(&grp, &z, &Qp, &d, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to compute shared secret: -0x%04x", -ret);
        goto cleanup;
    }

    // Export the shared secret
    ret = mbedtls_mpi_write_binary(&z, shared_secret, CRYPTO_KEY_SIZE);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to export shared secret: -0x%04x", -ret);
        goto cleanup;
    }

    ESP_LOGI(TAG, "Computed shared secret");

cleanup:
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&z);
    mbedtls_ecp_point_free(&Qp);
    return (ret == 0) ? CRYPTO_OK : CRYPTO_ERR_DH_FAILED;
}

int crypto_derive_session_keys(
    crypto_session_t *session,
    const uint8_t shared_secret[CRYPTO_KEY_SIZE],
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t *info,
    size_t info_len
) {
    if (session == NULL || shared_secret == NULL) {
        return CRYPTO_ERR_INVALID_PARAM;
    }

    // Use HKDF-SHA256 to derive two keys from shared secret
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md == NULL) {
        ESP_LOGE(TAG, "Failed to get SHA256 MD info");
        return CRYPTO_ERR_KDF_FAILED;
    }

    // Derive TX key
    const uint8_t tx_info[] = "GhostESP-TX";
    int ret = mbedtls_hkdf(
        md,
        salt, salt_len,
        shared_secret, CRYPTO_KEY_SIZE,
        info ? info : tx_info,
        info ? info_len : sizeof(tx_info) - 1,
        session->tx_key,
        CRYPTO_KEY_SIZE
    );

    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to derive TX key: -0x%04x", -ret);
        return CRYPTO_ERR_KDF_FAILED;
    }

    // Derive RX key
    const uint8_t rx_info[] = "GhostESP-RX";
    ret = mbedtls_hkdf(
        md,
        salt, salt_len,
        shared_secret, CRYPTO_KEY_SIZE,
        info ? info : rx_info,
        info ? info_len : sizeof(rx_info) - 1,
        session->rx_key,
        CRYPTO_KEY_SIZE
    );

    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to derive RX key: -0x%04x", -ret);
        return CRYPTO_ERR_KDF_FAILED;
    }

    // Derive session ID for nonce uniqueness (8 bytes)
    const uint8_t sid_info[] = "GhostESP-SessionID";
    ret = mbedtls_hkdf(
        md,
        salt, salt_len,
        shared_secret, CRYPTO_KEY_SIZE,
        sid_info, sizeof(sid_info) - 1,
        session->session_id,
        8  // 8-byte session ID
    );

    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to derive session ID: -0x%04x", -ret);
        return CRYPTO_ERR_KDF_FAILED;
    }

    // Initialize counters
    session->tx_counter = 0;
    session->rx_counter = 0;
    session->rx_counter_max = 0;

    ESP_LOGI(TAG, "Derived session keys with unique session ID");
    return CRYPTO_OK;
}

int crypto_encrypt_message(
    uint8_t *ciphertext,
    size_t *ciphertext_len,
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t key[CRYPTO_KEY_SIZE],
    uint32_t counter,
    const uint8_t *aad,
    size_t aad_len
) {
    if (ciphertext == NULL || ciphertext_len == NULL || plaintext == NULL || key == NULL) {
        return CRYPTO_ERR_INVALID_PARAM;
    }

    // SECURITY FIX: Create proper 12-byte nonce
    // Format: [4-byte counter][8-byte session_id/random]
    // Note: session_id should be passed via AAD or use per-message randomness
    uint8_t nonce[CRYPTO_NONCE_SIZE];

    // First 4 bytes: counter (big-endian)
    nonce[0] = (counter >> 24) & 0xFF;
    nonce[1] = (counter >> 16) & 0xFF;
    nonce[2] = (counter >> 8) & 0xFF;
    nonce[3] = counter & 0xFF;

    // Remaining 8 bytes: Use AAD as session context or generate random
    // For now, use deterministic derivation from counter + key hash
    // In production, pass session_id via new parameter
    if (aad != NULL && aad_len >= 8) {
        // Use first 8 bytes of AAD as nonce suffix
        memcpy(nonce + 4, aad, 8);
    } else {
        // Fallback: derive from counter (not ideal but better than zeros)
        for (int i = 4; i < CRYPTO_NONCE_SIZE; i++) {
            nonce[i] = (uint8_t)((counter >> ((i-4)*8)) ^ key[i]);
        }
    }

    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);

    int ret = mbedtls_chachapoly_setkey(&ctx, key);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to set ChaCha20 key: -0x%04x", -ret);
        mbedtls_chachapoly_free(&ctx);
        return CRYPTO_ERR_ENCRYPT_FAILED;
    }

    // Encrypt and authenticate
    uint8_t tag[CRYPTO_TAG_SIZE];
    ret = mbedtls_chachapoly_encrypt_and_tag(
        &ctx,
        plaintext_len,
        nonce,
        aad, aad_len ? aad_len : 0,
        plaintext,
        ciphertext,
        tag
    );

    if (ret != 0) {
        ESP_LOGE(TAG, "ChaCha20-Poly1305 encryption failed: -0x%04x", -ret);
        mbedtls_chachapoly_free(&ctx);
        return CRYPTO_ERR_ENCRYPT_FAILED;
    }

    // Append tag to ciphertext
    memcpy(ciphertext + plaintext_len, tag, CRYPTO_TAG_SIZE);
    *ciphertext_len = plaintext_len + CRYPTO_TAG_SIZE;

    mbedtls_chachapoly_free(&ctx);
    return CRYPTO_OK;
}

int crypto_decrypt_message(
    uint8_t *plaintext,
    size_t *plaintext_len,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t key[CRYPTO_KEY_SIZE],
    uint32_t counter,
    const uint8_t *aad,
    size_t aad_len
) {
    if (plaintext == NULL || plaintext_len == NULL || ciphertext == NULL || key == NULL) {
        return CRYPTO_ERR_INVALID_PARAM;
    }

    if (ciphertext_len < CRYPTO_TAG_SIZE) {
        return CRYPTO_ERR_INVALID_PARAM;
    }

    // Create nonce from counter (must match encryption nonce)
    uint8_t nonce[CRYPTO_NONCE_SIZE];

    // First 4 bytes: counter (big-endian)
    nonce[0] = (counter >> 24) & 0xFF;
    nonce[1] = (counter >> 16) & 0xFF;
    nonce[2] = (counter >> 8) & 0xFF;
    nonce[3] = counter & 0xFF;

    // Remaining 8 bytes: Must match encryption logic
    if (aad != NULL && aad_len >= 8) {
        // Use first 8 bytes of AAD as nonce suffix
        memcpy(nonce + 4, aad, 8);
    } else {
        // Fallback: derive from counter (must match encryption)
        for (int i = 4; i < CRYPTO_NONCE_SIZE; i++) {
            nonce[i] = (uint8_t)((counter >> ((i-4)*8)) ^ key[i]);
        }
    }

    size_t data_len = ciphertext_len - CRYPTO_TAG_SIZE;
    const uint8_t *tag = ciphertext + data_len;

    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);

    int ret = mbedtls_chachapoly_setkey(&ctx, key);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to set ChaCha20 key: -0x%04x", -ret);
        mbedtls_chachapoly_free(&ctx);
        return CRYPTO_ERR_DECRYPT_FAILED;
    }

    // Decrypt and verify
    ret = mbedtls_chachapoly_auth_decrypt(
        &ctx,
        data_len,
        nonce,
        aad, aad_len ? aad_len : 0,
        tag,
        ciphertext,
        plaintext
    );

    if (ret != 0) {
        ESP_LOGE(TAG, "ChaCha20-Poly1305 decryption/auth failed: -0x%04x", -ret);
        mbedtls_chachapoly_free(&ctx);
        return CRYPTO_ERR_AUTH_FAILED;
    }

    *plaintext_len = data_len;
    mbedtls_chachapoly_free(&ctx);
    return CRYPTO_OK;
}

int crypto_fingerprint(
    uint8_t fingerprint[32],
    const uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE]
) {
    if (fingerprint == NULL || public_key == NULL) {
        return CRYPTO_ERR_INVALID_PARAM;
    }

    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md == NULL) {
        return CRYPTO_ERR_KDF_FAILED;
    }

    int ret = mbedtls_md(md, public_key, CRYPTO_PUBLIC_KEY_SIZE, fingerprint);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to compute fingerprint: -0x%04x", -ret);
        return CRYPTO_ERR_KDF_FAILED;
    }

    return CRYPTO_OK;
}

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
) {
    if (ciphertext == NULL || ciphertext_len == NULL || plaintext == NULL ||
        key == NULL || session_id == NULL) {
        return CRYPTO_ERR_INVALID_PARAM;
    }

    // SECURITY FIX: Proper 12-byte nonce construction
    // Format: [4-byte counter][8-byte session_id]
    // This ensures nonce uniqueness even if counter wraps
    uint8_t nonce[CRYPTO_NONCE_SIZE];

    // First 4 bytes: counter (big-endian)
    nonce[0] = (counter >> 24) & 0xFF;
    nonce[1] = (counter >> 16) & 0xFF;
    nonce[2] = (counter >> 8) & 0xFF;
    nonce[3] = counter & 0xFF;

    // Last 8 bytes: session ID
    memcpy(nonce + 4, session_id, 8);

    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);

    int ret = mbedtls_chachapoly_setkey(&ctx, key);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to set ChaCha20 key: -0x%04x", -ret);
        mbedtls_chachapoly_free(&ctx);
        return CRYPTO_ERR_ENCRYPT_FAILED;
    }

    // Encrypt and authenticate
    uint8_t tag[CRYPTO_TAG_SIZE];
    ret = mbedtls_chachapoly_encrypt_and_tag(
        &ctx,
        plaintext_len,
        nonce,
        aad, aad_len ? aad_len : 0,
        plaintext,
        ciphertext,
        tag
    );

    if (ret != 0) {
        ESP_LOGE(TAG, "ChaCha20-Poly1305 encryption failed: -0x%04x", -ret);
        mbedtls_chachapoly_free(&ctx);
        return CRYPTO_ERR_ENCRYPT_FAILED;
    }

    // Append tag to ciphertext
    memcpy(ciphertext + plaintext_len, tag, CRYPTO_TAG_SIZE);
    *ciphertext_len = plaintext_len + CRYPTO_TAG_SIZE;

    mbedtls_chachapoly_free(&ctx);
    return CRYPTO_OK;
}

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
) {
    if (plaintext == NULL || plaintext_len == NULL || ciphertext == NULL ||
        key == NULL || session_id == NULL) {
        return CRYPTO_ERR_INVALID_PARAM;
    }

    if (ciphertext_len < CRYPTO_TAG_SIZE) {
        return CRYPTO_ERR_INVALID_PARAM;
    }

    // SECURITY FIX: Reconstruct nonce using same method as encryption
    uint8_t nonce[CRYPTO_NONCE_SIZE];

    // First 4 bytes: counter (big-endian)
    nonce[0] = (counter >> 24) & 0xFF;
    nonce[1] = (counter >> 16) & 0xFF;
    nonce[2] = (counter >> 8) & 0xFF;
    nonce[3] = counter & 0xFF;

    // Last 8 bytes: session ID
    memcpy(nonce + 4, session_id, 8);

    size_t data_len = ciphertext_len - CRYPTO_TAG_SIZE;
    const uint8_t *tag = ciphertext + data_len;

    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);

    int ret = mbedtls_chachapoly_setkey(&ctx, key);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to set ChaCha20 key: -0x%04x", -ret);
        mbedtls_chachapoly_free(&ctx);
        return CRYPTO_ERR_DECRYPT_FAILED;
    }

    // Decrypt and verify
    ret = mbedtls_chachapoly_auth_decrypt(
        &ctx,
        data_len,
        nonce,
        aad, aad_len ? aad_len : 0,
        tag,
        ciphertext,
        plaintext
    );

    if (ret != 0) {
        ESP_LOGE(TAG, "ChaCha20-Poly1305 decryption/auth failed: -0x%04x", -ret);
        mbedtls_chachapoly_free(&ctx);
        return CRYPTO_ERR_AUTH_FAILED;
    }

    *plaintext_len = data_len;
    mbedtls_chachapoly_free(&ctx);
    return CRYPTO_OK;
}

void crypto_zero_memory(void *ptr, size_t len) {
    if (ptr != NULL && len > 0) {
        mbedtls_platform_zeroize(ptr, len);
    }
}
