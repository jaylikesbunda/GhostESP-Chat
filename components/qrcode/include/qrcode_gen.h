#ifndef QRCODE_GEN_H
#define QRCODE_GEN_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * QR Code error levels
 */
typedef enum {
    QR_ECC_LOW = 0,      // ~7% error correction
    QR_ECC_MEDIUM,       // ~15% error correction
    QR_ECC_QUARTILE,     // ~25% error correction
    QR_ECC_HIGH          // ~30% error correction
} qr_ecc_level_t;

/**
 * Maximum QR code size
 */
#define QR_MAX_VERSION 40
#define QR_MAX_SIZE ((QR_MAX_VERSION * 4) + 17)

/**
 * QR code structure
 */
typedef struct {
    uint8_t version;           // QR version (1-40)
    uint8_t size;              // Module size (version*4 + 17)
    qr_ecc_level_t ecc_level;  // Error correction level
    uint8_t *modules;          // Module data (size*size bits)
} qrcode_t;

/**
 * Initialize QR code generator
 *
 * @return 0 on success, -1 on error
 */
int qrcode_init(void);

/**
 * Generate QR code from text
 *
 * @param qr Output QR code structure (must allocate modules buffer)
 * @param text Input text to encode
 * @param ecc_level Error correction level
 * @return 0 on success, -1 on error
 */
int qrcode_generate_text(qrcode_t *qr, const char *text, qr_ecc_level_t ecc_level);

/**
 * Render QR code as ASCII art
 *
 * @param qr QR code structure
 * @param buffer Output buffer
 * @param buffer_size Size of output buffer
 * @return Number of bytes written, -1 on error
 */
int qrcode_render_ascii(const qrcode_t *qr, char *buffer, size_t buffer_size);

/**
 * Render QR code as SVG
 *
 * @param qr QR code structure
 * @param buffer Output buffer
 * @param buffer_size Size of output buffer
 * @param module_size Size of each module in pixels
 * @return Number of bytes written, -1 on error
 */
int qrcode_render_svg(const qrcode_t *qr, char *buffer, size_t buffer_size, int module_size);

/**
 * Get module value at (x, y)
 *
 * @param qr QR code structure
 * @param x X coordinate
 * @param y Y coordinate
 * @return true if module is dark, false if light
 */
bool qrcode_get_module(const qrcode_t *qr, int x, int y);

/**
 * Free QR code resources
 *
 * @param qr QR code structure
 */
void qrcode_free(qrcode_t *qr);

#ifdef __cplusplus
}
#endif

#endif // QRCODE_GEN_H
