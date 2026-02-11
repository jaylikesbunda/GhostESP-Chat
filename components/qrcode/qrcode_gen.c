#include "qrcode_gen.h"
#include <string.h>
#include <stdio.h>
#include <esp_log.h>

static const char *TAG = "qrcode";

/**
 * NOTE: This is a stub implementation for Phase 4.
 *
 * For production, integrate qrcodegen library:
 * https://github.com/nayuki/QR-Code-generator
 *
 * The library is public domain and works well on embedded systems.
 */

int qrcode_init(void) {
    ESP_LOGI(TAG, "QR code generator initialized (stub)");
    return 0;
}

int qrcode_generate_text(qrcode_t *qr, const char *text, qr_ecc_level_t ecc_level) {
    if (!qr || !text) {
        return -1;
    }

    // Stub: Create a simple 21x21 QR code (version 1)
    qr->version = 1;
    qr->size = 21;
    qr->ecc_level = ecc_level;

    // Allocate module buffer
    size_t module_bytes = (qr->size * qr->size + 7) / 8;
    qr->modules = malloc(module_bytes);
    if (!qr->modules) {
        ESP_LOGE(TAG, "Failed to allocate QR modules");
        return -1;
    }

    // Fill with pattern (stub - not a real QR code)
    memset(qr->modules, 0xAA, module_bytes);

    ESP_LOGI(TAG, "Generated QR code stub for: %.30s... (size: %dx%d)",
             text, qr->size, qr->size);

    return 0;
}

int qrcode_render_ascii(const qrcode_t *qr, char *buffer, size_t buffer_size) {
    if (!qr || !buffer || buffer_size == 0) {
        return -1;
    }

    char *ptr = buffer;
    size_t remaining = buffer_size;

    // Title
    int written = snprintf(ptr, remaining,
                          "QR Code Stub (%dx%d)\n"
                          "===================\n",
                          qr->size, qr->size);
    if (written < 0 || written >= remaining) return -1;
    ptr += written;
    remaining -= written;

    // Simple ASCII representation
    for (int y = 0; y < qr->size && remaining > 2; y++) {
        for (int x = 0; x < qr->size && remaining > 2; x++) {
            bool module = qrcode_get_module(qr, x, y);
            *ptr++ = module ? '█' : ' ';
            remaining--;
        }
        *ptr++ = '\n';
        remaining--;
    }

    written = snprintf(ptr, remaining,
                      "===================\n"
                      "Note: Stub QR code\n");
    if (written < 0 || written >= remaining) return -1;
    ptr += written;

    return (ptr - buffer);
}

int qrcode_render_svg(const qrcode_t *qr, char *buffer, size_t buffer_size, int module_size) {
    if (!qr || !buffer || buffer_size == 0) {
        return -1;
    }

    char *ptr = buffer;
    size_t remaining = buffer_size;

    int img_size = qr->size * module_size;

    // SVG header
    int written = snprintf(ptr, remaining,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<svg xmlns=\"http://www.w3.org/2000/svg\" version=\"1.1\" "
        "viewBox=\"0 0 %d %d\" stroke=\"none\">\n"
        "<rect width=\"100%%\" height=\"100%%\" fill=\"#FFFFFF\"/>\n"
        "<g fill=\"#000000\">\n",
        img_size, img_size);

    if (written < 0 || written >= remaining) return -1;
    ptr += written;
    remaining -= written;

    // Render modules as rectangles
    for (int y = 0; y < qr->size; y++) {
        for (int x = 0; x < qr->size; x++) {
            if (qrcode_get_module(qr, x, y)) {
                written = snprintf(ptr, remaining,
                    "<rect x=\"%d\" y=\"%d\" width=\"%d\" height=\"%d\"/>\n",
                    x * module_size, y * module_size, module_size, module_size);

                if (written < 0 || written >= remaining) return -1;
                ptr += written;
                remaining -= written;
            }
        }
    }

    // SVG footer
    written = snprintf(ptr, remaining,
        "</g>\n"
        "<text x=\"%d\" y=\"%d\" font-family=\"monospace\" font-size=\"8\" fill=\"red\">"
        "STUB</text>\n"
        "</svg>\n",
        img_size / 2 - 10, img_size + 10);

    if (written < 0 || written >= remaining) return -1;
    ptr += written;

    return (ptr - buffer);
}

bool qrcode_get_module(const qrcode_t *qr, int x, int y) {
    if (!qr || !qr->modules || x < 0 || x >= qr->size || y < 0 || y >= qr->size) {
        return false;
    }

    // Get bit from modules array
    int index = y * qr->size + x;
    int byte_idx = index / 8;
    int bit_idx = index % 8;

    return (qr->modules[byte_idx] & (1 << bit_idx)) != 0;
}

void qrcode_free(qrcode_t *qr) {
    if (qr && qr->modules) {
        free(qr->modules);
        qr->modules = NULL;
    }
}
