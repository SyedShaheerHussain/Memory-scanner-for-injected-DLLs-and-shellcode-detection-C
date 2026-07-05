/*
 * MemoryScannerX - msx_sha256.h
 * Public-domain-style, dependency-free SHA-256 implementation used when
 * OpenSSL is not available. Read-only hashing utility only.
 */
#ifndef MSX_SHA256_H
#define MSX_SHA256_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t data[64];
    uint32_t datalen;
} msx_sha256_ctx_t;

void msx_sha256_init(msx_sha256_ctx_t *ctx);
void msx_sha256_update(msx_sha256_ctx_t *ctx, const uint8_t *data, size_t len);
void msx_sha256_final(msx_sha256_ctx_t *ctx, uint8_t out_hash[32]);

/* Convenience: hash a full buffer and hex-encode into out_hex[65]. */
void msx_sha256_hex(const uint8_t *data, size_t len, char out_hex[65]);

#ifdef __cplusplus
}
#endif

#endif /* MSX_SHA256_H */
