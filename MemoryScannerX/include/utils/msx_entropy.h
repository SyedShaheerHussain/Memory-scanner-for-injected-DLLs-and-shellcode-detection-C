/*
 * MemoryScannerX - msx_entropy.h
 * Shannon entropy calculation over byte buffers. Entropy alone is not
 * evidence of malicious activity; it is one contextual signal among many.
 */
#ifndef MSX_ENTROPY_H
#define MSX_ENTROPY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Returns entropy in bits/byte, range [0.0, 8.0]. Returns 0.0 for empty buf. */
double msx_shannon_entropy(const uint8_t *buf, size_t len);

/* Sliding-window entropy: computes entropy per window and reports the max,
 * useful for finding small packed/encrypted sub-regions inside a larger
 * mostly-normal region. window_size e.g. 256 or 4096. */
double msx_shannon_entropy_max_window(const uint8_t *buf, size_t len, size_t window_size);

#ifdef __cplusplus
}
#endif

#endif /* MSX_ENTROPY_H */
