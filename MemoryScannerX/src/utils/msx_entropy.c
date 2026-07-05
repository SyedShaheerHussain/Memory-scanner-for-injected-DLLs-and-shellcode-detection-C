#include "utils/msx_entropy.h"
#include <math.h>
#include <string.h>

double msx_shannon_entropy(const uint8_t *buf, size_t len) {
    if (!buf || len == 0) return 0.0;

    size_t freq[256];
    memset(freq, 0, sizeof(freq));
    for (size_t i = 0; i < len; i++) {
        freq[buf[i]]++;
    }

    double entropy = 0.0;
    double dlen = (double)len;
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        double p = (double)freq[i] / dlen;
        entropy -= p * log2(p);
    }
    return entropy;
}

double msx_shannon_entropy_max_window(const uint8_t *buf, size_t len, size_t window_size) {
    if (!buf || len == 0 || window_size == 0) return 0.0;
    if (window_size >= len) return msx_shannon_entropy(buf, len);

    double max_entropy = 0.0;
    /* Step by window_size (non-overlapping) to keep this O(n) rather than
     * O(n*window) — sufficient for coarse packed-region detection. */
    for (size_t off = 0; off + window_size <= len; off += window_size) {
        double e = msx_shannon_entropy(buf + off, window_size);
        if (e > max_entropy) max_entropy = e;
    }
    return max_entropy;
}
