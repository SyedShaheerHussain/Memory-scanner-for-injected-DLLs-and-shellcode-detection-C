#include "scanner/msx_shellcode.h"
#include "utils/msx_entropy.h"
#include "utils/msx_log.h"
#include <stdlib.h>
#include <string.h>

void msx_shellcode_config_default(msx_shellcode_config_t *cfg) {
    cfg->entropy_high_threshold = 7.2;
    cfg->nop_sled_min_len = 32;
    cfg->max_bytes_sampled_per_region = 1024 * 1024; /* 1 MB cap per region */
}

static int detect_nop_sled(const uint8_t *buf, size_t len, size_t min_len) {
    size_t run = 0, best = 0;
    for (size_t i = 0; i < len; i++) {
        if (buf[i] == 0x90) { /* x86 NOP opcode; heuristic only, not disassembly */
            run++;
            if (run > best) best = run;
        } else {
            run = 0;
        }
    }
    return best >= min_len;
}

static double zero_byte_ratio(const uint8_t *buf, size_t len) {
    if (len == 0) return 0.0;
    size_t zeros = 0;
    for (size_t i = 0; i < len; i++) if (buf[i] == 0) zeros++;
    return (double)zeros / (double)len;
}

msx_status_t msx_shellcode_scan_process(uint32_t pid,
                                         const msx_shellcode_config_t *cfg_in,
                                         msx_shellcode_finding_list_t *out) {
    if (!out) return MSX_ERR_INVALID_ARG;
    msx_shellcode_finding_list_t_init(out);

    msx_shellcode_config_t cfg;
    if (cfg_in) cfg = *cfg_in; else msx_shellcode_config_default(&cfg);

    msx_region_list_t regions;
    msx_status_t st = msx_memory_enum_regions(pid, &regions);
    if (st != MSX_OK) return st;

    for (size_t i = 0; i < regions.count; i++) {
        msx_memory_region_t *r = &regions.items[i];
        if (!r->executable) continue;

        size_t sample_size = MSX_MIN(r->region_size, cfg.max_bytes_sampled_per_region);
        if (sample_size == 0) continue;

        uint8_t *buf = (uint8_t *)malloc(sample_size);
        if (!buf) continue;

        size_t bytes_read = 0;
        msx_status_t rst = msx_memory_read(pid, r->base_address, buf, sample_size, &bytes_read);
        if (rst != MSX_OK && rst != MSX_ERR_PARTIAL_READ) {
            free(buf);
            continue; /* inaccessible region; skip rather than fabricate a finding */
        }
        if (bytes_read == 0) { free(buf); continue; }

        double entropy = msx_shannon_entropy(buf, bytes_read);
        int nop_sled = detect_nop_sled(buf, bytes_read, cfg.nop_sled_min_len);
        double zero_ratio = zero_byte_ratio(buf, bytes_read);
        int is_anon = (r->type == MSX_REGION_ANONYMOUS) && r->mapped_path[0] == '\0';

        int noteworthy = (entropy >= cfg.entropy_high_threshold) ||
                         nop_sled ||
                         (is_anon && r->executable) ||
                         (zero_ratio > 0.85 && r->executable);

        if (noteworthy) {
            msx_shellcode_finding_t f;
            memset(&f, 0, sizeof(f));
            f.address = r->base_address;
            f.size = r->region_size;
            f.entropy = entropy;
            f.is_anonymous_exec = is_anon;
            f.has_nop_sled = nop_sled;
            f.high_zero_ratio = zero_ratio > 0.85;
            f.no_backing_module = (r->mapped_path[0] == '\0');

            if (is_anon && nop_sled) {
                f.notes = "Anonymous executable region with a long NOP-sled-like byte run";
            } else if (is_anon) {
                f.notes = "Executable memory with no backing file (anonymous mapping)";
            } else if (nop_sled) {
                f.notes = "Long run of 0x90 bytes in executable memory (NOP-sled-like pattern)";
            } else if (entropy >= cfg.entropy_high_threshold) {
                f.notes = "High entropy in executable region; consistent with packed/encrypted "
                           "code but not proof of it";
            } else {
                f.notes = "Unusually high proportion of zero bytes in executable region";
            }

            msx_shellcode_finding_list_t_push(out, f);
        }

        free(buf);
    }

    msx_region_list_t_free(&regions);
    return MSX_OK;
}
