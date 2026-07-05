/*
 * MemoryScannerX - msx_shellcode.h
 * Static, read-only heuristic analysis of executable memory regions.
 * Never executes, disassembles-to-run, or emulates code; only inspects
 * bytes for statistical/structural anomalies. Conservative by design:
 * findings are signals for analyst review, not proof of maliciousness.
 */
#ifndef MSX_SHELLCODE_H
#define MSX_SHELLCODE_H

#include "utils/msx_common.h"
#include "memory/msx_memory.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uintptr_t address;
    size_t size;
    double entropy;              /* Shannon entropy of the sampled region */
    int is_anonymous_exec;       /* executable + no backing file */
    int has_nop_sled;            /* long run of 0x90 bytes */
    int high_zero_ratio;         /* mostly zero bytes despite being executable */
    int no_backing_module;       /* executable but not attributable to any known module */
    const char *notes;           /* short static explanation string */
} msx_shellcode_finding_t;

MSX_DECLARE_ARRAY(msx_shellcode_finding_list_t, msx_shellcode_finding_t)

typedef struct {
    double entropy_high_threshold;   /* default 7.2 */
    size_t nop_sled_min_len;          /* default 32 */
    size_t max_bytes_sampled_per_region; /* cap to keep scans fast, default 1MB */
} msx_shellcode_config_t;

void msx_shellcode_config_default(msx_shellcode_config_t *cfg);

/* Scans all executable regions of a process for heuristic indicators.
 * Read-only: uses msx_memory_read internally, never writes. */
msx_status_t msx_shellcode_scan_process(uint32_t pid,
                                         const msx_shellcode_config_t *cfg,
                                         msx_shellcode_finding_list_t *out);

#ifdef __cplusplus
}
#endif

#endif /* MSX_SHELLCODE_H */
