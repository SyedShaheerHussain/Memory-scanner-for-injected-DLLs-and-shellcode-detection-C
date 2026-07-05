/*
 * MemoryScannerX - msx_scan_engine.h
 * Orchestrates process, memory, module, and shellcode analyzers for a
 * single target process and produces a scored, explainable result.
 */
#ifndef MSX_SCAN_ENGINE_H
#define MSX_SCAN_ENGINE_H

#include "utils/msx_common.h"
#include "process/msx_process.h"
#include "memory/msx_memory.h"
#include "scanner/msx_modules.h"
#include "scanner/msx_shellcode.h"
#include "scanner/msx_scoring.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    msx_process_info_t process;
    msx_region_list_t regions;
    msx_module_anomaly_list_t module_anomalies;
    msx_shellcode_finding_list_t shellcode_findings;
    msx_score_report_t score;
    msx_status_t status; /* overall status of the scan attempt */
} msx_scan_result_t;

void msx_scan_result_init(msx_scan_result_t *r);
void msx_scan_result_free(msx_scan_result_t *r);

/* Runs the full defensive analysis pipeline against a single PID:
 *   1. process info
 *   2. memory region enumeration + WX/permission analysis
 *   3. module enumeration + hidden-module consistency check
 *   4. shellcode heuristic scan
 *   5. transparent threat scoring
 * Never modifies the target process. Individual sub-scans that fail due
 * to permissions are recorded but do not abort the whole scan. */
msx_status_t msx_scan_process(uint32_t pid, const msx_score_weights_t *weights,
                               msx_scan_result_t *out);

#ifdef __cplusplus
}
#endif

#endif /* MSX_SCAN_ENGINE_H */
