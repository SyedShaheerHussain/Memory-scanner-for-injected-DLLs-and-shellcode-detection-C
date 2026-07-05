#include "scanner/msx_scan_engine.h"
#include "utils/msx_log.h"
#include <string.h>

void msx_scan_result_init(msx_scan_result_t *r) {
    memset(&r->process, 0, sizeof(r->process));
    msx_region_list_t_init(&r->regions);
    msx_module_anomaly_list_t_init(&r->module_anomalies);
    msx_shellcode_finding_list_t_init(&r->shellcode_findings);
    msx_score_report_init(&r->score);
    r->status = MSX_OK;
}

void msx_scan_result_free(msx_scan_result_t *r) {
    msx_region_list_t_free(&r->regions);
    msx_module_anomaly_list_t_free(&r->module_anomalies);
    msx_shellcode_finding_list_t_free(&r->shellcode_findings);
    msx_score_report_free(&r->score);
}

msx_status_t msx_scan_process(uint32_t pid, const msx_score_weights_t *weights_in,
                               msx_scan_result_t *out) {
    if (!out) return MSX_ERR_INVALID_ARG;
    msx_scan_result_init(out);

    msx_score_weights_t weights;
    if (weights_in) weights = *weights_in; else msx_score_weights_default(&weights);

    msx_status_t pst = msx_process_get_info(pid, &out->process);
    if (pst != MSX_OK) {
        out->status = pst;
        return pst; /* can't do anything meaningful without basic process info */
    }

    /* --- Memory region + permission analysis --- */
    msx_status_t mst = msx_memory_enum_regions(pid, &out->regions);
    if (mst == MSX_OK) {
        for (size_t i = 0; i < out->regions.count; i++) {
            msx_memory_region_t *r = &out->regions.items[i];
            if (msx_memory_region_is_wx(r)) {
                const char *ctx = "unknown mapping";
                switch (r->type) {
                    case MSX_REGION_HEAP: ctx = "heap"; break;
                    case MSX_REGION_STACK: ctx = "stack"; break;
                    case MSX_REGION_ANONYMOUS: ctx = "anonymous mapping"; break;
                    case MSX_REGION_IMAGE: ctx = "executable image"; break;
                    case MSX_REGION_MAPPED_FILE: ctx = "mapped file"; break;
                    case MSX_REGION_SHARED_MEMORY: ctx = "shared memory"; break;
                    default: break;
                }
                msx_score_add(&out->score, weights.weight_wx_region,
                              "Writable+executable %s region at 0x%lx (size %zu)",
                              ctx, (unsigned long)r->base_address, r->region_size);
            } else if (r->executable && r->type == MSX_REGION_ANONYMOUS) {
                msx_score_add(&out->score, weights.weight_anon_exec,
                              "Executable anonymous region at 0x%lx (no backing file)",
                              (unsigned long)r->base_address);
            }
        }
    } else {
        MSX_LOG_WARN("Memory region enumeration failed for pid %u: %s",
                     pid, msx_status_str(mst));
    }

    /* --- Module anomaly / hidden module consistency check --- */
    msx_status_t anst = msx_modules_find_anomalies(pid, &out->module_anomalies);
    if (anst == MSX_OK) {
        for (size_t i = 0; i < out->module_anomalies.count; i++) {
            msx_module_anomaly_t *a = &out->module_anomalies.items[i];
            int pts = (strstr(a->reason, "deleted") != NULL)
                          ? weights.weight_deleted_backing_file
                          : weights.weight_module_anomaly;
            msx_score_add(&out->score, pts, "%s (%s)", a->reason, a->path);
        }
    } else {
        MSX_LOG_WARN("Module anomaly detection failed for pid %u: %s",
                     pid, msx_status_str(anst));
    }

    /* --- Shellcode heuristic scan --- */
    msx_shellcode_config_t sc_cfg;
    msx_shellcode_config_default(&sc_cfg);
    msx_status_t scst = msx_shellcode_scan_process(pid, &sc_cfg, &out->shellcode_findings);
    if (scst == MSX_OK) {
        for (size_t i = 0; i < out->shellcode_findings.count; i++) {
            msx_shellcode_finding_t *f = &out->shellcode_findings.items[i];
            int pts = f->has_nop_sled ? weights.weight_shellcode_nop_sled
                                       : weights.weight_high_entropy;
            msx_score_add(&out->score, pts,
                          "%s at 0x%lx (entropy=%.2f)",
                          f->notes, (unsigned long)f->address, f->entropy);
        }
    } else {
        MSX_LOG_WARN("Shellcode heuristic scan failed for pid %u: %s",
                     pid, msx_status_str(scst));
    }

    out->status = MSX_OK;
    return MSX_OK;
}
