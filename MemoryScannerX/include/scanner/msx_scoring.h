/*
 * MemoryScannerX - msx_scoring.h
 * Transparent, weighted threat-scoring engine. Every point added is
 * recorded with a human-readable reason so the final score is fully
 * explainable (no opaque black-box scoring).
 */
#ifndef MSX_SCORING_H
#define MSX_SCORING_H

#include "utils/msx_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char reason[256];
    int points;
} msx_score_entry_t;

MSX_DECLARE_ARRAY(msx_score_entry_list_t, msx_score_entry_t)

typedef struct {
    /* Configurable weights; all defaults chosen conservatively and
     * documented inline. Loadable from JSON via msx_config. */
    int weight_wx_region;
    int weight_anon_exec;
    int weight_module_anomaly;
    int weight_deleted_backing_file;
    int weight_shellcode_nop_sled;
    int weight_high_entropy;
} msx_score_weights_t;

void msx_score_weights_default(msx_score_weights_t *w);

typedef struct {
    msx_score_entry_list_t entries;
    int total;
    msx_risk_level_t risk;
} msx_score_report_t;

void msx_score_report_init(msx_score_report_t *rep);
void msx_score_report_free(msx_score_report_t *rep);

/* Adds a scored observation with an explanation; keeps a running total. */
void msx_score_add(msx_score_report_t *rep, int points, const char *reason_fmt, ...);

/* Maps a numeric total to a risk level. Thresholds are intentionally
 * simple and documented; tune via config for your environment. */
msx_risk_level_t msx_score_to_risk(int total);

#ifdef __cplusplus
}
#endif

#endif /* MSX_SCORING_H */
