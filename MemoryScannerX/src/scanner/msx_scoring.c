#include "scanner/msx_scoring.h"
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

void msx_score_weights_default(msx_score_weights_t *w) {
    w->weight_wx_region = 20;
    w->weight_anon_exec = 15;
    w->weight_module_anomaly = 30;
    w->weight_deleted_backing_file = 35;
    w->weight_shellcode_nop_sled = 25;
    w->weight_high_entropy = 15;
}

void msx_score_report_init(msx_score_report_t *rep) {
    msx_score_entry_list_t_init(&rep->entries);
    rep->total = 0;
    rep->risk = MSX_RISK_NONE;
}

void msx_score_report_free(msx_score_report_t *rep) {
    msx_score_entry_list_t_free(&rep->entries);
    rep->total = 0;
    rep->risk = MSX_RISK_NONE;
}

void msx_score_add(msx_score_report_t *rep, int points, const char *reason_fmt, ...) {
    msx_score_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.points = points;

    va_list args;
    va_start(args, reason_fmt);
    vsnprintf(entry.reason, sizeof(entry.reason), reason_fmt, args);
    va_end(args);

    msx_score_entry_list_t_push(&rep->entries, entry);
    rep->total += points;
    rep->risk = msx_score_to_risk(rep->total);
}

msx_risk_level_t msx_score_to_risk(int total) {
    if (total <= 0) return MSX_RISK_NONE;
    if (total < 25) return MSX_RISK_LOW;
    if (total < 60) return MSX_RISK_MEDIUM;
    if (total < 100) return MSX_RISK_HIGH;
    return MSX_RISK_CRITICAL;
}
