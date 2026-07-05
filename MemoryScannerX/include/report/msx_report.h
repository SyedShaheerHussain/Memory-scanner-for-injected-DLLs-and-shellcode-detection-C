/*
 * MemoryScannerX - msx_report.h
 * Forensic report generation. JSON (machine-readable) and plain-text
 * (human-readable) exporters. HTML/Markdown/CSV share the same data
 * model and are natural follow-on exporters (see docs/EXTENDING.md).
 */
#ifndef MSX_REPORT_H
#define MSX_REPORT_H

#include "utils/msx_common.h"
#include "scanner/msx_scan_engine.h"
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Writes a single-process scan result as pretty-printed JSON to `fp`. */
msx_status_t msx_report_write_json(FILE *fp, const msx_scan_result_t *result);

/* Writes a single-process scan result as a human-readable text report. */
msx_status_t msx_report_write_text(FILE *fp, const msx_scan_result_t *result);

#ifdef __cplusplus
}
#endif

#endif /* MSX_REPORT_H */
