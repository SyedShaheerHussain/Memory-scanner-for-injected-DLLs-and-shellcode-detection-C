#include "report/msx_report.h"
#include "memory/msx_memory.h"
#include <string.h>
#include <time.h>

static void json_escape_and_write(FILE *fp, const char *s) {
    if (!s) { fputs("\"\"", fp); return; }
    fputc('"', fp);
    for (const char *p = s; *p; p++) {
        switch (*p) {
            case '"': fputs("\\\"", fp); break;
            case '\\': fputs("\\\\", fp); break;
            case '\n': fputs("\\n", fp); break;
            case '\t': fputs("\\t", fp); break;
            default:
                if ((unsigned char)*p < 0x20) fprintf(fp, "\\u%04x", *p);
                else fputc(*p, fp);
        }
    }
    fputc('"', fp);
}

msx_status_t msx_report_write_json(FILE *fp, const msx_scan_result_t *result) {
    if (!fp || !result) return MSX_ERR_INVALID_ARG;

    time_t now = time(NULL);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));

    fprintf(fp, "{\n");
    fprintf(fp, "  \"scan_timestamp\": \"%s\",\n", ts);
    fprintf(fp, "  \"tool\": \"MemoryScannerX\",\n");
    fprintf(fp, "  \"process\": {\n");
    fprintf(fp, "    \"pid\": %u,\n", result->process.pid);
    fprintf(fp, "    \"ppid\": %u,\n", result->process.ppid);
    fprintf(fp, "    \"name\": "); json_escape_and_write(fp, result->process.name); fprintf(fp, ",\n");
    fprintf(fp, "    \"exe_path\": "); json_escape_and_write(fp, result->process.exe_path); fprintf(fp, ",\n");
    fprintf(fp, "    \"user\": "); json_escape_and_write(fp, result->process.user); fprintf(fp, ",\n");
    fprintf(fp, "    \"is_64bit\": %d,\n", result->process.is_64bit);
    fprintf(fp, "    \"thread_count\": %u,\n", result->process.thread_count);
    fprintf(fp, "    \"vm_rss_bytes\": %llu,\n", (unsigned long long)result->process.vm_rss_bytes);
    fprintf(fp, "    \"integrity_level\": %d\n", result->process.integrity_level);
    fprintf(fp, "  },\n");

    fprintf(fp, "  \"memory_regions\": {\n");
    fprintf(fp, "    \"total\": %zu,\n", result->regions.count);
    fprintf(fp, "    \"suspicious\": [\n");
    int first = 1;
    for (size_t i = 0; i < result->regions.count; i++) {
        msx_memory_region_t *r = &result->regions.items[i];
        if (!(msx_memory_region_is_wx(r) ||
              (r->executable && r->type == MSX_REGION_ANONYMOUS))) continue;
        if (!first) fprintf(fp, ",\n");
        first = 0;
        char perm[4];
        msx_memory_perm_string(r, perm);
        fprintf(fp, "      {\"base\": \"0x%lx\", \"size\": %zu, \"perms\": \"%s\", \"path\": ",
                (unsigned long)r->base_address, r->region_size, perm);
        json_escape_and_write(fp, r->mapped_path);
        fprintf(fp, "}");
    }
    fprintf(fp, "\n    ]\n  },\n");

    fprintf(fp, "  \"module_anomalies\": [\n");
    for (size_t i = 0; i < result->module_anomalies.count; i++) {
        msx_module_anomaly_t *a = &result->module_anomalies.items[i];
        fprintf(fp, "    {\"base\": \"0x%lx\", \"path\": ", (unsigned long)a->base_address);
        json_escape_and_write(fp, a->path);
        fprintf(fp, ", \"reason\": ");
        json_escape_and_write(fp, a->reason);
        fprintf(fp, "}%s\n", (i + 1 < result->module_anomalies.count) ? "," : "");
    }
    fprintf(fp, "  ],\n");

    fprintf(fp, "  \"shellcode_findings\": [\n");
    for (size_t i = 0; i < result->shellcode_findings.count; i++) {
        msx_shellcode_finding_t *f = &result->shellcode_findings.items[i];
        fprintf(fp, "    {\"address\": \"0x%lx\", \"size\": %zu, \"entropy\": %.3f, \"notes\": ",
                (unsigned long)f->address, f->size, f->entropy);
        json_escape_and_write(fp, f->notes);
        fprintf(fp, "}%s\n", (i + 1 < result->shellcode_findings.count) ? "," : "");
    }
    fprintf(fp, "  ],\n");

    fprintf(fp, "  \"threat_score\": {\n");
    fprintf(fp, "    \"total\": %d,\n", result->score.total);
    fprintf(fp, "    \"risk\": "); json_escape_and_write(fp, msx_risk_str(result->score.risk)); fprintf(fp, ",\n");
    fprintf(fp, "    \"explanation\": [\n");
    for (size_t i = 0; i < result->score.entries.count; i++) {
        msx_score_entry_t *e = &result->score.entries.items[i];
        fprintf(fp, "      {\"points\": %d, \"reason\": ", e->points);
        json_escape_and_write(fp, e->reason);
        fprintf(fp, "}%s\n", (i + 1 < result->score.entries.count) ? "," : "");
    }
    fprintf(fp, "    ]\n  }\n");
    fprintf(fp, "}\n");
    return MSX_OK;
}

msx_status_t msx_report_write_text(FILE *fp, const msx_scan_result_t *result) {
    if (!fp || !result) return MSX_ERR_INVALID_ARG;

    fprintf(fp, "================================================================\n");
    fprintf(fp, " MemoryScannerX Forensic Scan Report\n");
    fprintf(fp, "================================================================\n");
    fprintf(fp, "PID:            %u\n", result->process.pid);
    fprintf(fp, "PPID:           %u\n", result->process.ppid);
    fprintf(fp, "Name:           %s\n", result->process.name);
    fprintf(fp, "Executable:     %s\n", result->process.exe_path);
    fprintf(fp, "User:           %s\n", result->process.user);
    fprintf(fp, "Architecture:   %s\n",
            result->process.is_64bit == 1 ? "64-bit" :
            result->process.is_64bit == 0 ? "32-bit" : "unknown");
    fprintf(fp, "Threads:        %u\n", result->process.thread_count);
    fprintf(fp, "RSS:            %.2f MB\n", result->process.vm_rss_bytes / (1024.0 * 1024.0));
    fprintf(fp, "\n");

    fprintf(fp, "-- Memory Regions (%zu total) -----------------------------------\n",
            result->regions.count);
    for (size_t i = 0; i < result->regions.count; i++) {
        msx_memory_region_t *r = &result->regions.items[i];
        if (!(msx_memory_region_is_wx(r) ||
              (r->executable && r->type == MSX_REGION_ANONYMOUS))) continue;
        char perm[4];
        msx_memory_perm_string(r, perm);
        fprintf(fp, "  [SUSPICIOUS] 0x%016lx  size=%-10zu perms=%s  %s\n",
                (unsigned long)r->base_address, r->region_size, perm,
                r->mapped_path[0] ? r->mapped_path : "(anonymous)");
    }

    fprintf(fp, "\n-- Module Anomalies (%zu) ----------------------------------------\n",
            result->module_anomalies.count);
    for (size_t i = 0; i < result->module_anomalies.count; i++) {
        msx_module_anomaly_t *a = &result->module_anomalies.items[i];
        fprintf(fp, "  0x%016lx  %s\n      reason: %s\n",
                (unsigned long)a->base_address, a->path, a->reason);
    }

    fprintf(fp, "\n-- Shellcode Heuristic Findings (%zu) ------------------------------\n",
            result->shellcode_findings.count);
    for (size_t i = 0; i < result->shellcode_findings.count; i++) {
        msx_shellcode_finding_t *f = &result->shellcode_findings.items[i];
        fprintf(fp, "  0x%016lx  size=%-10zu entropy=%.2f\n      %s\n",
                (unsigned long)f->address, f->size, f->entropy, f->notes);
    }

    fprintf(fp, "\n-- Threat Score ----------------------------------------------------\n");
    for (size_t i = 0; i < result->score.entries.count; i++) {
        msx_score_entry_t *e = &result->score.entries.items[i];
        fprintf(fp, "  [+%3d] %s\n", e->points, e->reason);
    }
    fprintf(fp, "  ------------------------------------------------------------\n");
    fprintf(fp, "  TOTAL SCORE: %d   RISK LEVEL: %s\n",
            result->score.total, msx_risk_str(result->score.risk));
    fprintf(fp, "================================================================\n");
    return MSX_OK;
}
