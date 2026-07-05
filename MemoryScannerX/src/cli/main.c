/*
 * MemoryScannerX - main.c
 * Command-line interface. Read-only defensive memory forensics tool.
 *
 * Usage:
 *   memoryscannerx list
 *   memoryscannerx inspect --pid <PID>
 *   memoryscannerx scan --pid <PID> [--json out.json] [--text out.txt]
 *   memoryscannerx scan --all [--json out.json] [--min-risk medium]
 *   memoryscannerx --version
 *   memoryscannerx --help
 */
#include "utils/msx_common.h"
#include "utils/msx_log.h"
#include "process/msx_process.h"
#include "scanner/msx_scan_engine.h"
#include "report/msx_report.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MSX_VERSION "1.0.0-core"

static void print_help(void) {
    printf(
        "MemoryScannerX %s - defensive, read-only memory forensics tool\n\n"
        "USAGE:\n"
        "  memoryscannerx list\n"
        "      List all visible running processes.\n\n"
        "  memoryscannerx inspect --pid <PID>\n"
        "      Show detailed information about a single process.\n\n"
        "  memoryscannerx scan --pid <PID> [--json FILE] [--text FILE]\n"
        "      Run the full analysis pipeline (memory permissions, module\n"
        "      anomalies, shellcode heuristics, threat scoring) against PID.\n\n"
        "  memoryscannerx scan --all [--min-risk LEVEL] [--json FILE]\n"
        "      Scan every visible process; LEVEL in {low,medium,high,critical}.\n\n"
        "  memoryscannerx --version | --help\n\n"
        "NOTES:\n"
        "  - Read-only: never modifies, injects into, or terminates processes.\n"
        "  - Some processes may be inaccessible without elevated privileges;\n"
        "    those are skipped, not fabricated.\n",
        MSX_VERSION);
}

static void cmd_list(void) {
    msx_process_list_t procs;
    msx_status_t st = msx_process_enum(&procs);
    if (st != MSX_OK) {
        fprintf(stderr, "Failed to enumerate processes: %s\n", msx_status_str(st));
        return;
    }
    printf("%-8s %-8s %-24s %-8s %s\n", "PID", "PPID", "NAME", "ARCH", "EXE");
    printf("--------------------------------------------------------------------------\n");
    for (size_t i = 0; i < procs.count; i++) {
        msx_process_info_t *p = &procs.items[i];
        if (!p->accessible) continue;
        const char *arch = p->is_64bit == 1 ? "x64" : p->is_64bit == 0 ? "x86" : "?";
        printf("%-8u %-8u %-24s %-8s %s\n", p->pid, p->ppid, p->name, arch, p->exe_path);
    }
    printf("--------------------------------------------------------------------------\n");
    printf("Total: %zu processes\n", procs.count);
    msx_process_list_t_free(&procs);
}

static void cmd_inspect(uint32_t pid) {
    msx_process_info_t info;
    msx_status_t st = msx_process_get_info(pid, &info);
    if (st != MSX_OK) {
        fprintf(stderr, "Could not inspect PID %u: %s\n", pid, msx_status_str(st));
        return;
    }
    printf("PID:          %u\n", info.pid);
    printf("PPID:         %u\n", info.ppid);
    printf("Name:         %s\n", info.name);
    printf("Executable:   %s\n", info.exe_path);
    printf("Command line: %s\n", info.cmdline);
    printf("User:         %s\n", info.user);
    printf("Architecture: %s\n", info.is_64bit == 1 ? "64-bit" :
                                  info.is_64bit == 0 ? "32-bit" : "unknown");
    printf("Threads:      %u\n", info.thread_count);
    printf("VM RSS:       %.2f MB\n", info.vm_rss_bytes / (1024.0 * 1024.0));
    printf("VM Size:      %.2f MB\n", info.vm_size_bytes / (1024.0 * 1024.0));
    if (info.integrity_level >= 0) {
        static const char *levels[] = {"Low", "Medium", "High", "System"};
        printf("Integrity:    %s\n", levels[info.integrity_level]);
    }
}

static msx_risk_level_t parse_risk(const char *s) {
    if (!s) return MSX_RISK_NONE;
    if (strcmp(s, "low") == 0) return MSX_RISK_LOW;
    if (strcmp(s, "medium") == 0) return MSX_RISK_MEDIUM;
    if (strcmp(s, "high") == 0) return MSX_RISK_HIGH;
    if (strcmp(s, "critical") == 0) return MSX_RISK_CRITICAL;
    return MSX_RISK_NONE;
}

static void cmd_scan_single(uint32_t pid, const char *json_path, const char *text_path) {
    msx_scan_result_t result;
    msx_status_t st = msx_scan_process(pid, NULL, &result);
    if (st != MSX_OK) {
        fprintf(stderr, "Scan failed for PID %u: %s\n", pid, msx_status_str(st));
        return;
    }

    msx_report_write_text(stdout, &result);

    if (json_path) {
        FILE *f = fopen(json_path, "w");
        if (f) { msx_report_write_json(f, &result); fclose(f); printf("\nJSON report written to %s\n", json_path); }
        else fprintf(stderr, "Could not open %s for writing\n", json_path);
    }
    if (text_path) {
        FILE *f = fopen(text_path, "w");
        if (f) { msx_report_write_text(f, &result); fclose(f); printf("Text report written to %s\n", text_path); }
        else fprintf(stderr, "Could not open %s for writing\n", text_path);
    }

    msx_scan_result_free(&result);
}

static void cmd_scan_all(const char *json_path, msx_risk_level_t min_risk) {
    msx_process_list_t procs;
    msx_status_t st = msx_process_enum(&procs);
    if (st != MSX_OK) {
        fprintf(stderr, "Failed to enumerate processes: %s\n", msx_status_str(st));
        return;
    }

    FILE *json_fp = NULL;
    if (json_path) {
        json_fp = fopen(json_path, "w");
        if (json_fp) fprintf(json_fp, "[\n");
    }

    int scanned = 0, flagged = 0;
    for (size_t i = 0; i < procs.count; i++) {
        msx_process_info_t *p = &procs.items[i];
        if (!p->accessible) continue;

        msx_scan_result_t result;
        msx_status_t sst = msx_scan_process(p->pid, NULL, &result);
        if (sst != MSX_OK) continue;
        scanned++;

        if (result.score.risk >= min_risk && result.score.risk != MSX_RISK_NONE) {
            flagged++;
            printf("\n");
            msx_report_write_text(stdout, &result);
            if (json_fp) {
                if (flagged > 1) fprintf(json_fp, ",\n");
                msx_report_write_json(json_fp, &result);
            }
        }
        msx_scan_result_free(&result);
    }

    if (json_fp) { fprintf(json_fp, "]\n"); fclose(json_fp); }

    printf("\n============================================================\n");
    printf("Scanned %d processes, %d flagged at or above risk level.\n", scanned, flagged);
    if (json_path) printf("JSON report written to %s\n", json_path);

    msx_process_list_t_free(&procs);
}

int main(int argc, char **argv) {
    msx_log_init(NULL, MSX_LOG_INFO, 1);

    if (argc < 2 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        print_help();
        msx_log_shutdown();
        return argc < 2 ? 1 : 0;
    }

    if (strcmp(argv[1], "--version") == 0) {
        printf("MemoryScannerX %s\n", MSX_VERSION);
        msx_log_shutdown();
        return 0;
    }

    const char *cmd = argv[1];
    int rc = 0;

    if (strcmp(cmd, "list") == 0) {
        cmd_list();
    } else if (strcmp(cmd, "inspect") == 0) {
        uint32_t pid = 0;
        for (int i = 2; i < argc - 1; i++) {
            if (strcmp(argv[i], "--pid") == 0) pid = (uint32_t)strtoul(argv[i + 1], NULL, 10);
        }
        if (pid == 0) {
            fprintf(stderr, "inspect requires --pid <PID>\n");
            rc = 1;
        } else {
            cmd_inspect(pid);
        }
    } else if (strcmp(cmd, "scan") == 0) {
        uint32_t pid = 0;
        int all = 0;
        const char *json_path = NULL, *text_path = NULL;
        msx_risk_level_t min_risk = MSX_RISK_LOW;

        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc) pid = (uint32_t)strtoul(argv[++i], NULL, 10);
            else if (strcmp(argv[i], "--all") == 0) all = 1;
            else if (strcmp(argv[i], "--json") == 0 && i + 1 < argc) json_path = argv[++i];
            else if (strcmp(argv[i], "--text") == 0 && i + 1 < argc) text_path = argv[++i];
            else if (strcmp(argv[i], "--min-risk") == 0 && i + 1 < argc) min_risk = parse_risk(argv[++i]);
        }

        if (all) {
            cmd_scan_all(json_path, min_risk);
        } else if (pid != 0) {
            cmd_scan_single(pid, json_path, text_path);
        } else {
            fprintf(stderr, "scan requires --pid <PID> or --all\n");
            rc = 1;
        }
    } else {
        fprintf(stderr, "Unknown command: %s\n\n", cmd);
        print_help();
        rc = 1;
    }

    msx_log_shutdown();
    return rc;
}
