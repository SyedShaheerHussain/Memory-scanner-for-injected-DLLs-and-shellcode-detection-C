/*
 * MemoryScannerX - msx_process.h
 * Cross-platform process enumeration and inspection (read-only).
 */
#ifndef MSX_PROCESS_H
#define MSX_PROCESS_H

#include "utils/msx_common.h"
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t pid;
    uint32_t ppid;
    char name[MSX_MAX_NAME_LEN];
    char exe_path[MSX_MAX_PATH_LEN];
    char cmdline[MSX_MAX_CMDLINE_LEN];
    char user[MSX_MAX_USER_LEN];
    int is_64bit;              /* 1 = 64-bit, 0 = 32-bit, -1 = unknown */
    time_t create_time;        /* 0 if unavailable */
    uint32_t thread_count;
    uint32_t module_count;     /* filled by module enumerator if requested */
    uint64_t vm_rss_bytes;     /* resident set size */
    uint64_t vm_size_bytes;    /* virtual size */
    int integrity_level;       /* Windows only; -1 = n/a. 0=Low,1=Medium,2=High,3=System */
    int accessible;            /* 0 if we couldn't open/query the process at all */
} msx_process_info_t;

MSX_DECLARE_ARRAY(msx_process_list_t, msx_process_info_t)

/* Enumerate all processes visible to the current user/privilege level.
 * Populates `out` (caller must msx_process_list_t_free it).
 * Returns MSX_OK even if some individual processes were inaccessible
 * (those entries have accessible=0 and best-effort fields). */
msx_status_t msx_process_enum(msx_process_list_t *out);

/* Fetch detailed info for a single PID. */
msx_status_t msx_process_get_info(uint32_t pid, msx_process_info_t *out);

/* Returns 1 if process with pid exists and is queryable at all, else 0. */
int msx_process_exists(uint32_t pid);

#ifdef __cplusplus
}
#endif

#endif /* MSX_PROCESS_H */
