/*
 * MemoryScannerX - msx_memory.h
 * Virtual memory region enumeration and read-only acquisition.
 * Never modifies target process memory or protections.
 */
#ifndef MSX_MEMORY_H
#define MSX_MEMORY_H

#include "utils/msx_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    MSX_REGION_UNKNOWN = 0,
    MSX_REGION_IMAGE,        /* mapped executable/library file (PE/ELF) */
    MSX_REGION_HEAP,
    MSX_REGION_STACK,
    MSX_REGION_ANONYMOUS,
    MSX_REGION_MAPPED_FILE,
    MSX_REGION_SHARED_MEMORY,
    MSX_REGION_DEVICE,
    MSX_REGION_SPECIAL      /* kernel-provided pseudo-mappings: [vdso], [vsyscall],
                              * [vvar], etc. Not "modules" in the forensic sense;
                              * excluded from hidden-module comparison to avoid
                              * false positives. */
} msx_region_type_t;

typedef struct {
    uintptr_t base_address;
    uintptr_t end_address;
    size_t region_size;
    int readable;
    int writable;
    int executable;
    int shared;            /* 1 = shared mapping, 0 = private/copy-on-write */
    msx_region_type_t type;
    char mapped_path[MSX_MAX_PATH_LEN]; /* empty if anonymous */
} msx_memory_region_t;

MSX_DECLARE_ARRAY(msx_region_list_t, msx_memory_region_t)

/* Enumerate all memory regions of a process (permission-limited; regions
 * that cannot be queried are simply omitted, not fabricated). */
msx_status_t msx_memory_enum_regions(uint32_t pid, msx_region_list_t *out);

/* Read up to `len` bytes from target process at `addr` into `buf`.
 * Returns MSX_OK on full read, MSX_ERR_PARTIAL_READ if fewer bytes were
 * read (actual count in *bytes_read), or an error status. Read-only;
 * never writes to the target process. */
msx_status_t msx_memory_read(uint32_t pid, uintptr_t addr, void *buf,
                              size_t len, size_t *bytes_read);

/* Convenience: classify permission triplet as a human string, e.g. "r-x". */
void msx_memory_perm_string(const msx_memory_region_t *r, char out[4]);

/* Returns 1 if the region's permission combination is inherently suspicious
 * for defensive triage purposes (e.g. W+X together), else 0. This is a
 * coarse heuristic layer; msx_scanner does deeper contextual scoring. */
int msx_memory_region_is_wx(const msx_memory_region_t *r);

#ifdef __cplusplus
}
#endif

#endif /* MSX_MEMORY_H */
