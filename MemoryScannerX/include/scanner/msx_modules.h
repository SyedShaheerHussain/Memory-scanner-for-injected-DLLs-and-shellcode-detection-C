/*
 * MemoryScannerX - msx_modules.h
 * Loaded module (shared library / DLL) enumeration and hidden-module
 * consistency checking. Hidden-module detection here is purely
 * defensive: it cross-references two independently-derived, documented
 * information sources and flags disagreements for analyst review. It
 * does not claim malice, only inconsistency.
 */
#ifndef MSX_MODULES_H
#define MSX_MODULES_H

#include "utils/msx_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char name[MSX_MAX_NAME_LEN];
    char path[MSX_MAX_PATH_LEN];
    uintptr_t base_address;
    size_t image_size;
    char sha256_hex[65]; /* empty if not hashed */
} msx_module_info_t;

MSX_DECLARE_ARRAY(msx_module_list_t, msx_module_info_t)

/* Source A: loader-maintained list.
 *  - Linux: dl_iterate_phdr() within self is not usable cross-process, so
 *    for a *target* process we parse /proc/pid/maps unique image paths as
 *    the "loader view" analogue (documented, standard technique).
 *  - Windows: EnumProcessModules / Module32First via Toolhelp32 (documented
 *    loader-list APIs). */
msx_status_t msx_modules_enum_loader_list(uint32_t pid, msx_module_list_t *out);

/* Source B: memory-mapping derived list.
 *  - Linux: parses /proc/pid/maps directly, independent of any loader
 *    metadata, to build an image-mapping view.
 *  - Windows: VirtualQueryEx walk classifying MEM_IMAGE regions,
 *    independent of the loader's module list. */
msx_status_t msx_modules_enum_mapping_view(uint32_t pid, msx_module_list_t *out);

typedef struct {
    char path[MSX_MAX_PATH_LEN];
    uintptr_t base_address;
    const char *reason; /* human explanation, static string */
} msx_module_anomaly_t;

MSX_DECLARE_ARRAY(msx_module_anomaly_list_t, msx_module_anomaly_t)

/* Compares loader-list vs mapping-view for a process and reports
 * disagreements (present in mapping but absent from loader list, or
 * vice versa) as anomalies requiring analyst review. This is the
 * documented, conservative approach to "hidden module" defensive
 * detection — no undocumented kernel structures are touched. */
msx_status_t msx_modules_find_anomalies(uint32_t pid, msx_module_anomaly_list_t *out);

/* Compute SHA-256 of a file on disk; hex-encodes into out[65]. */
msx_status_t msx_hash_file_sha256(const char *path, char out_hex[65]);

#ifdef __cplusplus
}
#endif

#endif /* MSX_MODULES_H */
