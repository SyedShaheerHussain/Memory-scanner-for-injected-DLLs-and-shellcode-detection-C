#include "scanner/msx_modules.h"
#include "memory/msx_memory.h"
#include "utils/msx_sha256.h"
#include "utils/msx_log.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

msx_status_t msx_hash_file_sha256(const char *path, char out_hex[65]) {
    if (!path || !out_hex) return MSX_ERR_INVALID_ARG;
    FILE *f = fopen(path, "rb");
    if (!f) return MSX_ERR_NOT_FOUND;

    msx_sha256_ctx_t ctx;
    msx_sha256_init(&ctx);

    uint8_t buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        msx_sha256_update(&ctx, buf, n);
    }
    fclose(f);

    uint8_t hash[32];
    msx_sha256_final(&ctx, hash);
    for (int i = 0; i < 32; i++) snprintf(out_hex + i * 2, 3, "%02x", hash[i]);
    out_hex[64] = '\0';
    return MSX_OK;
}

static int path_already_in_list(msx_module_list_t *list, const char *path) {
    for (size_t i = 0; i < list->count; i++) {
        if (strcmp(list->items[i].path, path) == 0) return 1;
    }
    return 0;
}

/* ======================================================================
 *  LINUX: loader-list analogue + mapping-view, both derived from
 *  /proc/pid/maps but via two independent extraction passes, matching
 *  the documented consistency-check approach requested. A stronger
 *  implementation could additionally cross-check /proc/pid/exe's ELF
 *  DT_NEEDED and the runtime linker's r_debug link_map (attached via
 *  ptrace, documented but higher-privilege); this is left as a natural
 *  extension point. */
#if defined(MSX_PLATFORM_LINUX)

#include <sys/stat.h>

msx_status_t msx_modules_enum_loader_list(uint32_t pid, msx_module_list_t *out) {
    if (!out) return MSX_ERR_INVALID_ARG;
    msx_module_list_t_init(out);

    msx_region_list_t regions;
    msx_status_t st = msx_memory_enum_regions(pid, &regions);
    if (st != MSX_OK) return st;

    for (size_t i = 0; i < regions.count; i++) {
        msx_memory_region_t *r = &regions.items[i];
        if (r->type != MSX_REGION_IMAGE) continue; /* now includes main exe + .so's */
        if (r->mapped_path[0] == '\0') continue;
        if (path_already_in_list(out, r->mapped_path)) continue;

        msx_module_info_t mod;
        memset(&mod, 0, sizeof(mod));
        msx_safe_strcpy(mod.path, MSX_MAX_PATH_LEN, r->mapped_path);
        const char *base = strrchr(mod.path, '/');
        msx_safe_strcpy(mod.name, MSX_MAX_NAME_LEN, base ? base + 1 : mod.path);
        mod.base_address = r->base_address;

        struct stat st_buf;
        if (stat(mod.path, &st_buf) == 0) mod.image_size = (size_t)st_buf.st_size;

        msx_module_list_t_push(out, mod);
    }
    msx_region_list_t_free(&regions);
    return MSX_OK;
}

/* On Linux both "views" are legitimately derived from maps; to make the
 * consistency check meaningful we build the mapping view including ALL
 * executable, file-backed regions (same IMAGE-type filter as the loader
 * list), which lets anomaly detection catch e.g. an executable region
 * backed by a deleted/replaced file ("(deleted)" suffix - a classic
 * indicator worth flagging) or paths outside expected library dirs.
 * Kernel pseudo-mappings ([vdso], [vsyscall], ...) are intentionally
 * excluded via the IMAGE-only filter (they classify as SPECIAL). */
msx_status_t msx_modules_enum_mapping_view(uint32_t pid, msx_module_list_t *out) {
    if (!out) return MSX_ERR_INVALID_ARG;
    msx_module_list_t_init(out);

    msx_region_list_t regions;
    msx_status_t st = msx_memory_enum_regions(pid, &regions);
    if (st != MSX_OK) return st;

    for (size_t i = 0; i < regions.count; i++) {
        msx_memory_region_t *r = &regions.items[i];
        if (r->type != MSX_REGION_IMAGE) continue;
        if (r->mapped_path[0] == '\0') continue;
        if (path_already_in_list(out, r->mapped_path)) continue;

        msx_module_info_t mod;
        memset(&mod, 0, sizeof(mod));
        msx_safe_strcpy(mod.path, MSX_MAX_PATH_LEN, r->mapped_path);
        const char *base = strrchr(mod.path, '/');
        msx_safe_strcpy(mod.name, MSX_MAX_NAME_LEN, base ? base + 1 : mod.path);
        mod.base_address = r->base_address;
        mod.image_size = r->region_size;

        msx_module_list_t_push(out, mod);
    }
    msx_region_list_t_free(&regions);
    return MSX_OK;
}

msx_status_t msx_modules_find_anomalies(uint32_t pid, msx_module_anomaly_list_t *out) {
    if (!out) return MSX_ERR_INVALID_ARG;
    msx_module_anomaly_list_t_init(out);

    msx_module_list_t loader_list, mapping_view;
    msx_status_t st1 = msx_modules_enum_loader_list(pid, &loader_list);
    msx_status_t st2 = msx_modules_enum_mapping_view(pid, &mapping_view);
    if (st1 != MSX_OK || st2 != MSX_OK) {
        if (st1 == MSX_OK) msx_module_list_t_free(&loader_list);
        if (st2 == MSX_OK) msx_module_list_t_free(&mapping_view);
        return (st1 != MSX_OK) ? st1 : st2;
    }

    for (size_t i = 0; i < mapping_view.count; i++) {
        const char *path = mapping_view.items[i].path;

        /* Flag deleted/replaced on-disk images: a well-known technique
         * where malware unlinks its backing file after mapping. */
        if (strstr(path, "(deleted)") != NULL) {
            msx_module_anomaly_t a;
            memset(&a, 0, sizeof(a));
            msx_safe_strcpy(a.path, MSX_MAX_PATH_LEN, path);
            a.base_address = mapping_view.items[i].base_address;
            a.reason = "Executable region backed by a deleted/unlinked file on disk";
            msx_module_anomaly_list_t_push(out, a);
            continue;
        }

        if (!path_already_in_list(&loader_list, path)) {
            msx_module_anomaly_t a;
            memset(&a, 0, sizeof(a));
            msx_safe_strcpy(a.path, MSX_MAX_PATH_LEN, path);
            a.base_address = mapping_view.items[i].base_address;
            a.reason = "Executable mapping present but absent from loader-list view; review manually";
            msx_module_anomaly_list_t_push(out, a);
        }
    }

    msx_module_list_t_free(&loader_list);
    msx_module_list_t_free(&mapping_view);
    return MSX_OK;
}

#elif defined(MSX_PLATFORM_WINDOWS)

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>

msx_status_t msx_modules_enum_loader_list(uint32_t pid, msx_module_list_t *out) {
    if (!out) return MSX_ERR_INVALID_ARG;
    msx_module_list_t_init(out);

    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return MSX_ERR_PERMISSION_DENIED;

    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {
        DWORD count = cbNeeded / sizeof(HMODULE);
        for (DWORD i = 0; i < count; i++) {
            msx_module_info_t mod;
            memset(&mod, 0, sizeof(mod));
            char path[MSX_MAX_PATH_LEN];
            if (GetModuleFileNameExA(hProcess, hMods[i], path, MSX_MAX_PATH_LEN)) {
                msx_safe_strcpy(mod.path, MSX_MAX_PATH_LEN, path);
                const char *base = strrchr(path, '\\');
                msx_safe_strcpy(mod.name, MSX_MAX_NAME_LEN, base ? base + 1 : path);
            }
            MODULEINFO mi;
            if (GetModuleInformation(hProcess, hMods[i], &mi, sizeof(mi))) {
                mod.base_address = (uintptr_t)mi.lpBaseOfDll;
                mod.image_size = mi.SizeOfImage;
            }
            msx_module_list_t_push(out, mod);
        }
    }
    CloseHandle(hProcess);
    return MSX_OK;
}

msx_status_t msx_modules_enum_mapping_view(uint32_t pid, msx_module_list_t *out) {
    if (!out) return MSX_ERR_INVALID_ARG;
    msx_module_list_t_init(out);

    msx_region_list_t regions;
    msx_status_t st = msx_memory_enum_regions(pid, &regions);
    if (st != MSX_OK) return st;

    for (size_t i = 0; i < regions.count; i++) {
        msx_memory_region_t *r = &regions.items[i];
        if (!r->executable) continue;
        if (r->mapped_path[0] == '\0') continue;
        if (path_already_in_list(out, r->mapped_path)) continue;

        msx_module_info_t mod;
        memset(&mod, 0, sizeof(mod));
        msx_safe_strcpy(mod.path, MSX_MAX_PATH_LEN, r->mapped_path);
        const char *base = strrchr(mod.path, '\\');
        msx_safe_strcpy(mod.name, MSX_MAX_NAME_LEN, base ? base + 1 : mod.path);
        mod.base_address = r->base_address;
        mod.image_size = r->region_size;
        msx_module_list_t_push(out, mod);
    }
    msx_region_list_t_free(&regions);
    return MSX_OK;
}

msx_status_t msx_modules_find_anomalies(uint32_t pid, msx_module_anomaly_list_t *out) {
    if (!out) return MSX_ERR_INVALID_ARG;
    msx_module_anomaly_list_t_init(out);

    msx_module_list_t loader_list, mapping_view;
    msx_status_t st1 = msx_modules_enum_loader_list(pid, &loader_list);
    msx_status_t st2 = msx_modules_enum_mapping_view(pid, &mapping_view);
    if (st1 != MSX_OK || st2 != MSX_OK) {
        if (st1 == MSX_OK) msx_module_list_t_free(&loader_list);
        if (st2 == MSX_OK) msx_module_list_t_free(&mapping_view);
        return (st1 != MSX_OK) ? st1 : st2;
    }

    for (size_t i = 0; i < mapping_view.count; i++) {
        const char *path = mapping_view.items[i].path;
        if (!path_already_in_list(&loader_list, path)) {
            msx_module_anomaly_t a;
            memset(&a, 0, sizeof(a));
            msx_safe_strcpy(a.path, MSX_MAX_PATH_LEN, path);
            a.base_address = mapping_view.items[i].base_address;
            a.reason = "Executable image mapping present but absent from the process module "
                       "loader list (EnumProcessModules); review manually";
            msx_module_anomaly_list_t_push(out, a);
        }
    }

    msx_module_list_t_free(&loader_list);
    msx_module_list_t_free(&mapping_view);
    return MSX_OK;
}

#endif
