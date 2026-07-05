#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#include "memory/msx_memory.h"
#include "utils/msx_log.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void msx_memory_perm_string(const msx_memory_region_t *r, char out[4]) {
    out[0] = r->readable ? 'r' : '-';
    out[1] = r->writable ? 'w' : '-';
    out[2] = r->executable ? 'x' : '-';
    out[3] = '\0';
}

int msx_memory_region_is_wx(const msx_memory_region_t *r) {
    return r->writable && r->executable;
}

/* ======================================================================
 *  LINUX IMPLEMENTATION
 * ====================================================================== */
#if defined(MSX_PLATFORM_LINUX)

#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

static msx_region_type_t classify_region(const char *path, int shared, int executable) {
    if (path[0] == '\0') return MSX_REGION_ANONYMOUS;
    if (strcmp(path, "[heap]") == 0) return MSX_REGION_HEAP;
    if (strncmp(path, "[stack", 6) == 0) return MSX_REGION_STACK;
    /* [vdso], [vsyscall], [vvar], [anon:...] and similar bracketed pseudo
     * paths are kernel-provided, not on-disk files; they are not "modules"
     * for hidden-module comparison purposes and must not be treated as
     * anonymous-exec findings either (that would be a guaranteed false
     * positive on every single process). */
    if (path[0] == '[') return MSX_REGION_SPECIAL;
    /* Any executable, file-backed mapping is an "image" for our purposes
     * -- this includes both the main executable and shared libraries, so
     * the main binary is correctly recognized by the loader-list view and
     * never mistaken for a "hidden module". */
    if (executable) return MSX_REGION_IMAGE;
    if (shared) return MSX_REGION_SHARED_MEMORY;
    return MSX_REGION_MAPPED_FILE;
}

msx_status_t msx_memory_enum_regions(uint32_t pid, msx_region_list_t *out) {
    if (!out) return MSX_ERR_INVALID_ARG;
    msx_region_list_t_init(out);

    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return errno == EACCES ? MSX_ERR_PERMISSION_DENIED : MSX_ERR_NOT_FOUND;

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        uintptr_t start, end;
        char perms[8] = {0};
        unsigned long offset;
        char dev[16];
        unsigned long inode;
        char mapped_buf[MSX_MAX_PATH_LEN] = {0};

        int n = sscanf(line, "%lx-%lx %7s %lx %15s %lu %4095[^\n]",
                        &start, &end, perms, &offset, dev, &inode, mapped_buf);
        if (n < 6) continue;

        /* trim leading whitespace from mapped path */
        char *m = mapped_buf;
        while (*m == ' ') m++;

        msx_memory_region_t region;
        memset(&region, 0, sizeof(region));
        region.base_address = start;
        region.end_address = end;
        region.region_size = (size_t)(end - start);
        region.readable = strchr(perms, 'r') != NULL;
        region.writable = strchr(perms, 'w') != NULL;
        region.executable = strchr(perms, 'x') != NULL;
        region.shared = strchr(perms, 's') != NULL;
        msx_safe_strcpy(region.mapped_path, MSX_MAX_PATH_LEN, m);
        region.type = classify_region(m, region.shared, region.executable);

        if (msx_region_list_t_push(out, region) != 0) {
            fclose(f);
            msx_region_list_t_free(out);
            return MSX_ERR_OUT_OF_MEMORY;
        }
    }
    fclose(f);
    return MSX_OK;
}

msx_status_t msx_memory_read(uint32_t pid, uintptr_t addr, void *buf,
                              size_t len, size_t *bytes_read) {
    if (!buf || len == 0) return MSX_ERR_INVALID_ARG;

    struct iovec local = { .iov_base = buf, .iov_len = len };
    struct iovec remote = { .iov_base = (void *)addr, .iov_len = len };

    ssize_t n = process_vm_readv((pid_t)pid, &local, 1, &remote, 1, 0);
    if (n < 0) {
        if (bytes_read) *bytes_read = 0;
        if (errno == EPERM || errno == EACCES) return MSX_ERR_PERMISSION_DENIED;
        if (errno == ESRCH) return MSX_ERR_PROCESS_EXITED;
        return MSX_ERR_IO;
    }
    if (bytes_read) *bytes_read = (size_t)n;
    return (size_t)n == len ? MSX_OK : MSX_ERR_PARTIAL_READ;
}

/* ======================================================================
 *  WINDOWS IMPLEMENTATION
 * ====================================================================== */
#elif defined(MSX_PLATFORM_WINDOWS)

#include <windows.h>
#include <psapi.h>

static msx_region_type_t classify_region(MEMORY_BASIC_INFORMATION *mbi,
                                          const char *mapped_path) {
    if (mbi->Type == MEM_IMAGE) return MSX_REGION_IMAGE;
    if (mbi->Type == MEM_MAPPED) {
        return mapped_path[0] ? MSX_REGION_MAPPED_FILE : MSX_REGION_SHARED_MEMORY;
    }
    /* MEM_PRIVATE: heuristics for heap/stack are best-effort; a full
     * implementation would cross-reference GetProcessHeaps() / TEB stack
     * base-limit, done in the module/thread analyzers. */
    return MSX_REGION_ANONYMOUS;
}

msx_status_t msx_memory_enum_regions(uint32_t pid, msx_region_list_t *out) {
    if (!out) return MSX_ERR_INVALID_ARG;
    msx_region_list_t_init(out);

    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return MSX_ERR_PERMISSION_DENIED;

    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t addr = 0;

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    uintptr_t max_addr = (uintptr_t)si.lpMaximumApplicationAddress;

    while (addr <= max_addr &&
           VirtualQueryEx(hProcess, (LPCVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {

        if (mbi.State == MEM_COMMIT) {
            msx_memory_region_t region;
            memset(&region, 0, sizeof(region));
            region.base_address = (uintptr_t)mbi.BaseAddress;
            region.region_size = mbi.RegionSize;
            region.end_address = region.base_address + region.region_size;

            DWORD prot = mbi.Protect;
            region.readable = (prot & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ |
                                        PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY |
                                        PAGE_EXECUTE_WRITECOPY)) != 0;
            region.writable = (prot & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE |
                                        PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) != 0;
            region.executable = (prot & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                          PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
            region.shared = (mbi.Type == MEM_MAPPED) ? 1 : 0;

            char mapped_path[MSX_MAX_PATH_LEN] = {0};
            if (mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED) {
                GetMappedFileNameA(hProcess, mbi.BaseAddress, mapped_path, MSX_MAX_PATH_LEN);
            }
            msx_safe_strcpy(region.mapped_path, MSX_MAX_PATH_LEN, mapped_path);
            region.type = classify_region(&mbi, mapped_path);

            if (msx_region_list_t_push(out, region) != 0) {
                CloseHandle(hProcess);
                msx_region_list_t_free(out);
                return MSX_ERR_OUT_OF_MEMORY;
            }
        }

        uintptr_t next = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break; /* guard against non-advancing loop */
        addr = next;
    }

    CloseHandle(hProcess);
    return MSX_OK;
}

msx_status_t msx_memory_read(uint32_t pid, uintptr_t addr, void *buf,
                              size_t len, size_t *bytes_read) {
    if (!buf || len == 0) return MSX_ERR_INVALID_ARG;

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return MSX_ERR_PERMISSION_DENIED;

    SIZE_T n = 0;
    BOOL ok = ReadProcessMemory(hProcess, (LPCVOID)addr, buf, len, &n);
    CloseHandle(hProcess);

    if (bytes_read) *bytes_read = (size_t)n;
    if (!ok && n == 0) return MSX_ERR_IO;
    return (size_t)n == len ? MSX_OK : MSX_ERR_PARTIAL_READ;
}

#endif /* platform */
