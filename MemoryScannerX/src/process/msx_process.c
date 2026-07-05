#include "process/msx_process.h"
#include "utils/msx_log.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ======================================================================
 *  LINUX IMPLEMENTATION  (/proc filesystem, documented interfaces only)
 * ====================================================================== */
#if defined(MSX_PLATFORM_LINUX)

#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <ctype.h>

static int read_file_to_buf(const char *path, char *buf, size_t bufsize) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    size_t n = fread(buf, 1, bufsize - 1, f);
    buf[n] = '\0';
    fclose(f);
    return (int)n;
}

static void parse_status_fields(uint32_t pid, msx_process_info_t *info) {
    char path[128];
    snprintf(path, sizeof(path), "/proc/%u/status", pid);
    FILE *f = fopen(path, "r");
    if (!f) return;

    char line[512];
    uid_t uid = (uid_t)-1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "PPid:", 5) == 0) {
            info->ppid = (uint32_t)strtoul(line + 5, NULL, 10);
        } else if (strncmp(line, "Threads:", 8) == 0) {
            info->thread_count = (uint32_t)strtoul(line + 8, NULL, 10);
        } else if (strncmp(line, "VmRSS:", 6) == 0) {
            info->vm_rss_bytes = strtoull(line + 6, NULL, 10) * 1024ULL;
        } else if (strncmp(line, "VmSize:", 7) == 0) {
            info->vm_size_bytes = strtoull(line + 7, NULL, 10) * 1024ULL;
        } else if (strncmp(line, "Uid:", 4) == 0) {
            uid = (uid_t)strtoul(line + 4, NULL, 10);
        }
    }
    fclose(f);

    if (uid != (uid_t)-1) {
        struct passwd *pw = getpwuid(uid);
        if (pw && pw->pw_name) {
            msx_safe_strcpy(info->user, MSX_MAX_USER_LEN, pw->pw_name);
        } else {
            snprintf(info->user, MSX_MAX_USER_LEN, "uid:%u", (unsigned)uid);
        }
    }
}

static void parse_comm(uint32_t pid, msx_process_info_t *info) {
    char path[128], buf[MSX_MAX_NAME_LEN];
    snprintf(path, sizeof(path), "/proc/%u/comm", pid);
    if (read_file_to_buf(path, buf, sizeof(buf)) >= 0) {
        size_t len = strlen(buf);
        if (len > 0 && buf[len - 1] == '\n') buf[len - 1] = '\0';
        msx_safe_strcpy(info->name, MSX_MAX_NAME_LEN, buf);
    }
}

static void parse_exe(uint32_t pid, msx_process_info_t *info) {
    char path[128];
    snprintf(path, sizeof(path), "/proc/%u/exe", pid);
    ssize_t n = readlink(path, info->exe_path, MSX_MAX_PATH_LEN - 1);
    if (n >= 0) {
        info->exe_path[n] = '\0';
    } else {
        info->exe_path[0] = '\0';
    }
}

static void parse_cmdline(uint32_t pid, msx_process_info_t *info) {
    char path[128];
    snprintf(path, sizeof(path), "/proc/%u/cmdline", pid);
    FILE *f = fopen(path, "r");
    if (!f) { info->cmdline[0] = '\0'; return; }
    size_t n = fread(info->cmdline, 1, MSX_MAX_CMDLINE_LEN - 1, f);
    fclose(f);
    /* cmdline is NUL-separated args; join with spaces for display */
    for (size_t i = 0; i < n; i++) {
        if (info->cmdline[i] == '\0' && i != n - 1) info->cmdline[i] = ' ';
    }
    info->cmdline[n] = '\0';
}

static int detect_arch64(uint32_t pid) {
    char path[128];
    snprintf(path, sizeof(path), "/proc/%u/exe", pid);
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    unsigned char e_ident[5];
    size_t r = fread(e_ident, 1, 5, f);
    fclose(f);
    if (r < 5) return -1;
    if (e_ident[0] != 0x7f || e_ident[1] != 'E' || e_ident[2] != 'L' || e_ident[3] != 'F') return -1;
    return e_ident[4] == 2 ? 1 : 0; /* ELFCLASS64 = 2, ELFCLASS32 = 1 */
}

static void fill_single_proc(uint32_t pid, msx_process_info_t *info) {
    memset(info, 0, sizeof(*info));
    info->pid = pid;
    info->integrity_level = -1;
    info->is_64bit = -1;
    info->accessible = 1;

    parse_comm(pid, info);
    parse_exe(pid, info);
    parse_cmdline(pid, info);
    parse_status_fields(pid, info);
    info->is_64bit = detect_arch64(pid);

    if (info->name[0] == '\0' && info->exe_path[0] == '\0') {
        info->accessible = 0;
    }
}

msx_status_t msx_process_enum(msx_process_list_t *out) {
    if (!out) return MSX_ERR_INVALID_ARG;
    msx_process_list_t_init(out);

    DIR *d = opendir("/proc");
    if (!d) return MSX_ERR_IO;

    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        const char *name = entry->d_name;
        int is_numeric = name[0] != '\0';
        for (const char *p = name; *p; p++) {
            if (!isdigit((unsigned char)*p)) { is_numeric = 0; break; }
        }
        if (!is_numeric) continue;

        uint32_t pid = (uint32_t)strtoul(name, NULL, 10);
        msx_process_info_t info;
        fill_single_proc(pid, &info);
        if (msx_process_list_t_push(out, info) != 0) {
            closedir(d);
            msx_process_list_t_free(out);
            return MSX_ERR_OUT_OF_MEMORY;
        }
    }
    closedir(d);
    return MSX_OK;
}

msx_status_t msx_process_get_info(uint32_t pid, msx_process_info_t *out) {
    if (!out) return MSX_ERR_INVALID_ARG;
    if (!msx_process_exists(pid)) return MSX_ERR_NOT_FOUND;
    fill_single_proc(pid, out);
    return MSX_OK;
}

int msx_process_exists(uint32_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u", pid);
    struct stat st;
    return stat(path, &st) == 0;
}

/* ======================================================================
 *  WINDOWS IMPLEMENTATION  (documented Win32 / PSAPI / Toolhelp32 only)
 * ====================================================================== */
#elif defined(MSX_PLATFORM_WINDOWS)

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

static void get_process_user(HANDLE hProcess, char *out, size_t out_len) {
    msx_safe_strcpy(out, out_len, "unknown");
    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) return;

    DWORD len = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &len);
    if (len == 0) { CloseHandle(hToken); return; }

    PTOKEN_USER tokenUser = (PTOKEN_USER)malloc(len);
    if (!tokenUser) { CloseHandle(hToken); return; }

    if (GetTokenInformation(hToken, TokenUser, tokenUser, len, &len)) {
        char name[256], domain[256];
        DWORD nameLen = sizeof(name), domainLen = sizeof(domain);
        SID_NAME_USE sidType;
        if (LookupAccountSidA(NULL, tokenUser->User.Sid, name, &nameLen,
                               domain, &domainLen, &sidType)) {
            snprintf(out, out_len, "%s\\%s", domain, name);
        }
    }
    free(tokenUser);
    CloseHandle(hToken);
}

static int get_integrity_level(HANDLE hProcess) {
    HANDLE hToken = NULL;
    int level = -1;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) return -1;

    DWORD len = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &len);
    if (len == 0) { CloseHandle(hToken); return -1; }

    PTOKEN_MANDATORY_LABEL til = (PTOKEN_MANDATORY_LABEL)malloc(len);
    if (!til) { CloseHandle(hToken); return -1; }

    if (GetTokenInformation(hToken, TokenIntegrityLevel, til, len, &len)) {
        DWORD subAuthCount = *GetSidSubAuthorityCount(til->Label.Sid);
        DWORD rid = *GetSidSubAuthority(til->Label.Sid, subAuthCount - 1);
        if (rid < SECURITY_MANDATORY_MEDIUM_RID) level = 0;      /* Low */
        else if (rid < SECURITY_MANDATORY_HIGH_RID) level = 1;   /* Medium */
        else if (rid < SECURITY_MANDATORY_SYSTEM_RID) level = 2; /* High */
        else level = 3;                                          /* System */
    }
    free(til);
    CloseHandle(hToken);
    return level;
}

static void fill_single_proc(uint32_t pid, msx_process_info_t *info) {
    memset(info, 0, sizeof(*info));
    info->pid = pid;
    info->integrity_level = -1;
    info->is_64bit = -1;
    info->accessible = 0;

    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return;

    info->accessible = 1;

    char exePath[MSX_MAX_PATH_LEN];
    DWORD size = MSX_MAX_PATH_LEN;
    if (QueryFullProcessImageNameA(hProcess, 0, exePath, &size)) {
        msx_safe_strcpy(info->exe_path, MSX_MAX_PATH_LEN, exePath);
        const char *base = strrchr(exePath, '\\');
        msx_safe_strcpy(info->name, MSX_MAX_NAME_LEN, base ? base + 1 : exePath);
    }

    FILETIME create_ft, exit_ft, kernel_ft, user_ft;
    if (GetProcessTimes(hProcess, &create_ft, &exit_ft, &kernel_ft, &user_ft)) {
        ULARGE_INTEGER ull;
        ull.LowPart = create_ft.dwLowDateTime;
        ull.HighPart = create_ft.dwHighDateTime;
        /* Windows FILETIME epoch -> Unix epoch */
        info->create_time = (time_t)((ull.QuadPart - 116444736000000000ULL) / 10000000ULL);
    }

    PROCESS_MEMORY_COUNTERS_EX pmc;
    if (GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS *)&pmc, sizeof(pmc))) {
        info->vm_rss_bytes = pmc.WorkingSetSize;
        info->vm_size_bytes = pmc.PrivateUsage;
    }

    BOOL wow64 = FALSE;
    IsWow64Process(hProcess, &wow64);
    SYSTEM_INFO si; GetNativeSystemInfo(&si);
    if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
        si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) {
        info->is_64bit = wow64 ? 0 : 1;
    } else {
        info->is_64bit = 0;
    }

    get_process_user(hProcess, info->user, MSX_MAX_USER_LEN);
    info->integrity_level = get_integrity_level(hProcess);

    /* Thread count via Toolhelp32 snapshot (per-process) */
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te; te.dwSize = sizeof(te);
        uint32_t count = 0;
        if (Thread32First(hThreadSnap, &te)) {
            do {
                if (te.th32OwnerProcessID == pid) count++;
            } while (Thread32Next(hThreadSnap, &te));
        }
        info->thread_count = count;
        CloseHandle(hThreadSnap);
    }

    CloseHandle(hProcess);
}

msx_status_t msx_process_enum(msx_process_list_t *out) {
    if (!out) return MSX_ERR_INVALID_ARG;
    msx_process_list_t_init(out);

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return MSX_ERR_IO;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (!Process32First(hSnap, &pe)) {
        CloseHandle(hSnap);
        return MSX_ERR_IO;
    }

    do {
        msx_process_info_t info;
        fill_single_proc(pe.th32ProcessID, &info);
        info.ppid = pe.th32ParentProcessID;
        if (info.name[0] == '\0') {
            msx_safe_strcpy(info.name, MSX_MAX_NAME_LEN, pe.szExeFile);
        }
        if (msx_process_list_t_push(out, info) != 0) {
            CloseHandle(hSnap);
            msx_process_list_t_free(out);
            return MSX_ERR_OUT_OF_MEMORY;
        }
    } while (Process32Next(hSnap, &pe));

    CloseHandle(hSnap);
    return MSX_OK;
}

msx_status_t msx_process_get_info(uint32_t pid, msx_process_info_t *out) {
    if (!out) return MSX_ERR_INVALID_ARG;
    fill_single_proc(pid, out);
    if (!out->accessible) return MSX_ERR_PERMISSION_DENIED;
    return MSX_OK;
}

int msx_process_exists(uint32_t pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return 0;
    DWORD code;
    int alive = GetExitCodeProcess(h, &code) && code == STILL_ACTIVE;
    CloseHandle(h);
    return alive;
}

#endif /* platform */
