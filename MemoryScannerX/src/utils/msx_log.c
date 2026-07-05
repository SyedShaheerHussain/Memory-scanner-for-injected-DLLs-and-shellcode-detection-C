#include "utils/msx_log.h"
#include "utils/msx_common.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#if defined(MSX_PLATFORM_WINDOWS)
#include <windows.h>
static CRITICAL_SECTION g_log_mutex;
static int g_mutex_init = 0;
#else
#include <pthread.h>
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

static FILE *g_log_fp = NULL;
static msx_log_level_t g_min_level = MSX_LOG_INFO;
static int g_color = 1;

static void lock(void) {
#if defined(MSX_PLATFORM_WINDOWS)
    if (!g_mutex_init) { InitializeCriticalSection(&g_log_mutex); g_mutex_init = 1; }
    EnterCriticalSection(&g_log_mutex);
#else
    pthread_mutex_lock(&g_log_mutex);
#endif
}

static void unlock(void) {
#if defined(MSX_PLATFORM_WINDOWS)
    LeaveCriticalSection(&g_log_mutex);
#else
    pthread_mutex_unlock(&g_log_mutex);
#endif
}

void msx_log_init(const char *log_file_path, msx_log_level_t min_level, int color_console) {
    g_min_level = min_level;
    g_color = color_console;
    if (log_file_path && log_file_path[0]) {
        g_log_fp = fopen(log_file_path, "a");
    }
}

void msx_log_shutdown(void) {
    if (g_log_fp) { fclose(g_log_fp); g_log_fp = NULL; }
}

void msx_log_set_level(msx_log_level_t lvl) { g_min_level = lvl; }

static const char *level_name(msx_log_level_t lvl) {
    switch (lvl) {
        case MSX_LOG_TRACE: return "TRACE";
        case MSX_LOG_DEBUG: return "DEBUG";
        case MSX_LOG_INFO:  return "INFO ";
        case MSX_LOG_WARN:  return "WARN ";
        case MSX_LOG_ERROR: return "ERROR";
        default: return "?????";
    }
}

static const char *level_color(msx_log_level_t lvl) {
    switch (lvl) {
        case MSX_LOG_TRACE: return "\x1b[90m";
        case MSX_LOG_DEBUG: return "\x1b[36m";
        case MSX_LOG_INFO:  return "\x1b[32m";
        case MSX_LOG_WARN:  return "\x1b[33m";
        case MSX_LOG_ERROR: return "\x1b[31m";
        default: return "\x1b[0m";
    }
}

void msx_log_write(msx_log_level_t lvl, const char *file, int line, const char *fmt, ...) {
    if (lvl < g_min_level) return;

    time_t t = time(NULL);
    struct tm tm_buf;
#if defined(MSX_PLATFORM_WINDOWS)
    localtime_s(&tm_buf, &t);
#else
    localtime_r(&t, &tm_buf);
#endif
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm_buf);

    /* extract basename only, to keep logs concise */
    const char *base = strrchr(file, '/');
    if (!base) base = strrchr(file, '\\');
    base = base ? base + 1 : file;

    lock();

    va_list args;
    va_start(args, fmt);

    if (g_color) {
        fprintf(stdout, "%s[%s] %s (%s:%d) - ", level_color(lvl), ts, level_name(lvl), base, line);
        vfprintf(stdout, fmt, args);
        fprintf(stdout, "\x1b[0m\n");
    } else {
        fprintf(stdout, "[%s] %s (%s:%d) - ", ts, level_name(lvl), base, line);
        vfprintf(stdout, fmt, args);
        fprintf(stdout, "\n");
    }
    va_end(args);

    if (g_log_fp) {
        va_list args2;
        va_start(args2, fmt);
        fprintf(g_log_fp, "[%s] %s (%s:%d) - ", ts, level_name(lvl), base, line);
        vfprintf(g_log_fp, fmt, args2);
        fprintf(g_log_fp, "\n");
        fflush(g_log_fp);
        va_end(args2);
    }

    unlock();
}
