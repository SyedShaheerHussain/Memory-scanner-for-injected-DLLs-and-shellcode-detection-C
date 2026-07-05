/*
 * MemoryScannerX - msx_log.h
 * Lightweight thread-safe logging (console + optional file), leveled,
 * timestamped. Not async (kept simple/dependency-free); safe to swap
 * for spdlog-style backend later.
 */
#ifndef MSX_LOG_H
#define MSX_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    MSX_LOG_TRACE = 0,
    MSX_LOG_DEBUG,
    MSX_LOG_INFO,
    MSX_LOG_WARN,
    MSX_LOG_ERROR
} msx_log_level_t;

void msx_log_init(const char *log_file_path, msx_log_level_t min_level, int color_console);
void msx_log_shutdown(void);
void msx_log_set_level(msx_log_level_t lvl);

void msx_log_write(msx_log_level_t lvl, const char *file, int line, const char *fmt, ...);

#define MSX_LOG_TRACE(...) msx_log_write(MSX_LOG_TRACE, __FILE__, __LINE__, __VA_ARGS__)
#define MSX_LOG_DEBUG(...) msx_log_write(MSX_LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define MSX_LOG_INFO(...)  msx_log_write(MSX_LOG_INFO,  __FILE__, __LINE__, __VA_ARGS__)
#define MSX_LOG_WARN(...)  msx_log_write(MSX_LOG_WARN,  __FILE__, __LINE__, __VA_ARGS__)
#define MSX_LOG_ERROR(...) msx_log_write(MSX_LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif /* MSX_LOG_H */
