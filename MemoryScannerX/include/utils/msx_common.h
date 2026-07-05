/*
 * MemoryScannerX - msx_common.h
 * Common types, error codes and macros shared across all modules.
 *
 * Copyright (c) 2026
 * License: MIT (see LICENSE)
 */
#ifndef MSX_COMMON_H
#define MSX_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) || defined(_WIN64)
#define MSX_PLATFORM_WINDOWS 1
#else
#define MSX_PLATFORM_LINUX 1
#endif

/* ---- Error codes ---------------------------------------------------- */
typedef enum {
    MSX_OK = 0,
    MSX_ERR_UNKNOWN = -1,
    MSX_ERR_PERMISSION_DENIED = -2,
    MSX_ERR_NOT_FOUND = -3,
    MSX_ERR_INVALID_ARG = -4,
    MSX_ERR_OUT_OF_MEMORY = -5,
    MSX_ERR_IO = -6,
    MSX_ERR_UNSUPPORTED = -7,
    MSX_ERR_PARTIAL_READ = -8,
    MSX_ERR_PROCESS_EXITED = -9,
    MSX_ERR_BUFFER_TOO_SMALL = -10
} msx_status_t;

const char *msx_status_str(msx_status_t s);

/* ---- Risk levels ------------------------------------------------------ */
typedef enum {
    MSX_RISK_NONE = 0,
    MSX_RISK_LOW = 1,
    MSX_RISK_MEDIUM = 2,
    MSX_RISK_HIGH = 3,
    MSX_RISK_CRITICAL = 4
} msx_risk_level_t;

const char *msx_risk_str(msx_risk_level_t r);

/* ---- Generic dynamic array helper (macro-based, type-generic) -------- */
#define MSX_ARRAY_INIT_CAP 16

#define MSX_DECLARE_ARRAY(NAME, TYPE)                                       \
    typedef struct {                                                        \
        TYPE *items;                                                        \
        size_t count;                                                       \
        size_t capacity;                                                    \
    } NAME;                                                                 \
    static inline void NAME##_init(NAME *arr) {                             \
        arr->items = NULL; arr->count = 0; arr->capacity = 0;                \
    }                                                                       \
    static inline int NAME##_reserve(NAME *arr, size_t min_cap) {           \
        if (arr->capacity >= min_cap) return 0;                            \
        size_t new_cap = arr->capacity ? arr->capacity * 2 : MSX_ARRAY_INIT_CAP; \
        while (new_cap < min_cap) new_cap *= 2;                             \
        TYPE *p = (TYPE *)realloc(arr->items, new_cap * sizeof(TYPE));      \
        if (!p) return -1;                                                  \
        arr->items = p; arr->capacity = new_cap;                            \
        return 0;                                                           \
    }                                                                       \
    static inline int NAME##_push(NAME *arr, TYPE val) {                    \
        if (NAME##_reserve(arr, arr->count + 1) != 0) return -1;            \
        arr->items[arr->count++] = val;                                     \
        return 0;                                                           \
    }                                                                       \
    static inline void NAME##_free(NAME *arr) {                             \
        free(arr->items); arr->items = NULL; arr->count = 0; arr->capacity = 0; \
    }

/* ---- Shared size constants (used across process/memory/module modules) */
#define MSX_MAX_PATH_LEN 4096
#define MSX_MAX_NAME_LEN 512
#define MSX_MAX_CMDLINE_LEN 8192
#define MSX_MAX_USER_LEN 256

/* ---- Misc -------------------------------------------------------------- */
#define MSX_UNUSED(x) ((void)(x))
#define MSX_MIN(a, b) ((a) < (b) ? (a) : (b))
#define MSX_MAX(a, b) ((a) > (b) ? (a) : (b))
#define MSX_ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

/* Bounded string copy that always null-terminates `dst` (size dst_size)
 * and never reads past a NUL in `src`. Silences -Wstringop-truncation
 * (which strncpy legitimately triggers even when the truncation is
 * intentional and safe) and centralizes the "copy into fixed buffer"
 * pattern used throughout process/memory/module info structs. */
static inline void msx_safe_strcpy(char *dst, size_t dst_size, const char *src) {
    if (!dst || dst_size == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    size_t i = 0;
    for (; i + 1 < dst_size && src[i] != '\0'; i++) dst[i] = src[i];
    dst[i] = '\0';
}

#ifdef __cplusplus
}
#endif

#endif /* MSX_COMMON_H */
