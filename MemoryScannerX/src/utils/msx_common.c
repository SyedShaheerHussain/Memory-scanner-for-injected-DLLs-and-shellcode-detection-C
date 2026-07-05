#include "utils/msx_common.h"

const char *msx_status_str(msx_status_t s) {
    switch (s) {
        case MSX_OK: return "OK";
        case MSX_ERR_UNKNOWN: return "Unknown error";
        case MSX_ERR_PERMISSION_DENIED: return "Permission denied";
        case MSX_ERR_NOT_FOUND: return "Not found";
        case MSX_ERR_INVALID_ARG: return "Invalid argument";
        case MSX_ERR_OUT_OF_MEMORY: return "Out of memory";
        case MSX_ERR_IO: return "I/O error";
        case MSX_ERR_UNSUPPORTED: return "Unsupported operation";
        case MSX_ERR_PARTIAL_READ: return "Partial read";
        case MSX_ERR_PROCESS_EXITED: return "Process exited";
        case MSX_ERR_BUFFER_TOO_SMALL: return "Buffer too small";
        default: return "?";
    }
}

const char *msx_risk_str(msx_risk_level_t r) {
    switch (r) {
        case MSX_RISK_NONE: return "None";
        case MSX_RISK_LOW: return "Low";
        case MSX_RISK_MEDIUM: return "Medium";
        case MSX_RISK_HIGH: return "High";
        case MSX_RISK_CRITICAL: return "Critical";
        default: return "?";
    }
}
