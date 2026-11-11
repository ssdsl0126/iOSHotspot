#pragma once
#include <time.h>

// 同一套单调时钟与期限用于清理、父进程、IPC及界面，外层必须留出收尾时间。
enum {
    IHRadioStopTimeout = 4,
    IHVPNCleanupTimeout = 10,
    IHVPNStopTimeout = 12,
    IHMutationRequestTimeout = 18,
    IHHotspotTransitionTimeout = 25,
    IHStatusRequestTimeout = 4
};
static inline double IHMonotonicTime(void) {
    struct timespec value;
    clock_gettime(CLOCK_MONOTONIC, &value);
    return value.tv_sec + value.tv_nsec / 1e9;
}
