extern "C" {
#include "ddtrace8/clocks.h"

#include <Zend/zend_portability.h>
}

#include <ctime>  // for clock_gettime, CLOCK_MONOTONIC

ddtrace8_monotonic_nsec_t ddtrace8_monotonic_nsec(void) {
    struct timespec timespec {};
    if (UNEXPECTED(clock_gettime(CLOCK_MONOTONIC, &timespec))) {
        return 0;
    }
    return ((int64_t)timespec.tv_sec) * INT64_C(1000000000) + ((int64_t)timespec.tv_nsec);
}

ddtrace8_monotonic_usec_t ddtrace8_monotonic_usec(void) {
    struct timespec timespec {};
    if (UNEXPECTED(clock_gettime(CLOCK_MONOTONIC, &timespec))) {
        return 0;
    }
    return ((int64_t)timespec.tv_sec) * INT64_C(1000000) +
           ((int64_t)timespec.tv_nsec / INT64_C(1000));
}

ddtrace8_realtime_nsec_t ddtrace8_realtime_nsec(void) {
    struct timespec timespec {};
    if (UNEXPECTED(clock_gettime(CLOCK_REALTIME, &timespec))) {
        return 0;
    }
    return ((int64_t)timespec.tv_sec) * INT64_C(1000000000) + ((int64_t)timespec.tv_nsec);
}
