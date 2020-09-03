#ifndef DDTRACE8_CLOCK_H
#define DDTRACE8_CLOCK_H

#include <stdint.h>

typedef int64_t ddtrace8_monotonic_nsec_t;
typedef int64_t ddtrace8_monotonic_usec_t;
typedef int64_t ddtrace8_realtime_nsec_t;

ddtrace8_monotonic_nsec_t ddtrace8_monotonic_nsec(void);
ddtrace8_monotonic_usec_t ddtrace8_monotonic_usec(void);
ddtrace8_realtime_nsec_t ddtrace8_realtime_nsec(void);

#endif  // DDTRACE8_CLOCK_H
