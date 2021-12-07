#include "runtime.h"

#include <php.h>

// must happen after php.h
#include <ext/standard/php_random.h>

static datadog_php_uuid runtime_id = DATADOG_PHP_UUID_INIT;

void datadog_php_runtime_first_activate(void) {
    alignas(16) uint8_t data[16];

    if (php_random_bytes_silent(data, sizeof data) == SUCCESS) {
        datadog_php_uuidv4_bytes_ctor(&runtime_id, data);
    }
}

datadog_php_uuid datadog_php_runtime_id(void) { return runtime_id; }
