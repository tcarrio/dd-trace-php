#ifndef DATADOG_PHP_TRACE_H
#define DATADOG_PHP_TRACE_H

#include <components/uuid/uuid.h>
#include <stdint.h>

// TODO: handle forking

/**
 * Initialize the runtime id of the process.
 * @return true on success. If this fails, any runtime id returned will be the
           'nil' UUID 00000000-0000-0000-0000-000000000000.
 */
void datadog_php_runtime_first_activate(void);

datadog_php_uuid datadog_php_runtime_id(void);

#endif
