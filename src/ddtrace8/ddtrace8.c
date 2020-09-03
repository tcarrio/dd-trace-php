/* ddtrace8 extension for PHP */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <Zend/zend_observer.h>
#include <php.h>

#include <ext/standard/info.h>

#include "ddtrace8/integrations.h"
#include "ddtrace8/observers.h"
#include "ddtrace8_arginfo.h"
#include "php_ddtrace8.h"

// this is a dummy extension, used for resource_number
zend_extension ddtrace8_extension = {"ddtrace8", PHP_DDTRACE8_VERSION};

int ddtrace8_op_array_extension_slot1, ddtrace8_op_array_extension_slot2;

PHP_FUNCTION(dd_trace_noop) { ZEND_PARSE_PARAMETERS_NONE(); }

PHP_MINIT_FUNCTION(ddtrace8) {
    ddtrace8_op_array_extension_slot1 = zend_get_op_array_extension_handle();
    ddtrace8_op_array_extension_slot2 = zend_get_op_array_extension_handle();

    zend_get_resource_handle(&ddtrace8_extension);

    zend_observer_fcall_register(ddtrace8_observer_fcall_init);

    ddtrace8_integrations_minit();

    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(ddtrace8) {
    ddtrace8_integrations_mshutdown();

    return SUCCESS;
}

PHP_RINIT_FUNCTION(ddtrace8) {
#if defined(ZTS) && defined(COMPILE_DL_DDTRACE8)
    ZEND_TSRMLS_CACHE_UPDATE();
#endif
    ddtrace8_observer_rinit();
    ddtrace8_integrations_rinit();

    return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(ddtrace8) {
    ddtrace8_integrations_rshutdown();
    ddtrace8_observer_rshutdown();

    return SUCCESS;
}

PHP_MINFO_FUNCTION(ddtrace8) {
    php_info_print_table_start();
    php_info_print_table_header(2, "ddtrace8 support", "enabled");
    php_info_print_table_end();
}

zend_module_entry ddtrace8_module_entry = {
    STANDARD_MODULE_HEADER,
    "ddtrace8",              /* Extension name */
    ext_functions,           /* zend_function_entry */
    PHP_MINIT(ddtrace8),     /* PHP_MINIT - Module initialization */
    PHP_MSHUTDOWN(ddtrace8), /* PHP_MSHUTDOWN - Module shutdown */
    PHP_RINIT(ddtrace8),     /* PHP_RINIT - Request initialization */
    PHP_RSHUTDOWN(ddtrace8), /* PHP_RSHUTDOWN - Request shutdown */
    PHP_MINFO(ddtrace8),     /* PHP_MINFO - Module info */
    PHP_DDTRACE8_VERSION,    /* Version */
    STANDARD_MODULE_PROPERTIES};

#ifdef COMPILE_DL_DDTRACE8
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
#endif
ZEND_GET_MODULE(ddtrace8)
#endif
