/* ddtrace8 extension for PHP */

#ifndef PHP_DDTRACE8_H
#define PHP_DDTRACE8_H

#include <Zend/zend_extensions.h>
#include <Zend/zend_modules.h>

extern zend_extension ddtrace8_extension;
extern int ddtrace8_op_array_extension_slot1, ddtrace8_op_array_extension_slot2;

#define DDTRACE8_OP_ARRAY_EXTENSION(op_array, which) \
    ZEND_OP_ARRAY_EXTENSION(op_array, ddtrace8_op_array_extension_##which)

extern zend_module_entry ddtrace8_module_entry;
#define phpext_ddtrace8_ptr &ddtrace8_module_entry

#define PHP_DDTRACE8_VERSION "0.1.0"

#if defined(ZTS) && defined(COMPILE_DL_DDTRACE8)
ZEND_TSRMLS_CACHE_EXTERN()
#endif

#endif /* PHP_DDTRACE8_H */
