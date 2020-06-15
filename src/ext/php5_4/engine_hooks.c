#include "engine_hooks.h"

#include <Zend/zend.h>
#include <Zend/zend_exceptions.h>
#include <Zend/zend_interfaces.h>
#include <php.h>


#include "compatibility.h"
#include "ddtrace.h"
#include "dispatch.h"
#include "logging.h"

ZEND_EXTERN_MODULE_GLOBALS(ddtrace);

// todo: implement op_array.reserved caching for calls that do not trace
int ddtrace_resource = -1;

void ddtrace_opcode_minit(void) {}
void ddtrace_opcode_mshutdown(void) {}

void ddtrace_execute_internal_minit(void) {
    // TODO
}

void ddtrace_execute_internal_mshutdown(void) {
    // TODO
}
