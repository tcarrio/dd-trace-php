#include "engine_hooks.h"

#include <Zend/zend.h>
#include <Zend/zend_exceptions.h>
#include <Zend/zend_interfaces.h>
#include <php.h>

#include <ext/spl/spl_exceptions.h>

#include "../ddtrace.h"
#include "../dispatch.h"
#include "compatibility.h"
#include "ddtrace.h"
#include "dispatch.h"
#include "logging.h"
#include "span.h"

ZEND_EXTERN_MODULE_GLOBALS(ddtrace);

#define DDTRACE_NOT_TRACED ((void *)1)
int ddtrace_resource = -1;

static ddtrace_dispatch_t *dd_lookup_dispatch_from_fbc(zval *this, zend_function *fbc TSRMLS_DC) {
    if (DDTRACE_G(disable_in_current_request) || !DDTRACE_G(class_lookup) || !DDTRACE_G(function_lookup) || !fbc) {
        return NULL;
    }

    // Don't trace closures or functions without names
    if ((fbc->common.fn_flags & ZEND_ACC_CLOSURE) || !fbc->common.function_name) {
        return NULL;
    }

    zval fname_zv, *fname = &fname_zv;
    ZVAL_STRING(fname, fbc->common.function_name, 0);

    return ddtrace_find_dispatch(this ? Z_OBJCE_P(this) : fbc->common.scope, fname TSRMLS_CC);
}

static bool dd_should_trace_dispatch(ddtrace_dispatch_t *dispatch TSRMLS_DC) {
    if (dispatch->busy) {
        return false;
    }

    if (dispatch->options & (DDTRACE_DISPATCH_NON_TRACING)) {
        // non-tracing types should trigger regardless of limited tracing mode
        return true;
    }

    if (ddtrace_tracer_is_limited(TSRMLS_C) && (dispatch->options & DDTRACE_DISPATCH_INSTRUMENT_WHEN_LIMITED) == 0) {
        return false;
    }
    return true;
}

// args should be a valid but uninitialized zval.
static int ddtrace_copy_function_args(zval *args TSRMLS_DC) {
    void **p = zend_vm_stack_top(TSRMLS_C) - 1;
    int arg_count = (int)(zend_uintptr_t)*p;

    array_init_size(args, arg_count);
    return zend_copy_parameters_array(arg_count, args TSRMLS_CC);
}

typedef void (*ddtrace_execute_hook)(zend_op_array *op_array TSRMLS_DC);

static void (*dd_prev_execute)(zend_op_array *op_array TSRMLS_DC);

void ddtrace_execute_tracing_posthook(zend_op_array *op_array TSRMLS_DC) { dd_prev_execute(op_array TSRMLS_CC); }

void ddtrace_execute_non_tracing_posthook(zend_op_array *op_array TSRMLS_DC) {
    ddtrace_dispatch_t *dispatch = op_array->reserved[ddtrace_resource];

    zval *retval_dummy = NULL;
    bool free_retval = 0;
    if (!EG(return_value_ptr_ptr)) {
        EG(return_value_ptr_ptr) = &retval_dummy;
        free_retval = 1;
    }

    ddtrace_dispatch_copy(dispatch);
    dispatch->busy = 1;
    dd_prev_execute(op_array TSRMLS_CC);
    dispatch->busy = 0;
    ddtrace_dispatch_release(dispatch);

    zend_fcall_info fci = {0};
    zend_fcall_info_cache fcc = {0};

    if (zend_fcall_info_init(&dispatch->posthook, 0, &fci, &fcc, NULL, NULL TSRMLS_CC) != SUCCESS) {
        return;
    }

    /* We only bind $this on PHP 5, because if we don't it will flag any
     * closures that get defined within the prehook call to be static, which
     * means they can't be bound during trace_method.
     * Phooey.
     */
    fcc.initialized = 1;

    zval *args;
    MAKE_STD_ZVAL(args);
    ddtrace_copy_function_args(args TSRMLS_CC);

    // We don't do anything with the prehook return value
    zval *unused_retval = NULL;
    fci.retval_ptr_ptr = &unused_retval;

    zval *called_this = EG(uninitialized_zval_ptr), *called_scope = EG(uninitialized_zval_ptr);
    zend_class_entry *scope = EG(called_scope);  // is this right?
    if (scope) {
        fcc.called_scope = scope;
        if (EG(This)) {
            MAKE_STD_ZVAL(called_this);
            ZVAL_ZVAL(called_this, EG(This), 1, 0);
            fcc.object_ptr = called_this;
        }

        MAKE_STD_ZVAL(called_scope);
        ZVAL_STRINGL(called_scope, scope->name, scope->name_length, 1);

        if (zend_fcall_info_argn(&fci TSRMLS_CC, 4, &called_this, &called_scope, &args, EG(return_value_ptr_ptr)) !=
            SUCCESS) {
            goto release_args;
        }
    } else {
        if (zend_fcall_info_argn(&fci TSRMLS_CC, 2, &args, EG(return_value_ptr_ptr)) != SUCCESS) {
            goto release_args;
        }
    }

    ddtrace_dispatch_copy(dispatch);
    dispatch->busy = 1;

    if (zend_call_function(&fci, &fcc TSRMLS_CC) != SUCCESS) {
        // todo: debug
    }

    dispatch->busy = 0;
    ddtrace_dispatch_release(dispatch);

release_args:
    zend_fcall_info_args_clear(&fci, 1);
    if (called_this != EG(uninitialized_zval_ptr)) {
        zval_ptr_dtor(&called_this);
    }
    if (called_scope != EG(uninitialized_zval_ptr)) {
        zval_ptr_dtor(&called_scope);
    }
    if (unused_retval) {
        zval_ptr_dtor(&unused_retval);
    }
    zval_ptr_dtor(&args);

    if (free_retval && *EG(return_value_ptr_ptr)) {
        zval_ptr_dtor(EG(return_value_ptr_ptr));
        EG(return_value_ptr_ptr) = NULL;
    }
}

void ddtrace_execute_tracing_prehook(zend_op_array *op_array TSRMLS_DC) {
    // tracing prehook not yet supported on PHP 5
    dd_prev_execute(op_array TSRMLS_CC);
}

void ddtrace_execute_non_tracing_prehook(zend_op_array *op_array TSRMLS_DC) {
    ddtrace_dispatch_t *dispatch = op_array->reserved[ddtrace_resource];

    zend_fcall_info fci = {0};
    zend_fcall_info_cache fcc = {0};

    if (zend_fcall_info_init(&dispatch->prehook, 0, &fci, &fcc, NULL, NULL TSRMLS_CC) != SUCCESS) {
        goto call_previous;
    }

    /* We only bind $this on PHP 5, because if we don't it will flag any
     * closures that get defined within the prehook call to be static, which
     * means they can't be bound during trace_method.
     * Phooey.
     */
    fcc.initialized = 1;

    zval *args;
    MAKE_STD_ZVAL(args);
    ddtrace_copy_function_args(args TSRMLS_CC);

    // We don't do anything with the prehook return value
    zval *unused_retval = NULL;
    fci.retval_ptr_ptr = &unused_retval;

    zval *called_this = EG(uninitialized_zval_ptr), *called_scope = EG(uninitialized_zval_ptr);
    zend_class_entry *scope = EG(called_scope);  // is this right?
    if (scope) {
        fcc.called_scope = scope;
        if (EG(This)) {
            MAKE_STD_ZVAL(called_this);
            ZVAL_ZVAL(called_this, EG(This), 1, 0);
            fcc.object_ptr = called_this;
        }

        MAKE_STD_ZVAL(called_scope);
        ZVAL_STRINGL(called_scope, scope->name, scope->name_length, 1);

        if (zend_fcall_info_argn(&fci TSRMLS_CC, 3, &called_this, &called_scope, &args) != SUCCESS) {
            goto release_args;
        }
    } else {
        if (zend_fcall_info_argn(&fci TSRMLS_CC, 1, &args) != SUCCESS) {
            goto release_args;
        }
    }

    ddtrace_dispatch_copy(dispatch);
    dispatch->busy = 1;

    if (zend_call_function(&fci, &fcc TSRMLS_CC) != SUCCESS) {
        // todo: debug
    }

    dispatch->busy = 0;
    ddtrace_dispatch_release(dispatch);

release_args:
    zend_fcall_info_args_clear(&fci, 1);
    if (called_this != EG(uninitialized_zval_ptr)) {
        zval_ptr_dtor(&called_this);
    }
    if (called_scope != EG(uninitialized_zval_ptr)) {
        zval_ptr_dtor(&called_scope);
    }
    if (unused_retval) {
        zval_ptr_dtor(&unused_retval);
    }
    zval_ptr_dtor(&args);

call_previous:
    dd_prev_execute(op_array TSRMLS_CC);
}

static ddtrace_execute_hook execute_hooks[] = {
    [DDTRACE_DISPATCH_POSTHOOK] = ddtrace_execute_tracing_posthook,
    [DDTRACE_DISPATCH_POSTHOOK | DDTRACE_DISPATCH_NON_TRACING] = ddtrace_execute_non_tracing_posthook,
    [DDTRACE_DISPATCH_PREHOOK] = ddtrace_execute_tracing_prehook,
    [DDTRACE_DISPATCH_PREHOOK | DDTRACE_DISPATCH_NON_TRACING] = ddtrace_execute_non_tracing_prehook,
};

static bool ddtrace_try_fetch_dispatch(zend_op_array *op_array TSRMLS_DC, ddtrace_dispatch_t **dispatch_ptr) {
    void *slot = op_array->reserved[ddtrace_resource];

    if (slot == DDTRACE_NOT_TRACED) {
        return false;
    }

    // we're not yet set-up to respect a cached dispatch; only a NOT_TRACED flag
    ddtrace_dispatch_t *dispatch = NULL;
    zval *This = EG(This);
    zend_function *fbc = (zend_function *)op_array;
    dispatch = dd_lookup_dispatch_from_fbc(This, fbc TSRMLS_CC);
    op_array->reserved[ddtrace_resource] = dispatch ? dispatch : DDTRACE_NOT_TRACED;

    *dispatch_ptr = dispatch;

    return dispatch && dd_should_trace_dispatch(dispatch TSRMLS_CC);
}

static void ddtrace_execute(zend_op_array *op_array TSRMLS_DC) {
    ddtrace_dispatch_t *dispatch = NULL;
    ddtrace_execute_hook execute_hook = ddtrace_try_fetch_dispatch(op_array TSRMLS_CC, &dispatch)
                                            ? execute_hooks[dispatch->options & UINT16_C(3)]
                                            : dd_prev_execute;

    execute_hook(op_array TSRMLS_CC);
}

// todo: consolidate all these init hooks (no need for opcode and execute_internal to have own init/shutdown)
void ddtrace_opcode_minit(void) {}
void ddtrace_opcode_mshutdown(void) {}

void ddtrace_execute_internal_minit(void) {
    dd_prev_execute = zend_execute;
    zend_execute = ddtrace_execute;
}

void ddtrace_execute_internal_mshutdown(void) {
    if (zend_execute == ddtrace_execute) {
        zend_execute = dd_prev_execute;
    }
}
