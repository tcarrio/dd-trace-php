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

static bool _dd_should_trace_anything(void) {
    return !DDTRACE_G(disable_in_current_request) && DDTRACE_G(class_lookup) && DDTRACE_G(function_lookup);
}

static ddtrace_dispatch_t *_dd_lookup_dispatch_from_fbc(zval *this, zend_function *fbc TSRMLS_DC) {
    if (!_dd_should_trace_anything() || !fbc) {
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

static bool _dd_should_trace_dispatch(ddtrace_dispatch_t *dispatch TSRMLS_DC) {
    // currently, we only trace posthooks
    if (!(dispatch->options & DDTRACE_DISPATCH_POSTHOOK)) {
        return false;
    }

    if (dispatch->busy) {
        return false;
    }
    if (ddtrace_tracer_is_limited(TSRMLS_C) && (dispatch->options & DDTRACE_DISPATCH_INSTRUMENT_WHEN_LIMITED) == 0) {
        return false;
    }

    return true;
}

/**
 * user_args should be a valid but uninitialized zval.
 */
static int ddtrace_copy_function_args(zval *user_args TSRMLS_DC) {
    void **p = zend_vm_stack_top(TSRMLS_C) - 1;
    int arg_count = (int)(zend_uintptr_t)*p;

    array_init_size(user_args, arg_count);
    return zend_copy_parameters_array(arg_count, user_args TSRMLS_CC);
}

static zval *ddtrace_exception_get_entry(zval *object, char *name, int name_len TSRMLS_DC) {
    zend_class_entry *exception_ce = zend_exception_get_default(TSRMLS_C);
    return zend_read_property(exception_ce, object, name, name_len, 1 TSRMLS_CC);
}

static void ddtrace_span_attach_exception(ddtrace_span_t *span, ddtrace_exception_t *exception) {
    if (exception) {
        MAKE_STD_ZVAL(span->exception);
        ZVAL_COPY_VALUE(span->exception, exception);
        zval_copy_ctor(span->exception);
    }
}

BOOL_T ddtrace_execute_tracing_closure(ddtrace_dispatch_t *dispatch, zval *span_data, zend_function *fbc,
                                       zval *user_args, zval *user_retval, zval *exception TSRMLS_DC) {
    BOOL_T status = TRUE;
    zend_fcall_info fci = {0};
    zend_fcall_info_cache fcc = {0};
    zval *retval_ptr = NULL;
    zval **args[4];
    zval *null_zval = &EG(uninitialized_zval);
    zval *this = EG(This);

    if (!span_data || !user_args || !user_retval) {
        if (get_dd_trace_debug()) {
            const char *fname = Z_STRVAL(dispatch->function_name);
            ddtrace_log_errf("Tracing closure could not be run for %s() because it is in an invalid state", fname);
        }
        return FALSE;
    }

    if (zend_fcall_info_init(&dispatch->callable, 0, &fci, &fcc, NULL, NULL TSRMLS_CC) == FAILURE) {
        ddtrace_log_debug("Could not init tracing closure");
        return FALSE;
    }

    /* Note: In PHP 5 there is a bug where closures are automatically
     * marked as static if they are defined from a static method context.
     * @see https://3v4l.org/Rgo87
     */
    if (this) {
        bool is_instance_method = !(fbc->common.fn_flags & ZEND_ACC_STATIC);
        bool is_closure_static = (fcc.function_handler->common.fn_flags & ZEND_ACC_STATIC);
        if (is_instance_method && is_closure_static) {
            ddtrace_log_debug("Cannot trace non-static method with static tracing closure");
            return FALSE;
        }
    }

    // Arg 0: DDTrace\SpanData $span
    args[0] = &span_data;

    // Arg 1: array $args
    args[1] = &user_args;

    // Arg 2: mixed $retval
    args[2] = &user_retval;
    // Arg 3: Exception|null $exception
    args[3] = exception ? &exception : &null_zval;

    fci.param_count = 4;
    fci.params = args;
    fci.retval_ptr_ptr = &retval_ptr;

    fcc.initialized = 1;
    fcc.object_ptr = this;
    fcc.called_scope = EG(called_scope);
    // Give the tracing closure access to private & protected class members
    fcc.function_handler->common.scope = fcc.called_scope;

    if (zend_call_function(&fci, &fcc TSRMLS_CC) == FAILURE) {
        ddtrace_log_debug("Could not execute tracing closure");
    }

    if (fci.retval_ptr_ptr && retval_ptr) {
        if (Z_TYPE_P(retval_ptr) == IS_BOOL) {
            status = Z_LVAL_P(retval_ptr) ? TRUE : FALSE;
        }
        zval_ptr_dtor(&retval_ptr);
    }

    return status;
}

static void _dd_execute_end_span(zend_function *fbc, ddtrace_span_t *span, zval *user_retval,
                                 const zend_op *opline_before_exception TSRMLS_DC) {
    ddtrace_dispatch_t *dispatch = span->dispatch;
    zval *exception = NULL, *prev_exception = NULL;

    zval *user_args;
    ALLOC_INIT_ZVAL(user_args);

    dd_trace_stop_span_time(span);

    // works based on stack layout
    ddtrace_copy_function_args(user_args TSRMLS_CC);

    if (EG(exception)) {
        exception = EG(exception);
        EG(exception) = NULL;
        prev_exception = EG(prev_exception);
        EG(prev_exception) = NULL;
        ddtrace_span_attach_exception(span, exception);
        zend_clear_exception(TSRMLS_C);
    }

    BOOL_T keep_span = TRUE;
    if (Z_TYPE(dispatch->callable) == IS_OBJECT) {
        ddtrace_error_handling eh;
        ddtrace_backup_error_handling(&eh, EH_SUPPRESS TSRMLS_CC);
        keep_span = ddtrace_execute_tracing_closure(dispatch, span->span_data, fbc, user_args, user_retval,
                                                    exception TSRMLS_CC);

        if (get_dd_trace_debug() && PG(last_error_message) && eh.message != PG(last_error_message)) {
            const char *fname = Z_STRVAL(dispatch->function_name);
            ddtrace_log_errf("Error raised in tracing closure for %s(): %s in %s on line %d", fname,
                             PG(last_error_message), PG(last_error_file), PG(last_error_lineno));
        }

        ddtrace_restore_error_handling(&eh TSRMLS_CC);
        // If the tracing closure threw an exception, ignore it to not impact the original call
        if (get_dd_trace_debug() && EG(exception)) {
            zval *ex = EG(exception), *message = NULL;
            const char *type = Z_OBJCE_P(ex)->name;
            const char *name = Z_STRVAL(dispatch->function_name);
            message = ddtrace_exception_get_entry(ex, ZEND_STRL("message") TSRMLS_CC);
            const char *msg = message && Z_TYPE_P(message) == IS_STRING ? Z_STRVAL_P(message)
                                                                        : "(internal error reading exception message)";
            ddtrace_log_errf("%s thrown in tracing closure for %s: %s", type, name, msg);
        }
        ddtrace_maybe_clear_exception(TSRMLS_C);
    }

    if (keep_span == TRUE) {
        ddtrace_close_span(TSRMLS_C);
    } else {
        ddtrace_drop_top_open_span(TSRMLS_C);
    }

    if (exception) {
        EG(exception) = exception;
        EG(prev_exception) = prev_exception;
        EG(opline_before_exception) = (zend_op *)opline_before_exception;
        EG(current_execute_data)->opline = EG(exception_op);
    } else {
        zval_ptr_dtor(&user_args);
    }
}

static void (*_dd_prev_execute)(zend_op_array *op_array TSRMLS_DC);
static void ddtrace_execute(zend_op_array *op_array TSRMLS_DC) {
    zval *This = EG(This);
    zend_function *fbc = (zend_function *)op_array;
    ddtrace_dispatch_t *dispatch = _dd_lookup_dispatch_from_fbc(This, fbc TSRMLS_CC);
    bool should_trace;
    ddtrace_span_t *span = NULL;
    zend_op *opline = NULL;  // todo: how to get this?
    zval *retval = NULL;
    bool free_retval = false;

    if ((should_trace = dispatch && _dd_should_trace_dispatch(dispatch TSRMLS_CC))) {
        dispatch->busy = 1;
        ddtrace_dispatch_copy(dispatch);

        // don't have an execute frame here; EG(current_execute_data) is often NULL
        span = ddtrace_open_span(NULL, dispatch TSRMLS_CC);

        /* If the retval doesn't get used then sometimes the engine won't set
         * the retval_ptr_ptr at all. We expect it to always be present, so
         * adjust it. Be sure to dtor it later.
         */
        if (!EG(return_value_ptr_ptr)) {
            EG(return_value_ptr_ptr) = &retval;
            free_retval = true;
        }
    }

    _dd_prev_execute(op_array TSRMLS_DC);

    if (!should_trace) {
        return;
    }

    if (span == DDTRACE_G(open_spans_top)) {
        zval *return_value =
            (EG(return_value_ptr_ptr) && *EG(return_value_ptr_ptr)) ? *EG(return_value_ptr_ptr) : &zval_used_for_init;
        _dd_execute_end_span(fbc, span, return_value, opline TSRMLS_CC);
    } else {
        if (get_dd_trace_debug()) {
            const char *fname = Z_STRVAL(dispatch->function_name);
            ddtrace_log_errf("Cannot run tracing closure for %s(); spans out of sync", fname);
        }
    }

    if (free_retval && *EG(return_value_ptr_ptr)) {
        zval_ptr_dtor(EG(return_value_ptr_ptr));
        EG(return_value_ptr_ptr) = NULL;
    }
}

static void (*_dd_prev_execute_internal)(zend_execute_data *execute_data, int return_value_used TSRMLS_DC);
static void ddtrace_execute_internal(zend_execute_data *execute_data, int return_value_used TSRMLS_DC) {
    zval *This = EG(This);
    zend_function *fbc = execute_data->function_state.function;
    ddtrace_dispatch_t *dispatch = _dd_lookup_dispatch_from_fbc(This, fbc TSRMLS_CC);
    bool should_trace;
    ddtrace_span_t *span = NULL;

    zval *return_value = NULL, **return_value_ptr = NULL;
    if ((should_trace = dispatch && _dd_should_trace_dispatch(dispatch TSRMLS_CC))) {
        dispatch->busy = 1;
        ddtrace_dispatch_copy(dispatch);

        span = ddtrace_open_span(execute_data, dispatch TSRMLS_CC);

        // taken from `execute_internal` on PHP 5.4
        return_value_ptr = &(*(temp_variable *)((char *)EX(Ts) + EX(opline)->result.var)).var.ptr;
        return_value =
            (EX(function_state).function->common.fn_flags & ZEND_ACC_RETURN_REFERENCE) ? NULL : *return_value_ptr;
    }

    _dd_prev_execute_internal(execute_data, return_value_used TSRMLS_CC);

    if (!should_trace) {
        return;
    }

    if (span == DDTRACE_G(open_spans_top)) {
        _dd_execute_end_span(fbc, span, return_value, EX(opline) TSRMLS_CC);
    } else {
        if (get_dd_trace_debug()) {
            const char *fname = Z_STRVAL(dispatch->function_name);
            ddtrace_log_errf("Cannot run tracing closure for %s(); spans out of sync", fname);
        }
    }
}

void ddtrace_opcode_minit(void) {}
void ddtrace_opcode_mshutdown(void) {}

// todo: switch to startup because of module blacklisting
void ddtrace_execute_internal_minit(void) {
    if (DDTRACE_G(disable)) {
        return;
    }

    _dd_prev_execute = zend_execute;
    zend_execute = ddtrace_execute;

    _dd_prev_execute_internal = zend_execute_internal ?: execute_internal;
    zend_execute_internal = ddtrace_execute_internal;
}

void ddtrace_execute_internal_mshutdown(void) {
    if (DDTRACE_G(disable)) {
        return;
    }

    zend_execute = ddtrace_execute;
    zend_execute_internal = _dd_prev_execute_internal == execute_internal ? NULL : _dd_prev_execute_internal;
}
