#include "engine_hooks.h"

#include <Zend/zend_closures.h>
#include <Zend/zend_compile.h>
#include <Zend/zend_exceptions.h>
#include <Zend/zend_generators.h>
#include <Zend/zend_interfaces.h>
#include <src/ext/ddtrace.h>
#include <stdbool.h>

#include <ext/spl/spl_exceptions.h>

#include "compatibility.h"
#include "ddtrace.h"
#include "debug.h"
#include "dispatch.h"
#include "env_config.h"
#include "logging.h"
#include "span.h"

ZEND_EXTERN_MODULE_GLOBALS(ddtrace)

int ddtrace_resource = -1;

#if PHP_VERSION_ID >= 70400
int ddtrace_op_array_extension = 0;
#endif

// True gloals; only modify in minit/mshutdown
static user_opcode_handler_t _prev_ucall_handler;
static user_opcode_handler_t _prev_fcall_handler;
static user_opcode_handler_t _prev_fcall_by_name_handler;
static user_opcode_handler_t _prev_return_handler;
static user_opcode_handler_t _prev_return_by_ref_handler;
#if PHP_VERSION_ID >= 70100
static user_opcode_handler_t _prev_yield_handler;
static user_opcode_handler_t _prev_yield_from_handler;
#endif
static user_opcode_handler_t _prev_handle_exception_handler;
static user_opcode_handler_t _prev_exit_handler;

#if PHP_VERSION_ID < 70100
#define RETURN_VALUE_USED(opline) (!((opline)->result_type & EXT_TYPE_UNUSED))
#else
#define RETURN_VALUE_USED(opline) ((opline)->result_type != IS_UNUSED)
#endif

static zval *_dd_this(zend_execute_data *call) {
    if (Z_TYPE(call->This) == IS_OBJECT && Z_OBJ(call->This) != NULL) {
        return &call->This;
    }
    return NULL;
}

#define DDTRACE_NOT_TRACED ((void *)1)

static bool _dd_should_trace_helper(zend_execute_data *call, zend_function *fbc, ddtrace_dispatch_t **dispatch_ptr) {
    if (DDTRACE_G(class_lookup) == NULL || DDTRACE_G(function_lookup) == NULL) {
        return false;
    }

    // Don't trace closures or functions without names
    if ((fbc->common.fn_flags & ZEND_ACC_CLOSURE) || !fbc->common.function_name) {
        return false;
    }

    zval fname;
    ZVAL_STR(&fname, fbc->common.function_name);

    zval *this = _dd_this(call);

    /* TODO: we can possibly grab the lowercased variants off the opline.
     * Levi: Do we store the function and method names lowered in the oplines
     *       anywhere?
     * Nikita: yes
     * Nikita: Function call opcodes and similar usually have multiple
     *         literals in a row
     * Nikita: So the CONST operand points to the first literal, and then
     *         there's a few more after it, with lowercased variants, or
     *         variants without namespace etc
     *
     * It would avoid lowering the string and reduce memory churn; win-win.
     */
    zend_class_entry *scope = this ? Z_OBJCE_P(this) : fbc->common.scope;

    ddtrace_dispatch_t *dispatch = ddtrace_find_dispatch(scope, &fname);
    if (dispatch != NULL && dispatch->options & DDTRACE_DISPATCH_DEFERRED_LOADER) {
        if (!dispatch->busy && Z_TYPE(dispatch->deferred_load_function_name) != IS_NULL) {
            ddtrace_sandbox_backup backup = ddtrace_sandbox_begin();

            // protect against the free when closure is ran so we can set busy = 1 if successful
            ddtrace_dispatch_copy(dispatch);
            zval retval;
            if (SUCCESS == call_user_function(EG(function_table), NULL, &dispatch->deferred_load_function_name, &retval,
                                              0, NULL)) {
                // we never set this back to 0; once an integration has been deferred loaded it shouldn't try again
                dispatch->busy = 1;
                ddtrace_dispatch_release(dispatch);

                // attempt to load newly set dispatch fo function
                dispatch = ddtrace_find_dispatch(scope, &fname);
            } else {
                ddtrace_dispatch_release(dispatch);
                dispatch = NULL;
            }
            zval_ptr_dtor(&retval);

            ddtrace_sandbox_end(&backup);
        } else {
            dispatch = NULL;
        }
    }

    if (dispatch_ptr != NULL) {
        *dispatch_ptr = dispatch;
    }
    return dispatch;
}

static bool _dd_should_trace_runtime(ddtrace_dispatch_t *dispatch) {
    // the callable can be NULL for ddtrace_known_integrations
    if (Z_TYPE(dispatch->callable) != IS_OBJECT && Z_TYPE(dispatch->callable) != IS_STRING) {
        return false;
    }

    if (dispatch->busy) {
        return false;
    }

    if (dispatch->options & (DDTRACE_DISPATCH_NON_TRACING)) {
        // non-tracing types should trigger regardless of limited tracing mode
        return true;
    }

    // todo: should this interact with non-tracing calls at all?
    if ((ddtrace_tracer_is_limited() && (dispatch->options & DDTRACE_DISPATCH_INSTRUMENT_WHEN_LIMITED) == 0)) {
        return false;
    }
    return true;
}

static bool _dd_should_trace_call(zend_execute_data *call, zend_function *fbc, ddtrace_dispatch_t **dispatch) {
    if (DDTRACE_G(disable_in_current_request)) {
        return false;
    }

#if PHP_VERSION_ID >= 70300
    /* From PHP 7.3's UPGRADING.INTERNALS:
     * Special purpose zend_functions marked by ZEND_ACC_CALL_VIA_TRAMPOLINE or
     * ZEND_ACC_FAKE_CLOSURE flags use reserved[0] for internal purpose.
     * Third party extensions must not modify reserved[] fields of these functions.
     *
     * On PHP 7.4, it seems to get used as well.
     */
    if (fbc->common.type == ZEND_USER_FUNCTION && ddtrace_resource != -1 &&
        !(fbc->common.fn_flags & (ZEND_ACC_CALL_VIA_TRAMPOLINE | ZEND_ACC_FAKE_CLOSURE))) {
        /* On PHP 7.4 the op_array reserved flag can only be set on compilation.
         * After that, you must use ZEND_OP_ARRAY_EXTENSION.
         * We don't use it at compile-time yet, so only check this on < 7.4.
         */
#if PHP_VERSION_ID < 70400
        if (fbc->op_array.reserved[ddtrace_resource] == DDTRACE_NOT_TRACED) {
            return false;
        }
#else
        ddtrace_dispatch_t *cached_dispatch = DDTRACE_OP_ARRAY_EXTENSION(&fbc->op_array);
        if (cached_dispatch == DDTRACE_NOT_TRACED) {
            return false;
        }
#endif

        if (!_dd_should_trace_helper(call, fbc, dispatch)) {
#if PHP_VERSION_ID < 70400
            fbc->op_array.reserved[ddtrace_resource] = DDTRACE_NOT_TRACED;
#else
            DDTRACE_OP_ARRAY_EXTENSION(&fbc->op_array) = DDTRACE_NOT_TRACED;
#endif
            return false;
        }
        return _dd_should_trace_runtime(*dispatch);
    }
#else
    if (fbc->common.type == ZEND_USER_FUNCTION && ddtrace_resource != -1) {
        if (fbc->op_array.reserved[ddtrace_resource] == DDTRACE_NOT_TRACED) {
            return false;
        }
        if (!_dd_should_trace_helper(call, fbc, dispatch)) {
            fbc->op_array.reserved[ddtrace_resource] = DDTRACE_NOT_TRACED;
            return false;
        }
        return _dd_should_trace_runtime(*dispatch);
    }
#endif
    return _dd_should_trace_helper(call, fbc, dispatch) && _dd_should_trace_runtime(*dispatch);
}

#define _DD_TRACE_COPY_NULLABLE_ARG(q)      \
    {                                       \
        if (Z_TYPE_INFO_P(q) != IS_UNDEF) { \
            Z_TRY_ADDREF_P(q);              \
        } else {                            \
            q = &EG(uninitialized_zval);    \
        }                                   \
        ZEND_HASH_FILL_ADD(q);              \
    }

static void _dd_copy_function_args(zend_execute_data *call, zval *user_args, bool extra_args_moved) {
    uint32_t i, first_extra_arg, extra_arg_count;
    zval *p, *q;
    uint32_t arg_count = ZEND_CALL_NUM_ARGS(call);

    // @see https://github.com/php/php-src/blob/PHP-7.0/Zend/zend_builtin_functions.c#L506-L562
    array_init_size(user_args, arg_count);
    if (arg_count && call->func) {
        first_extra_arg = call->func->op_array.num_args;
        bool has_extra_args = arg_count > first_extra_arg;

        zend_hash_real_init(Z_ARRVAL_P(user_args), 1);
        ZEND_HASH_FILL_PACKED(Z_ARRVAL_P(user_args)) {
            i = 0;
            p = ZEND_CALL_ARG(call, 1);
            if (has_extra_args) {
                if (extra_args_moved) {
                    while (i < first_extra_arg) {
                        q = p;
                        _DD_TRACE_COPY_NULLABLE_ARG(q);
                        p++;
                        i++;
                    }
                    if (call->func->type != ZEND_INTERNAL_FUNCTION) {
                        p = ZEND_CALL_VAR_NUM(call, call->func->op_array.last_var + call->func->op_array.T);
                    }
                } else {
                    i = arg_count - first_extra_arg;
                }
            }
            while (i < arg_count) {
                q = p;
                _DD_TRACE_COPY_NULLABLE_ARG(q);
                p++;
                i++;
            }
            /* If we are copying arguments before i_init_func_execute_data() has run, the extra agruments
               have not yet been moved to a separate array. */
            if (has_extra_args && !extra_args_moved) {
                p = ZEND_CALL_VAR_NUM(call, first_extra_arg);
                extra_arg_count = arg_count - first_extra_arg;
                while (extra_arg_count--) {
                    q = p;
                    _DD_TRACE_COPY_NULLABLE_ARG(q);
                    p++;
                }
            }
        }
        ZEND_HASH_FILL_END();
        Z_ARRVAL_P(user_args)->nNumOfElements = arg_count;
    }
}

static void _dd_span_attach_exception(ddtrace_span_fci *span_fci, ddtrace_exception_t *exception) {
    if (exception && span_fci->exception == NULL) {
        GC_ADDREF(exception);
        span_fci->exception = exception;
    }
}

static bool _dd_execute_tracing_closure(zval *callable, zval *span_data, zend_execute_data *call, zval *user_args,
                                        zval *user_retval, zend_object *exception) {
    bool status = true;
    zend_fcall_info fci = {0};
    zend_fcall_info_cache fcc = {0};
    zval rv;
    INIT_ZVAL(rv);
    zval args[4];
    zval exception_arg = {.value = {0}};
    ZVAL_NULL(&exception_arg);
    if (exception) {
        ZVAL_OBJ(&exception_arg, exception);
    }
    zval *this = _dd_this(call);

    if (!callable || !span_data || !user_args) {
        if (get_dd_trace_debug()) {
            const char *fname = call->func ? ZSTR_VAL(call->func->common.function_name) : "{unknown}";
            ddtrace_log_errf("Tracing closure could not be run for %s() because it is in an invalid state", fname);
        }
        return false;
    }

    if (zend_fcall_info_init(callable, 0, &fci, &fcc, NULL, NULL) == FAILURE) {
        ddtrace_log_debug("Could not init tracing closure");
        return false;
    }

    if (this) {
        bool is_instance_method = (call->func && call->func->common.fn_flags & ZEND_ACC_STATIC) ? false : true;
        bool is_closure_static = (fcc.function_handler->common.fn_flags & ZEND_ACC_STATIC) ? true : false;
        if (is_instance_method && is_closure_static) {
            ddtrace_log_debug("Cannot trace non-static method with static tracing closure");
            return false;
        }
    }

    // Arg 0: DDTrace\SpanData $span
    ZVAL_COPY(&args[0], span_data);

    // Arg 1: array $args
    ZVAL_COPY(&args[1], user_args);

    // Arg 2: mixed $retval
    if (!user_retval || Z_TYPE_INFO_P(user_retval) == IS_UNDEF) {
        user_retval = &EG(uninitialized_zval);
    }
    ZVAL_COPY(&args[2], user_retval);

    // Arg 3: Exception|null $exception
    ZVAL_COPY(&args[3], &exception_arg);

    fci.param_count = 4;
    fci.params = args;
    fci.retval = &rv;

#if PHP_VERSION_ID < 70300
    fcc.initialized = 1;
#endif
    fcc.object = this ? Z_OBJ_P(this) : NULL;
    fcc.called_scope = zend_get_called_scope(call);
    // Give the tracing closure access to private & protected class members
    fcc.function_handler->common.scope = fcc.called_scope;

    if (zend_call_function(&fci, &fcc) == FAILURE) {
        ddtrace_log_debug("Could not execute tracing closure");
        status = false;
    } else if (Z_TYPE(rv) == IS_FALSE) {
        status = false;
    }

    zend_fcall_info_args_clear(&fci, 0);
    return status;
}

static zend_class_entry *_dd_get_exception_base(zval *object) {
    return instanceof_function(Z_OBJCE_P(object), zend_ce_exception) ? zend_ce_exception : zend_ce_error;
}

#if PHP_VERSION_ID < 70100
#define ZEND_STR_MESSAGE "message"
#define GET_PROPERTY(object, name) \
    zend_read_property(_dd_get_exception_base(object), (object), name, sizeof(name) - 1, 1, &rv)
#elif PHP_VERSION_ID < 70200
#define GET_PROPERTY(object, id) \
    zend_read_property_ex(_dd_get_exception_base(object), (object), CG(known_strings)[id], 1, &rv)
#else
#define GET_PROPERTY(object, id) zend_read_property_ex(_dd_get_exception_base(object), (object), ZSTR_KNOWN(id), 1, &rv)
#endif

static bool _dd_call_sandboxed_tracing_closure(ddtrace_span_fci *span_fci, zval *callable, zval *user_retval) {
    zend_execute_data *call = span_fci->execute_data;
    ddtrace_dispatch_t *dispatch = span_fci->dispatch;
    ddtrace_span_t *span = &span_fci->span;
    zval user_args;

    _dd_copy_function_args(call, &user_args, !(dispatch->options & DDTRACE_DISPATCH_PREHOOK));
    ddtrace_sandbox_backup backup = ddtrace_sandbox_begin();

    bool keep_span = true;

    keep_span = _dd_execute_tracing_closure(callable, span->span_data, call, &user_args, user_retval, backup.exception);

    if (get_dd_trace_debug() && PG(last_error_message) && backup.eh.message != PG(last_error_message)) {
        const char *fname = Z_STRVAL(dispatch->function_name);
        ddtrace_log_errf("Error raised in tracing closure for %s(): %s in %s on line %d", fname, PG(last_error_message),
                         PG(last_error_file), PG(last_error_lineno));
    }

    // If the tracing closure threw an exception, ignore it to not impact the original call
    if (get_dd_trace_debug() && EG(exception)) {
        zend_object *ex = EG(exception);
        const char *name = Z_STR(dispatch->function_name)->val;
        const char *type = ex->ce->name->val;
        zval rv, obj;
        ZVAL_OBJ(&obj, ex);
        zval *message = GET_PROPERTY(&obj, ZEND_STR_MESSAGE);
        const char *msg =
            Z_TYPE_P(message) == IS_STRING ? Z_STR_P(message)->val : "(internal error reading exception message)";
        ddtrace_log_errf("%s thrown in tracing closure for %s: %s", type, name, msg);
        if (message == &rv) {
            zval_dtor(message);
        }
    }

    ddtrace_sandbox_end(&backup);

    zval_dtor(&user_args);

    return keep_span;
}

// See zend_copy_parameters_array
static void dd_copy_prehook_args(zval *args, zend_execute_data *execute_data) {
    zval *param_ptr = ZEND_CALL_ARG(execute_data, 1);
    int arg_count = ZEND_CALL_NUM_ARGS(execute_data);

    int param_count = arg_count;
    array_init_size(args, param_count);

    while (param_count-- > 0) {
        if (Z_REFCOUNTED_P(param_ptr)) {
            Z_ADDREF_P(param_ptr);
        }
        zend_hash_next_index_insert_new(Z_ARRVAL_P(args), param_ptr);
        param_ptr++;
    }
}

static ZEND_RESULT_CODE ddtrace_do_hook_function_prehook(zend_execute_data *call, ddtrace_dispatch_t *dispatch) {
    ddtrace_sandbox_backup backup = ddtrace_sandbox_begin();
    ddtrace_dispatch_copy(dispatch);  // protecting against dispatch being freed during php code execution
    dispatch->busy = 1;               // guard against recursion, catching only topmost execution

    zend_fcall_info fci = {0};
    zend_fcall_info_cache fcc = {0};

    char *error = NULL;
    if (zend_fcall_info_init(&dispatch->prehook, 0, &fci, &fcc, NULL, &error) != SUCCESS) {
        if (error) {
            ddtrace_log_debug(error);
            efree(error);
            error = NULL;
        }
    }

    zval args = {.u1.type_info = IS_NULL};

    dd_copy_prehook_args(&args, call);

    ZEND_RESULT_CODE status = zend_fcall_info_argn(&fci, 1, &args);
    if (status != SUCCESS) {
        goto clean_args;
    }

    zval retval = {.u1.type_info = IS_NULL};
    fci.retval = &retval;

    status = zend_call_function(&fci, &fcc);

    zval_dtor(&retval);

clean_args:
    zend_fcall_info_args_clear(&fci, 1);
    zval_dtor(&args);

    dispatch->busy = 0;
    ddtrace_dispatch_release(dispatch);

    ddtrace_sandbox_end(&backup);

    return status;
}

static ZEND_RESULT_CODE ddtrace_do_hook_method_prehook(zend_execute_data *call, ddtrace_dispatch_t *dispatch) {
    ddtrace_sandbox_backup backup = ddtrace_sandbox_begin();
    ddtrace_dispatch_copy(dispatch);  // protecting against dispatch being freed during php code execution
    dispatch->busy = 1;               // guard against recursion, catching only topmost execution

    zend_fcall_info fci = {0};
    zend_fcall_info_cache fcc = {0};

    char *error = NULL;
    if (zend_fcall_info_init(&dispatch->prehook, 0, &fci, &fcc, NULL, &error) != SUCCESS) {
        if (error) {
            ddtrace_log_debug(error);
            efree(error);
            error = NULL;
        }
        // todo: goto where?
    }

    zend_object *called_this = zend_get_this_object(call);

    zval This = {.u1.type_info = IS_NULL}, scope = {.u1.type_info = IS_NULL}, args = {.u1.type_info = IS_NULL};

    if (called_this) {
        ZVAL_OBJ(&This, called_this);
    }

    zend_class_entry *called_scope = zend_get_called_scope(call);
    if (called_scope) {
        ZVAL_STR(&scope, called_scope->name);
    }

    dd_copy_prehook_args(&args, call);

    ZEND_RESULT_CODE status = zend_fcall_info_argn(&fci, 3, &This, &scope, &args);
    if (status != SUCCESS) {
        goto clean_args;
    }

    zval retval = {.u1.type_info = IS_NULL};
    fci.retval = &retval;

    status = zend_call_function(&fci, &fcc);

    zval_dtor(&retval);

clean_args:
    zend_fcall_info_args_clear(&fci, 1);
    zval_dtor(&args);

    dispatch->busy = 0;
    ddtrace_dispatch_release(dispatch);

    ddtrace_sandbox_end(&backup);

    return status;
}

static ddtrace_span_fci *ddtrace_fcall_begin_tracing_posthook(zend_execute_data *call, ddtrace_dispatch_t *dispatch) {
    ZEND_ASSERT(dispatch);

    ddtrace_dispatch_copy(dispatch);  // protecting against dispatch being freed during php code execution
    dispatch->busy = 1;               // guard against recursion, catching only topmost execution

    ddtrace_span_fci *span_fci = ecalloc(1, sizeof(*span_fci));
    span_fci->execute_data = call;
    span_fci->dispatch = dispatch;
    ddtrace_open_span(span_fci);

    return span_fci;
}

static ddtrace_span_fci *ddtrace_fcall_begin_tracing_prehook(zend_execute_data *call, ddtrace_dispatch_t *dispatch) {
    bool continue_tracing = true;
    ZEND_ASSERT(dispatch);

    // todo: extract common code to helper; weird to call posthook from prehook
    ddtrace_span_fci *span_fci = ddtrace_fcall_begin_tracing_posthook(call, dispatch);
    ZEND_ASSERT(span_fci);

    zval user_retval = {.u1.type_info = IS_NULL};
    continue_tracing = _dd_call_sandboxed_tracing_closure(span_fci, &dispatch->prehook, &user_retval);
    if (!continue_tracing) {
        ddtrace_drop_top_open_span();
        span_fci = NULL;
    }

    return span_fci;
}

static ddtrace_span_fci *ddtrace_fcall_begin_non_tracing_posthook(zend_execute_data *call,
                                                                  ddtrace_dispatch_t *dispatch) {
    /* This is a hack. We put a span into the span stack so we can "tag" the
     * frame as well as support close-at-exit functionality, but we want any
     * children that this makes to be inherited by the currently active span,
     * so we duplicate the span_id.
     */
    ddtrace_span_fci *span_fci = ecalloc(1, sizeof(*span_fci));
    span_fci->execute_data = call;
    span_fci->dispatch = dispatch;

    span_fci->next = DDTRACE_G(open_spans_top);
    DDTRACE_G(open_spans_top) = span_fci;

    ddtrace_span_t *span = &span_fci->span;

    // todo: can we get away without a SpanData object?
    span->span_data = NULL;
    span->trace_id = DDTRACE_G(trace_id);
    span->span_id = ddtrace_peek_span_id(TSRMLS_C);

    ddtrace_dispatch_copy(dispatch);  // protecting against dispatch being freed during php code execution
    dispatch->busy = 1;               // guard against recursion, catching only topmost execution

    return span_fci;
}

static ddtrace_span_fci *ddtrace_fcall_begin_non_tracing_prehook(zend_execute_data *call,
                                                                 ddtrace_dispatch_t *dispatch) {
    ZEND_ASSERT(dispatch);

    if (call->func->common.scope) {
        if (ddtrace_do_hook_method_prehook(call, dispatch) != SUCCESS) {
            // todo: debug
        }
    } else {
        if (ddtrace_do_hook_function_prehook(call, dispatch) != SUCCESS) {
            // todo: debug
        }
    }
    return NULL;
}

static ddtrace_span_fci *(*fcall_begin[])(zend_execute_data *call, ddtrace_dispatch_t *dispatch) = {
    [DDTRACE_DISPATCH_POSTHOOK] = ddtrace_fcall_begin_tracing_posthook,
    [DDTRACE_DISPATCH_POSTHOOK | DDTRACE_DISPATCH_NON_TRACING] = ddtrace_fcall_begin_non_tracing_posthook,
    [DDTRACE_DISPATCH_PREHOOK] = ddtrace_fcall_begin_tracing_prehook,
    [DDTRACE_DISPATCH_PREHOOK | DDTRACE_DISPATCH_NON_TRACING] = ddtrace_fcall_begin_non_tracing_prehook,
};

static ddtrace_span_fci *ddtrace_prehook(zend_execute_data *call, ddtrace_dispatch_t *dispatch) {
    return (fcall_begin[dispatch->options & 3u])(call, dispatch);
}

void _dd_set_fqn(zval *zv, zend_execute_data *ex) {
    if (!ex->func || !ex->func->common.function_name) {
        return;
    }
    zend_class_entry *called_scope = zend_get_called_scope(ex);
    if (called_scope) {
        // This cannot be cached on the dispatch since sub classes can share the same parent dispatch
        zend_string *fqn =
            strpprintf(0, "%s.%s", ZSTR_VAL(called_scope->name), ZSTR_VAL(ex->func->common.function_name));
        ZVAL_STR_COPY(zv, fqn);
        zend_string_release(fqn);
    } else {
        ZVAL_STR_COPY(zv, ex->func->common.function_name);
    }
}

static void _dd_set_default_properties(void) {
    ddtrace_span_fci *span_fci = DDTRACE_G(open_spans_top);
    if (span_fci == NULL || span_fci->span.span_data == NULL || span_fci->execute_data == NULL) {
        return;
    }

    ddtrace_span_t *span = &span_fci->span;
    // SpanData::$name defaults to fully qualified called name
    // The other span property defaults are set at serialization time
    zval *prop_name = ddtrace_spandata_property_name(span->span_data);
    if (prop_name && Z_TYPE_P(prop_name) == IS_NULL) {
        zval prop_name_default;
        ZVAL_NULL(&prop_name_default);
        _dd_set_fqn(&prop_name_default, span_fci->execute_data);
        ZVAL_COPY_VALUE(prop_name, &prop_name_default);
        zval_copy_ctor(prop_name);
        zval_dtor(&prop_name_default);
    }
}

static ZEND_RESULT_CODE ddtrace_do_hook_method_posthook(zend_execute_data *call, ddtrace_dispatch_t *dispatch,
                                                        zval *user_retval) {
    ddtrace_sandbox_backup backup = ddtrace_sandbox_begin();

    zend_fcall_info fci = {0};
    zend_fcall_info_cache fcc = {0};

    char *error = NULL;
    if (zend_fcall_info_init(&dispatch->posthook, 0, &fci, &fcc, NULL, &error) != SUCCESS) {
        if (error) {
            ddtrace_log_debug(error);
            efree(error);
            error = NULL;
        }
    }

    zend_object *called_this = zend_get_this_object(call);

    zval This = {.u1.type_info = IS_NULL}, scope = {.u1.type_info = IS_NULL}, args = {.u1.type_info = IS_NULL};
    zval tmp_retval = {.u1.type_info = IS_NULL};

    if (called_this) {
        ZVAL_OBJ(&This, called_this);
    }

    zend_class_entry *called_scope = zend_get_called_scope(call);
    if (called_scope) {
        ZVAL_STR(&scope, called_scope->name);
    }

    dd_copy_prehook_args(&args, call);

    if (!user_retval) {
        user_retval = &tmp_retval;
    }

    ZEND_RESULT_CODE status = zend_fcall_info_argn(&fci, 4, &This, &scope, &args, user_retval);
    if (status != SUCCESS) {
        goto clean_args;
    }

    zval retval = {.u1.type_info = IS_NULL};
    fci.retval = &retval;

    status = zend_call_function(&fci, &fcc);

    zval_dtor(&retval);

clean_args:
    zend_fcall_info_args_clear(&fci, 1);
    zval_dtor(&args);

    ddtrace_sandbox_end(&backup);

    return status;
}

static ZEND_RESULT_CODE ddtrace_do_hook_function_posthook(zend_execute_data *call, ddtrace_dispatch_t *dispatch,
                                                          zval *user_retval) {
    ddtrace_sandbox_backup backup = ddtrace_sandbox_begin();

    zend_fcall_info fci = {0};
    zend_fcall_info_cache fcc = {0};

    char *error = NULL;
    if (zend_fcall_info_init(&dispatch->prehook, 0, &fci, &fcc, NULL, &error) != SUCCESS) {
        if (error) {
            ddtrace_log_debug(error);
            efree(error);
            error = NULL;
        }
    }

    zval args = {.u1.type_info = IS_NULL}, tmp_retval = {.u1.type_info = IS_NULL};

    dd_copy_prehook_args(&args, call);

    if (!user_retval) {
        user_retval = &tmp_retval;
    }

    ZEND_RESULT_CODE status = zend_fcall_info_argn(&fci, 2, &args, user_retval);
    if (status != SUCCESS) {
        goto clean_args;
    }

    zval retval = {.u1.type_info = IS_NULL};
    fci.retval = &retval;

    status = zend_call_function(&fci, &fcc);

    zval_dtor(&retval);

clean_args:
    zend_fcall_info_args_clear(&fci, 1);
    zval_dtor(&args);

    ddtrace_sandbox_end(&backup);

    return status;
}

static void ddtrace_fcall_end_tracing_posthook(ddtrace_span_fci *span_fci, zval *user_retval) {
    ddtrace_dispatch_t *dispatch = span_fci->dispatch;
    _dd_span_attach_exception(span_fci, EG(exception));

    dd_trace_stop_span_time(&span_fci->span);

    bool keep_span = _dd_call_sandboxed_tracing_closure(span_fci, &dispatch->posthook, user_retval);

    if (keep_span) {
        _dd_set_default_properties();
        ddtrace_close_span();
    } else {
        ddtrace_drop_top_open_span();
    }
}

static void ddtrace_fcall_end_non_tracing_posthook(ddtrace_span_fci *span_fci, zval *user_retval) {
    zend_execute_data *call = span_fci->execute_data;
    ddtrace_dispatch_t *dispatch = span_fci->dispatch;
    if (call->func->common.scope) {
        if (ddtrace_do_hook_method_posthook(call, dispatch, user_retval) != SUCCESS) {
            // todo: debug
        }
    } else {
        if (ddtrace_do_hook_function_posthook(call, dispatch, user_retval) != SUCCESS) {
            // todo: debug
        }
    }

    // drop the placeholder span -- we do not need it
    DDTRACE_G(open_spans_top) = span_fci->next;
    ddtrace_drop_span(span_fci);
}

static void ddtrace_fcall_end_tracing_prehook(ddtrace_span_fci *span_fci, zval *user_retval) {
    PHP7_UNUSED(user_retval);
    _dd_span_attach_exception(span_fci, EG(exception));

    dd_trace_stop_span_time(&span_fci->span);

    _dd_set_default_properties();
    ddtrace_close_span();
}

static void ddtrace_fcall_end_non_tracing_prehook(ddtrace_span_fci *span_fci, zval *user_retval) {
    // nothing to do
    PHP7_UNUSED(span_fci, user_retval);
}

static void (*fcall_end[])(ddtrace_span_fci *span_fci, zval *user_retval) = {
    [DDTRACE_DISPATCH_POSTHOOK] = ddtrace_fcall_end_tracing_posthook,
    [DDTRACE_DISPATCH_POSTHOOK | DDTRACE_DISPATCH_NON_TRACING] = ddtrace_fcall_end_non_tracing_posthook,
    [DDTRACE_DISPATCH_PREHOOK] = ddtrace_fcall_end_tracing_prehook,
    [DDTRACE_DISPATCH_PREHOOK | DDTRACE_DISPATCH_NON_TRACING] = ddtrace_fcall_end_non_tracing_prehook,
};

static void ddtrace_posthook(zend_function *fbc, ddtrace_span_fci *span_fci, zval *user_retval) {
    if (span_fci == DDTRACE_G(open_spans_top)) {
        ddtrace_dispatch_t *dispatch = span_fci->dispatch;
        (fcall_end[dispatch->options & 3u])(span_fci, user_retval);
    } else if (fbc && get_dd_trace_debug()) {
        ddtrace_log_errf("Cannot run tracing closure for %s(); spans out of sync", ZSTR_VAL(fbc->common.function_name));
    }
}

static void _dd_fcall_helper(zend_execute_data *call, ddtrace_dispatch_t *dispatch) {
#if PHP_VERSION_ID < 70100
    /*
    For PHP < 7.1: The current execute_data gets replaced in the DO_FCALL handler and freed shortly
    afterward, so there is no way to track the execute_data that is allocated for a generator.
    */
    if ((call->func->common.fn_flags & ZEND_ACC_GENERATOR) != 0) {
        ddtrace_log_debug("Cannot instrument generators for PHP versions < 7.1");
        return;
    }
#endif

    ddtrace_prehook(call, dispatch);
}

static int _dd_do_ucall_handler(zend_execute_data *execute_data) {
    ddtrace_dispatch_t *dispatch = NULL;
    if (ZEND_DO_UCALL != EX(opline)->opcode || !EX(call)->func ||
        !_dd_should_trace_call(EX(call), EX(call)->func, &dispatch)) {
        return _prev_ucall_handler ? _prev_ucall_handler(execute_data) : ZEND_USER_OPCODE_DISPATCH;
    }
    _dd_fcall_helper(EX(call), dispatch);
    return _prev_ucall_handler ? _prev_ucall_handler(execute_data) : ZEND_USER_OPCODE_DISPATCH;
}

static int _dd_do_fcall_handler(zend_execute_data *execute_data) {
    ddtrace_dispatch_t *dispatch = NULL;
    if (ZEND_DO_FCALL != EX(opline)->opcode || !EX(call)->func || EX(call)->func->type == ZEND_INTERNAL_FUNCTION ||
        !_dd_should_trace_call(EX(call), EX(call)->func, &dispatch)) {
        return _prev_fcall_handler ? _prev_fcall_handler(execute_data) : ZEND_USER_OPCODE_DISPATCH;
    }
    _dd_fcall_helper(EX(call), dispatch);
    return _prev_fcall_handler ? _prev_fcall_handler(execute_data) : ZEND_USER_OPCODE_DISPATCH;
}

static int _dd_do_fcall_by_name_handler(zend_execute_data *execute_data) {
    ddtrace_dispatch_t *dispatch = NULL;
    if (ZEND_DO_FCALL_BY_NAME != EX(opline)->opcode || !EX(call)->func ||
        EX(call)->func->type == ZEND_INTERNAL_FUNCTION || !_dd_should_trace_call(EX(call), EX(call)->func, &dispatch)) {
        return _prev_fcall_by_name_handler ? _prev_fcall_by_name_handler(execute_data) : ZEND_USER_OPCODE_DISPATCH;
    }
    _dd_fcall_helper(EX(call), dispatch);
    return _prev_fcall_by_name_handler ? _prev_fcall_by_name_handler(execute_data) : ZEND_USER_OPCODE_DISPATCH;
}

static void _dd_return_helper(zend_execute_data *execute_data) {
    ddtrace_span_fci *span_fci = DDTRACE_G(open_spans_top);
    if (span_fci && span_fci->execute_data == execute_data) {
        zval rv;
        zval *retval = NULL;
        switch (EX(opline)->op1_type) {
            case IS_CONST:
#if PHP_VERSION_ID >= 70300
                retval = RT_CONSTANT(EX(opline), EX(opline)->op1);
#else
                retval = EX_CONSTANT(EX(opline)->op1);
#endif
                break;
            case IS_TMP_VAR:
            case IS_VAR:
            case IS_CV:
                retval = EX_VAR(EX(opline)->op1.var);
                break;
                /* IS_UNUSED is NULL */
        }
        if (!retval || Z_TYPE_INFO_P(retval) == IS_UNDEF) {
            ZVAL_NULL(&rv);
            retval = &rv;
        }
        ddtrace_posthook(NULL, span_fci, retval);
    }
}

static int _dd_return_handler(zend_execute_data *execute_data) {
    if (ZEND_RETURN == EX(opline)->opcode) {
        _dd_return_helper(execute_data);
    }
    return _prev_return_handler ? _prev_return_handler(execute_data) : ZEND_USER_OPCODE_DISPATCH;
}

static int _dd_return_by_ref_handler(zend_execute_data *execute_data) {
    if (ZEND_RETURN_BY_REF == EX(opline)->opcode) {
        _dd_return_helper(execute_data);
    }
    return _prev_return_by_ref_handler ? _prev_return_by_ref_handler(execute_data) : ZEND_USER_OPCODE_DISPATCH;
}

#if PHP_VERSION_ID >= 70100
static void _dd_yield_helper(zend_execute_data *execute_data) {
    ddtrace_span_fci *span_fci = DDTRACE_G(open_spans_top);
    /*
    Generators store their execute data on the heap and we lose the address to the original call
    so we grab the original address from the executor globals.
    */
    zend_execute_data *orig_ex = (zend_execute_data *)EG(vm_stack_top);
    if (span_fci && span_fci->execute_data == orig_ex) {
        zval rv;
        zval *retval = NULL;
        span_fci->execute_data = execute_data;
        switch (EX(opline)->op1_type) {
            case IS_CONST:
#if PHP_VERSION_ID >= 70300
                retval = RT_CONSTANT(EX(opline), EX(opline)->op1);
#else
                retval = EX_CONSTANT(EX(opline)->op1);
#endif
                break;
            case IS_TMP_VAR:
            case IS_VAR:
            case IS_CV:
                retval = EX_VAR(EX(opline)->op1.var);
                break;
                /* IS_UNUSED is NULL */
        }
        if (!retval || Z_TYPE_INFO_P(retval) == IS_UNDEF) {
            ZVAL_NULL(&rv);
            retval = &rv;
        }
        ddtrace_posthook(NULL, span_fci, retval);
    }
}

static int _dd_yield_handler(zend_execute_data *execute_data) {
    if (ZEND_YIELD == EX(opline)->opcode) {
        _dd_yield_helper(execute_data);
    }
    return _prev_yield_handler ? _prev_yield_handler(execute_data) : ZEND_USER_OPCODE_DISPATCH;
}

static int _dd_yield_from_handler(zend_execute_data *execute_data) {
    if (ZEND_YIELD_FROM == EX(opline)->opcode) {
        _dd_yield_helper(execute_data);
    }
    return _prev_yield_from_handler ? _prev_yield_from_handler(execute_data) : ZEND_USER_OPCODE_DISPATCH;
}
#endif

#if PHP_MINOR_VERSION == 0
static zend_op *_dd_get_next_catch_block(zend_execute_data *execute_data, zend_op *opline) {
    if (opline->result.num) {
        return NULL;
    }
    return &EX(func)->op_array.opcodes[opline->extended_value];
}
#elif PHP_MINOR_VERSION < 3
static zend_op *_dd_get_next_catch_block(zend_op *opline) {
    if (opline->result.num) {
        return NULL;
    }
    return ZEND_OFFSET_TO_OPLINE(opline, opline->extended_value);
}
#else
static zend_op *_dd_get_next_catch_block(zend_op *opline) {
    if (opline->extended_value & ZEND_LAST_CATCH) {
        return NULL;
    }
    return OP_JMP_ADDR(opline, opline->op2);
}
#endif

static zend_class_entry *_dd_get_catching_ce(zend_execute_data *execute_data, const zend_op *opline) {
    zend_class_entry *catch_ce = NULL;
#if PHP_MINOR_VERSION < 3
    catch_ce = CACHED_PTR(Z_CACHE_SLOT_P(EX_CONSTANT(opline->op1)));
    if (catch_ce == NULL) {
        catch_ce = zend_fetch_class_by_name(Z_STR_P(EX_CONSTANT(opline->op1)), EX_CONSTANT(opline->op1) + 1,
                                            ZEND_FETCH_CLASS_NO_AUTOLOAD);
    }
#elif PHP_MINOR_VERSION == 3
    catch_ce = CACHED_PTR(opline->extended_value & ~ZEND_LAST_CATCH);
    if (catch_ce == NULL) {
        catch_ce = zend_fetch_class_by_name(Z_STR_P(RT_CONSTANT(opline, opline->op1)),
                                            RT_CONSTANT(opline, opline->op1) + 1, ZEND_FETCH_CLASS_NO_AUTOLOAD);
    }
#else
    catch_ce = CACHED_PTR(opline->extended_value & ~ZEND_LAST_CATCH);
    if (catch_ce == NULL) {
        catch_ce =
            zend_fetch_class_by_name(Z_STR_P(RT_CONSTANT(opline, opline->op1)),
                                     Z_STR_P(RT_CONSTANT(opline, opline->op1) + 1), ZEND_FETCH_CLASS_NO_AUTOLOAD);
    }
#endif
    return catch_ce;
}

static bool _dd_is_catching_frame(zend_execute_data *execute_data) {
    zend_class_entry *ce, *catch_ce;
    zend_try_catch_element *try_catch;
    const zend_op *throw_op = EG(opline_before_exception);
    uint32_t throw_op_num = throw_op - EX(func)->op_array.opcodes;
    int i, current_try_catch_offset = -1;

    // TODO Handle exceptions thrown because of loop var destruction on return/break/...
    // https://heap.space/xref/PHP-7.4/Zend/zend_vm_def.h?r=760faa12#7494-7503

    // TODO Handle exceptions thrown from generator context

    // Find the innermost try/catch block the exception was thrown in
    for (i = 0; i < EX(func)->op_array.last_try_catch; i++) {
        try_catch = &EX(func)->op_array.try_catch_array[i];
        if (try_catch->try_op > throw_op_num) {
            // Exception was thrown before any remaining try/catch blocks
            break;
        }
        if (throw_op_num < try_catch->catch_op) {
            current_try_catch_offset = i;
        }
        // Ignore "finally" (try_catch->finally_end)
    }

    while (current_try_catch_offset > -1) {
        try_catch = &EX(func)->op_array.try_catch_array[current_try_catch_offset];
        // Found a catch block
        if (throw_op_num < try_catch->catch_op) {
            zend_op *opline = &EX(func)->op_array.opcodes[try_catch->catch_op];
            // Travese all the catch blocks
            do {
                catch_ce = _dd_get_catching_ce(execute_data, opline);
                if (catch_ce != NULL) {
                    ce = EG(exception)->ce;
                    if (ce == catch_ce || instanceof_function(ce, catch_ce)) {
                        return true;
                    }
                }
#if PHP_MINOR_VERSION == 0
                opline = _dd_get_next_catch_block(execute_data, opline);
#else
                opline = _dd_get_next_catch_block(opline);
#endif
            } while (opline != NULL);
        }
        current_try_catch_offset--;
    }

    return false;
}

static int _dd_handle_exception_handler(zend_execute_data *execute_data) {
    ddtrace_span_fci *span_fci = DDTRACE_G(open_spans_top);
    if (ZEND_HANDLE_EXCEPTION == EX(opline)->opcode && span_fci && span_fci->execute_data == execute_data) {
        zval retval;
        ZVAL_NULL(&retval);
        // The catching frame's span will get closed by the return handler so we leave it open
        if (_dd_is_catching_frame(execute_data) == false) {
            if (EG(exception)) {
                _dd_span_attach_exception(span_fci, EG(exception));
            }
            ddtrace_posthook(NULL, span_fci, &retval);
        }
    }

    return _prev_handle_exception_handler ? _prev_handle_exception_handler(execute_data) : ZEND_USER_OPCODE_DISPATCH;
}

static int _dd_exit_handler(zend_execute_data *execute_data) {
    ddtrace_span_fci *span_fci;
    if (ZEND_EXIT == EX(opline)->opcode) {
        while ((span_fci = DDTRACE_G(open_spans_top))) {
            zval retval;
            ZVAL_NULL(&retval);
            ddtrace_posthook(NULL, span_fci, &retval);
        }
    }

    return _prev_exit_handler ? _prev_exit_handler(execute_data) : ZEND_USER_OPCODE_DISPATCH;
}

void ddtrace_opcode_minit(void) {
    _prev_ucall_handler = zend_get_user_opcode_handler(ZEND_DO_UCALL);
    _prev_fcall_handler = zend_get_user_opcode_handler(ZEND_DO_FCALL);
    _prev_fcall_by_name_handler = zend_get_user_opcode_handler(ZEND_DO_FCALL_BY_NAME);

    zend_set_user_opcode_handler(ZEND_DO_FCALL, _dd_do_fcall_handler);
    zend_set_user_opcode_handler(ZEND_DO_FCALL_BY_NAME, _dd_do_fcall_by_name_handler);
    zend_set_user_opcode_handler(ZEND_DO_UCALL, _dd_do_ucall_handler);

    _prev_return_handler = zend_get_user_opcode_handler(ZEND_RETURN);
    zend_set_user_opcode_handler(ZEND_RETURN, _dd_return_handler);
    _prev_return_by_ref_handler = zend_get_user_opcode_handler(ZEND_RETURN_BY_REF);
    zend_set_user_opcode_handler(ZEND_RETURN_BY_REF, _dd_return_by_ref_handler);
#if PHP_VERSION_ID >= 70100
    _prev_yield_handler = zend_get_user_opcode_handler(ZEND_YIELD);
    zend_set_user_opcode_handler(ZEND_YIELD, _dd_yield_handler);
    _prev_yield_from_handler = zend_get_user_opcode_handler(ZEND_YIELD_FROM);
    zend_set_user_opcode_handler(ZEND_YIELD_FROM, _dd_yield_from_handler);
#endif
    _prev_handle_exception_handler = zend_get_user_opcode_handler(ZEND_HANDLE_EXCEPTION);
    zend_set_user_opcode_handler(ZEND_HANDLE_EXCEPTION, _dd_handle_exception_handler);
    _prev_exit_handler = zend_get_user_opcode_handler(ZEND_EXIT);
    zend_set_user_opcode_handler(ZEND_EXIT, _dd_exit_handler);
}

void ddtrace_opcode_mshutdown(void) {
    zend_set_user_opcode_handler(ZEND_DO_UCALL, NULL);
    zend_set_user_opcode_handler(ZEND_DO_FCALL, NULL);
    zend_set_user_opcode_handler(ZEND_DO_FCALL_BY_NAME, NULL);

    zend_set_user_opcode_handler(ZEND_RETURN, NULL);
    zend_set_user_opcode_handler(ZEND_RETURN_BY_REF, NULL);
#if PHP_VERSION_ID >= 70100
    zend_set_user_opcode_handler(ZEND_YIELD, NULL);
    zend_set_user_opcode_handler(ZEND_YIELD_FROM, NULL);
#endif
    zend_set_user_opcode_handler(ZEND_HANDLE_EXCEPTION, NULL);
    zend_set_user_opcode_handler(ZEND_EXIT, NULL);
}

void ddtrace_execute_internal_minit(void) {}
void ddtrace_execute_internal_mshutdown(void) {}

PHP_FUNCTION(ddtrace_internal_function_handler) {
    ddtrace_dispatch_t *dispatch;
    void (*handler)(INTERNAL_FUNCTION_PARAMETERS) = EX(func)->internal_function.reserved[ddtrace_resource];

    if (!get_dd_trace_sandbox_enabled() || !_dd_should_trace_call(execute_data, EX(func), &dispatch)) {
        handler(INTERNAL_FUNCTION_PARAM_PASSTHRU);
        return;
    }

    ddtrace_span_fci *span_fci = ddtrace_prehook(execute_data, dispatch);
    handler(INTERNAL_FUNCTION_PARAM_PASSTHRU);
    if (span_fci) {
        ddtrace_posthook(EX(func), span_fci, return_value);
    }
}
