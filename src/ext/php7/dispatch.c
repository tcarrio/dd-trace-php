#include "dispatch.h"

#include <php.h>

#include "compatibility.h"
#include "ddtrace.h"

ZEND_EXTERN_MODULE_GLOBALS(ddtrace)

zend_function *ddtrace_ftable_get(const HashTable *table, zval *name) {
    if (Z_TYPE_P(name) != IS_STRING) {
        return NULL;
    }

    // todo: use (and enhance if needed first) ddtrace_hash_find_ptr_lc
    zend_string *key = zend_string_tolower(Z_STR_P(name));
    zend_function *ptr = zend_hash_find_ptr(table, key);
    zend_string_release(key);
    return ptr;
}

void ddtrace_dispatch_dtor(ddtrace_dispatch_t *dispatch) {
    zval_ptr_dtor(&dispatch->function_name);
    zval *callable;
    if (dispatch->options & DDTRACE_DISPATCH_PREHOOK) {
        callable = &dispatch->prehook;
    } else if (dispatch->options & DDTRACE_DISPATCH_POSTHOOK) {
        callable = &dispatch->posthook;
    } else {
        // Shouldn't happen; but if we've made it this far let's not crash because of a bad assumption
        return;
    }
    zval_ptr_dtor(callable);
}

void ddtrace_class_lookup_release_compat(zval *zv) {
    ddtrace_dispatch_t *dispatch = Z_PTR_P(zv);
    ddtrace_dispatch_release(dispatch);
}

HashTable *ddtrace_new_class_lookup(zval *class_name) {
    HashTable *class_lookup;

    ALLOC_HASHTABLE(class_lookup);
    zend_hash_init(class_lookup, 8, NULL, ddtrace_class_lookup_release_compat, 0);
    zend_hash_update_ptr(DDTRACE_G(class_lookup), Z_STR_P(class_name), class_lookup);

    return class_lookup;
}

#if PHP_VERSION_ID >= 70300
#define DDTRACE_IS_ARRAY_PERSISTENT IS_ARRAY_PERSISTENT
#else
#define DDTRACE_IS_ARRAY_PERSISTENT HASH_FLAG_PERSISTENT
#endif

zend_bool ddtrace_dispatch_store(HashTable *lookup, ddtrace_dispatch_t *dispatch_orig) {
    ddtrace_dispatch_t *dispatch = pemalloc(sizeof(ddtrace_dispatch_t), lookup->u.flags & DDTRACE_IS_ARRAY_PERSISTENT);

    memcpy(dispatch, dispatch_orig, sizeof(ddtrace_dispatch_t));
    ddtrace_dispatch_copy(dispatch);
    return zend_hash_update_ptr(lookup, Z_STR(dispatch->function_name), dispatch) != NULL;
}
