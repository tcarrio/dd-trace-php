extern "C" {
#include "ddtrace8/observers.h"

#include "ddtrace8/clocks.h"
#include "php_ddtrace8.h"
}

#include <deque>
#include <memory>
#include <string>
#include <unordered_map>

#include "ddtrace8/integration.hh"

using std::deque;
using std::string;
using std::unique_ptr;
using std::unordered_map;

// int32_t chosen just for packing reasons (fits next to error)
enum class span_type : int32_t {
    CUSTOM = 0,
    WEB,
    DB,
    CACHE,
};

struct span {
    string service, name, resource;
    uint64_t trace_id, span_id, parent_id;
    ddtrace8_realtime_nsec_t start_realtime;
    union {
        ddtrace8_monotonic_nsec_t start_monotonic, duration;
    };
    int32_t error;
    span_type type;
    unordered_map<string, string> meta;
    unordered_map<string, double> metrics;
};

struct activation_frame {
    zend_execute_data *execute_data;
    unique_ptr<struct span> span;
    bool open;
};

ZEND_TLS uint64_t id;
ZEND_TLS deque<activation_frame> frames;  // use as a stack
ZEND_TLS deque<span> closed_spans;

static string concat3(const char *string1, size_t length1, const char *string2, size_t length2,
                      const char *string3, size_t length3) {
    string result;
    result.reserve(length1 + length2 + length3);
    result.append(string1);
    result.append(string2);
    result.append(string3);
    return result;
}

static activation_frame *active_frame(deque<activation_frame> &frames) {
    auto rend = frames.rend();
    for (auto rbegin = frames.rbegin(); rbegin != rend; ++rbegin) {
        if (rbegin->span && rbegin->open) {
            return &(*rbegin);
        }
    }
    return nullptr;
}

static span *active_span(deque<activation_frame> &frames) {
    auto frame = active_frame(frames);
    if (frame) {
        return &(*frame->span);
    }
    return nullptr;
}

static void ddtrace8_observe_fcall_begin(zend_execute_data *execute_data) {
    ZEND_ASSERT(execute_data->func);
    ZEND_ASSERT(execute_data->func->type == ZEND_USER_FUNCTION);

    zend_op_array *op_array = &execute_data->func->op_array;
    // already being measured
    if (DDTRACE8_OP_ARRAY_EXTENSION(op_array, slot1)) {
        return;
    }

    ZEND_ASSERT(!frames.empty());

    DDTRACE8_OP_ARRAY_EXTENSION(op_array, slot1) = (void *)execute_data;

    auto parent_span = active_span(frames);
    if (!parent_span) {
        // todo: how to handle this situation?
        return;
    }

    span span{};
    span.trace_id = parent_span->trace_id;
    span.parent_id = parent_span->span_id;
    span.span_id = ++id;
    span.name = op_array->scope
                    ? concat3(ZSTR_VAL(op_array->scope->name), ZSTR_LEN(op_array->scope->name),
                              ZEND_STRL("::"), ZSTR_VAL(op_array->function_name),
                              ZSTR_LEN(op_array->function_name))
                    : string{ZSTR_VAL(op_array->function_name), ZSTR_LEN(op_array->function_name)};

    span.start_monotonic = ddtrace8_monotonic_nsec();
    span.start_realtime = ddtrace8_realtime_nsec();

    unique_ptr<struct span> span_ptr{new struct span(std::move(span))};
    activation_frame frame{execute_data, std::move(span_ptr), true};
    frames.emplace_back(std::move(frame));
}

static void ddtrace8_observe_fcall_end(zend_execute_data *execute_data, zval *retval) {
    zend_op_array *op_array = &execute_data->func->op_array;

    if ((zend_execute_data *)DDTRACE8_OP_ARRAY_EXTENSION(op_array, slot1) != execute_data) {
        return;
    }

    DDTRACE8_OP_ARRAY_EXTENSION(op_array, slot1) = nullptr;

    if (UNEXPECTED(frames.empty())) {
        // uh-oh
        return;
    }

    auto frame = std::move(frames.back());
    frame.open = false;
    frames.pop_back();

    if (!frame.span) {
        return;
    }

    auto span = std::move(frame.span);

    ddtrace8_monotonic_nsec_t end = ddtrace8_monotonic_nsec();
    span->duration = end - span->start_monotonic;

    closed_spans.emplace_back(*span.release());
}

zend_observer_fcall ddtrace8_observer_fcall_init(zend_function *func) {
    bool has_name = func->common.function_name;
    uint32_t fn_flags = func->common.fn_flags;
    bool is_generator = fn_flags & ZEND_ACC_GENERATOR;
    bool op_array_in_use = fn_flags & (ZEND_ACC_CALL_VIA_TRAMPOLINE | ZEND_ACC_FAKE_CLOSURE);
    bool is_user_fn = func->type == ZEND_USER_FUNCTION;

    if (has_name && !is_generator && !op_array_in_use && is_user_fn) {
        zend_class_entry *ce = func->common.scope;
        zend_string *zstr_fname = func->common.function_name;
        string fname{ZSTR_VAL(zstr_fname), ZSTR_LEN(zstr_fname)};
        zend_str_tolower(fname.data(), fname.size());

        zend_observer_fcall handlers{nullptr, nullptr};
        if (ce) {
            string class_name{ZSTR_VAL(ce->name), ZSTR_LEN(ce->name)};
            zend_str_tolower(class_name.data(), class_name.size());
            handlers = user_integrations.find(class_name, fname);
        } else {
            handlers = user_integrations.find(fname);
        }

        return handlers;
    }
    return {nullptr, nullptr};
}

void ddtrace8_observer_rinit(void) {
    deque<activation_frame> tmp_stack{};
    frames.swap(tmp_stack);

    id = 1;
    auto span = new struct span();
    span->trace_id = id;
    span->parent_id = 0;
    span->span_id = span->trace_id;
    span->name = "web.request";
    span->type = span_type::WEB;
    span->start_realtime = ddtrace8_realtime_nsec();
    span->start_monotonic = ddtrace8_monotonic_nsec();
    span->service = "php";

    unique_ptr<struct span> span_ptr{span};
    activation_frame frame{nullptr, std::move(span_ptr), true};

    frames.emplace_back(std::move(frame));

    deque<struct span> tmp_deque{};
    closed_spans.swap(tmp_deque);
}

void ddtrace8_observer_rshutdown(void) {
    if (frames.size() == 1) {
        auto frame = std::move(frames.back());
        frames.pop_back();

        auto root = std::move(frame.span);
        if (root) {
            root->duration = ddtrace8_monotonic_nsec() - root->start_monotonic;
            closed_spans.emplace_back(*root.release());
        }
    }

    zend_printf("[\n");
    for (auto it = closed_spans.begin(); it != closed_spans.end(); it = closed_spans.erase(it)) {
        auto span = std::move(*it);
        zend_printf("\t{.trace_id = %" PRIx64 ", .parent_id = %" PRIx64 ", .span_id = %" PRIx64
                    ", .name = %s"
                    ", .duration = %" PRIu64 "},\n",
                    span.trace_id, span.parent_id, span.span_id, span.name.c_str(), span.duration);
    }
    zend_printf("]\n");
}
