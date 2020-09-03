#ifndef DDTRACE8_INTEGRATION_HH
#define DDTRACE8_INTEGRATION_HH

extern "C" {
#include <Zend/zend_observer.h>
};

#include <functional>
#include <string>
#include <unordered_set>

struct integration;
struct integration_function;
struct integration_class;

namespace std {
template <>
struct hash<integration> {
    size_t operator()(const integration &that) const noexcept;
};

template <>
struct hash<integration_function> {
    size_t operator()(const integration_function &that) const noexcept;
};

template <>
struct hash<integration_class> {
    size_t operator()(const integration_class &that) const noexcept;
};
}  // namespace std

struct integration_function {
    std::string lc_name;
    zend_observer_fcall handlers;

    bool operator==(const integration_function &that) const noexcept;
};

struct integration_class {
    std::string lc_name;
    std::unordered_set<integration_function> methods;

    bool operator==(const integration_class &that) const noexcept;
};

struct integration {
    std::string lc_name;
    std::unordered_set<integration_class> classes;
    std::unordered_set<integration_function> functions;

    bool operator==(const integration &other) const noexcept;
};

// only call in startup! Do not call at runtime!
void register_internal_integration(struct integration integration);

// only call only at runtime!
void register_user_integration(struct integration integration);

#endif  // DDTRACE8_INTEGRATION_HH