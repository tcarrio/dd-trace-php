#ifndef DDTRACE8_INTEGRATIONS_HH
#define DDTRACE8_INTEGRATIONS_HH

extern "C" {
#include <Zend/zend_observer.h>
};

#include <string>
#include <unordered_set>

#include "integration.hh"

struct integrations {
    zend_observer_fcall find(std::string lc_name);
    zend_observer_fcall find(std::string lc_class_name, std::string lc_function_name);

    std::unordered_set<integration_function> functions;
    std::unordered_set<integration_class> classes;
};

#endif  // DDTRACE8_INTEGRATIONS_HH
