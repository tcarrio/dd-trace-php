extern "C" {
#include "ddtrace8/integrations.h"
#include "php.h"
#include "php_ddtrace8.h"
}

#include <unordered_set>
#include "ddtrace8/integration.hh"

std::unordered_set<integration> internal_integrations{};
ZEND_TLS std::unordered_set<integration> user_integrations{};

#if 0
ZEND_FUNCTION(ddtrace_internal_function_handler) {
    void (*handler)(INTERNAL_FUNCTION_PARAMETERS) = EX(func)->internal_function.reserved[ddtrace8_extension.resource_number];
}
#endif

// only call in startup! Do not call at runtime!
void register_internal_integration(struct integration integration) {
    if (!zend_hash_str_exists(&module_registry, integration.lc_name.data(),
                              integration.lc_name.length())) {
        return;
    }

    internal_integrations.insert(std::move(integration));
}

// only call only at runtime!
void register_user_integration(struct integration integration) {
    user_integrations.insert(std::move(integration));
}

void ddtrace8_integrations_minit(void) { internal_integrations.clear(); }
void ddtrace8_integrations_mshutdown(void) { internal_integrations.clear(); }

void guzzle_client_constructor_end(zend_execute_data *execute_data, zval *retval) {
    // GuzzleHttp\ClientInterface::MAJOR_VERSION exists on Guzzle 7
    // GuzzleHttp\ClientInterface::VERSION exists on Guzzle 6
}

void ddtrace8_integrations_rinit(void) {
    user_integrations.clear();

    {
        integration guzzle{"guzzle"};

        integration_class guzzle_client{"guzzlehttp\\client"};
        integration_function constructor = {"__construct",
                                            {nullptr, guzzle_client_constructor_end}};
        guzzle_client.methods.insert(std::move(constructor));
        guzzle.classes.insert(std::move(guzzle_client));
        user_integrations.insert(std::move(guzzle));
    }
}

void ddtrace8_integrations_rshutdown(void) { user_integrations.clear(); }
