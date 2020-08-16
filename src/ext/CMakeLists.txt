# TODO: add execinfo, backtrace, etc
configure_file(config.h.in config.h)

set(DDTRACE_SOURCES ddtrace.c
    arrays.c 
    circuit_breaker.c 
    comms_php.c 
    compat_string.c 
    coms.c 
    configuration.c 
    configuration_php_iface.c 
    ddtrace_string.c 
    dispatch.c 
    dogstatsd_client.c 
    engine_hooks.c 
    env_config.c 
    logging.c 
    memory_limit.c 
    mpack/mpack.c 
    random.c 
    request_hooks.c 
    signals.c 
    span.c 
    third-party/mt19937-64.c 
    integrations/integrations.c 
)

set (DDTRACE_PHP5_4_SOURCES
      php5_4/auto_flush.c 
      php5_4/blacklist.c 
      php5_4/dispatch.c 
      php5_4/distributed_tracing.c 
      php5_4/engine_hooks.c 
      php5_4/handlers_internal.c 
      php5_4/serializer.c 
      php5/startup_logging.c 
)

set(DDTRACE_PHP5_SOURCES
      php5/auto_flush.c 
      php5/blacklist.c 
      php5/dispatch.c 
      php5/distributed_tracing.c 
      php5/engine_api.c 
      php5/engine_hooks.c 
      php5/handlers_curl.c 
      php5/handlers_internal.c 
      php5/serializer.c 
      php5/startup_logging.c 
)

set (DDTRACE_PHP7_SOURCES
      php7/auto_flush.c 
      php7/blacklist.c 
      php7/dispatch.c 
      php7/distributed_tracing.c 
      php7/engine_api.c 
      php7/engine_hooks.c 
      php7/handlers_curl.c 
      php7/handlers_internal.c 
      php7/handlers_memcached.c 
      php7/handlers_mysqli.c 
      php7/handlers_pdo.c 
      php7/handlers_phpredis.c 
      php7/serializer.c 
      php7/startup_logging.c 
)

add_library(DDTracePHP MODULE)
set_target_properties(DDTracePHP PROPERTIES
    # It should be named ddtrace.so, not libDDTracePHP.so
    PREFIX ""
    OUTPUT_NAME ddtrace

    PUBLIC_HEADER ddtrace.h
)

target_sources(DDTracePHP PRIVATE ${DDTRACE_SOURCES})

if (${PHP_VERSION_ID} STRLESS 50500)
    target_sources(DDTracePHP PRIVATE ${DDTRACE_PHP5_4_SOURCES})
elseif (${PHP_VERSION_ID} STRLESS 70000)
    target_sources(DDTracePHP PRIVATE ${DDTRACE_PHP5_SOURCES})
elseif (${PHP_VERSION_ID} STRLESS 80000)
    target_sources(DDTracePHP PRIVATE ${DDTRACE_PHP7_SOURCES})
endif ()

target_compile_features(DDTracePHP PRIVATE c_std_11)
target_compile_definitions(DDTracePHP PRIVATE -DHAVE_CONFIG_H)

target_link_libraries(DDTracePHP
    PUBLIC
        PHP::PHP
    PRIVATE
        CURL::libcurl
        DogstatsdClient::DogstatsdClient
)

find_library(LIB_RT rt OPTIONAL)
if (LIB_RT)
    target_link_libraries(DDTracePHP PRIVATE ${RT_LIB})
endif ()

target_include_directories(DDTracePHP
    PRIVATE 
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/mpack>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/third-party>
)

#[[ On Apple platforms we need to ignore PHP's symbols such as __zend_malloc.
    I wish PHP provided libzend.so by default to avoid such things.
]]
if (APPLE)
    target_link_libraries(DDTracePHP PRIVATE "-undefined dynamic_lookup")
endif ()

install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/ddtrace.so
    DESTINATION ${PHP_EXTENSION_DIR}
)

