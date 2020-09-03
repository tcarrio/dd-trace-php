cmake_minimum_required(VERSION 3.12)
project(DDTracePHP8 LANGUAGES C CXX)

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

find_package(PHP REQUIRED)

# TODO: add execinfo, backtrace, etc
configure_file(config.h.in config.h)

add_library(DDTracePHP8 MODULE)
set_target_properties(DDTracePHP8 PROPERTIES
    # It should be named ddtrace8.so, not libDDTracePHP8.so
    PREFIX ""
    OUTPUT_NAME ddtrace8
    PUBLIC_HEADER php_ddtrace8.h
)

target_sources(DDTracePHP8 PRIVATE ddtrace8.c observers.cc clocks.cc integration.cc integrations.cc)
target_compile_features(DDTracePHP8 PRIVATE c_std_11 cxx_std_17)
target_compile_definitions(DDTracePHP8 PRIVATE -DHAVE_CONFIG_H)

target_link_libraries(DDTracePHP8 PUBLIC PHP::PHP)

find_library(LIB_RT rt OPTIONAL)
if (LIB_RT)
    target_link_libraries(DDTracePHP8 PRIVATE ${RT_LIB})
endif ()

target_include_directories(DDTracePHP8
    PRIVATE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
)

#[[ On Apple platforms we need to ignore PHP's symbols such as __zend_malloc.
    I wish PHP provided libzend.so by default to avoid such things.
]]
if (APPLE)
    target_link_libraries(DDTracePHP8 PRIVATE "-undefined dynamic_lookup")
endif ()

install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/ddtrace8.so
    DESTINATION ${PHP_EXTENSION_DIR}
)
