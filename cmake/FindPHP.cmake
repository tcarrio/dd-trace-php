
find_program(PHP_CONFIG_EXECUTABLE NAMES php-config)

if (PHP_CONFIG_EXECUTABLE)
    execute_process(
        COMMAND ${PHP_CONFIG_EXECUTABLE} --php-binary
        OUTPUT_VARIABLE PHP_EXECUTABLE
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    execute_process(
        COMMAND ${PHP_CONFIG_EXECUTABLE} --extension-dir
        OUTPUT_VARIABLE PHP_EXTENSION_DIR
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    execute_process(
        COMMAND ${PHP_CONFIG_EXECUTABLE} --includes
        OUTPUT_VARIABLE PHP_INCLUDES
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    list(TRANSFORM PHP_INCLUDES REPLACE "^-I" "")
    list(TRANSFORM PHP_INCLUDES REPLACE " -I" " ")
    separate_arguments(PHP_INCLUDES)

    execute_process(
        COMMAND ${PHP_CONFIG_EXECUTABLE} --version
        OUTPUT_VARIABLE PHP_VERSION
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    execute_process(
        COMMAND ${PHP_CONFIG_EXECUTABLE} --vernum
        OUTPUT_VARIABLE PHP_VERSION_ID
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    add_library(PHP::PHP INTERFACE IMPORTED)
    target_include_directories(PHP::PHP SYSTEM INTERFACE ${PHP_INCLUDES})

    # We can't seem to set the version on an INTERFACE library
    # set_target_properties(PHP::PHP PROPERTIES VERSION ${PHP_VERSION})

    set(PHP_FOUND TRUE)
else ()
    set(PHP_FOUND FALSE)
endif ()
