cmake_minimum_required(VERSION 3.12)
project(DDTracePHP LANGUAGES C)

find_package(CURL REQUIRED)

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

find_package(PHP REQUIRED)

#[[ We use EXCLUDE_FROM_ALL because we don't want to install its libs, includes,
    etc, into the prefix when we install ddtrace.so
]]
add_subdirectory(src/dogstatsd EXCLUDE_FROM_ALL)

# The main build happens here
add_subdirectory(src/ext)
