PHP_ARG_ENABLE([ddtrace8],
  [whether to enable ddtrace8 support],
  [AS_HELP_STRING([--enable-ddtrace8],
    [Enable ddtrace8 support])],
  [no])

if test "$PHP_DDTRACE8" != "no"; then
  dnl In case of no dependencies
  AC_DEFINE(HAVE_DDTRACE8, 1, [ Have ddtrace8 support ])

  PHP_REQUIRE_CXX()
  PHP_CXX_COMPILE_STDCXX(17, mandatory, PHP_DDTRACE8_STDCXX)

  PHP_NEW_EXTENSION(ddtrace8, ddtrace8.c, $ext_shared)

  PHP_DDTRACE8_CXX_SOURCES="observers.cc clocks.cc integration.cc integrations.cc"
  PHP_DDTRACE8_CXX_FLAGS="$PHP_DDTRACE8_STDCXX"

  if test "$ext_shared" = "no"; then
    PHP_ADD_SOURCES(PHP_EXT_DIR(ddtrace8), $PHP_DDTRACE8_CXX_SOURCES, $PHP_DDTRACE8_CXX_FLAGS)
  else
    PHP_ADD_SOURCES_X(PHP_EXT_DIR(ddtrace8), $PHP_DDTRACE8_CXX_SOURCES, $PHP_DDTRACE8_CXX_FLAGS, shared_objects_ddtrace8, yes)
  fi
fi
