# - Try to find relic
# Once done this will define
#  RELIC_FOUND - System has relic
#  RELIC_INCLUDE_DIRS - The relic include directories
#  RELIC_LIBRARIES - The libraries needed to use relic
#  RELIC_DEFINITIONS - Compiler switches required for using relic

find_package(PkgConfig)
pkg_check_modules(PC_RELIC QUIET relic)
set(RELIC_DEFINITIONS ${PC_RELIC_CFLAGS_OTHER})
set(RELIC_VERSION_STRING ${PC_RELIC_VERSION})

find_path(RELIC_INCLUDE_DIR relic.h
          HINTS ${PC_LIBRELIC_INCLUDEDIR} ${PC_RELIC_INCLUDE_DIRS}
          PATH_SUFFIXES relic)

find_library(RELIC_LIBRARY NAMES relic librelic
             HINTS ${PC_RELIC_LIBDIR} ${PC_RELIC_LIBRARY_DIRS})

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set RELIC_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(relic
                                  FOUND_VAR RELIC_FOUND
                                  REQUIRED_VARS RELIC_LIBRARY RELIC_INCLUDE_DIR
                                  VERSION_VAR RELIC_VERSION_STRING)

mark_as_advanced(RELIC_INCLUDE_DIR RELIC_LIBRARY RELIC_VERSION_STRING)

set(RELIC_LIBRARIES ${RELIC_LIBRARY})
set(RELIC_INCLUDE_DIRS ${RELIC_INCLUDE_DIR})
