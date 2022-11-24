# - Try to find libsodium
# Once done this will define
# LIBSODIUM_FOUND - System has libsodium
# libsodium::sodium
# LIBSODIUM_LIBRARIES - The libraries needed to use libsodium
# LIBSODIUM_DEFINITIONS - Compiler switches required for using libsodium

find_package(PkgConfig)
pkg_check_modules(PC_LIBSODIUM QUIET libsodium)
set(LIBSODIUM_DEFINITIONS ${PC_LIBSODIUM_CFLAGS_OTHER})

find_path(LIBSODIUM_INCLUDE_DIR sodium.h
    HINTS ${PC_LIBLIBSODIUM_INCLUDEDIR} ${PC_LIBSODIUM_INCLUDE_DIRS})

find_library(LIBSODIUM_LIBRARY NAMES sodium libsodium
    HINTS ${PC_LIBSODIUM_LIBDIR} ${PC_LIBSODIUM_LIBRARY_DIRS})

include(FindPackageHandleStandardArgs)

# handle the QUIETLY and REQUIRED arguments and set LIBSODIUM_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(libsodium
    FOUND_VAR LIBSODIUM_FOUND
    REQUIRED_VARS LIBSODIUM_LIBRARY LIBSODIUM_INCLUDE_DIR
    VERSION_VAR LIBSODIUM_VERSION_STRING)

mark_as_advanced(LIBSODIUM_INCLUDE_DIR LIBSODIUM_LIBRARY LIBSODIUM_VERSION_STRING)

if(LIBSODIUM_FOUND AND NOT TARGET libsodium::sodium)
    add_library(libsodium::sodium UNKNOWN IMPORTED)
    set_target_properties(libsodium::sodium PROPERTIES
        IMPORTED_LOCATION "${LIBSODIUM_LIBRARY}"
        INTERFACE_COMPILE_OPTIONS "${PC_LIBSODIUM_CFLAGS_OTHER}"
        INTERFACE_INCLUDE_DIRECTORIES "${LIBSODIUM_INCLUDE_DIR}"
    )
endif()
