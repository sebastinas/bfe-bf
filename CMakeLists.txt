cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

# honor visibility properties
cmake_policy(SET CMP0063 NEW)
# enforce IPO if enabled
cmake_policy(SET CMP0069 NEW)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Choose the type of build." FORCE)
endif()

project(bfe-bf LANGUAGES C VERSION 2.0 DESCRIPTION "Bloom Filter Encryption library with Boneh-Franklin IBE")

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# settings
set(MAX_BLOOMFILTER_HASH_COUNT 16 CACHE STRING "Maximal number of bloom filter hash functions.")
set(MAX_BFE_BF_KEY_SIZE 32 CACHE STRING "Maximal size of encapsulated key.")

include(GNUInstallDirs)
include(CheckCCompilerFlag)
include(CheckIPOSupported)
include(CheckIncludeFiles)
include(CheckSymbolExists)

function(check_c_compiler_flag_and_add flag result)
  check_c_compiler_flag("${flag}" ${result})
  if(${result})
    add_compile_options("${flag}")
  endif()
endfunction()

check_c_compiler_flag_and_add(-Wall CC_SUPPORTS_WALL)
check_c_compiler_flag_and_add(-Wextra CC_SUPPORTS_WEXTRA)
check_c_compiler_flag_and_add(-Wshadow CC_SUPPORTS_WSHADOW)
check_c_compiler_flag_and_add(-Werror=implicit-function-declaration CC_SUPPORTS_WERROR_IMPLICIT_FUNCTION_DECLARATION)
check_c_compiler_flag_and_add(-Werror=vla CC_SUPPORTS_WERROR_VLA)

# check availability of some functions
check_symbol_exists(explicit_bzero string.h HAVE_EXPLICIT_BZERO)

check_ipo_supported(RESULT LTO_SUPPORTED)

find_package(relic REQUIRED)
find_package(Doxygen)
find_package(OpenMP)

# generate config.h
configure_file(config.h.in config.h)

add_library(bfebf SHARED
            bfe-bf.c
            crypto_api.c
            FIPS202-opt64/KeccakHash.c
            FIPS202-opt64/KeccakP-1600-opt64.c
            FIPS202-opt64/KeccakSpongeWidth1600.c)

set_target_properties(bfebf PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(bfebf PROPERTIES C_VISIBILITY_PRESET hidden)
if (LTO_SUPPORTED)
  set_target_properties(bfebf PROPERTIES INTERPROCEDURAL_OPTIMIZATION TRUE)
endif()

configure_file(bfe-bf.pc.in bfe-bf.pc @ONLY)

target_link_libraries(bfebf PUBLIC ${RELIC_LIBRARY})
target_link_libraries(bfebf PRIVATE m)
target_include_directories(bfebf PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${RELIC_INCLUDE_DIR})
if(OpenMP_C_FOUND)
  target_link_libraries(bfebf PRIVATE OpenMP::OpenMP_C)
endif()

install(TARGETS bfebf
        EXPORT bfe-bf-targets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES ${CMAKE_BINARY_DIR}/bfe-bf.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/bfe-bf)
install(EXPORT bfe-bf-targets
        NAMESPACE bfe-bf::
        FILE bfe-bf-config.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/bfe-bf)

if(DOXYGEN_FOUND)
  set(DOXYGEN_RECURSIVE NO)
  set(DOXYGEN_EXTRACT_ALL YES)
  set(DOXYGEN_OPTIMIZE_OUTPUT_FOR_C YES)
  set(DOXYGEN_TYPEDEF_HIDES_STRUCT YES)
  set(DOXYGEN_SOURCE_BROWSER YES)
  set(DOXYGEN_PREDEFINED "BFE_BF_VISIBLE=")
  set(DOXYGEN_ENABLE_PREPROCESSING YES)
  set(DOXYGEN_MACRO_EXPANSION YES)
  set(DOXYGEN_EXPAND_ONLY_PREDEF YES)
  doxygen_add_docs(doxygen ${CMAKE_CURRENT_SOURCE_DIR}/include COMMENT "Generate doxygen documentation")
endif()

# benchmarks
add_executable(bench bench.c)
target_link_libraries(bench PRIVATE bfebf ${RELIC_LIBRARY})

# testing
enable_testing()
add_subdirectory(tests)
