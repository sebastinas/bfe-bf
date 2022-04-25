cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

# honor visibility properties
cmake_policy(SET CMP0063 NEW)
# enforce IPO if enabled
cmake_policy(SET CMP0069 NEW)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Choose the type of build." FORCE)
endif()

project(bfe LANGUAGES C CXX VERSION 2.0 DESCRIPTION "Bloom Filter Encryption library")

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# settings
set(MAX_BLOOMFILTER_HASH_COUNT 16 CACHE STRING "Maximal number of bloom filter hash functions.")
set(MAX_BFE_KEY_SIZE 32 CACHE STRING "Maximal size of encapsulated key.")

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
check_c_compiler_flag_and_add(-Werror=vla CC_SUPPORTS_WERROR_VLA)

# check availability of some functions
check_symbol_exists(explicit_bzero string.h HAVE_EXPLICIT_BZERO)

check_ipo_supported(RESULT LTO_SUPPORTED)

find_package(relic REQUIRED)
find_package(Doxygen)
find_package(OpenMP REQUIRED)

# generate config.h
configure_file(config.h.in config.h)

list(APPEND BFE_SOURCES
     FIPS202-opt64/KeccakHash.c
     FIPS202-opt64/KeccakP-1600-opt64.c
     FIPS202-opt64/KeccakSpongeWidth1600.c
     bfe-bf.c
     core.c
     crypto_api.c
     tbfe-bbg.c
     vector.c)

add_library(bfe SHARED ${BFE_SOURCES})
add_library(bfe_static STATIC ${BFE_SOURCES})
target_compile_definitions(bfe_static PRIVATE BFE_STATIC)
if (LTO_SUPPORTED)
  set_target_properties(bfe_static PROPERTIES INTERPROCEDURAL_OPTIMIZATION TRUE)
endif()

set_target_properties(bfe PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(bfe PROPERTIES C_VISIBILITY_PRESET hidden)
if (LTO_SUPPORTED)
  set_target_properties(bfe PROPERTIES INTERPROCEDURAL_OPTIMIZATION TRUE)
endif()

configure_file(bfe.pc.in bfe.pc @ONLY)

target_link_libraries(bfe PUBLIC ${RELIC_LIBRARY})
target_link_libraries(bfe PRIVATE m)
target_include_directories(bfe PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${RELIC_INCLUDE_DIR})
target_link_libraries(bfe PRIVATE OpenMP::OpenMP_C)

target_link_libraries(bfe_static PUBLIC ${RELIC_LIBRARY})
target_link_libraries(bfe_static PUBLIC m)
target_include_directories(bfe_static PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${RELIC_INCLUDE_DIR})
target_link_libraries(bfe_static PUBLIC OpenMP::OpenMP_C)

install(TARGETS bfe
        EXPORT bfe-targets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES ${CMAKE_BINARY_DIR}/bfe.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/bfe)
install(EXPORT bfe-targets
        NAMESPACE bfe::
        FILE bfe-config.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/bfe)

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
add_executable(bench bench.cpp)
target_link_libraries(bench PRIVATE bfe)
if (LTO_SUPPORTED)
  set_target_properties(bench PROPERTIES INTERPROCEDURAL_OPTIMIZATION TRUE)
endif()

# testing
enable_testing()
add_subdirectory(tests)
