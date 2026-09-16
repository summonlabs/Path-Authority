cmake_minimum_required(VERSION 3.25)

project(PathAuthority
  VERSION 1.0.0
  DESCRIPTION "Authoritative path-legality runtime for the Distributed Fabric Infrastructure / Fabric OS stack"
  HOMEPAGE_URL "https://github.com/pngen/Path-Authority"
  LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Global language settings
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(PATH_AUTHORITY_BUILD_TESTS "Build the Path Authority test suites" ON)
option(PATH_AUTHORITY_BUILD_EXAMPLES "Build the Path Authority examples" ON)
option(PATH_AUTHORITY_BUILD_BENCHMARKS "Build the Path Authority benchmarks" ON)
option(PATH_AUTHORITY_BUILD_CLI "Build the path_authority command line tool" ON)
option(PATH_AUTHORITY_WARNINGS_AS_ERRORS "Treat first-party compiler warnings as errors" ON)
option(PATH_AUTHORITY_ENABLE_ASAN "Instrument first-party code with AddressSanitizer" OFF)
option(PATH_AUTHORITY_ENABLE_ANALYZE "Run MSVC static analysis on first-party code" OFF)

set(PATH_AUTHORITY_LIBRARY_TYPE "STATIC" CACHE STRING "Library type: STATIC or SHARED")
set_property(CACHE PATH_AUTHORITY_LIBRARY_TYPE PROPERTY STRINGS STATIC SHARED)

# ---------------------------------------------------------------------------
# Compiler contract
# ---------------------------------------------------------------------------
if(MSVC)
  add_library(path_authority_project_options INTERFACE)
  target_compile_options(path_authority_project_options INTERFACE
    /W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc /MP)
  if(PATH_AUTHORITY_WARNINGS_AS_ERRORS)
    target_compile_options(path_authority_project_options INTERFACE /WX)
  endif()
  if(PATH_AUTHORITY_ENABLE_ASAN)
    target_compile_options(path_authority_project_options INTERFACE /fsanitize=address /Zi)
    target_link_options(path_authority_project_options INTERFACE /INCREMENTAL:NO /DEBUG)
  endif()
  if(PATH_AUTHORITY_ENABLE_ANALYZE)
    target_compile_options(path_authority_project_options INTERFACE /analyze /wd6011)
  endif()
  target_compile_definitions(path_authority_project_options INTERFACE
    _CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
else()
  add_library(path_authority_project_options INTERFACE)
  target_compile_options(path_authority_project_options INTERFACE
    -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion)
  if(PATH_AUTHORITY_WARNINGS_AS_ERRORS)
    target_compile_options(path_authority_project_options INTERFACE -Werror)
  endif()
  if(PATH_AUTHORITY_ENABLE_ASAN)
    target_compile_options(path_authority_project_options INTERFACE -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(path_authority_project_options INTERFACE -fsanitize=address)
  endif()
endif()

# ---------------------------------------------------------------------------
# Library
# ---------------------------------------------------------------------------
set(PATH_AUTHORITY_SOURCES
  src/authority.cpp
  src/canonical.cpp
  src/constraints.cpp
  src/distributed.cpp
  src/evidence.cpp
  src/in_memory.cpp
  src/json.cpp
  src/limits.cpp
  src/local_evidence.cpp
  src/path.cpp
  src/persistence.cpp
  src/runtime.cpp
  src/snapshot.cpp
  src/strong_id.cpp
  src/synthetic.cpp
  src/version.cpp
  src/wire.cpp)

add_library(PathAuthority ${PATH_AUTHORITY_LIBRARY_TYPE} ${PATH_AUTHORITY_SOURCES})
add_library(SummonSoftwareLabs::PathAuthority ALIAS PathAuthority)

target_include_directories(PathAuthority PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

target_compile_features(PathAuthority PUBLIC cxx_std_20)
# Build-tree only: first-party warning, sanitizer and analysis settings must not
# leak into the exported package interface.
target_link_libraries(PathAuthority PRIVATE $<BUILD_INTERFACE:path_authority_project_options>)

set_target_properties(PathAuthority PROPERTIES
  OUTPUT_NAME PathAuthority
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR}
  DEFINE_SYMBOL path_authority_EXPORTS)

if(WIN32)
  target_link_libraries(PathAuthority PUBLIC ws2_32 iphlpapi)
endif()

if(PATH_AUTHORITY_LIBRARY_TYPE STREQUAL "SHARED")
  target_compile_definitions(PathAuthority PUBLIC PATH_AUTHORITY_SHARED)
endif()

# ---------------------------------------------------------------------------
# CLI, examples, benchmarks, tests
# ---------------------------------------------------------------------------
if(PATH_AUTHORITY_BUILD_CLI)
  add_executable(path_authority tools/path_authority_cli.cpp)
  target_link_libraries(path_authority PRIVATE PathAuthority path_authority_project_options)
  set_target_properties(path_authority PROPERTIES OUTPUT_NAME path_authority)
endif()

if(PATH_AUTHORITY_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

if(PATH_AUTHORITY_BUILD_BENCHMARKS)
  add_executable(path_authority_benchmarks benchmarks/path_authority_benchmarks.cpp)
  target_link_libraries(path_authority_benchmarks PRIVATE PathAuthority path_authority_project_options)
  target_compile_definitions(path_authority_benchmarks PRIVATE
    PATH_AUTHORITY_BENCHMARK_TEMP_ROOT="${CMAKE_CURRENT_BINARY_DIR}/benchmark-tmp")
endif()

if(PATH_AUTHORITY_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

# ---------------------------------------------------------------------------
# Install and package export
# ---------------------------------------------------------------------------
install(TARGETS PathAuthority
  EXPORT PathAuthorityTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

if(PATH_AUTHORITY_BUILD_CLI)
  install(TARGETS path_authority RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

install(EXPORT PathAuthorityTargets
  FILE PathAuthorityTargets.cmake
  NAMESPACE SummonSoftwareLabs::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/PathAuthority)

configure_package_config_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/PathAuthorityConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/PathAuthorityConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/PathAuthority)

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/PathAuthorityConfigVersion.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion)

install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/PathAuthorityConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/PathAuthorityConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/PathAuthority)
