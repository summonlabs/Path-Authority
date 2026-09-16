# Path Authority 1.0.0 - Summon Software Labs.
# Apache License 2.0. See LICENSE.
#
# Independent downstream project. It is deliberately not part of the main build:
# it must configure and build against installed artifacts only.
cmake_minimum_required(VERSION 3.25)
project(path_authority_consumer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PathAuthority CONFIG REQUIRED)

add_executable(consumer main.cpp)
target_link_libraries(consumer PRIVATE SummonSoftwareLabs::PathAuthority)

# Fail fast if the installed package leaks its source tree or loses the target.
get_target_property(consumer_includes SummonSoftwareLabs::PathAuthority
                    INTERFACE_INCLUDE_DIRECTORIES)
if(NOT consumer_includes)
  message(FATAL_ERROR "the installed package exports no include directories")
endif()
if(PathAuthority_VERSION VERSION_LESS 1.0.0)
  message(FATAL_ERROR "unexpected PathAuthority package version ${PathAuthority_VERSION}")
endif()
