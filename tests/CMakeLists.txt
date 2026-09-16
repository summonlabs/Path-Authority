# Path Authority 1.0.0 - Summon Software Labs.
# Apache License 2.0. See LICENSE.

set(PATH_AUTHORITY_TEST_LIBRARIES PathAuthority path_authority_project_options)

function(path_authority_add_test name)
  add_executable(${name} ${name}.cpp test_support.hpp)
  target_link_libraries(${name} PRIVATE ${PATH_AUTHORITY_TEST_LIBRARIES})
  target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  target_compile_definitions(${name} PRIVATE
    PATH_AUTHORITY_CLI_PATH="$<TARGET_FILE:path_authority>"
    PATH_AUTHORITY_TEST_TEMP_ROOT="${CMAKE_CURRENT_BINARY_DIR}/tmp")
  add_test(NAME ${name} COMMAND ${name})
endfunction()

path_authority_add_test(pa_test_core)
path_authority_add_test(pa_test_authority)
path_authority_add_test(pa_test_dependencies)
path_authority_add_test(pa_test_persistence)
path_authority_add_test(pa_test_limits)
path_authority_add_test(pa_test_wire)
path_authority_add_test(pa_test_concurrency)
path_authority_add_test(pa_test_property)
path_authority_add_test(pa_test_adversarial)
path_authority_add_test(pa_test_distributed)
path_authority_add_test(pa_test_local_evidence)

# The distributed suite and the CLI must exist before it runs.
if(TARGET path_authority)
  set_tests_properties(pa_test_distributed PROPERTIES DEPENDS path_authority)
endif()
