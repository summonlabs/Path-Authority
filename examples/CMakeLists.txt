# Path Authority 1.0.0 - Summon Software Labs.
# Apache License 2.0. See LICENSE.

set(PATH_AUTHORITY_EXAMPLES
  ex_authorized_path
  ex_link_down
  ex_missing_capability
  ex_failure_domain
  ex_stale_epoch
  ex_port_disabled
  ex_revalidation
  ex_primary_backup_diversity
  ex_persistence_recovery)

foreach(example IN LISTS PATH_AUTHORITY_EXAMPLES)
  add_executable(${example} ${example}.cpp example_support.hpp)
  target_link_libraries(${example} PRIVATE PathAuthority path_authority_project_options)
  target_include_directories(${example} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
endforeach()
