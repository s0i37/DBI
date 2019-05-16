cmake_minimum_required(VERSION 2.6)

if (NOT DEFINED DynamoRIO_DIR)
  set(DynamoRIO_DIR "${PROJECT_SOURCE_DIR}/../cmake" CACHE PATH
    "DynamoRIO installation's cmake directory")
endif (NOT DEFINED DynamoRIO_DIR)

find_package(DynamoRIO 7.0)
if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIO package required to build")
endif(NOT DynamoRIO_FOUND)

function (add_sample_client name source_file_list extension_list)
  add_library(${name} SHARED ${source_file_list})
  configure_DynamoRIO_client(${name})
  foreach (ext ${extension_list})
    use_DynamoRIO_extension(${name} ${ext})
  endforeach (ext)

  # Provide a hint for how to use the client
  if (NOT DynamoRIO_INTERNAL OR NOT "${CMAKE_GENERATOR}" MATCHES "Ninja")
    get_target_property(path ${name} LOCATION${location_suffix})
    add_custom_command(TARGET ${name}
      POST_BUILD
      COMMAND ${CMAKE_COMMAND}
      ARGS -E echo "Usage: pass to drconfig or drrun: -c ${path}"
      VERBATIM)
  endif ()

endfunction (add_sample_client)

add_sample_client(sample       "sample.c"         "drmgr;drwrap")

