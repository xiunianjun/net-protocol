file(GLOB_RECURSE ALL_SOURCE_FILES
src;include/*.c
src;include/*.h)
foreach(FILE ${ALL_SOURCE_FILES})
  execute_process(COMMAND /usr/bin/clang-format -style=file --dry-run ${FILE}
                  RESULT_VARIABLE result)
  if(NOT result EQUAL 0)
    message(WARNING "Formatting errors in ${FILE}")
  endif()
endforeach()