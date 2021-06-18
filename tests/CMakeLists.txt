find_package(cgreen)
if(cgreen_FOUND)
  add_executable(bfe_test bfe.c)
  target_link_libraries(bfe_test PRIVATE bfe ${CGREEN_LIBRARIES})
  target_include_directories(bfe_test PRIVATE ${CGREEN_INCLUDE_DIRS})
  add_test(NAME BFE COMMAND bfe_test)

  add_executable(crypto_api crypto_api.c)
  target_link_libraries(crypto_api PRIVATE bfe ${CGREEN_LIBRARIES})
  target_include_directories(crypto_api PRIVATE ${CGREEN_INCLUDE_DIRS})
  add_test(NAME crypto_api COMMAND crypto_api)

  add_executable(tbfe_test tbfe.c)
  target_link_libraries(tbfe_test PRIVATE bfe_static ${CGREEN_LIBRARIES})
  target_include_directories(tbfe_test PRIVATE ${CGREEN_INCLUDE_DIRS})
  add_test(NAME TBFE COMMAND tbfe_test)
endif()

