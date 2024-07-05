include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/WBMatrix/include)

set(TEST_BUILD_NAME fpe_test)

add_executable(${TEST_BUILD_NAME} fpe_test.c test_utils.c)
TARGET_LINK_LIBRARIES(${TEST_BUILD_NAME} wbcrypto -lssl -lcrypto -lm)
target_link_libraries(${TEST_BUILD_NAME} ${SDF_LIBRARY})
#target_compile_definitions(${TEST_BUILD_NAME} PRIVATE SDF_LIBRARY_PATH="${SDF_LIBRARY}")


# set(TEST_BUILD_NAME fpe_app_test)
# add_executable(${TEST_BUILD_NAME} fpe_app_test.c test_utils.c)
# TARGET_LINK_LIBRARIES(${TEST_BUILD_NAME} wbcrypto -lssl -lcrypto -lm)

# set(TEST_BUILD_NAME wbsm4_fpe_app_test)
# add_executable(${TEST_BUILD_NAME} wbsm4_fpe_app_test.c test_utils.c)
# TARGET_LINK_LIBRARIES(${TEST_BUILD_NAME} wbcrypto -lssl -lcrypto -lm)

# set(TEST_BUILD_NAME key2file)
# add_executable(${TEST_BUILD_NAME} key2file.c test_utils.c)
# TARGET_LINK_LIBRARIES(${TEST_BUILD_NAME} wbcrypto -lssl -lcrypto -lm)

set(TEST_BUILD_NAME fpe_app_speed_test)
# set(CMAKE_BUILD_RPATH ${CMAKE_SOURCE_DIR})
add_executable(${TEST_BUILD_NAME} fpe_app_speed_test.c test_utils.c)
TARGET_LINK_LIBRARIES(${TEST_BUILD_NAME} wbcrypto -lssl -lcrypto -lm)