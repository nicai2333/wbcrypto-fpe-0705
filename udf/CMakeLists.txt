cmake_minimum_required(VERSION 3.9.0)

project(fpe_udf)

set(CMAKE_BUILD_TYPE Release)

include_directories(/usr/include/mysql)
include_directories(../include)

link_directories(/usr/lib/mysql)
#link_directories(/usr/lib64/mysql)
link_directories(../build/out)

option(MYSQL8 "using mysql8" on)
message(MYSQL8)
if (MYSQL8)
    add_library(fpeudf SHARED mysql8_n.cpp)
    message("Note: mysql version should be 8")
else()
    add_library(fpeudf SHARED mysql5.cpp)
    message("Note: mysql version should be 5")
endif()

target_link_libraries(fpeudf mysqlclient wbcrypto -lm)

set_target_properties(fpeudf PROPERTIES PREFIX "")

install(TARGETS fpeudf DESTINATION /usr/lib/mysql/plugin)
#install(TARGETS fpeudf DESTINATION /usr/lib64/mysql/plugin)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -Wl,-rpath=\"/usr/local/lib\" -O2")

