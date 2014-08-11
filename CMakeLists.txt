cmake_minimum_required(VERSION 2.6)
project(psykoosi)

SET(CMAKE_CXX_FLAGS "-std=c++11 -Og -g")

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

link_directories(${PROJECT_BINARY_DIR})

add_subdirectory(depends)
add_subdirectory(psykoosi)
