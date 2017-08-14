cmake_minimum_required(VERSION 3.8)
set(CMAKE_C_STANDARD 11)

project(libnet)

file(GLOB_RECURSE SOURCE_FILES src/**)
add_library(net SHARED ${SOURCE_FILES})
