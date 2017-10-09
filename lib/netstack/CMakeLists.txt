cmake_minimum_required(VERSION 3.8)
set(CMAKE_C_STANDARD 11)

##################
##   netstack   ##
##################

project(netstack)

file(GLOB_RECURSE NETSTACK_SOURCE_FILES src/**)
add_library(netstack SHARED ${NETSTACK_SOURCE_FILES})
include_directories(include)

target_link_libraries(netstack
        pthread  # POSIX threads
)
