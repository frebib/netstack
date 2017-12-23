cmake_minimum_required(VERSION 3.8)
set(CMAKE_C_STANDARD 11)

##################
##   netstack   ##
##################

set(CMAKE_CXX_FLAGS "-Wall -Werror -Wpedantic -Wno-unused-variable")

project(netstack)

file(GLOB_RECURSE NETSTACK_SOURCE_FILES lib/**)
add_library(netstack SHARED ${NETSTACK_SOURCE_FILES})
include_directories(include)

# include netd
add_subdirectory(tools/netd)

target_link_libraries(netstack
        pthread  # POSIX threads
)
