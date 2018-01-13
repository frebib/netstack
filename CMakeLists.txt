cmake_minimum_required(VERSION 3.8)
set(CMAKE_C_STANDARD 11)

##################
##   netstack   ##
##################

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Werror -Wno-unused-variable -Wno-unused-function -Wno-missing-braces -fstack-protector -O3")

project(netstack)

# Check if _GNU_SOURCE is available.
include (CheckSymbolExists)
if (NOT _GNU_SOURCE)
  CHECK_SYMBOL_EXISTS(__GNU_LIBRARY__ "features.h" _GNU_SOURCE)
  if (NOT _GNU_SOURCE)
    unset(_GNU_SOURCE CACHE)
    CHECK_SYMBOL_EXISTS(_GNU_SOURCE "features.h" _GNU_SOURCE)
  endif()
endif()
if (_GNU_SOURCE)
    add_definitions(-D_GNU_SOURCE)
endif()

file(GLOB_RECURSE NETSTACK_SOURCE_FILES lib/**)
add_library(netstack SHARED ${NETSTACK_SOURCE_FILES})
include_directories(include)
include_directories(ext/ring_buffer/src)

add_custom_target(rbuf
        COMMAND make dynamic
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/ext/ring_buffer
)
add_dependencies(netstack rbuf)

# include netd
add_subdirectory(tools/netd)

target_link_libraries(netstack
        pthread  # POSIX threads
        rt       # realtime for timer_* and semaphores
        ${CMAKE_CURRENT_SOURCE_DIR}/ext/ring_buffer/librbuf.so     # Ring Buffers
)
