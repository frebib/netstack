cmake_minimum_required(VERSION 3.8)
set(CMAKE_C_STANDARD 11)

##################
##     netd     ##
##################

project(netd)

file(GLOB_RECURSE NETD_SOURCE_FILES src/**)
add_executable(netd ${NETD_SOURCE_FILES})

# add libnetstack header files
include_directories(../../include)

target_link_libraries(netd
        netstack # the network stack implementation
        cap      # libcap for capabilities (CAP_NET_RAW)
        dl       # dynamic libraries for overriding syscalls
        pthread  # POSIX threads
)

IF (NOT $ENV{USER} STREQUAL "root")
    SET(SUDO_COMMAND gksudo)
    IF($ENV{USE_SUDO})
        SET(SUDO_COMMAND sudo)
    ENDIF($ENV{USE_SUDO})
ENDIF (NOT $ENV{USER} STREQUAL "root")

IF(NOT "$ENV{NO_SETCAP}")
    add_custom_command(TARGET netd POST_BUILD
        COMMAND ${SUDO_COMMAND} setcap cap_net_raw,cap_net_admin+ep netd
        WORKING_DIRECTORY ${EXECUTABLE_OUTPUT_PATH})
ENDIF(NOT "$ENV{NO_SETCAP}")
