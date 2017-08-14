cmake_minimum_required(VERSION 3.8)
set(CMAKE_C_STANDARD 11)

project(netd)

add_subdirectory(libnet)

file(GLOB_RECURSE SOURCE_FILES src/**)
add_executable(netd ${SOURCE_FILES})

target_link_libraries(netd
        net      # libnet, the network stack implementation
        cap      # libcap for capabilities (CAP_NET_RAW)
        dl       # dynamic libraries for overriding syscalls
)

SET(SUDO_COMMAND gksudo)
IF($ENV{USE_SUDO})
    SET(SUDO_COMMAND sudo)
ENDIF($ENV{USE_SUDO})

add_custom_command(TARGET netd POST_BUILD
        COMMAND ${SUDO_COMMAND} setcap cap_net_raw+ep netd
        WORKING_DIRECTORY ${EXECUTABLE_OUTPUT_PATH})
