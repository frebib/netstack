cmake_minimum_required(VERSION 3.8)
project(tcpd)

set(CMAKE_C_STANDARD 11)

set(SOURCE_FILES src/main.c)
add_executable(tcpd ${SOURCE_FILES})

target_link_libraries(tcpd cap)

SET(SUDO_COMMAND gksudo)
IF($ENV{USE_NORMAL_SUDO})
    SET(SUDO_COMMAND sudo)
ENDIF($ENV{USE_NORMAL_SUDO})

add_custom_command(TARGET tcpd POST_BUILD
        COMMAND ${SUDO_COMMAND} setcap cap_net_raw+ep tcpd
        WORKING_DIRECTORY ${EXECUTABLE_OUTPUT_PATH})