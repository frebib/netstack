cmake_minimum_required(VERSION 3.8)
set(CMAKE_C_STANDARD 11)

##################
##    libnet    ##
##################

project(libnet)

include_directories(include)

file(GLOB_RECURSE SOURCE_FILES lib/**)
add_library(net SHARED ${SOURCE_FILES})


##################
##     netd     ##
##################

project(netd)

file(GLOB_RECURSE SOURCE_FILES src/**)
add_executable(netd ${SOURCE_FILES})

target_link_libraries(netd
        net      # libnet, the network stack implementation
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
