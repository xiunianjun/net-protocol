cmake_minimum_required(VERSION 3.0.0)
project(net VERSION 0.1.0)

#Add extra source files here if any
set(EXTRA_FILE 
    
)

if(WIN32)
    set(PCAP wpcap)
else()
    set(PCAP pcap)
endif()

add_compile_options(-Wall -g)
#set(EXECUTABLE_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/test) 
include_directories(./include ./Npcap/Include)
link_directories(./Npcap/Lib ./Npcap/Lib/x64)
aux_source_directory(./src DIR_SRCS)

add_executable(main ${DIR_SRCS})
message(${DIR_SRCS})
target_link_libraries(main ${PCAP})

set(TEST_FIX_SOURCE 
    testing/faker/driver.c 
    testing/global.c
    src/net.c
    src/buf.c
    src/map.c
    src/utils.c
    src/tcp.c
)

# aux_source_directory(./testing DIR_TEST)
add_executable(eth_in 
    testing/eth_in.c
    src/ethernet.c
    testing/faker/arp.c
    testing/faker/ip.c
    testing/faker/icmp.c
    testing/faker/udp.c
    ${TEST_FIX_SOURCE}
    ${EXTRA_FILE}
)
target_link_libraries(eth_in ${PCAP})
target_compile_definitions(eth_in PUBLIC TEST)

add_executable(eth_out
    testing/eth_out.c
    src/ethernet.c
    testing/faker/arp.c
    testing/faker/ip.c
    testing/faker/icmp.c
    testing/faker/udp.c
    ${TEST_FIX_SOURCE}
    ${EXTRA_FILE}
)
target_link_libraries(eth_out ${PCAP})
target_compile_definitions(eth_out PUBLIC TEST)

add_executable(arp_test
    testing/arp_test.c
    src/ethernet.c
    src/arp.c
    testing/faker/ip.c
    testing/faker/icmp.c
    testing/faker/udp.c
    ${TEST_FIX_SOURCE}
    ${EXTRA_FILE}
)
target_link_libraries(arp_test ${PCAP})
target_compile_definitions(arp_test PUBLIC TEST)

add_executable(ip_test
    testing/ip_test.c
    src/ethernet.c
    src/arp.c
    src/ip.c
    testing/faker/icmp.c
    testing/faker/udp.c
    ${TEST_FIX_SOURCE}
    ${EXTRA_FILE}
)
target_link_libraries(ip_test ${PCAP})
target_compile_definitions(ip_test PUBLIC TEST)

add_executable(ip_frag_test
    testing/ip_frag_test.c
    testing/faker/arp.c
    src/ethernet.c
    src/ip.c
    testing/faker/icmp.c
    testing/faker/udp.c
    ${TEST_FIX_SOURCE}
    ${EXTRA_FILE}
)
target_link_libraries(ip_frag_test ${PCAP})
target_compile_definitions(ip_frag_test PUBLIC TEST)

add_executable(icmp_test
    testing/icmp_test.c
    src/ethernet.c
    src/arp.c
    src/ip.c
    src/icmp.c
    testing/faker/udp.c
    ${TEST_FIX_SOURCE}
    ${EXTRA_FILE}
)
target_link_libraries(icmp_test ${PCAP})
target_compile_definitions(icmp_test PUBLIC TEST)

enable_testing()

add_test(
    NAME eth_in 
    COMMAND $<TARGET_FILE:eth_in> ${CMAKE_CURRENT_LIST_DIR}/testing/data/eth_in
)

add_test(
    NAME eth_out
    COMMAND $<TARGET_FILE:eth_out> ${CMAKE_CURRENT_LIST_DIR}/testing/data/eth_out
)

add_test(
    NAME arp_test
    COMMAND $<TARGET_FILE:arp_test> ${CMAKE_CURRENT_LIST_DIR}/testing/data/arp_test
)

add_test(
    NAME ip_test
    COMMAND $<TARGET_FILE:ip_test> ${CMAKE_CURRENT_LIST_DIR}/testing/data/ip_test
)

add_test(
    NAME ip_frag_test
    COMMAND $<TARGET_FILE:ip_frag_test> ${CMAKE_CURRENT_LIST_DIR}/testing/data/ip_frag_test
)

add_test(
    NAME icmp_test
    COMMAND $<TARGET_FILE:icmp_test> ${CMAKE_CURRENT_LIST_DIR}/testing/data/icmp_test
)

message("Executable files is in ${EXECUTABLE_OUTPUT_PATH}.")

# 寻找 clang-format
find_program(CLANG_FORMAT "clang-format")
if(NOT CLANG_FORMAT)
    message(FATAL_ERROR "clang-format not found")
endif()

# 定义源文件和头文件的目录列表
set(SOURCE_DIRS "src" "include")
# 使用 SOURCE_DIRS 变量来获取所有源文件和头文件
foreach(SOURCE_DIR ${SOURCE_DIRS})
    file(GLOB_RECURSE DIR_SOURCE_FILES
        RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
        CONFIGURE_DEPENDS
        "${SOURCE_DIR}/*.c"
        "${SOURCE_DIR}/*.h"
    )
    list(APPEND ALL_SOURCE_FILES ${DIR_SOURCE_FILES})
endforeach()

# 确保 ALL_SOURCE_FILES 变量是唯一的
list(REMOVE_DUPLICATES ALL_SOURCE_FILES)

message(${ALL_SOURCE_FILES})

# 添加一个自定义命令，用于在 make format 时运行 clang-format
add_custom_target(
    format
    COMMAND ${CLANG_FORMAT}
    -i
    -style=file
    ${ALL_SOURCE_FILES}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Formatting code"
    VERBATIM
)

# 添加一个检查格式的命令，用于持续集成测试
add_custom_target(
    check-format
    COMMAND ${CMAKE_COMMAND} -D CLANG_FORMAT=${CLANG_FORMAT}
    -D SOURCE_DIR=${SOURCE_DIRS}
    -P ${CMAKE_SOURCE_DIR}/clang_format_check.cmake
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Checking code format"
    VERBATIM
)

# 可选：创建一个 cmake 脚本用于检查格式
file(WRITE ${CMAKE_SOURCE_DIR}/clang_format_check.cmake
    "file(GLOB_RECURSE ALL_SOURCE_FILES\n"
    "${SOURCE_DIRS}/*.c\n"
    "${SOURCE_DIRS}/*.h)\n"
    "foreach(FILE \${ALL_SOURCE_FILES})\n"
    "  execute_process(COMMAND ${CLANG_FORMAT} -style=file --dry-run \${FILE}\n"
    "                  RESULT_VARIABLE result)\n"
    "  if(NOT result EQUAL 0)\n"
    "    message(WARNING \"Formatting errors in \${FILE}\")\n"
    "  endif()\n"
    "endforeach()"
)