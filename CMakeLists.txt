cmake_minimum_required(VERSION 3.19.0)
set(CMAKE_MESSAGE_LOG_LEVEL INFO)

if("${CMAKE_BUILD_PLATFORM}" STREQUAL "Device")
    message(STATUS "Device platform selected")
    set(CMAKE_TOOLCHAIN_FILE utilities/cmake/arm-none-eabi-gcc.cmake)
    set(PROJECT Cypherock-${FIRMWARE_TYPE}) # FIRMWARE_TYPE should be passed as a CMake argument
elseif("${CMAKE_BUILD_PLATFORM}" STREQUAL "Simulator")
    message(STATUS "Simulator platform selected")
    set(PROJECT Cypherock_Simulator)
else()
    message(WARNING "No platform specified, defaulting to Simulator. Specify using -DCMAKE_BUILD_PLATFORM=<Type> Type can be Device or Simulator")
    set(PROJECT Cypherock_Simulator)
    set(CMAKE_BUILD_PLATFORM "Simulator") # Explicitly set for clarity if defaulting
endif()

project(${PROJECT})

find_package( Python3 REQUIRED COMPONENTS Interpreter )
execute_process(COMMAND sh utilities/proto/generate-protob.sh WORKING_DIRECTORY ${PROJECT_SOURCE_DIR} COMMAND_ERROR_IS_FATAL ANY )

include(utilities/cmake/version.cmake) # Populates version.c

file(GLOB_RECURSE PROTO_SRCS "generated/proto/*.*")
list(APPEND PROTO_SRCS "vendor/nanopb/pb_common.c" "vendor/nanopb/pb_decode.c" "vendor/nanopb/pb_encode.c" "vendor/nanopb/pb_common.h" "vendor/nanopb/pb_decode.h" "vendor/nanopb/pb_encode.h" "vendor/nanopb/pb.h")

list (APPEND MINI_GMP_SRCS "vendor/mini-gmp/mini-gmp-helpers.c" "vendor/mini-gmp/mini-gmp.c")
list (APPEND POSEIDON_SRCS "vendor/poseidon/sources/f251.c" "vendor/poseidon/sources/poseidon.c" "vendor/poseidon/sources/poseidon_rc.c")

OPTION(DEV_SWITCH "Additional features/logs to aid developers" OFF)
OPTION(UNIT_TESTS_SWITCH "Compile build for main firmware or unit tests" OFF)
OPTION(btc_only "Build firmware for Bitcoin only" OFF)

IF(UNIT_TESTS_SWITCH)
    add_compile_definitions( STATIC= )
ELSE()
    add_compile_definitions( STATIC=static )
ENDIF(UNIT_TESTS_SWITCH)

if ("${CMAKE_BUILD_TYPE}" STREQUAL "Release")
    add_compile_definitions(FIRMWARE_HASH_CALC=1)
else()
    add_compile_definitions(FIRMWARE_HASH_CALC=0)
endif()

if("${CMAKE_BUILD_PLATFORM}" STREQUAL "Device")
    include(utilities/cmake/firmware/firmware.cmake)
else() # Simulator or default
    include(utilities/cmake/simulator/simulator.cmake)
endif()

if(TARGET ${EXECUTABLE})
    target_include_directories( ${EXECUTABLE} PRIVATE 
        "${CMAKE_SOURCE_DIR}/vendor/nanopb"
        "${CMAKE_SOURCE_DIR}/generated/proto"
        "${CMAKE_SOURCE_DIR}/vendor/mini-gmp"
        "${CMAKE_SOURCE_DIR}/vendor/poseidon/sources"
    )
    target_compile_definitions( ${EXECUTABLE} PRIVATE PB_ENABLE_MALLOC=1 PB_NO_ERRMSG=1)
else()
    if("${CMAKE_BUILD_PLATFORM}" STREQUAL "Device" OR (NOT CMAKE_BUILD_PLATFORM AND NOT PROJECT STREQUAL "Cypherock_Simulator"))
        # This warning might appear if firmware.cmake itself fails early due to a parse error
        message(WARNING "EXECUTABLE target not defined when expected. Common includes/definitions for EXECUTABLE might be skipped.")
    endif()
endif()