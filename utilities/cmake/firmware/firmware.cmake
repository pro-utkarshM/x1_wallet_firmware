enable_language(C ASM)
set(EXECUTABLE ${PROJECT_NAME}.elf)
set(LINKER_SCRIPT STM32L486RGTX_FLASH.ld)
# STARTUP_FILE is picked by glob if in stm32-hal, e.g. startup_stm32l486xx.s
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

message(STATUS "-----------------------------------------------------")
message(STATUS "Firmware Build Configuration (firmware.cmake):")
message(STATUS "  Project Name: ${PROJECT_NAME}")
message(STATUS "  Target Executable: ${EXECUTABLE}")
message(STATUS "  BTC-Only Build: ${btc_only}")
message(STATUS "  Unit Tests: ${UNIT_TESTS_SWITCH}")
message(STATUS "  Dev Build: ${DEV_SWITCH}")
message(STATUS "  Firmware Type: ${FIRMWARE_TYPE}")
message(STATUS "  Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "-----------------------------------------------------")

set(SOURCES_TO_GLOB "")

list(APPEND SOURCES_TO_GLOB
    "${CMAKE_SOURCE_DIR}/stm32-hal/*.*"
    "${CMAKE_SOURCE_DIR}/src/*.*"
)
# Add startup file from root if it's there, as seen in tree.txt
list(APPEND SOURCES_TO_GLOB "${CMAKE_SOURCE_DIR}/startup_stm32l486xx.s")


if(btc_only)
    message(STATUS "Configuring for BTC-only app sources and RESTRICTED common sources")
    list(APPEND SOURCES_TO_GLOB
        "${CMAKE_SOURCE_DIR}/apps/manager_app/*.*"
        "${CMAKE_SOURCE_DIR}/apps/btc_family/btc/*.*"
        "${CMAKE_SOURCE_DIR}/apps/btc_family/btc_api.c"
        "${CMAKE_SOURCE_DIR}/apps/btc_family/btc_helpers.c"
        "${CMAKE_SOURCE_DIR}/apps/btc_family/btc_inputs_validator.c"
        "${CMAKE_SOURCE_DIR}/apps/btc_family/btc_main.c"
        "${CMAKE_SOURCE_DIR}/apps/btc_family/btc_pub_key.c"
        "${CMAKE_SOURCE_DIR}/apps/btc_family/btc_script.c"
        "${CMAKE_SOURCE_DIR}/apps/btc_family/btc_txn.c"
        "${CMAKE_SOURCE_DIR}/apps/btc_family/btc_txn_helpers.c"
        "${CMAKE_SOURCE_DIR}/apps/btc_family/btc_xpub.c"
        "${CMAKE_SOURCE_DIR}/apps/inheritance_app/*.*"
    )

    list(APPEND SOURCES_TO_GLOB
        "${CMAKE_SOURCE_DIR}/common/interfaces/*.*"
        "${CMAKE_SOURCE_DIR}/common/libraries/*.*"
        "${CMAKE_SOURCE_DIR}/common/startup/*.*"
        "${CMAKE_SOURCE_DIR}/common/logger/*.*"
        "${CMAKE_SOURCE_DIR}/common/flash/*.*"
        "${CMAKE_SOURCE_DIR}/common/Firewall/*.*"
        "${CMAKE_SOURCE_DIR}/common/core/*.*"
        "${CMAKE_SOURCE_DIR}/common/timers/*.*"
        "${CMAKE_SOURCE_DIR}/common/lvgl/*.*"
        # Explicitly list any files from common/coin_support needed for BTC-only build.
        # For example:
        # "${CMAKE_SOURCE_DIR}/common/coin_support/your_btc_specific_or_generic_util.c"
    )
else() # Build All (btc_only=OFF)
    message(STATUS "Configuring for all app sources and all common sources")
    list(APPEND SOURCES_TO_GLOB "${CMAKE_SOURCE_DIR}/apps/*.*")
    list(APPEND SOURCES_TO_GLOB "${CMAKE_SOURCE_DIR}/common/*.*")
endif()

IF(UNIT_TESTS_SWITCH)
    message(STATUS "Unit tests enabled, collecting test sources.")
    list(APPEND SOURCES_TO_GLOB
        "${CMAKE_SOURCE_DIR}/tests/framework/*.*"
        "${CMAKE_SOURCE_DIR}/tests/common/core/*.*"
        "${CMAKE_SOURCE_DIR}/tests/common/util/*.*"
        "${CMAKE_SOURCE_DIR}/tests/p0_events/*.*"
        "${CMAKE_SOURCE_DIR}/tests/ui/ui_events_test/*.*"
        "${CMAKE_SOURCE_DIR}/tests/usb/events/*.*"
        "${CMAKE_SOURCE_DIR}/tests/nfc/*.*"
    )
    if(btc_only)
        message(STATUS "Collecting BTC-only specific app test sources.")
        list(APPEND SOURCES_TO_GLOB
            "${CMAKE_SOURCE_DIR}/tests/apps/manager_app/*.*"
            "${CMAKE_SOURCE_DIR}/tests/apps/btc_app/*.*"
            "${CMAKE_SOURCE_DIR}/tests/apps/inheritance_app/*.*"
        )
    else()
        message(STATUS "Collecting all app test sources.")
        list(APPEND SOURCES_TO_GLOB "${CMAKE_SOURCE_DIR}/tests/apps/*.*")
    endif()
ENDIF()

file(GLOB_RECURSE ALL_SOURCES ${SOURCES_TO_GLOB})
list(REMOVE_DUPLICATES ALL_SOURCES)

if(NOT ALL_SOURCES AND NOT UNIT_TESTS_SWITCH)
    if(SOURCES_TO_GLOB)
         message(WARNING "No source files found by GLOB_RECURSE for the current configuration. Review paths in SOURCES_TO_GLOB: ${SOURCES_TO_GLOB}")
    endif()
endif()
set(SOURCES ${ALL_SOURCES})

IF(UNIT_TESTS_SWITCH)
    LIST(REMOVE_ITEM SOURCES "${CMAKE_SOURCE_DIR}/src/main.c")
ENDIF()

add_executable(${EXECUTABLE}
    ${SOURCES}
    ${CMAKE_CURRENT_BINARY_DIR}/version.c
    ${MINI_GMP_SRCS}
    ${POSEIDON_SRCS}
    ${PROTO_SRCS}
)

target_compile_definitions(${EXECUTABLE} PRIVATE
    USE_HAL_DRIVER STM32L486xx
    USE_SIMULATOR=0 USE_BIP32_CACHE=0 USE_BIP39_CACHE=0 STM32L4 USBD_SOF_DISABLED ENABLE_HID_WEBUSB_COMM=1
)
IF (DEV_SWITCH)
    target_compile_definitions(${EXECUTABLE} PRIVATE DEV_BUILD)
ENDIF()
if(btc_only)
    target_compile_definitions(${EXECUTABLE} PRIVATE BTC_ONLY_BUILD)
endif()
if ("${FIRMWARE_TYPE}" STREQUAL "Main")
    target_compile_definitions(${EXECUTABLE} PRIVATE X1WALLET_INITIAL=0 X1WALLET_MAIN=1)
elseif("${FIRMWARE_TYPE}" STREQUAL "Initial")
    target_compile_definitions(${EXECUTABLE} PRIVATE X1WALLET_INITIAL=1 X1WALLET_MAIN=0)
else()
    message(FATAL_ERROR "Firmware type not specified. Specify using -DFIRMWARE_TYPE=<Type> Type can be Main or Initial")
endif()
IF(UNIT_TESTS_SWITCH)
    target_compile_definitions(${EXECUTABLE} PRIVATE UNITY_INCLUDE_CONFIG_H UNITY_FIXTURE_NO_EXTRAS)
ENDIF()

target_include_directories(${EXECUTABLE} PRIVATE
    "${CMAKE_SOURCE_DIR}/src" "${CMAKE_SOURCE_DIR}/src/menu" "${CMAKE_SOURCE_DIR}/src/wallet" "${CMAKE_SOURCE_DIR}/src/restricted_app" "${CMAKE_SOURCE_DIR}/src/onboarding" "${CMAKE_SOURCE_DIR}/src/settings"
    "${CMAKE_SOURCE_DIR}/src/card_operations" "${CMAKE_SOURCE_DIR}/src/card_flows"
    "${CMAKE_SOURCE_DIR}/src/level_one/controller" "${CMAKE_SOURCE_DIR}/src/level_one/tasks"
    "${CMAKE_SOURCE_DIR}/src/level_two/controller" "${CMAKE_SOURCE_DIR}/src/level_two/tasks"
    "${CMAKE_SOURCE_DIR}/src/level_three/add_wallet/controller" "${CMAKE_SOURCE_DIR}/src/level_three/add_wallet/tasks"
    "${CMAKE_SOURCE_DIR}/src/level_three/advanced_settings/controller" "${CMAKE_SOURCE_DIR}/src/level_three/advanced_settings/tasks"
    "${CMAKE_SOURCE_DIR}/src/level_three/old_wallet/controller" "${CMAKE_SOURCE_DIR}/src/level_three/old_wallet/tasks"
    "${CMAKE_SOURCE_DIR}/src/level_four/core/controller" "${CMAKE_SOURCE_DIR}/src/level_four/core/tasks"
    "${CMAKE_SOURCE_DIR}/src/level_four/card_health_check" "${CMAKE_SOURCE_DIR}/src/level_four/factory_reset"
    "${CMAKE_SOURCE_DIR}/src/level_four/tap_cards/controller" "${CMAKE_SOURCE_DIR}/src/level_four/tap_cards/tasks"
    "${CMAKE_SOURCE_DIR}/common/interfaces/card_interface" "${CMAKE_SOURCE_DIR}/common/interfaces/desktop_app_interface"
    "${CMAKE_SOURCE_DIR}/common/interfaces/flash_interface" "${CMAKE_SOURCE_DIR}/common/interfaces/user_interface"
    "${CMAKE_SOURCE_DIR}/common/libraries/atecc" "${CMAKE_SOURCE_DIR}/common/libraries/atecc/atcacert" "${CMAKE_SOURCE_DIR}/common/libraries/atecc/basic"
    "${CMAKE_SOURCE_DIR}/common/libraries/atecc/crypto" "${CMAKE_SOURCE_DIR}/common/libraries/atecc/crypto/hashes"
    "${CMAKE_SOURCE_DIR}/common/libraries/atecc/hal" "${CMAKE_SOURCE_DIR}/common/libraries/atecc/host" "${CMAKE_SOURCE_DIR}/common/libraries/atecc/jwt"
    "${CMAKE_SOURCE_DIR}/common/libraries/crypto" "${CMAKE_SOURCE_DIR}/common/libraries/crypto/mpz_operations" "${CMAKE_SOURCE_DIR}/common/libraries/crypto/aes"
    "${CMAKE_SOURCE_DIR}/common/libraries/crypto/chacha20poly1305" "${CMAKE_SOURCE_DIR}/common/libraries/crypto/ed25519-donna"
    "${CMAKE_SOURCE_DIR}/common/libraries/crypto/monero" "${CMAKE_SOURCE_DIR}/common/libraries/crypto/random_gen"
    "${CMAKE_SOURCE_DIR}/common/libraries/proof_of_work" "${CMAKE_SOURCE_DIR}/common/libraries/shamir" "${CMAKE_SOURCE_DIR}/common/libraries/util"
    "${CMAKE_SOURCE_DIR}/common/startup" "${CMAKE_SOURCE_DIR}/common/logger"
    "${CMAKE_SOURCE_DIR}/common/coin_support"
    "${CMAKE_SOURCE_DIR}/common/flash" "${CMAKE_SOURCE_DIR}/common/Firewall" "${CMAKE_SOURCE_DIR}/common/core" "${CMAKE_SOURCE_DIR}/common/timers" "${CMAKE_SOURCE_DIR}/common"
    "${CMAKE_SOURCE_DIR}/common/lvgl" "${CMAKE_SOURCE_DIR}/common/lvgl/porting" "${CMAKE_SOURCE_DIR}/common/lvgl/src" "${CMAKE_SOURCE_DIR}/common/lvgl/src/lv_core"
    "${CMAKE_SOURCE_DIR}/common/lvgl/src/lv_draw" "${CMAKE_SOURCE_DIR}/common/lvgl/src/lv_font" "${CMAKE_SOURCE_DIR}/common/lvgl/src/lv_hal"
    "${CMAKE_SOURCE_DIR}/common/lvgl/src/lv_misc" "${CMAKE_SOURCE_DIR}/common/lvgl/src/lv_objx" "${CMAKE_SOURCE_DIR}/common/lvgl/src/lv_themes"
    "${CMAKE_SOURCE_DIR}/stm32-hal" "${CMAKE_SOURCE_DIR}/stm32-hal/BSP" "${CMAKE_SOURCE_DIR}/stm32-hal/Inc"
    "${CMAKE_SOURCE_DIR}/stm32-hal/Drivers/CMSIS/Include" "${CMAKE_SOURCE_DIR}/stm32-hal/Drivers/CMSIS/Device/ST/STM32L4xx/Include"
    "${CMAKE_SOURCE_DIR}/stm32-hal/Drivers/STM32L4xx_HAL_Driver/Inc" "${CMAKE_SOURCE_DIR}/stm32-hal/Drivers/STM32L4xx_HAL_Driver/Inc/Legacy"
    "${CMAKE_SOURCE_DIR}/stm32-hal/Startup"
    "${CMAKE_SOURCE_DIR}/stm32-hal/Middlewares/ST/STM32_USB_Device_Library/Class/CDC/Inc"
    "${CMAKE_SOURCE_DIR}/stm32-hal/Middlewares/ST/STM32_USB_Device_Library/Core/Inc"
    "${CMAKE_SOURCE_DIR}/stm32-hal/Peripherals" "${CMAKE_SOURCE_DIR}/stm32-hal/Peripherals/Buzzer" "${CMAKE_SOURCE_DIR}/stm32-hal/Peripherals/display"
    "${CMAKE_SOURCE_DIR}/stm32-hal/Peripherals/display/SSD1306" "${CMAKE_SOURCE_DIR}/stm32-hal/Peripherals/flash/"
    "${CMAKE_SOURCE_DIR}/stm32-hal/Peripherals/logger/" "${CMAKE_SOURCE_DIR}/stm32-hal/Peripherals/nfc/"
    "${CMAKE_SOURCE_DIR}/stm32-hal/porting" "${CMAKE_SOURCE_DIR}/stm32-hal/libusb/" "${CMAKE_SOURCE_DIR}/stm32-hal/libusb/inc"
)

if ("${FIRMWARE_TYPE}" STREQUAL "Main")
    target_include_directories(${EXECUTABLE} PRIVATE "${CMAKE_SOURCE_DIR}/main/config/")
elseif("${FIRMWARE_TYPE}" STREQUAL "Initial")
    target_include_directories(${EXECUTABLE} PRIVATE "${CMAKE_SOURCE_DIR}/initial/config/")
endif()

target_include_directories(${EXECUTABLE} PRIVATE "${CMAKE_SOURCE_DIR}/apps/manager_app")
target_include_directories(${EXECUTABLE} PRIVATE "${CMAKE_SOURCE_DIR}/apps/inheritance_app")

if(btc_only)
    target_include_directories(${EXECUTABLE} PRIVATE "${CMAKE_SOURCE_DIR}/apps/btc_family/btc")
    target_include_directories(${EXECUTABLE} PRIVATE "${CMAKE_SOURCE_DIR}/apps/btc_family")
else() # Build All
    target_include_directories(${EXECUTABLE} PRIVATE
        "${CMAKE_SOURCE_DIR}/apps/btc_family"
        "${CMAKE_SOURCE_DIR}/apps/btc_family/btc"
        "${CMAKE_SOURCE_DIR}/apps/btc_family/dash"
        "${CMAKE_SOURCE_DIR}/apps/btc_family/doge"
        "${CMAKE_SOURCE_DIR}/apps/btc_family/ltc"
        "${CMAKE_SOURCE_DIR}/apps/evm_family"
        "${CMAKE_SOURCE_DIR}/apps/evm_family/eth"
        "${CMAKE_SOURCE_DIR}/apps/evm_family/polygon"
        "${CMAKE_SOURCE_DIR}/apps/evm_family/bsc"
        "${CMAKE_SOURCE_DIR}/apps/evm_family/fantom"
        "${CMAKE_SOURCE_DIR}/apps/evm_family/avalanche"
        "${CMAKE_SOURCE_DIR}/apps/evm_family/optimism"
        "${CMAKE_SOURCE_DIR}/apps/evm_family/arbitrum"
        "${CMAKE_SOURCE_DIR}/apps/near_app"
        "${CMAKE_SOURCE_DIR}/apps/solana_app"
        "${CMAKE_SOURCE_DIR}/apps/tron_app"
        "${CMAKE_SOURCE_DIR}/apps/starknet_app"
        "${CMAKE_SOURCE_DIR}/apps/xrp_app"
        "${CMAKE_SOURCE_DIR}/apps/icp_app"
        "${CMAKE_SOURCE_DIR}/common/coin_support/eth_sign_data"
        "${CMAKE_SOURCE_DIR}/common/coin_support/tron_parse_txn"
    )
endif()

IF(UNIT_TESTS_SWITCH)
    target_include_directories(${EXECUTABLE} PRIVATE
        "${CMAKE_SOURCE_DIR}/tests/framework/unity"
        "${CMAKE_SOURCE_DIR}/tests/framework/unity/src"
        "${CMAKE_SOURCE_DIR}/tests/framework/unity/extras/fixture/src"
        "${CMAKE_SOURCE_DIR}/tests"
        "${CMAKE_SOURCE_DIR}/tests/common/core"
        "${CMAKE_SOURCE_DIR}/tests/common/util"
        "${CMAKE_SOURCE_DIR}/tests/p0_events"
        "${CMAKE_SOURCE_DIR}/tests/ui/ui_events_test"
        "${CMAKE_SOURCE_DIR}/tests/usb/events"
        "${CMAKE_SOURCE_DIR}/tests/nfc"
    )
    if(btc_only)
        target_include_directories(${EXECUTABLE} PRIVATE
            "${CMAKE_SOURCE_DIR}/tests/apps/manager_app"
            "${CMAKE_SOURCE_DIR}/tests/apps/btc_app"
            "${CMAKE_SOURCE_DIR}/tests/apps/inheritance_app"
        )
    else()
        target_include_directories(${EXECUTABLE} PRIVATE
            "${CMAKE_SOURCE_DIR}/tests/apps/manager_app"
            "${CMAKE_SOURCE_DIR}/tests/apps/btc_app"
            "${CMAKE_SOURCE_DIR}/tests/apps/evm_app"
            "${CMAKE_SOURCE_DIR}/tests/apps/near_app"
            "${CMAKE_SOURCE_DIR}/tests/apps/solana_app"
            "${CMAKE_SOURCE_DIR}/tests/apps/inheritance_app"
            "${CMAKE_SOURCE_DIR}/tests/apps/xrp_app"
            "${CMAKE_SOURCE_DIR}/tests/apps/icp_app"
        )
    endif()
ENDIF()

target_compile_options(${EXECUTABLE} PRIVATE
    -mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard
    -fdata-sections -ffunction-sections
    -Wall -Wno-format-truncation -Wno-unused-but-set-variable -Wno-return-type
    -D_POSIX_C_SOURCE=200809L
    $<$<CONFIG:Debug>:-g3>
    $<$<CONFIG:Release>:-O2 -Werror>
)

target_link_options(${EXECUTABLE} PRIVATE
    -T${CMAKE_SOURCE_DIR}/${LINKER_SCRIPT}
    -mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16
    -mfloat-abi=hard -u _printf_float -lc -lm -lnosys
    -Wl,-Map=${PROJECT_NAME}.map,--cref -Wl,--gc-sections
)

file(GLOB_RECURSE LIBRARIES_SRC_DIRS_TO_QUIET
    "${CMAKE_SOURCE_DIR}/common/libraries/atecc/*.c"
    "${CMAKE_SOURCE_DIR}/common/lvgl/*.c"
    "${CMAKE_SOURCE_DIR}/common/libraries/crypto/*.c"
    "${CMAKE_SOURCE_DIR}/stm32-hal/Peripherals/*.c"
)
# Ensure this if statement has parentheses around its condition
if(LIBRARIES_SRC_DIRS_TO_QUIET)
    set_source_files_properties(${LIBRARIES_SRC_DIRS_TO_QUIET} PROPERTIES COMPILE_FLAGS "-w")
endif()

add_custom_command(TARGET ${EXECUTABLE} POST_BUILD
    COMMAND ${CMAKE_SIZE_UTIL} ${EXECUTABLE}
    COMMENT "Show executable size"
)
add_custom_command(TARGET ${EXECUTABLE} POST_BUILD
    COMMAND ${CMAKE_OBJCOPY} -O ihex ${EXECUTABLE} ${PROJECT_NAME}.hex
    COMMAND ${CMAKE_OBJCOPY} -O binary ${EXECUTABLE} ${PROJECT_NAME}.bin
    COMMENT "Generating .hex and .bin files"
)
if (SIGN_BINARY)
    add_custom_command(TARGET ${EXECUTABLE} POST_BUILD
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/utilities/script/index.py add-header --input="${PROJECT_NAME}.bin" --output=${PROJECT_NAME}_Header.bin --version=${CMAKE_SOURCE_DIR}/version.txt --private-key=${CMAKE_SOURCE_DIR}/utilities/script/private_key1.h
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/utilities/script/index.py sign-header --input=${PROJECT_NAME}_Header.bin --output=${PROJECT_NAME}-signed.bin --private-key=${CMAKE_SOURCE_DIR}/utilities/script/private_key2.h
        COMMAND ${CMAKE_COMMAND} -E remove ${PROJECT_NAME}_Header.bin
        COMMENT "Signing binary"
    )
endif()