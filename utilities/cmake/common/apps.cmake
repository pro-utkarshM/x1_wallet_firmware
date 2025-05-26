if(btc_only)
    message(STATUS "BTC-only firmware enabled")
    file(GLOB_RECURSE APP_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/../../../apps/btc_family/src/*.c
        ${CMAKE_CURRENT_LIST_DIR}/../../../apps/manager/src/*.c
    )
    target_include_directories(${EXECUTABLE} PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/../../../apps/btc_family/include
        ${CMAKE_CURRENT_LIST_DIR}/../../../apps/manager/include
    )
else()
    message(STATUS "Including all apps")
    file(GLOB_RECURSE APP_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/../../../apps/*/src/*.c
    )
    file(GLOB_RECURSE APP_HEADERS
        ${CMAKE_CURRENT_LIST_DIR}/../../../apps/*/include/*.h
    )
    set(INCLUDE_DIRS "")
    foreach(H ${APP_HEADERS})
        get_filename_component(DIR ${H} DIRECTORY)
        list(APPEND INCLUDE_DIRS ${DIR})
    endforeach()
    list(REMOVE_DUPLICATES INCLUDE_DIRS)
    target_include_directories(${EXECUTABLE} PRIVATE ${INCLUDE_DIRS})
endif()

target_sources(${EXECUTABLE} PRIVATE ${APP_SOURCES})
