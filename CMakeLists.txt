cmake_minimum_required(VERSION 3.22)

project(ExLoader
    VERSION 0.1.0
    LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(EXLOADER_BUILD_TESTS "Build ExLoader unit/integration tests" ON)

add_library(nlohmann_json INTERFACE)
target_include_directories(nlohmann_json INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/json-develop/include)

add_library(cli11 INTERFACE)
target_include_directories(cli11 INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/cli11)

add_library(exloader_ipc STATIC
    ipc/src/named_pipe.cpp)
target_include_directories(exloader_ipc
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)

if(WIN32 OR MINGW)
    set(MINHOOK_SOURCES
        third_party/minhook/src/buffer.c
        third_party/minhook/src/hook.c
        third_party/minhook/src/trampoline.c
        third_party/minhook/src/hde/hde32.c
        third_party/minhook/src/hde/hde64.c)

    add_library(minhook STATIC ${MINHOOK_SOURCES})
    target_include_directories(minhook
        PUBLIC
            ${CMAKE_CURRENT_SOURCE_DIR}/third_party/minhook/include)
    target_include_directories(minhook
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/third_party/minhook/src)
    target_compile_definitions(minhook PRIVATE MH_STATIC)
endif()

add_library(exloader_logging STATIC
    logging/src/json_logger.cpp)
target_include_directories(exloader_logging
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_link_libraries(exloader_logging
    PUBLIC nlohmann_json)

add_library(exadapter_runtime STATIC
    runtime/src/runtime.cpp
    runtime/src/hooks/event_utils.cpp
    runtime/src/hooks/crypto/key_store.cpp
    runtime/src/hooks/plugin_manager.cpp
    runtime/src/hooks/modules/dummy_plugin.cpp
    runtime/src/hooks/modules/winhttp_hook.cpp
    runtime/src/hooks/modules/winhttp_extended/winhttp_extended_hook.cpp
    runtime/src/hooks/modules/urlmon_hook/urlmon_hook.cpp
    runtime/src/hooks/modules/win32web_hook/win32web_hook.cpp
    runtime/src/hooks/modules/proxy_hook/proxy_hook.cpp
    runtime/src/hooks/modules/libcurl_hook/libcurl_hook.cpp
    runtime/src/hooks/modules/schannel_hook/schannel_hook.cpp
    runtime/src/hooks/modules/http_sys_hook/http_sys_hook.cpp
    runtime/src/hooks/modules/wininet_hook.cpp
    runtime/src/hooks/modules/winsock_hook.cpp
    runtime/src/hooks/modules/stringmon_hook.cpp
    runtime/src/hooks/modules/mathmon_hook.cpp
    runtime/src/hooks/modules/filemon_hook.cpp
    runtime/src/hooks/modules/bcrypt_hook.cpp
    runtime/src/hooks/modules/cryptoapi_hook.cpp)

target_include_directories(exadapter_runtime
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/runtime/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/json-develop/include)

target_compile_definitions(exadapter_runtime
    PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)

target_compile_features(exadapter_runtime PUBLIC cxx_std_20)
target_link_libraries(exadapter_runtime
    PUBLIC
        exloader_ipc
        nlohmann_json
        minhook)

if(WIN32 OR MINGW)
    target_link_libraries(exadapter_runtime
        PRIVATE
            winhttp
            wininet
            ws2_32
            bcrypt
            advapi32
            httpapi)
endif()

add_library(exadapter_core SHARED
    runtime/src/dllmain.cpp
    runtime/src/runtime_entry.cpp)
target_include_directories(exadapter_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/runtime/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_link_libraries(exadapter_core PRIVATE exadapter_runtime exloader_logging)
target_sources(exadapter_core PRIVATE compat/win_time_shim.cpp)
if(MINGW)
    target_link_options(exadapter_core PRIVATE
        -static-libgcc
        -static-libstdc++
        -static)
endif()

add_executable(exloader
    injector/src/main.cpp
    injector/src/cli_parser.cpp
    injector/src/injector_app.cpp
    injector/src/config_loader.cpp
    injector/src/process_launcher.cpp
    compat/win_time_shim.cpp)

target_include_directories(exloader
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/injector/include
        ${CMAKE_CURRENT_SOURCE_DIR}/runtime/include
        ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(exloader PRIVATE
    exadapter_runtime
    exloader_logging
    nlohmann_json
    cli11)

if(WIN32 OR MINGW)
    target_link_libraries(exloader PRIVATE psapi)
endif()

if(MINGW)
    target_link_options(exloader PRIVATE
        -static-libgcc
        -static-libstdc++
        -static)
endif()

if(EXLOADER_BUILD_TESTS)
    enable_testing()
    add_executable(exloader_runtime_tests tests/runtime/runtime_smoke.cpp)
    target_link_libraries(exloader_runtime_tests PRIVATE exadapter_runtime exloader_logging)
    target_include_directories(exloader_runtime_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/runtime/include
        ${CMAKE_CURRENT_SOURCE_DIR}/include)
    if(MINGW)
        target_link_options(exloader_runtime_tests PRIVATE
            -static-libgcc
            -static-libstdc++
            -static)
    endif()
    add_test(NAME runtime_smoke COMMAND exloader_runtime_tests)
endif()

# Optional: Build test target application
option(EXLOADER_BUILD_TEST_TARGET "Build test target application for hook testing" ON)
if(EXLOADER_BUILD_TEST_TARGET)
    add_subdirectory(examples/test_target examples/test_target_build)
endif()
