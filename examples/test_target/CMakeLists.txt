cmake_minimum_required(VERSION 3.22)
project(ExLoaderTestTarget)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(test_target
    main.cpp
    http_operations.cpp
    http_server.cpp
    crypto_operations.cpp
    network_operations.cpp
    modern_ui.cpp
    gui_crackme.cpp)

if(WIN32 OR MINGW)
    target_link_libraries(test_target
        PRIVATE
            winhttp
            wininet
            ws2_32
            bcrypt
            advapi32
            urlmon
            ole32
            comctl32
            gdi32
            msimg32)

    # Static linking for standalone binary
    if(MINGW)
        target_link_options(test_target PRIVATE
            -static-libgcc
            -static-libstdc++
            -static)
    endif()
endif()

target_compile_definitions(test_target PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    UNICODE
    _UNICODE)
