cmake_minimum_required(VERSION 3.16)
project(MemoryScannerX C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

option(MSX_ENABLE_ASAN "Build with AddressSanitizer" OFF)

if(MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Wshadow -Wformat=2)
    if(MSX_ENABLE_ASAN)
        add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
        add_link_options(-fsanitize=address,undefined)
    endif()
endif()

include_directories(
    ${CMAKE_SOURCE_DIR}/include
)

file(GLOB_RECURSE MSX_SOURCES
    "${CMAKE_SOURCE_DIR}/src/*.c"
)

add_executable(memoryscannerx ${MSX_SOURCES})

if(UNIX AND NOT APPLE)
    target_link_libraries(memoryscannerx m pthread)
elseif(WIN32)
    target_link_libraries(memoryscannerx psapi ntdll advapi32)
endif()

enable_testing()
add_subdirectory(tests)

install(TARGETS memoryscannerx RUNTIME DESTINATION bin)
