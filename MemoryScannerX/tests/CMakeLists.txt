add_executable(msx_unit_tests test_main.c)
target_include_directories(msx_unit_tests PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_sources(msx_unit_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/src/utils/msx_entropy.c
    ${CMAKE_SOURCE_DIR}/src/utils/msx_sha256.c
    ${CMAKE_SOURCE_DIR}/src/utils/msx_common.c
    ${CMAKE_SOURCE_DIR}/src/scanner/msx_scoring.c
)
if(UNIX AND NOT APPLE)
    target_link_libraries(msx_unit_tests m)
endif()
add_test(NAME msx_unit_tests COMMAND msx_unit_tests)
