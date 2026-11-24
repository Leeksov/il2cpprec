cmake_minimum_required(VERSION 3.28)
project(il2cpprec LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(IL2CPPREC_BUILD_CLI "Build the il2cpprec_cli executable" ON)
option(IL2CPPREC_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

if(IL2CPPREC_ENABLE_SANITIZERS)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "AppleClang|Clang|GNU")
        message(FATAL_ERROR "IL2CPPREC_ENABLE_SANITIZERS requires AppleClang, Clang, or GNU.")
    endif()
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

if(NOT CMAKE_CROSSCOMPILING)
    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(CAPSTONE_PC QUIET capstone)
    endif()
    if(APPLE)
        set(CAPSTONE_HOST_HINTS /opt/homebrew/include /opt/homebrew/lib /usr/local/include /usr/local/lib)
    endif()
endif()

if(CMAKE_CROSSCOMPILING)
    set(CAPSTONE_FIND_OPTIONS NO_DEFAULT_PATH)
endif()

find_path(CAPSTONE_INCLUDE_DIR
    NAMES capstone/capstone.h
    HINTS ${CAPSTONE_PC_INCLUDE_DIRS} ${CAPSTONE_ROOT} ${CAPSTONE_HOST_HINTS}
    PATH_SUFFIXES include
    ${CAPSTONE_FIND_OPTIONS}
)
find_library(CAPSTONE_LIBRARY
    NAMES capstone
    HINTS ${CAPSTONE_PC_LIBRARY_DIRS} ${CAPSTONE_ROOT} ${CAPSTONE_HOST_HINTS}
    PATH_SUFFIXES lib lib64
    ${CAPSTONE_FIND_OPTIONS}
)

if(NOT CAPSTONE_INCLUDE_DIR OR NOT CAPSTONE_LIBRARY)
    message(FATAL_ERROR "Capstone was not found. Set CAPSTONE_ROOT, or CAPSTONE_INCLUDE_DIR and CAPSTONE_LIBRARY, for the target platform.")
endif()

add_library(Capstone::Capstone UNKNOWN IMPORTED)
set_target_properties(Capstone::Capstone PROPERTIES
    IMPORTED_LOCATION "${CAPSTONE_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${CAPSTONE_INCLUDE_DIR}"
)

file(GLOB_RECURSE IL2CPPREC_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
)
list(REMOVE_ITEM IL2CPPREC_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp")
list(SORT IL2CPPREC_SOURCES)

add_library(il2cpprec STATIC ${IL2CPPREC_SOURCES})
target_include_directories(il2cpprec PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(il2cpprec PUBLIC Capstone::Capstone)

function(il2cpprec_enable_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /permissive-)
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "AppleClang|Clang|GNU")
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
    endif()
endfunction()

il2cpprec_enable_warnings(il2cpprec)

if(WIN32)
    target_compile_definitions(il2cpprec PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
    target_link_libraries(il2cpprec PUBLIC ws2_32)
endif()

if(IL2CPPREC_BUILD_CLI)
    add_executable(il2cpprec_cli src/main.cpp)
    target_link_libraries(il2cpprec_cli PRIVATE il2cpprec)
    il2cpprec_enable_warnings(il2cpprec_cli)
endif()

include(CTest)
if(BUILD_TESTING AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/CMakeLists.txt")
    add_subdirectory(tests)

    if(TARGET il2cpprec_core_tests)
        set(IL2CPPREC_TEST_LABELS core)
        file(GLOB IL2CPPREC_VERSION_TEST_SOURCES CONFIGURE_DEPENDS
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/core/*Tests.cpp"
        )
        foreach(IL2CPPREC_VERSION_TEST_SOURCE IN LISTS IL2CPPREC_VERSION_TEST_SOURCES)
            get_filename_component(IL2CPPREC_VERSION_TEST_NAME "${IL2CPPREC_VERSION_TEST_SOURCE}" NAME)
            if(NOT IL2CPPREC_VERSION_TEST_NAME MATCHES "Legacy|Unity|Version")
                continue()
            endif()
            set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${IL2CPPREC_VERSION_TEST_SOURCE}")
            if(IL2CPPREC_VERSION_TEST_NAME MATCHES "Legacy")
                list(APPEND IL2CPPREC_TEST_LABELS legacy)
            endif()
            file(STRINGS "${IL2CPPREC_VERSION_TEST_SOURCE}" IL2CPPREC_TEST_CASES REGEX "TEST_CASE")
            foreach(IL2CPPREC_TEST_CASE IN LISTS IL2CPPREC_TEST_CASES)
                string(REGEX MATCH "IL2CPP ([0-9][0-9][0-9][0-9])" IL2CPPREC_UNITY_MATCH "${IL2CPPREC_TEST_CASE}")
                if(NOT IL2CPPREC_UNITY_MATCH STREQUAL "")
                    list(APPEND IL2CPPREC_TEST_LABELS "unity-${CMAKE_MATCH_1}")
                endif()
                string(REGEX MATCH "(^|[^A-Za-z0-9])v([0-9]+)" IL2CPPREC_METADATA_MATCH "${IL2CPPREC_TEST_CASE}")
                if(NOT IL2CPPREC_METADATA_MATCH STREQUAL "")
                    list(APPEND IL2CPPREC_TEST_LABELS "metadata-v${CMAKE_MATCH_2}")
                endif()
            endforeach()
        endforeach()
        list(REMOVE_DUPLICATES IL2CPPREC_TEST_LABELS)
        set_tests_properties(il2cpprec_core_tests DIRECTORY tests
            PROPERTIES LABELS "${IL2CPPREC_TEST_LABELS}"
        )
    endif()
endif()
