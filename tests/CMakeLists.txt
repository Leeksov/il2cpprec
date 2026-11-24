cmake_minimum_required(VERSION 3.20)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(il2cpprec_core_tests LANGUAGES CXX)
    set(CMAKE_CXX_STANDARD 20)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(CMAKE_CXX_EXTENSIONS OFF)
    set(IL2CPPREC_BUILD_CLI OFF CACHE BOOL "Build the il2cpprec_cli executable" FORCE)
    set(BUILD_TESTING OFF CACHE BOOL "Build tests" FORCE)
    add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/.." "${CMAKE_CURRENT_BINARY_DIR}/il2cpprec")
endif()

add_executable(il2cpprec_core_tests
    core/TestMain.cpp
    core/TestSupport.cpp
    core/CriticalRegressionTests.cpp
    core/ExceptionRegionCacheTests.cpp
    core/GoldenTests.cpp
    core/Legacy2017Tests.cpp
    core/LegacyVersionMatrixTests.cpp
    core/LegacyMatrixExpansionTests.cpp
    core/MetadataTests.cpp
    core/PipelineTests.cpp
    core/ProjectDeclarationTests.cpp
    core/TypeSystemGenericTests.cpp
    modern/MetadataFixtures.cpp
    modern/ModernMetadataTests.cpp
)
target_link_libraries(il2cpprec_core_tests PRIVATE il2cpprec)
target_compile_definitions(il2cpprec_core_tests PRIVATE
    IL2CPPREC_TEST_SOURCE_DIR="${CMAKE_CURRENT_LIST_DIR}"
)
if(MSVC)
    target_compile_options(il2cpprec_core_tests PRIVATE /W4 /permissive-)
else()
    target_compile_options(il2cpprec_core_tests PRIVATE -Wall -Wextra -Wpedantic)
endif()

enable_testing()
add_test(NAME il2cpprec_core_tests COMMAND il2cpprec_core_tests)

add_executable(il2cpprec_verifier_tests verification/SemanticVerifierTests.cpp)
target_link_libraries(il2cpprec_verifier_tests PRIVATE il2cpprec)
add_test(NAME il2cpprec_verifier_tests COMMAND il2cpprec_verifier_tests)

add_executable(il2cpprec_runtime_helper_tests core/RuntimeHelperTests.cpp)
target_link_libraries(il2cpprec_runtime_helper_tests PRIVATE il2cpprec)
add_test(NAME il2cpprec_runtime_helper_tests COMMAND il2cpprec_runtime_helper_tests)

find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
    add_test(
        NAME il2cpprec_corpus_gate_tests
        COMMAND "${Python3_EXECUTABLE}" -m unittest discover
                -s "${CMAKE_CURRENT_SOURCE_DIR}/acceptance" -p test_corpus_gate.py
    )
endif()
