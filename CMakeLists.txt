cmake_minimum_required(VERSION 3.16)
project(datase_probe VERSION 0.1.0 LANGUAGES CXX)

add_executable(datase_probe src/main.cpp)
target_compile_features(datase_probe PRIVATE cxx_std_17)
if(MSVC)
    target_compile_options(datase_probe PRIVATE /W4 /permissive-)
else()
    target_compile_options(datase_probe PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)
endif()

include(CTest)
set(DATASE_BIN_DIR "" CACHE PATH "Path to the directory containing WORDS.BIN and WORDSEVE.BIN for integration testing")
find_package(Python3 COMPONENTS Interpreter QUIET)
if(BUILD_TESTING AND Python3_Interpreter_FOUND AND DATASE_BIN_DIR)
    add_test(
        NAME datase_probe_integration
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/verify_outputs.py"
                "$<TARGET_FILE:datase_probe>"
                "${DATASE_BIN_DIR}"
    )
elseif(BUILD_TESTING AND Python3_Interpreter_FOUND)
    message(STATUS "Integration test not registered: set -DDATASE_BIN_DIR=/path/to/DATASE/BIN to test against your samples.")
endif()
