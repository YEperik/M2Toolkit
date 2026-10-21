cmake_minimum_required(VERSION 3.16)
project(datase_probe VERSION 0.1.0 LANGUAGES CXX)

add_executable(datase_probe src/main.cpp)
add_executable(datase_package_probe src/package_probe.cpp)
foreach(target IN ITEMS datase_probe datase_package_probe)
    target_compile_features(${target} PRIVATE cxx_std_17)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /permissive-)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)
    endif()
endforeach()

include(CTest)
set(DATASE_BIN_DIR "" CACHE PATH "Path to the directory containing WORDS.BIN and WORDSEVE.BIN for integration testing")
set(DATASE_ROOT "" CACHE PATH "Path to the DATASE directory containing PACKAGE.BIN for package tests")
set(DATASE_PACKAGE_CANDIDATES "" CACHE FILEPATH "Fresh vertex_batch_candidates.csv, including pseudo chunk 24 for global Part B")
set(DATASE_EXECUTABLE "" CACHE FILEPATH "Path to extracted SLUS_*.ELF for VIF MPG extraction integration testing")
set(DATASE_VIF_CONTROL_CSV "" CACHE FILEPATH "Mapped vif_batch_control_tags.csv for MSCAL cross-reference testing")
find_package(Python3 COMPONENTS Interpreter QUIET)
if(BUILD_TESTING AND Python3_Interpreter_FOUND AND DATASE_BIN_DIR)
    add_test(
        NAME datase_probe_integration
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/verify_outputs.py"
                "$<TARGET_FILE:datase_probe>"
                "${DATASE_BIN_DIR}"
    )
endif()
if(BUILD_TESTING AND Python3_Interpreter_FOUND AND DATASE_ROOT)
    add_test(
        NAME datase_package_probe_integration
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/verify_package_outputs.py"
                "$<TARGET_FILE:datase_package_probe>"
                "${DATASE_ROOT}/PACKAGE.BIN"
    )
endif()
if(BUILD_TESTING AND Python3_Interpreter_FOUND)
    add_test(
        NAME datase_vif_unpack_tool_synthetic
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_vif_unpack_tool.py"
                "${CMAKE_CURRENT_SOURCE_DIR}/tools/extract_vif_unpack_chain.py"
    )
endif()
if(BUILD_TESTING AND Python3_Interpreter_FOUND)
    add_test(
        NAME datase_vertex_batch_scanner_synthetic
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_vertex_batch_scanner.py"
                "${CMAKE_CURRENT_SOURCE_DIR}/tools/scan_vertex_batches.py"
    )
endif()
if(BUILD_TESTING AND Python3_Interpreter_FOUND AND NOT DATASE_BIN_DIR AND NOT DATASE_ROOT)
    message(STATUS "Sample-based tests not registered. Set -DDATASE_BIN_DIR=... and/or -DDATASE_ROOT=... to test supplied samples.")
endif()

if(BUILD_TESTING AND Python3_Interpreter_FOUND)
    add_test(
        NAME datase_package_layout_synthetic
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_package_layout.py"
                "${CMAKE_CURRENT_SOURCE_DIR}/tools/map_package_assets.py"
    )
endif()
if(BUILD_TESTING AND Python3_Interpreter_FOUND AND DATASE_ROOT AND DATASE_PACKAGE_CANDIDATES)
    add_test(
        NAME datase_stage6_mapping_integration
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/verify_stage6_package_map.py"
                "${DATASE_ROOT}/PACKAGE.BIN" "${DATASE_PACKAGE_CANDIDATES}"
                "${CMAKE_CURRENT_SOURCE_DIR}/tools/map_package_assets.py"
    )
endif()

if(BUILD_TESTING AND Python3_Interpreter_FOUND AND DATASE_EXECUTABLE AND DATASE_VIF_CONTROL_CSV)
    add_test(
        NAME datase_vu_mpg_extraction_integration
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/verify_vu_mpg_extraction.py"
                "${DATASE_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/extract_vu_microprogram_candidates.py"
                "${DATASE_VIF_CONTROL_CSV}"
    )
endif()


# Stage 8: static VU microprogram disassembly and VIF linkage tools.
if(BUILD_TESTING AND Python3_Interpreter_FOUND)
    add_test(
        NAME datase_vu_disassembler_synthetic
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_disassemble_vu.py"
    )
    add_test(
        NAME datase_vu_disassembler_real
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_real_microprograms.py"
    )
    add_test(
        NAME datase_vertex_attribute_export_synthetic
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_vertex_attributes.py"
    )
    add_test(
        NAME datase_vif_microprogram_link_synthetic
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_vif_link.py"
    )
endif()

# Stage 9: replay the observed VIF STCYCL/STMASK/STROW state into a TOPS-relative QW map.
if(BUILD_TESTING AND Python3_Interpreter_FOUND)
    add_test(
        NAME datase_vif_cycle_layout_synthetic
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_vif_cycle_layout.py"
                "${CMAKE_CURRENT_SOURCE_DIR}/tools/reconstruct_vif_cycle_layout.py"
    )
endif()

# Stage 9: bounded GIF A+D packet decode and real PACKAGE.BIN VIF-cycle reconstruction.
if(BUILD_TESTING AND Python3_Interpreter_FOUND)
    add_test(
        NAME datase_gif_ad_packet_synthetic
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_gif_ad_packet.py"
                "${CMAKE_CURRENT_SOURCE_DIR}/tools/decode_gif_ad_packet.py"
    )
endif()
if(BUILD_TESTING AND Python3_Interpreter_FOUND AND DATASE_ROOT)
    add_test(
        NAME datase_vif_cycle_layout_real_package
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/verify_vif_cycle_layout_real.py"
                "${DATASE_ROOT}/PACKAGE.BIN" "${CMAKE_CURRENT_SOURCE_DIR}/tools/reconstruct_vif_cycle_layout.py"
    )
endif()

if(BUILD_TESTING AND Python3_Interpreter_FOUND)
    add_test(
        NAME datase_texture_upload_cross_reference_synthetic
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_texture_cross_reference.py"
                "${CMAKE_CURRENT_SOURCE_DIR}/tools/crossref_prebatch_texture_uploads.py"
    )
endif()
