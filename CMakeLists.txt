cmake_minimum_required(VERSION 3.10)

project(DPI-Engine-Pro VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS_DEBUG "-g -O0")
set(CMAKE_CXX_FLAGS_RELEASE "-O2")

include_directories(${PROJECT_SOURCE_DIR}/include)

set(SOURCES
    src/flow_features.cpp
    src/training_data.cpp
    src/decision_tree.cpp
    src/ml_classifier.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/main_pro.cpp
)

add_executable(dpi_engine_pro ${SOURCES})

target_compile_options(dpi_engine_pro PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)

set(TEST_SOURCES
    src/flow_features.cpp
    src/training_data.cpp
    src/decision_tree.cpp
    src/ml_classifier.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    tests/test_classifier.cpp
)

add_executable(test_classifier ${TEST_SOURCES})

target_compile_options(test_classifier PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)

message(STATUS "Project: ${PROJECT_NAME}")
message(STATUS "Version: ${PROJECT_VERSION}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")