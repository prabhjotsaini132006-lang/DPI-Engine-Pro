cmake_minimum_required(VERSION 3.10)
project(DPI-Engine-Pro VERSION 2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS_DEBUG   "-g -O0")
set(CMAKE_CXX_FLAGS_RELEASE "-O2")

include_directories(${PROJECT_SOURCE_DIR}/include)

set(SHARED_SOURCES
    src/flow_features.cpp
    src/training_data.cpp
    src/decision_tree.cpp
    src/ml_classifier.cpp
    src/random_forest.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/rule_manager.cpp
    src/connection_tracker.cpp
    src/fast_path.cpp
    src/load_balancer.cpp
    src/dpi_engine.cpp
    src/signal_handler.cpp
    src/logger.cpp
    src/model_evaluator.cpp
    src/feature_importance.cpp
    src/config_parser.cpp
    src/stats_dashboard.cpp
    src/benchmark.cpp
    src/ml_metrics.cpp
    src/protocol_parser.cpp
    src/anomaly_detector.cpp
    src/live_capture.cpp
    src/stream_reassembler.cpp
)

if(WIN32)
    set(PLATFORM_LIBS ws2_32 iphlpapi)
else()
    set(PLATFORM_LIBS)
endif()

add_executable(dpi_engine_pro
    ${SHARED_SOURCES}
    src/dpi_mt.cpp
)
target_compile_options(dpi_engine_pro PRIVATE -Wall -Wextra)
target_link_libraries(dpi_engine_pro pthread ${PLATFORM_LIBS})

add_executable(test_classifier
    ${SHARED_SOURCES}
    tests/test_classifier.cpp
)
target_compile_options(test_classifier PRIVATE -Wall -Wextra)
target_link_libraries(test_classifier pthread ${PLATFORM_LIBS})

message(STATUS "Project: ${PROJECT_NAME} v${PROJECT_VERSION}")
message(STATUS "Build:   ${CMAKE_BUILD_TYPE}")
message(STATUS "C++:     ${CMAKE_CXX_STANDARD}")