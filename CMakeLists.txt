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

# ── Shared sources (used by all executables) ──
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
)
# ── Single-threaded executable ──
add_executable(dpi_engine_pro
    ${SHARED_SOURCES}
    src/main_pro.cpp
)

target_compile_options(dpi_engine_pro PRIVATE
    -Wall -Wextra
)

# Link pthreads for threading support
target_link_libraries(dpi_engine_pro
    pthread
)

# ── Multi-threaded executable ──
add_executable(dpi_mt
    ${SHARED_SOURCES}
    src/dpi_mt.cpp
)

target_compile_options(dpi_mt PRIVATE
    -Wall -Wextra
)

target_link_libraries(dpi_mt
    pthread
)

# ── Test executable ──
add_executable(test_classifier
    ${SHARED_SOURCES}
    tests/test_classifier.cpp
)

target_compile_options(test_classifier PRIVATE
    -Wall -Wextra
)

target_link_libraries(test_classifier
    pthread
)

message(STATUS "Project: ${PROJECT_NAME}")
message(STATUS "Version: ${PROJECT_VERSION}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")