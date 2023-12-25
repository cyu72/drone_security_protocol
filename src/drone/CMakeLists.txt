cmake_minimum_required(VERSION 3.14)
project(drone)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add the path to CMake's module path where it can find additional libraries (if needed)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# Include FetchContent module
include(FetchContent)

# Declare Google Test
# FetchContent_Declare(
#   googletest
#   GIT_REPOSITORY https://github.com/google/googletest.git
#   GIT_TAG        release-1.10.0
# )
# FetchContent_MakeAvailable(googletest)

# Declare nlohmann_json
FetchContent_Declare(
  nlohmann_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG        v3.7.3
)
set(JSON_BuildTests OFF CACHE INTERNAL "")
FetchContent_MakeAvailable(nlohmann_json)

# openSSL
find_package(OpenSSL REQUIRED)

enable_testing()
add_executable(
    drone
    drone.cpp
)
target_link_libraries(
    drone
    # GTest::gtest_main
    nlohmann_json::nlohmann_json
    ssl
    crypto
)
# include(GoogleTest)
# gtest_discover_tests(drone_test)