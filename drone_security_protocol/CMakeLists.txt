cmake_minimum_required(VERSION 3.14)
project(drone)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

file(GLOB_RECURSE SOURCES "src/*.cpp")

include_directories(${PROJECT_SOURCE_DIR}/include)
include(FetchContent)

FetchContent_Declare(
  nlohmann_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG        v3.7.3
)
set(JSON_BuildTests OFF CACHE INTERNAL "")
FetchContent_MakeAvailable(nlohmann_json)

find_package(OpenSSL REQUIRED)

enable_testing()
add_library(drone SHARED ${SOURCES})
target_include_directories(drone PUBLIC ${PROJECT_SOURCE_DIR}/include)

target_link_libraries(
    drone
    PRIVATE
    nlohmann_json::nlohmann_json
    ssl
    crypto
)