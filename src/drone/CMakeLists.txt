cmake_minimum_required(VERSION 3.14)
project(drone)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

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
add_executable(
    drone
    drone.cpp
    tesla.cpp
    hashTree.cpp
    routingMap.hpp
)
target_link_libraries(
    drone
    nlohmann_json::nlohmann_json
    ssl
    crypto
)