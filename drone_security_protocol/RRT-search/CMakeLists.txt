cmake_minimum_required(VERSION 3.14)
project(rrt_search)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add the DroneRouting subdirectory
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../DroneRouting ${CMAKE_CURRENT_BINARY_DIR}/DroneRouting)

include(FetchContent)

FetchContent_Declare(
  nlohmann_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG        v3.7.3
)
set(JSON_BuildTests OFF CACHE INTERNAL "")
FetchContent_MakeAvailable(nlohmann_json)

FetchContent_Declare(
    asio
    GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
    GIT_TAG asio-1-28-0
)
FetchContent_MakeAvailable(asio)

# Set Asio variables for Crow
set(ASIO_INCLUDE_DIR ${asio_SOURCE_DIR}/asio/include CACHE INTERNAL "")
set(ASIO_FOUND TRUE CACHE INTERNAL "")

FetchContent_Declare(
    Crow
    GIT_REPOSITORY https://github.com/CrowCpp/Crow.git
    GIT_TAG v1.2.0
)
FetchContent_MakeAvailable(Crow)

FetchContent_Declare(
    cpr
    GIT_REPOSITORY https://github.com/libcpr/cpr.git
    GIT_TAG 1.11.0
)
FetchContent_MakeAvailable(cpr)

find_package(OpenSSL REQUIRED)

# rrt Executable
add_executable(rrt 
    rrt.cpp
)

# Add include directories
target_include_directories(rrt 
    PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../DroneRouting/include
)

target_link_libraries(rrt
    PRIVATE
    DroneRouting
    Crow::Crow
    cpr::cpr
    nlohmann_json::nlohmann_json
    DroneRouting
    OpenSSL::SSL
    OpenSSL::Crypto
)

set_target_properties(rrt PROPERTIES 
  OUTPUT_NAME "rrt"
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)