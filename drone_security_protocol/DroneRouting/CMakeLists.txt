cmake_minimum_required(VERSION 3.14)
project(drone_routing)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable parallel compilation
include(ProcessorCount)
ProcessorCount(N)
if(NOT N EQUAL 0)
  set(CMAKE_BUILD_PARALLEL_LEVEL ${N})
endif()

add_compile_options(-O3)

file(GLOB_RECURSE LIB_SOURCES "src/*.cpp")

include_directories(${PROJECT_SOURCE_DIR}/include)
include(FetchContent)

FetchContent_Declare(
  nlohmann_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG        v3.7.3
)
set(JSON_BuildTests OFF CACHE INTERNAL "")
set(JSON_Install OFF CACHE INTERNAL "")
FetchContent_MakeAvailable(nlohmann_json)

find_package(OpenSSL REQUIRED)

# DroneRouting Library
add_library(DroneRouting SHARED ${LIB_SOURCES})
target_include_directories(DroneRouting PUBLIC ${PROJECT_SOURCE_DIR}/include)

target_link_libraries(
    DroneRouting
    PRIVATE
    nlohmann_json::nlohmann_json
    OpenSSL::SSL
    OpenSSL::Crypto
)

set_target_properties(DroneRouting PROPERTIES 
  OUTPUT_NAME "drone_routing"
  UNITY_BUILD ON
)

# Use precompiled headers
target_precompile_headers(DroneRouting PRIVATE
  <vector>
  <string>
  <nlohmann/json.hpp>
  <openssl/ssl.h>
  <openssl/crypto.h>
)