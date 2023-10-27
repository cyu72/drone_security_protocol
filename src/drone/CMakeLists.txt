cmake_minimum_required(VERSION 3.14)
project(drone)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(
  googletest
  # Specify the commit you depend on and update it regularly.
  URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
FetchContent_MakeAvailable(googletest)

enable_testing()
add_executable(
    drone_test
    drone_test.cpp
)
target_link_libraries(
    drone_test 
    GTest::gtest_main
)
include(GoogleTest)
gtest_discover_tests(drone_test)