cmake_minimum_required(VERSION 3.20)
project(3gpp_test_suite
    VERSION 1.0.0
    DESCRIPTION "3GPP Telecom Protocol Test Suite & Training Framework in Modern C++"
    LANGUAGES C CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler flags
if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic -Wno-unused-parameter)
endif()

# Dependencies
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

include(FetchContent)

# GoogleTest for automated unit testing
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.15.2
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# Include directories
include_directories(include)

# Core library
add_subdirectory(src)

# Standalone demo executables
add_subdirectory(apps)

# Automated test suite
enable_testing()
add_subdirectory(tests)
