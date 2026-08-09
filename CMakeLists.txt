cmake_minimum_required(VERSION 3.12)
project(ITL_Amalia_eBpf C CXX)

# Project settings
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Build options
option(BUILD_KERNEL_PROGRAMS "Build eBPF kernel programs" ON)
option(BUILD_USERSPACE "Build userspace applications" ON)
option(ENABLE_TESTS "Enable testing" ON)

# Set compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic")

# Find required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)

include_directories(${LIBBPF_INCLUDE_DIRS})
link_directories(${LIBBPF_LIBRARY_DIRS})

# Subdirectories
if(BUILD_KERNEL_PROGRAMS)
    add_subdirectory(kernel)
endif()

if(BUILD_USERSPACE)
    add_subdirectory(userspace)
endif()

if(ENABLE_TESTS)
    enable_testing()
    # Add test subdirectories here
endif()

# Print summary
message(STATUS "Build Configuration:")
message(STATUS "  Kernel Programs: ${BUILD_KERNEL_PROGRAMS}")
message(STATUS "  Userspace: ${BUILD_USERSPACE}")
message(STATUS "  Tests: ${ENABLE_TESTS}")
