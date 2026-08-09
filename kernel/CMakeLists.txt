find_program(CLANG clang)
if(NOT CLANG)
    message(FATAL_ERROR "clang is required to compile eBPF programs")
endif()

# Add subdirectories for kernel programs
# add_subdirectory(programs)
