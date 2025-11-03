cmake_minimum_required(VERSION 3.14)

include(FetchContent)

FetchContent_Declare(MemoryOperation
        GIT_REPOSITORY https://github.com/TechMecca/MemoryOperation.git
        GIT_TAG        2.6
)

FetchContent_MakeAvailable(MemoryOperation)