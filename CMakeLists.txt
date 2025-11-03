set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")


cmake_minimum_required(VERSION 3.24)
project(WowProjects VERSION 0 LANGUAGES C CXX)


set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Tell the Windows headers which CPU we’re targeting (fallback for Ninja env issues)
if(MSVC)
     
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    add_compile_definitions(_AMD64_=1)
  else()
    add_compile_definitions(_X86_=1)
  endif()
endif()

add_subdirectory(External/MemoryOperation)
add_subdirectory ("Warden Export")

Add_dependencies(Warden_Export MemoryOperation)

target_link_libraries(Warden_Export PUBLIC
    MemoryOperation::MemoryOperation
)


set(CMAKE_INSTALL_PREFIX "${CMAKE_BINARY_DIR}/install" CACHE PATH "" FORCE)
install(TARGETS Warden_Export
        RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}/$<CONFIG>
)