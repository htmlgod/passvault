cmake_minimum_required(VERSION 3.2)
set(CMAKE_CXX_STANDARD 17)

include("cmake/HunterGate.cmake")
HunterGate(
    URL "https://github.com/cpp-pm/hunter/archive/v0.24.14.tar.gz"
    SHA1 "00901c19eefc02d24b16705b5f5a2b4f093a73fb"
)

project(passvault)

set(CLIP_EXAMPLES OFF CACHE BOOL "Compile clip examples")
set(CLIP_TESTS OFF CACHE BOOL "Compile clip tests")
add_subdirectory(third_party/clip)
include_directories(
    third_party/clip
)

hunter_add_package(Boost COMPONENTS program_options)
find_package(Boost CONFIG REQUIRED program_options)

add_executable(passvault sources/passvault.cpp)
target_link_libraries(passvault PUBLIC Boost::program_options clip)
