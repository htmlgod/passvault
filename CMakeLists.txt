cmake_minimum_required(VERSION 3.2)
set(CMAKE_CXX_STANDARD 17)

include("third_party/hunter-gate/cmake/HunterGate.cmake")

HunterGate(
    URL "https://github.com/cpp-pm/hunter/archive/v0.23.297.tar.gz"
    SHA1 "3319fe6a3b08090df7df98dee75134d68e2ef5a3"
)


project(passvault)

hunter_add_package(Boost COMPONENTS program_options)

find_package(Boost CONFIG REQUIRED program_options)

add_executable(passvault sources/passvault.cpp)

target_link_libraries(passvault PUBLIC Boost::program_options)
