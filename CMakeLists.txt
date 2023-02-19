cmake_minimum_required(VERSION 3.2)
set(CMAKE_CXX_STANDARD 20)

include("cmake/HunterGate.cmake")
HunterGate(
    URL "https://github.com/cpp-pm/hunter/archive/v0.24.14.tar.gz"
    SHA1 "00901c19eefc02d24b16705b5f5a2b4f093a73fb"
)

project(passvault VERSION 0.0.1)

set(CLIP_EXAMPLES OFF CACHE BOOL "Compile clip examples")
set(CLIP_TESTS OFF CACHE BOOL "Compile clip tests")
add_subdirectory(third_party/clip)

hunter_add_package(Boost COMPONENTS program_options)
find_package(Boost CONFIG REQUIRED program_options)

add_executable(
    ${PROJECT_NAME} 
    ${CMAKE_CURRENT_SOURCE_DIR}/sources/passvault.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/sources/vault.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/sources/secrets.cpp
)
target_include_directories(
    ${PROJECT_NAME}
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/headers
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party
)

target_link_libraries(${PROJECT_NAME} 
    PUBLIC 
    Boost::program_options 
    clip
    #${CMAKE_CURRENT_SOURCE_DIR}/third_party/cppcrypto/streebog.o
    #${CMAKE_CURRENT_SOURCE_DIR}/third_party/cppcrypto/cpuinfo.o
    #${CMAKE_CURRENT_SOURCE_DIR}/third_party/cppcrypto/crypto_hash.o
    #${CMAKE_CURRENT_SOURCE_DIR}/third_party/cppcrypto/gost3411-2012-sse2.o
    #${CMAKE_CURRENT_SOURCE_DIR}/third_party/cppcrypto/gost3411-2012-sse41.o
    #${CMAKE_CURRENT_SOURCE_DIR}/third_party/cppcrypto/block_cipher.o
    #${CMAKE_CURRENT_SOURCE_DIR}/third_party/cppcrypto/kuznyechik.o
    #${CMAKE_CURRENT_SOURCE_DIR}/third_party/cppcrypto/hmac.o
    #${CMAKE_CURRENT_SOURCE_DIR}/third_party/cppcrypto/pbkdf2.o
    #${CMAKE_CURRENT_SOURCE_DIR}/third_party/cppcrypto/ctr.o
    #${CMAKE_CURRENT_SOURCE_DIR}/third_party/cppcrypto/ctr-sse41.o
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/cppcrypto/libcppcrypto.a
)

set(INSTALL_DIRECTORY "/usr/local/bin")
set(CFG_DIRECTORY "/etc/passvault")
if (WIN32)
    set(INSTALL_DIRECTORY "/usr/local/bin")
    set(CFG_DIRECTORY "/etc/passvault")
endif (WIN32)

install(TARGETS ${PROJECT_NAME} DESTINATION ${INSTALL_DIRECTORY})
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/dist/passvault_config.cfg DESTINATION ${CFG_DIRECTORY})

set(CPACK_GENERATOR "DEB")

# Set a Package Maintainer.
# This is required
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "htmlgod")

# Set a Package Version
set(CPACK_PACKAGE_VERSION ${CMAKE_PROJECT_VERSION})

# Include CPack
include(CPack)
