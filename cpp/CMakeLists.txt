cmake_minimum_required(VERSION 3.16)
project(eudi_game_wallet CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(eudi_game_wallet INTERFACE)
target_include_directories(eudi_game_wallet INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)

find_package(OpenSSL QUIET)
if(OpenSSL_FOUND)
    target_link_libraries(eudi_game_wallet INTERFACE OpenSSL::Crypto)
    target_compile_definitions(eudi_game_wallet INTERFACE EUDI_GW_HAS_OPENSSL)
endif()

enable_testing()
add_executable(wallet_tests tests/test_wallet.cpp)
target_link_libraries(wallet_tests PRIVATE eudi_game_wallet)
add_test(NAME wallet_tests COMMAND wallet_tests
         ${CMAKE_CURRENT_SOURCE_DIR}/../test-vectors/vectors.json)

add_executable(basic_flow examples/basic_flow.cpp)
target_link_libraries(basic_flow PRIVATE eudi_game_wallet)
