cmake_minimum_required(VERSION 3.22.1)
project(KokuinCrypto)
set(CMAKE_CXX_STANDARD 20)

add_library(KokuinCrypto SHARED ../cpp/HybridCrypto.cpp cpp-adapter.cpp)
target_include_directories(KokuinCrypto PRIVATE ../cpp)
add_library(kokuin_crypto_ffi STATIC IMPORTED)
set_target_properties(kokuin_crypto_ffi PROPERTIES IMPORTED_LOCATION
  "${CMAKE_CURRENT_SOURCE_DIR}/../prebuilt/android/${ANDROID_ABI}/libkokuin_crypto_ffi.a")
include(../nitrogen/generated/android/KokuinCrypto+autolinking.cmake)
target_link_libraries(KokuinCrypto kokuin_crypto_ffi android log dl m)
