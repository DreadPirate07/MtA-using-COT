cmake_minimum_required(VERSION 3.14)
project(MtA C)

file(GLOB TREZOR_CRYPTO_OBJ
     ${CMAKE_SOURCE_DIR}/trezor-firmware/crypto/*.o
     ${CMAKE_SOURCE_DIR}/trezor-firmware/crypto/aes/*.o
     ${CMAKE_SOURCE_DIR}/trezor-firmware/crypto/chacha20poly1305/*.o
     ${CMAKE_SOURCE_DIR}/trezor-firmware/crypto/ed25519-donna/*.o
)

list(FILTER TREZOR_CRYPTO_OBJ EXCLUDE REGEX ".*/.*tst\\.o$")

file(GLOB APP_SOURCES 
    ${CMAKE_SOURCE_DIR}/src/*.c
)

add_executable(MtA ${APP_SOURCES} ${TREZOR_CRYPTO_OBJ})

target_include_directories(MtA PUBLIC
 ${CMAKE_SOURCE_DIR}/trezor-firmware/crypto/
)

