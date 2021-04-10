CMAKE_MINIMUM_REQUIRED( VERSION 3.3 )

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED YES)

SET(BTC_LIB_NAME btc)
PROJECT(${BTC_LIB_NAME})

set(WITH_LOGDB <value>... CACHE <type> <docstring> [
set(WITH_LOGDB <value>... CACHE <type> <docstring> [

add_definitions(-DUSE_NUM_GMP)
add_definitions(-DUSE_FIELD_10X26)
add_definitions(-DUSE_FIELD_INV_BUILTIN)
add_definitions(-DUSE_SCALAR_8X32)
add_definitions(-DUSE_SCALAR_INV_BUILTIN)
add_definitions(-DRANDOM_DEVICE="/dev/urandom")
add_definitions(-DENABLE_MODULE_RECOVERY)
add_definitions(-DECMULT_WINDOW_SIZE=15)
add_definitions(-DECMULT_GEN_PREC_BITS=4)

FILE(GLOB SOURCES src/*.c)
list(REMOVE_ITEM SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/net.c)

FILE(GLOB HEADERS include/btc/*.h)
list(REMOVE_ITEM HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/include/btc/net.h)

FILE(GLOB LOGDB src/logdb/*.c)

SET(TREZOR_CRYPTO
    src/trezor-crypto/base58.c
    src/trezor-crypto/blake2b.c
    src/trezor-crypto/blake256.c
    src/trezor-crypto/groestl.c
    src/trezor-crypto/hasher.c
    src/trezor-crypto/hmac.c
    src/trezor-crypto/memzero.c
    src/trezor-crypto/ripemd160.c
    src/trezor-crypto/segwit_addr.c
    src/trezor-crypto/sha2.c
    src/trezor-crypto/sha3.c
)

FILE(GLOB SECP256K1 src/secp256k1/src/*.c)
list(REMOVE_ITEM SECP256K1 ${CMAKE_CURRENT_SOURCE_DIR}/src/secp256k1/src/tests.c)
list(REMOVE_ITEM SECP256K1 ${CMAKE_CURRENT_SOURCE_DIR}/src/secp256k1/src/bench_ecdh.c)
list(REMOVE_ITEM SECP256K1 ${CMAKE_CURRENT_SOURCE_DIR}/src/secp256k1/src/bench_ecmult.c)
list(REMOVE_ITEM SECP256K1 ${CMAKE_CURRENT_SOURCE_DIR}/src/secp256k1/src/bench_recover.c)
list(REMOVE_ITEM SECP256K1 ${CMAKE_CURRENT_SOURCE_DIR}/src/secp256k1/src/bench_sign.c)
list(REMOVE_ITEM SECP256K1 ${CMAKE_CURRENT_SOURCE_DIR}/src/secp256k1/src/bench_verify.c)
list(REMOVE_ITEM SECP256K1 ${CMAKE_CURRENT_SOURCE_DIR}/src/secp256k1/src/bench_ecdh.c)
list(REMOVE_ITEM SECP256K1 ${CMAKE_CURRENT_SOURCE_DIR}/src/secp256k1/src/bench_internal.c)
list(REMOVE_ITEM SECP256K1 ${CMAKE_CURRENT_SOURCE_DIR}/src/secp256k1/src/bench_schnorr_verify.c)

INCLUDE_DIRECTORIES(include)
INCLUDE_DIRECTORIES(src/logdb/include)
INCLUDE_DIRECTORIES(src/secp256k1)
INCLUDE_DIRECTORIES(${GMP_INSTALL_DIR}/include)

ADD_LIBRARY(${BTC_LIB_NAME} ${SOURCES} ${LOGDB} ${TREZOR_CRYPTO} ${SECP256K1} ${HEADERS})
TARGET_LINK_LIBRARIES(${BTC_LIB_NAME})

ADD_EXECUTABLE(
