cmake_minimum_required(VERSION 3.22.1)
project(bowie_android C)

include(FetchContent)

if(NOT BOWIE_ANDROID_DEPS)
    message(FATAL_ERROR "Set -PbowieDeps=<path> to a directory containing include/openssl, include/juice, and libs/<ANDROID_ABI>/libcrypto.so and libjuice.so")
endif()
set(BOWIE_DEPS "${BOWIE_ANDROID_DEPS}")
set(BOWIE_ROOT "${CMAKE_CURRENT_LIST_DIR}/../..")

file(GLOB_RECURSE BOWIE_SOURCES CONFIGURE_DEPENDS "${BOWIE_ROOT}/src/*.c")
list(FILTER BOWIE_SOURCES EXCLUDE REGEX "/src/platform/linux/")
list(FILTER BOWIE_SOURCES EXCLUDE REGEX "/src/platform/android/")
list(FILTER BOWIE_SOURCES EXCLUDE REGEX "/src/platform/posix/(rand|log|sock)\\.c$")
list(FILTER BOWIE_SOURCES EXCLUDE REGEX "/src/tunnel/tun_linux\\.c$")
list(FILTER BOWIE_SOURCES EXCLUDE REGEX "/src/engine/signal_metered_stub\\.c$")
# These files are empty placeholders for API groups that are not implemented.
# A translation unit with no declarations is rejected by Android Clang under
# -Werror=empty-translation-unit, so do not pass the placeholders to CMake.
list(FILTER BOWIE_SOURCES EXCLUDE REGEX "/src/api/(bowie|engine|peers|scan)\\.c$")
list(APPEND BOWIE_SOURCES
    "${BOWIE_ROOT}/src/platform/android/jni.c"
    "${BOWIE_ROOT}/src/platform/android/interfaces.c"
    "${BOWIE_ROOT}/src/platform/android/log.c"
    "${BOWIE_ROOT}/src/platform/android/permissions.c"
    "${BOWIE_ROOT}/src/platform/android/rand.c"
    "${BOWIE_ROOT}/src/platform/android/sock.c")
list(APPEND BOWIE_SOURCES "${CMAKE_CURRENT_LIST_DIR}/userspace_gateway.c")

# Metered Realtime Messaging uses libwebsockets and Jansson. Fetch pinned
# upstream releases and build them with the same Android toolchain/ABI as Bowie.
set(JANSSON_BUILD_DOCS OFF CACHE BOOL "" FORCE)
set(JANSSON_WITHOUT_TESTS ON CACHE BOOL "" FORCE)
set(JANSSON_EXAMPLES OFF CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(LWS_WITH_SSL ON CACHE BOOL "" FORCE)
set(LWS_WITH_CLIENT ON CACHE BOOL "" FORCE)
set(LWS_WITH_SERVER OFF CACHE BOOL "" FORCE)
set(LWS_WITHOUT_EXTENSIONS ON CACHE BOOL "" FORCE)
set(LWS_WITHOUT_TESTAPPS ON CACHE BOOL "" FORCE)
set(LWS_WITHOUT_TEST_SERVER ON CACHE BOOL "" FORCE)
set(LWS_WITHOUT_TEST_PING ON CACHE BOOL "" FORCE)
set(LWS_WITH_SHARED OFF CACHE BOOL "" FORCE)
set(LWS_WITH_STATIC ON CACHE BOOL "" FORCE)
set(LWS_WITH_ZLIB OFF CACHE BOOL "" FORCE)
set(LWS_HAVE_HMAC_CTX_new ON CACHE BOOL "" FORCE)
set(LWS_HAVE_EVP_MD_CTX_free ON CACHE BOOL "" FORCE)
set(OPENSSL_ROOT_DIR "${BOWIE_DEPS}")
set(OPENSSL_INCLUDE_DIR "${BOWIE_DEPS}/include")
set(OPENSSL_SSL_LIBRARY "${BOWIE_DEPS}/libs/${ANDROID_ABI}/libssl.so")
set(OPENSSL_CRYPTO_LIBRARY "${BOWIE_DEPS}/libs/${ANDROID_ABI}/libcrypto.so")
set(LWS_OPENSSL_LIBRARIES "${BOWIE_DEPS}/libs/${ANDROID_ABI}/libssl.so;${BOWIE_DEPS}/libs/${ANDROID_ABI}/libcrypto.so" CACHE STRING "" FORCE)
set(LWS_OPENSSL_INCLUDE_DIRS "${BOWIE_DEPS}/include" CACHE STRING "" FORCE)

FetchContent_Declare(jansson
    GIT_REPOSITORY https://github.com/akheron/jansson.git
    GIT_TAG c0d8816701b1dc1b9b9be993443de9f1458755a1)
FetchContent_Declare(libwebsockets
    GIT_REPOSITORY https://github.com/warmcat/libwebsockets.git
    GIT_TAG 4415e84c095857629863804e941b9e1c2e9347ef)
FetchContent_MakeAvailable(jansson libwebsockets)

if(NOT TARGET jansson AND TARGET jansson_static)
    add_library(jansson ALIAS jansson_static)
endif()

add_library(crypto SHARED IMPORTED)
set_target_properties(crypto PROPERTIES IMPORTED_LOCATION "${BOWIE_DEPS}/libs/${ANDROID_ABI}/libcrypto.so")
add_library(juice SHARED IMPORTED)
set_target_properties(juice PROPERTIES IMPORTED_LOCATION "${BOWIE_DEPS}/libs/${ANDROID_ABI}/libjuice.so")
add_library(ssl SHARED IMPORTED)
set_target_properties(ssl PROPERTIES IMPORTED_LOCATION "${BOWIE_DEPS}/libs/${ANDROID_ABI}/libssl.so")

add_library(bowie SHARED ${BOWIE_SOURCES})
target_include_directories(bowie PRIVATE "${BOWIE_ROOT}/include" "${BOWIE_ROOT}/src" "${CMAKE_CURRENT_LIST_DIR}" "${BOWIE_DEPS}/include" "${jansson_SOURCE_DIR}/src" "${jansson_BINARY_DIR}/include")
target_compile_definitions(bowie PRIVATE _GNU_SOURCE _POSIX_C_SOURCE=200809L BOWIE_PLATFORM_ANDROID)
target_compile_options(bowie PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_link_libraries(bowie PRIVATE crypto ssl juice websockets jansson log android)
