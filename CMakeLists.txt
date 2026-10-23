cmake_minimum_required(VERSION 3.22)
project(bowie VERSION 0.1.0 LANGUAGES C)

include(GNUInstallDirs)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_package(SQLite3 REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(JUICE QUIET IMPORTED_TARGET libjuice)
pkg_check_modules(LWS QUIET IMPORTED_TARGET libwebsockets jansson)
if(JUICE_FOUND)
    set(BOWIE_JUICE_TARGET PkgConfig::JUICE)
else()
    find_path(JUICE_INCLUDE_DIR NAMES juice/juice.h REQUIRED)
    find_library(JUICE_LIBRARY NAMES juice REQUIRED)
    add_library(bowie-juice UNKNOWN IMPORTED)
    set_target_properties(bowie-juice PROPERTIES IMPORTED_LOCATION "${JUICE_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${JUICE_INCLUDE_DIR}")
    set(BOWIE_JUICE_TARGET bowie-juice)
endif()

file(GLOB_RECURSE BOWIE_COMMON_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c")
list(FILTER BOWIE_COMMON_SOURCES EXCLUDE REGEX "/src/platform/(android|linux)/")
list(FILTER BOWIE_COMMON_SOURCES EXCLUDE REGEX "/src/platform/posix/(rand|log|sock)\\.c$")
list(FILTER BOWIE_COMMON_SOURCES EXCLUDE REGEX "/src/tunnel/tun_linux\\.c$")
list(FILTER BOWIE_COMMON_SOURCES EXCLUDE REGEX "/src/api/(bowie|engine|peers|scan)\\.c$")
list(FILTER BOWIE_COMMON_SOURCES EXCLUDE REGEX "/src/engine/signal_metered\\.c$")
list(FILTER BOWIE_COMMON_SOURCES EXCLUDE REGEX "/src/engine/signal_metered_stub\\.c$")

set(BOWIE_PLATFORM_SOURCES
    src/platform/posix/rand.c
    src/platform/posix/log.c
    src/platform/posix/sock.c
    src/platform/linux/netlink.c
    src/tunnel/tun_linux.c
    src/nat/nat_libjuice.c)

if(LWS_FOUND)
    list(APPEND BOWIE_PLATFORM_SOURCES src/engine/signal_metered.c)
else()
    message(STATUS "Metered signaling disabled: libwebsockets and jansson were not both found")
    list(APPEND BOWIE_PLATFORM_SOURCES src/engine/signal_metered_stub.c)
endif()

add_library(bowie STATIC ${BOWIE_COMMON_SOURCES} ${BOWIE_PLATFORM_SOURCES})
add_library(Bowie::bowie ALIAS bowie)
target_include_directories(bowie PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_compile_features(bowie PUBLIC c_std_11)
target_compile_definitions(bowie PRIVATE _GNU_SOURCE _POSIX_C_SOURCE=200809L BOWIE_PLATFORM_LINUX)
target_compile_options(bowie PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_link_libraries(bowie PUBLIC OpenSSL::Crypto ${BOWIE_JUICE_TARGET} Threads::Threads m rt)
if(LWS_FOUND)
    target_link_libraries(bowie PUBLIC PkgConfig::LWS)
endif()

add_executable(bowie-linux platforms/linux/lan.c platforms/linux/egress.c platforms/linux/quota_store.c)
target_compile_definitions(bowie-linux PRIVATE _GNU_SOURCE _POSIX_C_SOURCE=200809L BOWIE_PLATFORM_LINUX)
target_compile_options(bowie-linux PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_include_directories(bowie-linux PRIVATE include src)
target_link_libraries(bowie-linux PRIVATE Bowie::bowie SQLite3::SQLite3)

add_executable(bowie-linux-diagnostic platforms/linux/main.c)
target_compile_definitions(bowie-linux-diagnostic PRIVATE _GNU_SOURCE _POSIX_C_SOURCE=200809L BOWIE_PLATFORM_LINUX)
target_compile_options(bowie-linux-diagnostic PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_include_directories(bowie-linux-diagnostic PRIVATE include src)
target_link_libraries(bowie-linux-diagnostic PRIVATE Bowie::bowie)

add_executable(bowie-signal-relay platforms/linux/signal_relay.c)
target_compile_definitions(bowie-signal-relay PRIVATE _GNU_SOURCE _POSIX_C_SOURCE=200809L BOWIE_PLATFORM_LINUX)
target_compile_options(bowie-signal-relay PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_include_directories(bowie-signal-relay PRIVATE include src)

add_executable(test-gateway-loopback tests/e2e/test_gateway_loopback.c)
target_compile_options(test-gateway-loopback PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_include_directories(test-gateway-loopback PRIVATE include src)
target_link_libraries(test-gateway-loopback PRIVATE Bowie::bowie)

add_executable(test-dht-discovery-loopback tests/e2e/test_dht_discovery_loopback.c)
target_compile_options(test-dht-discovery-loopback PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_include_directories(test-dht-discovery-loopback PRIVATE include src)
target_link_libraries(test-dht-discovery-loopback PRIVATE Bowie::bowie)

add_executable(test-peer-scale tests/e2e/test_peer_scale.c)
target_compile_options(test-peer-scale PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_include_directories(test-peer-scale PRIVATE include src)
target_link_libraries(test-peer-scale PRIVATE Bowie::bowie)

add_custom_target(e2e-local
    COMMAND $<TARGET_FILE:test-gateway-loopback>
    DEPENDS test-gateway-loopback USES_TERMINAL)
add_custom_target(e2e-dht
    COMMAND $<TARGET_FILE:test-dht-discovery-loopback>
    DEPENDS test-dht-discovery-loopback USES_TERMINAL)
add_custom_target(e2e-scale
    COMMAND $<TARGET_FILE:test-peer-scale>
    DEPENDS test-peer-scale USES_TERMINAL)

install(TARGETS bowie bowie-linux bowie-signal-relay
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
