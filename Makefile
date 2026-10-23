# Compatibility frontend. CMake owns all compilation and link rules.
BUILD_DIR ?= out
CONFIG ?= Debug
BOWIE_ANDROID_DEPS ?=
BOWIE_ANDROID_ABIS ?= arm64-v8a
GRADLE ?= gradle

.PHONY: all library linux android diagnostic signal-relay e2e-local e2e-loopback e2e-metered e2e-dht e2e-scale e2e-android-device configure clean help

all: linux
library: | configure
	cmake --build "$(BUILD_DIR)" --target bowie
linux: | configure
	cmake --build "$(BUILD_DIR)" --target bowie-linux
diagnostic: | configure
	cmake --build "$(BUILD_DIR)" --target bowie-linux-diagnostic
signal-relay: | configure
	cmake --build "$(BUILD_DIR)" --target bowie-signal-relay
e2e-local: | configure
	cmake --build "$(BUILD_DIR)" --target e2e-local
e2e-dht: | configure
	cmake --build "$(BUILD_DIR)" --target e2e-dht
e2e-scale: | configure
	cmake --build "$(BUILD_DIR)" --target e2e-scale
e2e-loopback:
	./tests/e2e/test_loopback.sh
e2e-metered:
	./tests/e2e/test_metered.sh
e2e-android-device:
	./tests/e2e/test_android_linux_device.sh
android:
	$(GRADLE) -p platforms/android :app:assembleFullDebug -PbowieDeps="$(BOWIE_ANDROID_DEPS)" -PbowieAbis="$(BOWIE_ANDROID_ABIS)"
configure:
	cmake -S . -B "$(BUILD_DIR)" -DCMAKE_BUILD_TYPE="$(CONFIG)"
clean:
	cmake -E rm -rf "$(BUILD_DIR)"
help:
	@printf '%s\n' 'CMake is the build system; use cmake -S . -B out && cmake --build out.' \
	  'Targets: bowie, bowie-linux, bowie-linux-diagnostic, bowie-signal-relay,' \
	  'e2e-local, e2e-dht, e2e-scale. Android uses Gradle with its CMake project.'
