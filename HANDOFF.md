# Bowie project handoff

## Current implementation

- The Linux Source and Android Full app can issue and enforce signed per-Grant
  cumulative byte limits. The Android Guest app is a standalone installable
  client build with UI for connection settings and importing a `.grant` file.
- Linux Source persists limited Grant usage in
  `$XDG_CONFIG_HOME/bowie/grant-usage.sqlite3`, or
  `~/.config/bowie/grant-usage.sqlite3` when `XDG_CONFIG_HOME` is unset.
  Usage is durably reserved in 64 KiB steps before forwarding. A restart can
  conservatively charge up to 64 KiB extra to a Grant, but cannot restore that
  reserved allowance. Database errors fail closed. Android Source does not
  yet configure a durable quota store.
- The quota counts Bowie packet bytes in both directions. TURN provider billing
  can be higher because relay protocol overhead is not included.
- The grant wire format changed to include the signed data limit. Reissue older
  grants and rebuild both peers from the same protocol version.

## Build and verification

Linux configuration and build completed successfully with CMake in the clean
source branch. No automated tests or physical-device checks were run in that
branch. Android builds need the Android SDK/NDK and the OpenSSL/libjuice
dependency bundle described in `platforms/android/CMakeLists.txt`.

Build the Linux binaries:

```sh
cmake -S . -B out -DCMAKE_BUILD_TYPE=Debug
cmake --build out --parallel
```

Build Android variants with Gradle, setting `bowieDeps` to the dependency
bundle path and `bowieAbis` to the desired ABI. Debug APKs are build outputs;
do not add them to Git.

## Repository handling

Keep issued `.grant` files, TURN/Metered credentials, private identity keys,
signing keys, APKs, SDK archives, and generated build directories out of Git.
The Linux quota database is local application data and must not be committed.
