# Android guest testing

This guide describes a manual Linux Source to Android Guest test. It requires
an Android SDK/NDK dependency bundle with OpenSSL and libjuice, a reachable DHT
bootstrap endpoint, and an owner-controlled signaling/ICE setup. Bowie does
not provide public bootstrap or TURN services.

## Build the standalone Guest APK

From the repository root, replace `/path/to/bowie-android-deps` with the
dependency bundle described in `platforms/android/CMakeLists.txt`:

```sh
gradle -p platforms/android :app:assembleGuestDebug \
  -PbowieDeps=/path/to/bowie-android-deps -PbowieAbis=arm64-v8a
```

The debug APK is written to
`platforms/android/app/build/outputs/apk/guest/debug/app-guest-debug.apk`.
Transfer that APK to the phone and install it using Android's package
installer. Debug APKs are generated locally and should not be committed.

## Connect to a Linux Source

1. Open the Guest app and configure the DHT bootstrap endpoint, room name,
   overlay address, DNS, and any Metered or TURN settings in the app UI.
2. Prepare the VPN and share the displayed Guest peer ID with the Source owner
   over a trusted channel.
3. On the Linux Source, create a peer-specific signed grant. For example:

   ```sh
   ./out/bowie-linux grant GUEST_PEER_ID guest.grant --ttl 1h --data-limit 100MB
   ```

   Transfer `guest.grant` privately to the Guest. Do not commit it to Git.
4. Start Linux Source with the same DHT bootstrap and room settings. Configure
   signaling and TURN as required by the network. TURN use may incur provider
   charges and is separate from Bowie's source packet-byte quota.
5. In the Guest app, import the grant through the Android file picker and
   connect to the room.

The grant limit applies to packet bytes counted by Bowie in both directions.
Linux Source persists usage across process restarts. Android Source currently
does not have durable quota accounting. The limit does not represent the exact
byte total billed by a TURN provider.

## Build the Full app

For source-side controls and device testing, build the Full flavor:

```sh
gradle -p platforms/android :app:assembleFullDebug \
  -PbowieDeps=/path/to/bowie-android-deps -PbowieAbis=arm64-v8a
```

Keep Metered keys, TURN credentials, private identity keys, and grants out of
shell history, logs, screenshots, and Git.
