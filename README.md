 clean-release
# Bowie —  

Version: 2.2.0 (draft, reconciled with SITUATION_REPORT 2026-10-09)
License: GPL-3
Namespace: bowie_*

> v2.1 described the plan. v2.2 describes the project as it actually
> is, based on the situation report. Changes from v2.1 are marked
> **[v2.2]**. Items I could not reconcile are NOT silently decided:
> they are listed in Appendix A for the owner to rule on.
> Test status quoted here (16 suites, 633 checks, 0 failures) comes
> from the owner's own build, not from this document's author.

---

## 1. What is Bowie?

A **P2P Egress sharing tool**. One person with Internet shares it
with someone far away through an encrypted P2P tunnel.

Bowie shares access to the owner's Internet connection, not the Internet
itself: client traffic exits through the source's uplink and generally appears
to originate from the owner's external IP address.

Bowie is NOT an Internet provider, a VPN service, a proxy server, a
blockchain, or a cryptocurrency. Bowie has no central server and
does not track users.

## 2. Use Cases

1. **Family sharing** — Alice shares with her Mom in another city.
2. **Remote friend** — Jack shares with Sara, who has no signal.
3. **Emergency backup** — when a home uplink fails, route through a
   friend's shared connection.
4. **Always-on source** — a router or Box at home shares even when
   nobody is home and the owner is travelling.

## 3. Core Concepts

- **Owner** — holds the Ed25519 private key; signs grants.
- **Peer** — a Bowie node: Device, Router, or Box.
- **Capabilities** — SOURCE (share Internet), CLIENT (receive it),
  GATEWAY (forward packets). Set by the platform, not by a fork of
  the code.
- **PoO (Proof of Ownership)** — owner proves control of a key by
  signing a challenge.
- **Grant** — owner-signed permission for one peer.
- **NAT backend [v2.2]** — a pluggable implementation of NAT
  traversal behind Bowie's own interface (see §8). Xury is one
  backend, not a hard dependency.

Router is not a Bowie peer by itself unless it runs Bowie on its
own firmware. The portable pattern is a **Box**: a small always-on
device behind an ordinary router.

## 4. Architecture

```
                         BOWIE
                           │
                  ┌────────┴────────┐
                  │                 │
              ENGINE               APPS
                  │                 │
       ┌──────────┼─────────┐      ├── Linux
       │          │         │      ├── Android
      NAT       Tunnel   Security  └── Router/Box
       │                    │
 [backend: libjuice]   Signed identity +
                       encrypted session
```

Router firmware (or the app) calls the Bowie public API locally;
the Engine runs on the device itself.

## 5. Layers  **[v2.2: corrected]**

| Layer | Name | Contents |
|---|---|---|
| 1 | Foundation | api (version, types, err, config, hooks), core (mem, log, endian, bytes, rand, time, sock) |
| 2 | Crypto | hash, cipher, sign, keypair (OpenSSL EVP) |
| 3 | Platform + Net | platform, socket, peer, capabilities |
| 4 | DHT | bencode, message, node, bucket, routing, search, storage, token, security |
| 5 | NAT | `nat.h` interface + backends |
| 6 | Tunnel | tun, packet, mtu |
| 7 | Session & Permission | enforcement: grant verify, session challenge |
| 8 | Protocol | handshake, framing, message |
| 9 | Gateway | gateway, route, conntrack, ip_forward |
| 10 | Tier1 | relay policy, quota |
| 11 | Security Admin | owner setup, grant signing, revocation |
| 12 | Apps | Linux, Android, Router/Box; engine orchestration (see A-5) |

Rules: a layer depends only on layers below it, never above, never
skipping. **[v2.2]** `engine/event/state/thread` were listed under
Layer 2 in v2.1; they are removed from it. An engine that
orchestrates layers 3–11 cannot sit at layer 2 without depending
upward — the same mistake that was fixed for Security.

## 6. Security Model (PoO v1)

- **Ed25519** signs/proves ownership; **X25519** agrees session keys.
  Never reuse one key for both.
- **Private key format [v2.2, locked]:** Bowie's canonical private
  key is 64 bytes (seed ‖ public). OpenSSL is given only the 32-byte
  seed.
- **Grant [v2.2, locked]:**

```c
typedef struct bowie_grant {
    bowie_public_id_t subject;      /* peer being authorized */
    bowie_public_id_t issuer;       /* owner (was "object") */
    bowie_grant_id_t  grant_id;     /* nonce */
    uint32_t          permissions;
    bowie_wtime_t     issued_at;
    bowie_wtime_t     expires_at;
    uint8_t           signature[64]; /* Ed25519 */
} bowie_grant_t;
```

- **Chain of trust:** Owner → peer only (star). No sub-owner
  delegation in v1.
- **Revocation:** time-limited grants plus signed revocation by the
  owner. No revocation server.
- **Enforcement point:** Layer 7. A connection is authorized once at
  session establishment; Tunnel and Gateway trust the verified
  session and do not re-check per packet.
- **Deferred:** key recovery and ownership transfer
  (CBOR vs JSON), public-ID string format, session protocol details,
  full threat model.
- Permission logic is engine-level; platforms provide storage only.

## 7. Crypto  **[v2.2]**

- OpenSSL **EVP** interface for SHA-256, SHA-1, MD5 (not the
  deprecated low-level one-shots), and `EVP_MAC` for HMAC (OpenSSL 3).
- Tests use **known test vectors**, never self-comparison.
- Status: hash, cipher, sign, keypair implemented and tested.
- Open: whether `include/crypto/*` should be public API at all
  (Appendix A-2).

## 8. NAT  **[v2.2: replaces "Xury as hard dependency"]**

Bowie owns the NAT interface; backends implement it.

```c
typedef struct bowie_nat bowie_nat_t;

bowie_error_t bowie_nat_new(bowie_nat_t **out);
bowie_error_t bowie_nat_start(bowie_nat_t *nat);
bowie_error_t bowie_nat_connect(bowie_nat_t *nat,
                                const bowie_addr_t *peer,
                                uint32_t timeout_ms,
                                int *out_sock_fd);
bowie_error_t bowie_nat_disconnect(bowie_nat_t *nat);
void          bowie_nat_free(bowie_nat_t *nat);
```

| `NAT_BACKEND` | Source | External lib |
|---|---|---|
| `libjuice` (current) | `src/nat/nat_libjuice.c` | `-ljuice` |

Selected at **build time**. CMake currently builds the libjuice backend;
Xury is not present in this checkout. A small Makefile remains as a
compatibility frontend and delegates compilation to CMake.

Definitions used by the project: a *backend* is a real
implementation; a *placeholder* is partial work and must be named
as such; a *stub* is fake and is forbidden.

## 9. Gateway, Tunnel flow

Bowie shares the source owner's Internet egress: client packets cross the
encrypted peer tunnel, then the source operating system forwards them through
its uplink. Internet destinations therefore generally see the source's public
IP address. Bowie does not provide Internet service itself.

The Linux listener now detects its IPv4 default uplink, enables IPv4
forwarding for the session, and installs a private nftables table for tunnel
forwarding and source masquerading. It removes that table and restores the
previous forwarding setting when it exits. If there is no IPv4 default route,
it stays overlay-only. Client-destination filtering runs before packets enter
the source host stack: private/special IPv4 ranges and IPv6 are denied by
default. Android CONNECT mode routes client defaults through the VPN and uses
an explicitly selected IPv4 DNS resolver. Linux clients are overlay-only by
default. Direct IPv4 connects can opt into a policy-routing table with
`--full-tunnel --dns <IPv4>`: known peer, signaling-relay, STUN, and TURN
addresses use the existing main routes, while other IPv4 traffic uses the
Bowie TUN. The option requires systemd-resolved (`resolvectl`), numeric IPv4
transport endpoints, and an available policy-rule/table slot. IPv6 is
blackholed. DHT and room lookup are supported when the bootstrap host is a
numeric IPv4 address. DHT nodes, signaling peers, and numeric IPv4/IPv6 ICE
candidate addresses receive bounded destination-specific underlay rules as
they are learned. mDNS ICE candidates cannot be converted into routes by this
Linux policy-routing path. Endpoint exceptions apply by destination to the whole host, so
traffic from any local process to those endpoint IPs also uses the underlay.
DNS uses ordinary client packets to the selected resolver; Bowie has no DNS
proxy. Quota helpers and byte counters are not yet wired into forwarding
enforcement.

The source-side Linux setup requires `nft` and permission to create TUN
interfaces, update `net.ipv4.ip_forward`, and install firewall rules. It only
manages the IPv4 path. Android's source-side Internet gateway path is not
implemented. Linux connector mode is overlay-only unless full-tunnel routing is
requested explicitly; policy routes and DNS settings are removed when the
session exits normally.

## 10. Public API  **[v2.2]**

**Locked:**

```c
bowie_engine_t *bowie_create(const bowie_config_t *config,
                             const bowie_hooks_t  *hooks);
bowie_error_t   bowie_start(bowie_engine_t *e);
bowie_error_t   bowie_stop(bowie_engine_t *e);
void            bowie_destroy(bowie_engine_t *e);
```

`config == NULL` → library defaults. `hooks == NULL` → no hooks.
`bowie_shutdown()` was removed (duplicated `bowie_destroy()`).

**Proposed, NOT locked** (from v2.1 §13.5; semantics still UNKNOWN):
`bowie_connect/disconnect`, `bowie_add_peer/remove_peer`,
`bowie_owner_init/get_public_id`, `bowie_grant_new/sign/verify`,
`bowie_get_socket_fd/detach_socket`. Do not implement them until
each has been audited against the layers it depends on.

Other locked behaviors **[v2.2]**: `bowie_sock_sendto/recvfrom`
return `(long)BOWIE_ERR_*` directly (codes are already negative);
`BOWIE_LOG_NONE` disables all logging; `bowie_log_t` is not
thread-safe and the engine serializes access.

## Linux and Android run paths

Bowie keeps a device identity across restarts. Linux stores the 32-byte
Ed25519 seed in `$XDG_CONFIG_HOME/bowie/identity.key` (or
`~/.config/bowie/identity.key`) with owner-only file permissions. Android
stores the seed encrypted in app-private storage; its AES wrapping key is
held by Android Keystore. The displayed `bowie-xxxxxxxxxx` name is a short,
stable alias derived from the peer ID. It is a convenient label, not a
globally reserved username: verify the full peer ID when authorizing a peer.
Uninstalling the Android app removes its local identity.

Configure and build the Linux LAN app and static library with CMake:

```sh
cmake -S . -B out -DCMAKE_BUILD_TYPE=Debug
cmake --build out --parallel
```

The LAN app performs direct endpoint signaling, ICE setup,
peer-ID pinning, a signed X25519 handshake, and starts the encrypted
TUN gateway when given a TUN interface. The Linux CLI loads the persistent
identity described above, so its peer ID remains stable across process
restarts. Exchange the full peer ID with the other device before connecting.

The easiest end-to-end check is the CMake `e2e-local` target. It starts both peers
inside one process, so there is no ID or port to copy and no TUN setup:

```sh
cmake --build out --target e2e-local
```

For a full Linux CLI test with real TUN interfaces, run `./tests/e2e/test_loopback.sh`.
It starts both CLI processes, picks up their IDs and signaling ports, issues
the connector's owner grant, and authorizes the connection automatically. It needs Linux network tools and
sudo access to create isolated network namespaces and TUN interfaces.

To do the CLI exchange by hand, use two terminals:

```sh
# Terminal 1 (requires CAP_NET_ADMIN for the packet gateway)
sudo ./out/bowie-linux listen bowie0 10.77.0.1/24

# Terminal 2, using the listener's printed peer ID and signal port
sudo ./out/bowie-linux connect bowie1 10.77.0.2/24 127.0.0.1 SIGNAL_PORT LISTENER_PEER_ID --grant-file sara.grant
```

For a direct IPv4 connector that should send ordinary device traffic through
the source, add `--full-tunnel --dns 1.1.1.1` (or another reachable resolver)
to the connect command. This needs `iproute2`, `systemd-resolved`, and network
administration permission. Known Bowie endpoint addresses bypass the tunnel;
traffic to those same addresses from other local apps also uses the underlay.
For DHT discovery in full-tunnel mode, use a numeric IPv4 bootstrap endpoint
and add `--full-tunnel --dns <IPv4>`; learned DHT, signaling, and ICE endpoints
receive routes dynamically. Metered signaling is not supported in this mode.

For DHT discovery, give both processes the same reachable bootstrap
node. The listener announces its signaling port, and the connector
resolves the peer ID before connecting:

```sh
# Terminal 1
sudo ./out/bowie-linux listen bowie0 10.77.0.1/24 BOOTSTRAP_HOST BOOTSTRAP_PORT

# Terminal 2
sudo ./out/bowie-linux connect-dht bowie1 10.77.0.2/24 LISTENER_PEER_ID BOOTSTRAP_HOST BOOTSTRAP_PORT --grant-file sara.grant
```

For the explicit-ID flow, copy the connector's printed peer ID into Terminal
1. Then press Enter in Terminal 2. Once both report `CONNECTED`, run `ping
10.77.0.2` from Terminal 1. For two machines, use the listener's LAN address
instead of `127.0.0.1`. Both sides need permission to create TUN interfaces.

Before connecting, the owner source grants access to the connector's stable
peer identity. On the connector, run `identity` once and give that ID to the
owner. The owner creates a signed, peer-specific grant (valid for 30 days by
default). Use `--ttl 1h` (or `30m`, `7d`) for a shorter lifetime:

```sh
# Connector: share this stable ID with the owner through a trusted channel
./out/bowie-linux identity

# Owner/source: create a grant for that exact peer ID
./out/bowie-linux grant CONNECTOR_PEER_ID sara.grant --ttl 1h --data-limit 100MB
```

Transfer `sara.grant` to the connector through a trusted channel. The connector
must present it on every connection:

```sh
sudo ./out/bowie-linux connect-dht bowie1 10.77.0.2/24 OWNER_PEER_ID BOOTSTRAP_HOST BOOTSTRAP_PORT --grant-file sara.grant
```

The source verifies the signature, issuer, subject, expiration, internet-use
permission, data limit, and revocation status during the authenticated
handshake. A grant data limit counts source gateway IP packet bytes in both
directions. When the limit is consumed, Bowie automatically disconnects that
peer. Usage for a grant survives reconnects while its source engine remains
running; Linux Source persists per-Grant usage in
`~/.config/bowie/grant-usage.sqlite3` (or `$XDG_CONFIG_HOME/bowie/`), and
durably reserves quota in 64 KiB chunks before forwarding. After a crash,
accounting can conservatively count up to 64 KiB extra as used for that Grant,
but it will not restore that allowance. If the store cannot be written,
quota-limited forwarding fails closed. Android Source currently has no durable
quota store configured.

When configuring STUN/TURN, BYOT (bring your own TURN) means you supply a TURN
provider account and credentials. TURN-relayed bytes may count against that
provider's quota or billing. STUN assists address discovery and does not relay
tunnel payloads. Missing,
expired, altered, or peer-mismatched grants are rejected. The source's private
identity key must remain under the owner's control; anyone holding it can
issue grants. The same grant-file option applies to `connect` and
`connect-room`.

To discover by a shared room instead of exchanging peer IDs, start the
listener with `--room` and connect with `connect-room`:

```sh
# Terminal 1: announce a room and accept peers with valid owner grants
sudo ./out/bowie-linux listen bowie0 10.77.0.1/24 BOOTSTRAP_HOST BOOTSTRAP_PORT --room SHARED_ROOM_KEY

# Terminal 2: discover a room member and request an authenticated connection
sudo ./out/bowie-linux connect-room bowie1 10.77.0.2/24 SHARED_ROOM_KEY BOOTSTRAP_HOST BOOTSTRAP_PORT --grant-file sara.grant
```

In room mode, each handshake signature also proves possession of that
identity's key over a domain-separated challenge containing the room's DHT
hash. A mismatched room fails signature verification. The room string remains
a DHT lookup key, not an access-control secret or an exclusive owner registry;
the owner-issued grant controls access. A router can therefore remain the
internet source while its owner grants a traveling peer permission to connect
from elsewhere. Granting a peer permission to connect does not yet make Bowie
forward a second peer's traffic through that session: multi-peer transit and
delegated grants still need relay support in the engine.

While connected with a TUN interface, each process prints cumulative
`GATEWAY` packet counters every five seconds. `packets_out` counts
packets read from local TUN and accepted by the data channel;
`packets_in` counts authenticated packets written into local TUN;
`dropped` counts packets rejected or not delivered. These counters
help locate which side of the encrypted path stopped moving.

For a transport-only handshake check in environments without TUN
access, use `listen - -` and `connect - - HOST PORT PEER_ID`. This
does not exercise gateway packet forwarding.

To exercise both real engines and the encrypted packet gateway without
creating kernel TUN devices, run `cmake --build out --target e2e-local`. It creates two
packet-preserving local tunnel FDs, completes the authenticated ICE
handshake, then sends and verifies one IP packet in each direction.
This tests the complete userspace gateway path; a Linux kernel TUN or
Android `VpnService` device run is still required to verify platform
interface configuration.

For a Linux kernel TUN and CLI test, `./tests/e2e/test_loopback.sh` runs
`tests/e2e/test_loopback.sh`. It starts an isolated two-peer connection,
automatically exchanges peer IDs, sets both tunnel interfaces to MTU 1500,
and pings across the overlay.

To test Metered signaling, set a publishable key and channel and run
`./tests/e2e/test_metered.sh`. The script starts two local CLI peers and exchanges their
peer IDs and authorization prompts automatically. It verifies signaling and
the authenticated connection without creating TUN interfaces:

```sh
METERED_API_KEY=pk_live_... METERED_CHANNEL=your-channel ./tests/e2e/test_metered.sh
```

The NAT data channel splits larger encrypted messages into bounded UDP
datagrams and reassembles them before decryption, preserving the original IP
packet. `tests/e2e/test_loopback_no_loss.sh` runs a 30-packet, 1472-byte
payload baseline with netem disabled and requires all 30 replies. Compare it with
`tests/e2e/test_packet_loss.sh`, which uses the same defaults with 10%
simulated link loss; adjust `LOSS_PERCENT`, `PING_COUNT`, and `PING_SIZE` to
change that lossy run. These report observed ping results and do not promise
delivery of every packet on a lossy link.

`cmake --build out --target e2e-scale` starts 100 independent engine instances concurrently and
checks that each receives a unique peer ID and signaling port. Set
`BOWIE_SCALE_PEERS` to test a smaller count. This measures concurrent peer
startup only; the current engine holds one active peer session per engine,
so this check does not establish 100 connected sessions.

`cmake --build out --target e2e-dht` runs a local bootstrap-node exchange: the engine gets a
token, announces a peer or room signaling endpoint, discovers a second room
member without its peer ID, then verifies both approval and rejection during
the signed connection handshake.

Android has a VpnService app under `platforms/android`. It transfers
the established VPN file descriptor to the common tunnel handle and
uses the same engine APIs. Build with Android SDK/NDK installed and
prebuilt OpenSSL/libjuice packages for the selected ABI:

```sh
gradle -p platforms/android :app:assembleFullDebug -PbowieDeps=/path/to/android-deps
```

The dependency directory must contain `include/openssl`,
`include/juice`, and `libs/<ANDROID_ABI>/libcrypto.so` plus
`libjuice.so`. The default ABI is `arm64-v8a`. To build another ABI,
provide matching Android builds of those libraries and run:

```sh
gradle -p platforms/android :app:assembleFullDebug -PbowieDeps=/path/to/android-deps -PbowieAbis=x86_64
```

Build the standalone guest-only APK with:

```sh
gradle -p platforms/android :app:assembleGuestDebug -PbowieDeps=/path/to/android-deps
```

The installable guest APK is `platforms/android/app/build/outputs/apk/guest/debug/app-guest-debug.apk`.
It has a Connect-only interface, accepts owner grants through the Android file
picker, and keeps connection settings on the device. The guest can prepare its
device ID, send that ID to the source owner, then add the owner's peer ID and
select the returned `.grant` file from **Sources & Grants**.

`BOWIE_ANDROID_ABIS` accepts a comma-separated list when dependencies
are available for each ABI. The app targets Android API 28 or newer.
For an Android guest, first prepare Bowie and share its device code with the
source owner. After they issue a grant, open **Sources & Grants**, choose
**Add Linux Source**, enter the owner's peer ID, and select the `.grant` file
through Android's document picker. The app checks the grant recipient against
the prepared guest device ID and the engine validates its signature and expiry.

For a connected Android phone and Linux host on the same Wi-Fi, run
`BOWIE_ANDROID_DEPS=/path/to/android-deps ./tests/e2e/test_android_linux_device.sh`. The
script runs the Linux userspace gateway test, builds both peers, installs the
APK as an update, starts a local signaling relay on UDP 3479, supplies both
peer IDs automatically, and pings the Linux overlay address through the real
Android and Linux TUN interfaces. The Linux TUN setup needs sudo access (run
`sudo -v` first if needed). Open UDP 3479 on the Linux host firewall. Android
VPN consent may need approval on the phone the first time. Set
`BOWIE_ANDROID_HOST` if the script cannot infer the Linux Wi-Fi address,
`RELAY_PORT` if 3479 is already in use, or `ADB` to select an ADB executable.
`./tests/e2e/test_loopback.sh` separately tests two Linux TUN interfaces.

For the phone installation and two-device DHT room walkthrough, see
[ANDROID_TESTING.md](ANDROID_TESTING.md).

For Android DHT room testing, configure the same numeric IPv4 bootstrap host
and UDP port, room name, and distinct overlay addresses (for example
`10.77.0.1/24` and `10.77.0.2/24`) on both phones. On the Router Source,
prepare the VPN, share its peer ID, issue a grant to the Guest Client's peer
ID, send that `.grant` file through a trusted channel, then tap **ANNOUNCE &
WAIT IN ROOM**. On the Guest Client, import the grant, prepare the VPN, and
tap **DISCOVER & CONNECT**. Configure optional STUN/TURN UDP server details
on each phone before preparing the VPN; enter TURN credentials there when
the relay requires them. A shared room is a discovery key, not authorization:
the source still checks the signed owner grant. Android Router Source now has
a rootless IPv4 packet-to-socket dataplane for TCP and UDP, including DNS. It
translates decrypted guest packets into sockets on the phone's physical
network and sends synthesized replies back through the peer tunnel. This path
has built successfully but still needs physical-device testing across mobile
and Wi-Fi networks. IPv6, fragmented packets, and protocols other than TCP
and UDP are fail-closed. The Linux CLI accepts optional
`--stun HOST PORT` and `--turn HOST PORT` arguments on `listen`, `connect`,
and `connect-dht`. For example, add `--turn global.relay.example 80` to
either peer's command; it prompts for the TURN username and password with
terminal echo disabled. Do not put TURN credentials in the command line.
Both peers need compatible ICE server configuration. The current libjuice
interface accepts one STUN endpoint and one TURN endpoint over UDP; TURN
TCP/TLS URL variants are not supported by this integration. Credentials
are passed to the native engine for the session and are not logged or
persisted by the app or CLI.

For networks that isolate Wi-Fi clients from one another, TURN does not
carry Bowie's SDP signaling. Run the separate UDP signaling relay on a
publicly reachable host (allow inbound UDP on its chosen port), then set
the same relay host and port on both peers. Build and start the relay with:

```sh
cmake --build out --target bowie-signal-relay
./out/bowie-signal-relay 0.0.0.0 3479
```

For a Linux listener, add `--signal-relay RELAY_HOST 3479` to `listen`;
for a Linux connector, add it to `connect` or `connect-dht`. Android has
matching Signal Relay host/UDP port fields in the optional servers section.
The relay forwards only signaling datagrams; ICE media still connects
directly or through the configured TURN server. Both peers must use the
same relay. This first relay implementation is an unauthenticated UDP
rendezvous service intended for testing; do not expose it as a production
service without adding registration authentication and abuse controls.

## 11. Current implementation and verification

- `cmake --build out` builds the Linux LAN CLI and static library.
- `cmake --build out --target bowie-linux-diagnostic` builds the legacy diagnostic harness separately.
- `cmake --build out --target e2e-local` verifies authenticated ICE setup and bidirectional
  encrypted packet forwarding through two gateways using packet FDs.
- `cmake --build out --target e2e-dht` verifies bootstrap token exchange, peer-ID lookup, room-based
  discovery without a peer ID, owner-grant authorization, and rejection when
  the source receives no grant against a local DHT bootstrap node.
- `tests/e2e/test_loopback.sh` checks a Linux two-peer overlay ping;
  `tests/e2e/test_packet_loss.sh` repeats it with simulated packet loss.
- `cmake --build out --target e2e-scale` measures up to 100 independent concurrent peer engines,
  checking startup, unique identities, and unique signaling ports.
- The manual two-terminal commands above exercise separate Linux
  processes. A kernel TUN ping still needs verification on a host with
  `/dev/net/tun` and network-administration permission.
- Android has a VpnService app, JNI engine lifecycle, direct endpoint
  connection, optional DHT bootstrap/lookup, and optional STUN/TURN UDP
  configuration. The arm64 APK builds and its signature verifies, but
  device behavior still needs testing.

The gateway forwards packets between the supplied tunnel and the
encrypted peer data channel. The Linux listener configures IPv4 forwarding
and masquerading as described in §9. Android CONNECT mode now routes IPv4
and IPv6 defaults through the Bowie VPN, sets an explicit IPv4 DNS resolver,
and excludes the Bowie app's own sockets so signaling and ICE remain on the
underlying network. Enter a numeric resolver address in the DNS field before
preparing CONNECT mode. This is client-side DNS selection; Bowie does not yet
proxy DNS itself. The overlay's more-specific route remains active.

Android Router Source uses the user-space packet-to-socket dataplane described
above; it does not depend on kernel IP forwarding or NAT. Source egress is not
subject to a global daily byte cap. Each signed grant may carry a cumulative
data limit. Linux Source durably reserves usage in 64 KiB chunks, so restarts
cannot restore reserved quota; Android Source currently retains usage only in
process memory. IPv6 is routed into the client tunnel
to prevent local-network leakage, but source egress remains IPv4-only and
fail-closed for IPv6. Linux direct-connect policy routing is available as an
opt-in; it installs dynamic DHT/ICE exception routes for numeric addresses.
mDNS ICE candidates remain unsupported by Linux policy routing.

## Egress behavior and remaining implementation

The source endpoint sees decrypted IP packets and the owner's uplink carries
their Internet traffic. The Linux source gateway currently blocks private,
special-use, and IPv6 destinations before host injection. These are required
network boundaries for an Internet-egress feature, rather than access to the
owner's local network.

Current gateway byte counters describe the active session and are not
persistent accounting. Quota primitives exist but are not connected to packet
forwarding. DNS queries go to the resolver selected by the client; ordinary
unencrypted DNS is visible to the source and resolver. Application encryption
such as HTTPS remains end-to-end. These properties should be reflected in the
owner and client interfaces as implementation proceeds.

## 12. Build and test commands

```sh
cmake -S . -B out -DCMAKE_BUILD_TYPE=Debug
cmake --build out --parallel
cmake --build out --target e2e-local
cmake --build out --target e2e-dht
cmake --build out --target e2e-scale
gradle -p platforms/android :app:assembleFullDebug -PbowieDeps=/path/to/android-deps
```

Linux dependencies are OpenSSL, libjuice, SQLite, and pthreads. Android also
needs the Android SDK/NDK and ABI-specific OpenSSL/libjuice packages as
described above. The loopback E2Es exercise real engine, ICE, crypto,
gateway, and DHT code; they do not replace a kernel-TUN or device test.

---

## Appendix A — Earlier architecture review questions

These notes predate the current platform, DHT, NAT, tunnel, and gateway
implementation. They are retained as design history, not as current
build status or verified findings.

**A-1. Public header layout.** The report's §3.9 is titled "bowie.h is
in include/, not include/bowie/", but its own tree shows
`include/bowie/bowie.h`; only crypto sits at `include/crypto/`. If
`include/crypto/` is installed to `/usr/local/include/crypto/`, it can
collide with any other package using a generic `crypto/` directory.
Public headers are normally namespaced: `include/bowie/crypto/hash.h`.
Recommend: move under `include/bowie/` before more modules copy the
pattern (net/, dht/, tunnel/ …).

**A-2. Is crypto public API?** A host sharing Internet doesn't need
`bowie_hash_md5()`. Public headers are a long-term compatibility
promise. If crypto is an implementation detail, its headers belong in
`src/crypto/`. If hosts need only ownership/grant operations, expose
those, not raw hash/cipher.

**A-3. "A caller cannot tell which backend is in use"** (report rule 7)
is risky: a user on the placeholder backend could believe NAT
traversal works. Recommend a query such as backend name plus a
capability flag ("performs NAT traversal: yes/no"), and honest
failure when traversal is required but unavailable.

**A-4. No-server promise vs. libjuice.** ICE libraries typically rely
on STUN/TURN servers. If used, that contradicts Bowie's no-server
claim. I have not verified libjuice's API. Recommend: allow
server-dependent backends in development builds only, and have
release builds reject them.

**A-5. Where does the engine live?** The report defers it to "Phase 11
(Apps)", but Phase 11 is Security Admin and Apps is Phase 12. Also
`engine/event/state/thread` are removed from Layer 2 here (they would
depend upward). Confirm the intended phase and location. §8.4 of the
report refers to `src/core/engine.c`; the engine is not in core.

**A-6. `peer.c` vs `peers.c` vs `net/peer.c`.** Report says
`api/peer.c`; the owner's file list says `api/peers.c`; Layer 3 also
has `net/peer.c`. Pick one name per module.

**A-7. `bowie_create` failure reporting.** It returns a pointer, so a
failed creation gives the caller no error code. Decide whether to
add an out-parameter or an error accessor.

**A-8. `bowie_nat_new(out)` takes no config or hooks**, so a backend
has no timeouts or logging path. Decide whether config/hooks are
passed here or via the engine. `int *out_sock_fd` is POSIX-only;
Windows would need a different socket type.

**A-9. Report §8.1 is labelled "Open" but is answered** ("yes, this is
the right approach"). Close it.

**A-10. Not verifiable from here.** I cannot see the repository.
Everything marked ✅ above is as reported by the owner.

END OF DOCUMENT# Bowie
p2p internet share
 
 main
 
