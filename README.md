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

A **P2P Internet sharing tool**. One person with Internet shares it
with someone far away through an encrypted P2P tunnel.

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
 [backend: xury /      Session +
  libjuice /           Permission
  placeholder]
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
- **Deferred:** key recovery, ownership transfer, grant wire format
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
| `placeholder` (default) | built-in | none |
| `libjuice` | `src/nat_libjuice.c` | `-ljuice` |
| `xury` | `src/nat_xury.c` | `-lxury` |

Selected at **build time**. Phase 5 is no longer blocked on Xury;
Layers 6–12 depend on this interface, not on any backend.

Definitions used by the project: a *backend* is a real
implementation; a *placeholder* is a backend that does real but
partial work; a *stub* is fake and is forbidden. A placeholder is
only acceptable if it is honest about what it cannot do
(Appendix A-3).

Xury (sibling project, no-server by design) remains the preferred
backend and the only one that keeps Bowie's "no server" promise
by construction.

## 9. Gateway, Tunnel flow

Unchanged from v2.1 in intent: outbound = peer → tunnel (decrypt)
→ gateway → router stack → ISP; inbound reverses with conntrack.
Linux: iptables + ip_forward. Android: VpnService. DNS is forwarded
(UDP 53) by the donor, not provided by Bowie. Detail deferred to
Layer 9.

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

## 11. Directory Structure (actual state)

```
bowie/
├── Makefile                                  ✅
├── external/xury/                            (optional backend)
├── include/
│   ├── bowie/   bowie.h version.h types.h err.h config.h hooks.h   ✅
│   └── crypto/  hash.h cipher.h sign.h keypair.h                   ✅  ← see A-1
├── src/
│   ├── api/     version.c types.c err.c config.c hooks.c           ✅
│   │            (bowie.c engine.c peer(s).c scan.c — deferred)
│   ├── core/    internal/*.h + endian mem bytes time rand log sock ✅
│   └── crypto/  hash.c cipher.c sign.c keypair.c                   ✅
├── tests/
│   ├── test.h                                ✅ (not yet used)
│   └── unit/{api(5), core(7), crypto(4)}     ✅  16 suites, 633 checks, 0 failed
└── doc/     BOWIE.md  SITUATION_REPORT.md  BOWIE_TREE.md
```
Not started: platform, net, dht, nat, tunnel, security (session,
permission, admin), proto, gateway, tier1, apps.

`src/api/internal/` is not created: no module has needed a private
helper yet. Create it only when a real one appears.

## 12. Phase Plan

| Phase | Layer | Status |
|---|---|---|
| 1 | Foundation | ✅ done (except deferred top-of-stack files) |
| 2 | Crypto | ✅ done |
| 3 | Platform + Net | ⏳ next |
| 4 | DHT | ⏳ |
| 5 | NAT interface + backends | ⏳ unblocked |
| 6 | Tunnel | ⏳ |
| 7 | Session & Permission | ⏳ |
| 8 | Protocol | ⏳ |
| 9 | Gateway | ⏳ |
| 10 | Tier1 | ⏳ |
| 11 | Security Admin | ⏳ |
| 12 | Apps + engine orchestration | ⏳ |

## 13. Build & Test

Prototype: Makefile (Foundation only so far). Production: CMake
after the prototype succeeds, with no source changes. Tests use the
Check framework with known vectors; every public function and every
error path is tested; no mocks, no stubs. Real-network tests must
use a genuinely separate NAT path, never two devices on one LAN.

## 14. Working Rules

1. Header before source, source before test, test before next file.
2. No stubs; write the dependency or defer the dependent file.
3. Audit-before-fix; quote exact lines; classify failures.
4. Never invent constants or semantics; mark UNKNOWN.
5. "Mismatch" is not "contradiction" until proven.
6. The AI cannot compile; the owner builds and reports. The AI says
   "ready to verify", never "passing".
7. **[v2.2]** NAT backend is chosen at build time and must be
   honest about its capabilities.
8. **[v2.2]** Create a directory or internal header only when
   something real needs it.

## 15. Glossary

Bowie (product) · Engine (core handle) · Peer · Owner · PoO ·
Grant · Capability · Backend (real NAT implementation) ·
Placeholder (honest partial backend) · Stub (fake, forbidden) ·
Xury (NAT traversal library) · Layer · Phase.

---

## Appendix A — Issues found while reconciling (owner decides)

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
 
 
 <img width="349" height="351" alt="Well well well a average Balkaners" src="https://github.com/user-attachments/assets/bd95dba2-a166-43f3-9581-bd93b10cf192" />


me now


