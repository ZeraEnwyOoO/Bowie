                      
                         
                         
   __/\\\\\\\\\\\\\________________________________________________________        
 _\/\\\/////////\\\______________________________________________________       
  _\/\\\_______\/\\\__________________________________/\\\________________      
   _\/\\\\\\\\\\\\\\______/\\\\\_____/\\____/\\___/\\_\///______/\\\\\\\\__     
    _\/\\\/////////\\\___/\\\///\\\__\/\\\__/\\\\_/\\\__/\\\___/\\\/////\\\_    
     _\/\\\_______\/\\\__/\\\__\//\\\_\//\\\/\\\\\/\\\__\/\\\__/\\\\\\\\\\\__   
      _\/\\\_______\/\\\_\//\\\__/\\\___\//\\\\\/\\\\\___\/\\\_\//\\///////___  
       _\/\\\\\\\\\\\\\/___\///\\\\\/_____\//\\\\//\\\____\/\\\__\//\\\\\\\\\\_ 
        _\/////////////_______\/////________\///__\///_____\///____\//////////__                      
                         
                         
                         
                         
      EXPLAIN
 
---

**What it is**

Bowie lets one person share their internet connection with another person they trust, through an encrypted peer to peer tunnel.

The Connector's traffic leaves through the Sharer's connection, so websites see the Sharer's IP address.

The Sharer pays for the bandwidth and decides who connects, for how long, and how much.

---

**What it is not**

| Not this             | Reason                            |
|----------------------|-----------------------------------|
| Internet provider    | No public service                 |
| Public VPN           | Private, invitation only          |
| Proxy service        | Peer to peer, not central         |
| Blockchain or crypto | No tokens, no chain               |
| Account system       |  No central accounts, no tracking |

---

**Two things to know first**

| Point                       | Meaning                                                                                                       |
|-----------------------------|---------------------------------------------------------------------------------------------------------------|
| Sharer sees packets         | The Sharer's machine sees the Connector's decrypted IP packets. HTTPS still protects content from the Sharer. |
| Connector must trust Sharer | Bowie is meant for family and friends.                                                                        |

---

**Status**

| Line  | State                                                                                                                                                                       |
|-------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Alpha | Works as a proof of concept on LAN and, in observed runs, over the internet with a TURN relay. Uses libjuice, public STUN/TURN, and Metered signaling. Frozen as reference. |
| Beta  | In progress. Removes libjuice, STUN, TURN, and Metered. Own UDP signaling, DHT discovery, mutual-open connection backend. No real-network beta result yet.                  |

---

**What alpha proved**

A real run on 2026-10-25: Android phone on mobile data (Wi-Fi off) to Linux laptop, carried by a TURN relay.

| Result             | Detail                                                         |
|--------------------|----------------------------------------------------------------|
| Same public IP     | Phone and laptop showed the same public IPv4 address           |
| No IPv6            | IPv6 not detected on either side                               |
| Real traffic       | 3 min 4 sec session, about 2.3 MB sent, about 14.3 MB received |
| Core layers worked | Identity, signed grants, encrypted tunnel, fail-closed gateway |
| Local checks pass  | Loopback suites for gateway, DHT, scale, room discovery        |





<img width="576" height="1280" alt="photo_6260426459474235825_y(4)" src="https://github.com/user-attachments/assets/615d7fe1-2f1f-4076-96d0-e1ab8c573f06" />












**What alpha did not prove:** that the connection works without a third-party relay. The successful runs used TURN, which beta removes.


**What went wrong in alpha**

| Problem | What happened | Lesson for beta |
|-------------------------------|-------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------|
| Third-party dependence        | STUN, TURN, Metered were needed. A relayed run can be billed.                 | Remove all of them. Use own UDP signaling and DHT.                                                          |
| Connector used mobile data    | 14 MB received was real data on the phone's plan. Sharing saved nothing.      | Tunnel traffic must use unmetered Wi-Fi only. Never silently move to mobile data.                           |
| Quota counted one leg         | Only forwarded payload counted once. Sharer pays twice.                       | Meter both legs. Data limit means total charged bytes.                                                      |
| Reconnect storms              | Tunnel connected, then dropped. Android and Linux reacted to network hints.   | Debounce network events. Use callback values.                                                               |
| Android grant rejected (-120) | Saved owner grant rejected during local validation. Root cause not confirmed. | Invites are version 2, require a real device code. Clock skew tolerance added. Not yet confirmed on device. |
| Linux signaling timeout (-41) | Listener got no signaling datagram. Flaky in some runs.                       | Beta signaling is typed, signed, encrypted, with own tests.                                                 |
| Manual pairing                | 40 hex digit peer ID copied by hand. Easy to mistype.                         | One-time invite link, automatic grant delivery, Remove button.                                              |
| Roles tied to platform        | Linux always source, Android always client.                                   | Peers are equal. Role comes from the verified grant, not the OS.                                            |
| Android source path           | Rootless IPv4 packet-to-socket path built but never validated on a device.    | Treated as unverified. Android as Sharer is not a beta gate.                                                |
| Test evidence weak            | Many unit tests not wired into the runner. Docs drifted.                      | Every claim carries an evidence level: built, unit, loopback, or real network.                              |
| Unauthenticated signal relay  | Test relay forwards signaling for anyone.                                     | Test infrastructure only. Removed in beta.                                                                  |




---

**What alpha gave to beta**

| Finding                   | Meaning                                                                                                                          |
|---------------------------|----------------------------------------------------------------------------------------------------------------------------------|
| Idea works                | Same public IP on both devices, real traffic counted                                                                             |
| Hard part is NAT          | The tunnel is not the hard part. The connection path through NAT without a third party is.                                       |
| Honest accounting matters | Who pays for what must be real, not assumed                                                                                      |
| Rules from real runs      | Connector on unmetered Wi-Fi only. Sharer pays both legs. Status must match real state. A relay success is not a direct success. |
| Concrete failure list     | Each failure has a fix attempt. Fixes are verified only at their evidence level.                                                 |

---

**Beta in one paragraph**

Two equal peers find each other through the DHT (a hint, never authorization). Each side deliberately opens for the friend. When both are open, they send UDP probes at each other at the same time, so both NATs allow the replies. This follows NAT rules instead of fighting them. Small signaling messages coordinate the moment and may travel over 4G/5G. Then the existing authenticated handshake checks the signed grant, and only then are Sharer and Connector decided. Nothing is relayed and there is no third machine. If it cannot connect, Bowie says so and gives a reason. The success rate on real networks is unknown until measured.

---

**Run the alpha (reference)**

Dependencies on the alpha line:

| Dependency |    Use  |
|------------|---------|
| OpenSSL    | Crypto  |
| libjuice   | ICE     |
| SQLite     | Storage |
| pthreads   | Threads |

Linux Sharer setup needs `nft` and permission for TUN and forwarding.

Android needs SDK/NDK and ABI-specific OpenSSL and libjuice builds.

```
cmake -S . -B out -DCMAKE_BUILD_TYPE=Debug
cmake --build out --parallel
cmake --build out --target e2e-local
cmake --build out --target e2e-dht
cmake --build out --target e2e-scale
```

Identity and grant:

```
./out/bowie-linux identity
./out/bowie-linux grant CONNECTOR_PEER_ID sara.grant --ttl 1h --data-limit 100MB
```

Connect over LAN or known address:

```
sudo ./out/bowie-linux listen bowie0 10.77.0.1/24
sudo ./out/bowie-linux connect bowie1 10.77.0.2/24 SOURCE_ADDRESS SIGNAL_PORT SOURCE_PEER_ID --grant-file sara.grant
```

Discover through a DHT bootstrap node:

```
sudo ./out/bowie-linux listen bowie0 10.77.0.1/24 BOOTSTRAP_HOST BOOTSTRAP_PORT
sudo ./out/bowie-linux connect-dht bowie1 10.77.0.2/24 SOURCE_PEER_ID BOOTSTRAP_HOST BOOTSTRAP_PORT --grant-file sara.grant
```

Android app:

```
gradle -p platforms/android :app:assembleFullDebug -PbowieDeps=/path/to/android-deps
```

See `ANDROID_TESTING.md` and `HOW TO USE.md` for the phone walkthrough. Both describe the alpha flow with STUN, TURN, and Metered, which beta removes.

Keep credentials private. Do not put TURN usernames, passwords, Metered keys, grants, or identity keys in the repository, shell history, or a public issue.

---

**Security model (short)**

| Rule                      | Detail |
|---------------------------|--------------------------------------------------------------------------------------------------------------------------------------------|
| Keys                      | Ed25519 proves ownership and signs grants. X25519 agrees session keys. One key is never reused for both.                                   |
| Grants                    | Signed by the owner for one peer. Includes expiry, permissions, cumulative data limit. Trust is a star: owner to peer only. No delegation. |
| Revocation                | Time-limited grants plus owner revocation. No revocation server.                                                                           |                 
| Authorization             | Checked at handshake. Gateway blocks private, special, and IPv6 destinations by default.                                                   |
| Identity key              | Must stay under owner's control. Anyone holding it can issue grants.                                                                       |

---

**Known limitations of alpha**

| Limitation                   | Detail |
|------------------------------|---------------------------------------------------------------------------------|
| Third-party services         | Needs STUN, TURN, Metered. A relayed connection can be billed by the provider.  |
| No direct WAN proof          | Real-network success without a relay was never demonstrated.                    |
| Quota counts one leg         | Payload counted once, not both legs. Android Sharer keeps usage in memory only. |
| DNS                          | Goes to the resolver the Connector picks. No DNS proxy.                         |
| IPv4 only egress             | IPv6, fragments, and non-TCP/UDP fail closed on the Android source path.        |
| Linux needs admin            | TUN, forwarding, firewall rules require administrator permissions.              |
| Android -120                 | Grant rejection not confirmed fixed.                                            |

---

**Feedback**

If you test Bowie on real networks, a useful report includes:

| Include                                                 | Do not include |
|---------------------------------------------------------|------------------------------|
| Date                                                    | Keys                         |
| Devices                                                 | Grant files                  |
| Both network types                                      | Credentials                  |
| How far it got (signaling, probe, handshake, connected) |                              |
| Exact error                                             |                              |
| Bytes up and down                                       |                              |
| Seconds to connect                                      |                              |

---

**License**

GPL-3. Copyright 2026 ASBM Team.
