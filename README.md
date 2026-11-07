 Bowie
Private internet sharing between people who trust each other. GPL-3. Namespace bowie_*. By the ASBM Team.
Status: alpha. This README describes the alpha line. Alpha was built to answer one question: is peer to peer bandwidth sharing really possible? It was also built to collect real data and real problems so the beta could be designed on evidence. It is a proof of concept, not a product. It depends on third-party services (STUN, TURN, Metered) that the beta removes. Do not use it to protect anything important.
1. What Bowie is
Bowie lets one person (the Sharer) share access to their internet connection with another person (the Connector) through an encrypted peer to peer tunnel. The Connector's traffic exits through the Sharer's connection, so websites generally see the Sharer's public IP address. The Sharer pays for the bandwidth. The Sharer decides who may connect, for how long, and how much, using a signed grant.
Bowie is not an internet provider, a public VPN, a proxy service, a blockchain or a cryptocurrency. It has no central account system and does not track users.
Two honest properties to know before you use it:
• The Sharer's machine sees the Connector's decrypted IP packets, like any internet source. Bowie protects the path between the two peers. HTTPS in the Connector's apps protects content from the Sharer.
• A Connector must trust the Sharer. Bowie is meant for family and friends.
2. Status at a glance
Line
State
Alpha (this README)
Works as a proof of concept on a LAN and, in observed runs, over the internet with a TURN relay. Uses libjuice (ICE), public STUN/TURN and Metered signaling. Frozen as a reference.
Beta (in progress)
Removes libjuice, STUN, TURN and Metered. Own UDP signaling, DHT discovery and a mutual-open connection backend. Designed and partly built. No real-network (WAN) beta result exists yet.
Beta design documents: BETA_LOCK.md (the source of truth), BETA_PLAN.md, newnat.md, friend_relay.md, irds_design.md, signaling_design.md, bandwidth_share_design.md, add_friend_design.md.
3. What alpha proved
Observed on 2026-10-25, Android phone to Linux laptop, phone on mobile data with Wi-Fi off, connection carried by a TURN relay:
• The phone and the laptop reported the same public IPv4 address on an IP-check site, and IPv6 was not detected on either. The phone really left the internet through the Linux host.
• The Android VPN dialog showed a 3 minute 4 second session with about 2.3 MB sent (6,922 packets) and about 14.3 MB received (14,440 packets). Real browsing traffic, not only a ping.
• The layers that matter most for the product worked end to end: identity, signed peer-specific grants with expiry and a data limit, the authenticated encrypted tunnel, and a fail-closed gateway (IPv6, private and special ranges blocked).
• Local checks on the maintainer's Linux machine also pass: the loopback end-to-end suites (local gateway, DHT discovery, scale, room discovery). These prove the logic. They do not prove WAN behavior.
What alpha does not prove: that the connection works without a third-party relay. The successful runs used a TURN relay, which is exactly what beta removes.
4. What went wrong in alpha, and what it taught us
Problem we hit
What we saw
What it means for beta
Third-party dependence
STUN, TURN and Metered signaling were needed. A relayed run can be billed by the provider. This contradicts the no-central-server promise.
Remove all of them. Bowie's own UDP signaling and DHT replace them.
Connector used mobile data
In the 4G run, the 14 MB received was real data on the phone's plan. Sharing saved the Connector nothing.
Tunnel traffic must use unmetered Wi-Fi only. The Connector must never silently move to mobile data.
Quota counted one leg
Alpha counted the forwarded payload once. A Sharer pays for the internet leg and again for the leg to the Connector, about double.
The Sharer meters both legs. The data limit means total charged bytes, enforced before forwarding.
Reconnect storms
The tunnel reached CONNECTED, then dropped. Android treated a transient cellular capability update as a network change, and Linux reacted to a netlink hint.
Recovery triggers were changed. Beta debounces network events and uses the values passed to the callback.
Android grant rejected (-120)
The saved owner grant was rejected during local validation, before any peer operation. Root cause not confirmed in alpha.
Invites are version 2 and require a real device code before saving a grant. New grants are issued with issued_at set 300 seconds in the past to tolerate phone clock skew. Not yet confirmed on a device.
Linux signaling timeout (-41)
The listener received no signaling datagram and timed out. Seen as a flaky result in some runs.
Beta signaling is typed, signed and encrypted, with its own tests. Flakiness is being tracked.
Manual pairing
The Connector copied a 40 hex digit peer ID to the Sharer, who made a QR and sent it back. Easy to mistype.
Beta adds a one-time invite link, automatic grant delivery and a Remove button.
Roles tied to platform
Linux was always the source and Android the client.
Peers are equal. A role comes from the verified grant, not from the operating system.
Android source path
A rootless IPv4 packet-to-socket path was built but never validated on a device.
Treated as unverified. Android as Sharer is not a beta gate.
Test evidence
Many unit tests were not wired into the test runner, so a green run said little. Docs drifted from the code.
Every claim carries an evidence level: built, unit, loopback, or real network.
Unauthenticated signal relay
The test relay forwards signaling for anyone who reaches it.
It is test infrastructure only and is removed in beta.
5. The data alpha gave to beta
• Bandwidth sharing works as an idea: same public IP on both devices, real traffic counted.
• The hard part is not the tunnel. It is the connection path through NAT without a third party, and the honest accounting of who pays.
• Rules that came from real runs, not theory: Connector on unmetered Wi-Fi only, Sharer pays both legs, status must match real state, a relay-carried success is not a direct-connection success.
• A list of concrete failures (above) with a fix attempt each. Beta fixes are in the design documents and are verified only at the level their evidence label says.
6. Beta in one paragraph
Two equal peers find each other through the DHT (a hint, never authorization). Each side deliberately opens for the friend, and when both are open they send UDP probes at each other at the same time, so both NATs allow the replies. This follows NAT rules instead of fighting them. Small signaling messages coordinate the moment, and may travel over 4G/5G. Then the existing authenticated handshake checks the signed grant, and only then are the Sharer and the Connector decided. Nothing is relayed and there is no third machine. If it cannot connect, Bowie says so and gives a reason. The success rate on real networks is unknown until it is measured.
7. Run the alpha (reference)
Dependencies on the alpha line: OpenSSL, libjuice, SQLite, pthreads. Linux Sharer setup needs nft and permission for TUN and forwarding. Android needs the SDK/NDK and ABI-specific OpenSSL and libjuice builds.
cmake -S . -B out -DCMAKE_BUILD_TYPE=Debug
cmake --build out --parallel
cmake --build out --target e2e-local
cmake --build out --target e2e-dht
cmake --build out --target e2e-scale
Identity and grant (the Connector shares its ID, the Sharer signs a peer-specific grant):
./out/bowie-linux identity
./out/bowie-linux grant CONNECTOR_PEER_ID sara.grant --ttl 1h --data-limit 100MB
Connect over a LAN or a known address:
sudo ./out/bowie-linux listen bowie0 10.77.0.1/24
sudo ./out/bowie-linux connect bowie1 10.77.0.2/24 SOURCE_ADDRESS SIGNAL_PORT SOURCE_PEER_ID --grant-file sara.grant
Discover through a DHT bootstrap node:
sudo ./out/bowie-linux listen bowie0 10.77.0.1/24 BOOTSTRAP_HOST BOOTSTRAP_PORT
sudo ./out/bowie-linux connect-dht bowie1 10.77.0.2/24 SOURCE_PEER_ID BOOTSTRAP_HOST BOOTSTRAP_PORT --grant-file sara.grant
Android app:
gradle -p platforms/android :app:assembleFullDebug -PbowieDeps=/path/to/android-deps
For the phone and two-device walkthrough, see ANDROID_TESTING.md and HOW TO USE.md. Both describe the alpha flow with STUN, TURN and Metered, which the beta removes.
Keep credentials private. Do not put TURN usernames or passwords, Metered keys, grants or identity keys in the repository, in shell history, or in a public issue.
8. Security model (short)
• Ed25519 proves ownership and signs grants. X25519 agrees session keys. The tunnel uses authenticated encryption. One key is never reused for both signing and key agreement.
• A grant is signed by the owner for one peer, with an expiry, permissions and a cumulative data limit. Trust is a star: owner to peer only. No delegation.
• Revocation is time-limited grants plus owner revocation. There is no revocation server.
• A connection is authorized at the handshake. The gateway blocks private, special and IPv6 destinations by default.
• The Sharer's private identity key must stay under the owner's control. Anyone holding it can issue grants.
9. Known limitations of alpha
• Needs third-party services (STUN, TURN, Metered). A relayed connection can be billed by the provider.
• Real-network success without a relay was never demonstrated.
• Quota counts payload once, not both legs. Android Sharer keeps usage in memory only.
• DNS goes to the resolver the Connector picks. Bowie has no DNS proxy.
• IPv4 egress only. IPv6, fragments and protocols other than TCP and UDP fail closed on the Android source path.
• Linux Sharer needs administrator permissions for TUN, forwarding and firewall rules.
• The Android -120 grant rejection is not confirmed fixed.
10. Feedback
If you test Bowie on real networks, the useful report is: date, devices, both network types, how far it got (signaling, probe, handshake, connected), the exact error, bytes up and down, and seconds to connect. Never include keys, grant files or credentials.
11. License
GPL-3. Copyright 2026 ASBM Team.
