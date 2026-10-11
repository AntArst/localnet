# localnet

Serverless multiplayer sessions on a local network, in Rust. Devices find each
other over mDNS, connect directly over QUIC with TLS 1.3, and exchange game
traffic through an adapter for [GGRS](https://github.com/gschup/ggrs) rollback
netcode. There is no server, no account and no internet connection involved.

It was built for [localPong](https://micronant.com/localpong/), a four-player
LAN Pong for Android and desktop, and extracted here as its own crate.

## What it does

| Module | |
|---|---|
| `discovery` | Advertises a session over mDNS and browses for others. Each host's self-signed certificate travels in the service's TXT record, split into base64 chunks. |
| `transport` | QUIC (`quinn`) with TLS 1.3 (`rustls`). Key exchange is the hybrid post-quantum X25519MLKEM768 only, through aws-lc-rs; a peer that offers only classical X25519 is refused. A host generates a certificate per session with `rcgen`; a client trusts exactly that certificate and nothing else. Datagrams for game traffic, streams when needed. |
| `session` | Host or join, a lobby → starting → in-progress lifecycle, per-peer connection quality, and events for peers joining, leaving and reconnecting. |
| `socket` | `LocalnetSocket`, an implementation of GGRS's `NonBlockingSocket`, so a rollback session runs over the QUIC connection without the game touching the transport. |
| `clock`, `ptp`, `ptp_udp` | A software clock disciplined by PTP (IEEE 1588) over UDP, using [`statime`](https://github.com/pendulum-project/statime). localPong uses it to keep background music in sync on every device. |
| `media` | RTP-style framing for media datagrams. Experimental. |

## Trust model

mDNS is unauthenticated, so anyone on the network can advertise a session.
Pinning the advertised certificate means a match is encrypted against everyone
listening, and a client only ever talks to the host whose advertisement it
chose. It does not prove that the host is who its advertisement claims to be.
That suits games on a home network; anything more sensitive would need
discovery with its own authentication, such as a code shown on the host's
screen.

The two tests in `tests/pinning.rs` show the model directly over loopback: a
client that pins the host's certificate connects and exchanges datagrams, and a
client that pins any other certificate is refused during the TLS handshake.

## Lobby admission (optional)

With the `admission` feature, a host can seat only players who prove in zero
knowledge that they hold a credential from a known group, at most one seat per
credential per match, without revealing which credential. It is Semaphore's
construction (Groth16 over BN254, Poseidon), and the classical baseline for
[oneSeat](https://micronant.com/oneseat/).

- Each proof is bound to the TLS exporter value of its own QUIC connection, so
  it cannot be replayed on another.
- The host proves its own seat, bound to the certificate clients pin, and sends
  every client the roster of seats; clients check every proof in it.
- `AdmissionKeys::setup` runs the Groth16 setup locally. Whoever runs it can
  forge proofs, so it suits a prototype; a real deployment needs a ceremony.

`Session::accept_admitted_peer` and `Session::request_admission` wire it into a
session; `tests/admission.rs` covers it end to end over loopback.

```sh
cargo test --features admission
cargo run --release --features admission --example admission_bench
```

## Usage

Hosting advertises the session and waits for players:

```rust
use std::collections::HashMap;
use localnet::{PeerAddr, Session};

let mut host = Session::host(
    "0.0.0.0:0".parse()?,
    PeerAddr("host-1".into()),
    "my-game",            // app id: prefixes the mDNS instance name, and is the TLS server name
    "Alice",              // display name shown to other players
    HashMap::new(),       // free-form metadata, e.g. game mode
    4,                    // capacity
)?;
let peer = host.accept_peer().await?;
```

Joining browses for hosts, picks one and connects with the certificate it
advertised:

```rust
use localnet::{PeerAddr, PeerDiscovery, Session};

let discovery = PeerDiscovery::start()?;
// Hosts appear as their advertisements arrive: poll `peers()`, or subscribe
// with `events()` for found and lost notifications.
let host_info = discovery.peers().into_iter().next().expect("a host on the LAN");

let mut client = Session::join("0.0.0.0:0".parse()?, PeerAddr("client-1".into()), "my-game")?;
client.connect_to_host(host_info.addr, host_info.cert_der, "my-game").await?;
```

For rollback netcode, give `session.socket()` to a GGRS `P2PSession` as its
socket, and call `session.pump_datagrams().await` once per frame to carry its
messages over QUIC in both directions.

## Status

Used by localPong on Android and desktop. Not published to crates.io, and the
API may change. Discovery needs multicast, which some access points disable.

```sh
cargo test    # the certificate-pinning tests, over loopback
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
