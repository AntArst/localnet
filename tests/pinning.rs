//! The trust model in two tests, over loopback so no multicast is needed: a
//! client that pins the host's advertised certificate connects and exchanges
//! datagrams, and a client that pins any other certificate is refused during
//! the TLS handshake.

use std::net::SocketAddr;

use localnet::QuinnTransport;

const APP_ID: &str = "localnet-test";

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

#[tokio::test]
async fn pinned_certificate_connects_and_carries_datagrams() {
    let host = QuinnTransport::bind(loopback(), APP_ID).unwrap();
    let client = QuinnTransport::bind(loopback(), APP_ID).unwrap();
    let host_addr = host.local_addr().unwrap();

    let (accepted, connected) = tokio::join!(
        host.accept_peer(),
        client.connect_peer(host_addr, host.certificate_der(), APP_ID),
    );
    let host_side = accepted.expect("host accepts");
    let client_side = connected.expect("client connects with the pinned certificate");

    client_side.send_datagram(b"ping".to_vec()).await.unwrap();
    assert_eq!(host_side.receive_datagram().await.unwrap(), b"ping");
    host_side.send_datagram(b"pong".to_vec()).await.unwrap();
    assert_eq!(client_side.receive_datagram().await.unwrap(), b"pong");
}

#[tokio::test]
async fn a_different_certificate_is_refused() {
    let host = QuinnTransport::bind(loopback(), APP_ID).unwrap();
    let impostor = QuinnTransport::bind(loopback(), APP_ID).unwrap();
    let client = QuinnTransport::bind(loopback(), APP_ID).unwrap();
    let host_addr = host.local_addr().unwrap();

    // The host is accepting, so a failure here is the handshake rejecting the
    // certificate, not a connection that nobody answered.
    let (_, connected) = tokio::join!(
        host.accept_peer_waiting(3_000),
        client.connect_with_timeout(host_addr, impostor.certificate_der(), APP_ID, 3_000),
    );
    let err = match connected {
        Ok(_) => panic!("a certificate other than the host's must be refused"),
        Err(e) => format!("{e:#}"),
    };
    assert!(err.contains("certificate"), "expected a certificate error, got: {err}");
}
