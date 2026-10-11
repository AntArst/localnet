//! Every localnet connection uses the hybrid X25519MLKEM768 key exchange. Checked
//! from outside with hand-built clients over loopback: one that offers only the
//! hybrid connects, so that is what was negotiated, and one that offers only
//! classical X25519 is refused during the handshake.

use std::net::SocketAddr;
use std::sync::Arc;

use localnet::QuinnTransport;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::{aws_lc_rs, SupportedKxGroup};
use rustls::RootCertStore;
use rustls_pki_types::CertificateDer;

const APP_ID: &str = "localnet-test";

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

/// A client that pins `cert` and offers only `group` for key exchange.
fn client_offering(group: &'static dyn SupportedKxGroup, cert: CertificateDer<'static>) -> Endpoint {
    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = vec![group];
    let provider = Arc::new(provider);

    let mut roots = RootCertStore::empty();
    roots.add(cert).unwrap();
    let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .unwrap();
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_webpki_verifier(verifier)
        .with_no_client_auth();

    let mut endpoint = Endpoint::client(loopback()).unwrap();
    endpoint.set_default_client_config(ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(tls).unwrap(),
    )));
    endpoint
}

#[tokio::test]
async fn a_client_offering_only_the_hybrid_connects() {
    let host = QuinnTransport::bind(loopback(), APP_ID).unwrap();
    let client = client_offering(aws_lc_rs::kx_group::X25519MLKEM768, host.certificate_der());

    let (accepted, connected) = tokio::join!(
        host.accept_peer_waiting(3_000),
        async { client.connect(host.local_addr().unwrap(), APP_ID).unwrap().await },
    );
    connected.expect("the hybrid key exchange is accepted");
    assert!(accepted.unwrap().is_some());
}

#[tokio::test]
async fn a_client_offering_only_classical_x25519_is_refused() {
    let host = QuinnTransport::bind(loopback(), APP_ID).unwrap();
    let client = client_offering(aws_lc_rs::kx_group::X25519, host.certificate_der());

    // The host is accepting, so a failure is the handshake finding no common group.
    let (_, connected) = tokio::join!(
        host.accept_peer_waiting(3_000),
        async { client.connect(host.local_addr().unwrap(), APP_ID).unwrap().await },
    );
    let err = match connected {
        Ok(_) => panic!("a classical-only client must be refused"),
        Err(e) => e.to_string(),
    };
    assert!(
        err.contains("NoKxGroupsInCommon"),
        "expected no key exchange group in common, got: {err}"
    );
}
