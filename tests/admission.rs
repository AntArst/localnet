//! Lobby admission end to end over loopback QUIC: honest players get distinct seats,
//! and a second seat for one credential, a proof replayed on another connection, an
//! outsider and a tampered roster are all refused.

use std::net::SocketAddr;
use std::sync::OnceLock;

use localnet::admission::{
    request_admission, receive_roster, send_roster, submit_admission, AdmissionError,
    AdmissionKeys, Binding, Credential, Group, HostGate, Identity, Nullifier, Root, Scope,
};
use localnet::{QuinnPeer, QuinnTransport, SessionId};
use rand::rngs::OsRng;

const APP_ID: &str = "localnet-test";

/// One setup for the whole file: it is the slow part.
fn keys() -> &'static AdmissionKeys {
    static KEYS: OnceLock<AdmissionKeys> = OnceLock::new();
    KEYS.get_or_init(|| AdmissionKeys::setup(&mut OsRng).unwrap())
}

struct Members {
    identities: Vec<Identity>,
    group: Group,
}

impl Members {
    fn new(n: usize) -> Self {
        let identities: Vec<_> = (0..n).map(|_| Identity::generate(&mut OsRng)).collect();
        let group = Group::new(&identities.iter().map(Identity::commitment).collect::<Vec<_>>()).unwrap();
        Self { identities, group }
    }

    fn credential(&self, i: usize) -> Credential {
        self.group.credential(&self.identities[i]).unwrap()
    }

    fn root(&self) -> Root {
        self.group.root()
    }
}

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn scope() -> Scope {
    Scope::for_match(APP_ID, &SessionId::new())
}

/// A new client connection to the host: the host's end, the client's end, and the
/// client's endpoint, kept alive for as long as the connection is used.
async fn connect(host: &QuinnTransport) -> (QuinnPeer, QuinnPeer, QuinnTransport) {
    let client = QuinnTransport::bind(loopback(), APP_ID).unwrap();
    let (accepted, connected) = tokio::join!(
        host.accept_peer(),
        client.connect_peer(host.local_addr().unwrap(), host.certificate_der(), APP_ID),
    );
    (accepted.unwrap(), connected.unwrap(), client)
}

fn gate(host: &QuinnTransport, members: &Members, host_index: usize, scope: Scope) -> HostGate {
    HostGate::new(
        keys(),
        &members.credential(host_index),
        members.root(),
        scope,
        host.certificate_der().as_ref(),
        4,
    )
    .unwrap()
}

#[tokio::test]
async fn honest_players_take_distinct_seats_and_verify_the_roster() {
    let members = Members::new(6);
    let scope = scope();
    let host = QuinnTransport::bind(loopback(), APP_ID).unwrap();
    let mut gate = gate(&host, &members, 0, scope);

    let mut clients = Vec::new();
    for i in 1..=3 {
        let (host_end, client_end, _client) = connect(&host).await;
        let credential = members.credential(i);
        let (admitted, requested) = tokio::join!(
            gate.admit(&host_end),
            request_admission(&client_end, keys(), &credential, members.root(), scope),
        );
        let nullifier = admitted.unwrap();
        let (seat, own) = requested.unwrap();
        assert_eq!(seat, i);
        assert_eq!(own, nullifier);
        clients.push((host_end, client_end, own, _client));
    }

    let verifier = keys().verifier();
    for (host_end, client_end, own, _) in &clients {
        send_roster(host_end, gate.roster()).await.unwrap();
        let roster = receive_roster(client_end).await.unwrap();
        assert_eq!(roster.seats.len(), 4);
        verifier
            .verify_roster(&members.root(), &scope, host.certificate_der().as_ref(), own, &roster)
            .unwrap();
    }
}

#[tokio::test]
async fn a_second_seat_for_the_same_credential_is_refused() {
    let members = Members::new(3);
    let scope = scope();
    let host = QuinnTransport::bind(loopback(), APP_ID).unwrap();
    let mut gate = gate(&host, &members, 0, scope);

    let (host_end, client_end, _client) = connect(&host).await;
    let credential = members.credential(1);
    let (admitted, _) = tokio::join!(
        gate.admit(&host_end),
        request_admission(&client_end, keys(), &credential, members.root(), scope),
    );
    admitted.unwrap();

    // Same credential, fresh connection, fresh proof: a valid proof, a repeated nullifier.
    let (host_end, client_end, _client) = connect(&host).await;
    let credential = members.credential(1);
    let (admitted, requested) = tokio::join!(
        gate.admit(&host_end),
        request_admission(&client_end, keys(), &credential, members.root(), scope),
    );
    let err = format!("{:#}", admitted.unwrap_err());
    assert!(err.contains(&AdmissionError::DuplicateNullifier.to_string()), "{err}");
    assert!(requested.is_err());
    assert_eq!(gate.roster().seats.len(), 2);
}

#[tokio::test]
async fn a_proof_replayed_on_another_connection_is_refused() {
    let members = Members::new(3);
    let scope = scope();
    let host = QuinnTransport::bind(loopback(), APP_ID).unwrap();
    let mut gate = gate(&host, &members, 0, scope);

    // A claim made for one connection, then sent over a different one before its
    // owner uses it, as an eavesdropper racing the owner for the seat would.
    let (_victim_host_end, victim_end, _victim) = connect(&host).await;
    let binding = Binding::for_connection(&victim_end.connection, &scope).unwrap();
    let stolen = keys()
        .prove(&members.credential(1), &members.root(), &scope, &binding)
        .unwrap();

    let (host_end, attacker_end, _attacker) = connect(&host).await;
    let (admitted, submitted) =
        tokio::join!(gate.admit(&host_end), submit_admission(&attacker_end, &stolen));
    let err = format!("{:#}", admitted.unwrap_err());
    assert!(err.contains(&AdmissionError::InvalidProof.to_string()), "{err}");
    assert!(submitted.is_err());
}

#[tokio::test]
async fn an_identity_outside_the_group_is_refused() {
    let members = Members::new(3);
    let outsiders = Members::new(1);
    let scope = scope();
    let host = QuinnTransport::bind(loopback(), APP_ID).unwrap();
    let mut gate = gate(&host, &members, 0, scope);

    // A real credential for a different group: the outsider can only prove against
    // that group's root, and the host checks against its own.
    let (host_end, client_end, _client) = connect(&host).await;
    let credential = outsiders.credential(0);
    let (admitted, _) = tokio::join!(
        gate.admit(&host_end),
        request_admission(&client_end, keys(), &credential, outsiders.root(), scope),
    );
    let err = format!("{:#}", admitted.unwrap_err());
    assert!(err.contains(&AdmissionError::InvalidProof.to_string()), "{err}");
}

#[tokio::test]
async fn a_tampered_roster_is_caught_by_the_client() {
    let members = Members::new(3);
    let scope = scope();
    let host = QuinnTransport::bind(loopback(), APP_ID).unwrap();
    let mut gate = gate(&host, &members, 0, scope);

    let (host_end, client_end, _client) = connect(&host).await;
    let credential = members.credential(1);
    let (_, requested) = tokio::join!(
        gate.admit(&host_end),
        request_admission(&client_end, keys(), &credential, members.root(), scope),
    );
    let (_, own) = requested.unwrap();
    let verifier = keys().verifier();
    let cert = host.certificate_der();
    let check = |roster| verifier.verify_roster(&members.root(), &scope, cert.as_ref(), &own, roster);

    assert_eq!(check(gate.roster()), Ok(()));

    // An invented seat: a nullifier with no proof behind it.
    let mut invented = gate.roster().clone();
    let mut fake = invented.seats[1].clone();
    fake.admission.nullifier = Nullifier([7; 32]);
    invented.seats.push(fake);
    assert!(check(&invented).is_err());

    // The same seat listed twice.
    let mut doubled = gate.roster().clone();
    doubled.seats.push(doubled.seats[1].clone());
    assert_eq!(check(&doubled), Err(AdmissionError::DuplicateNullifier));

    // This client's seat left out.
    let mut dropped = gate.roster().clone();
    dropped.seats.truncate(1);
    assert_eq!(check(&dropped), Err(AdmissionError::MissingOwnSeat));

    // A host seat bound to some other certificate.
    let impostor = QuinnTransport::bind(loopback(), APP_ID).unwrap();
    assert_eq!(
        verifier.verify_roster(&members.root(), &scope, impostor.certificate_der().as_ref(), &own, gate.roster()),
        Err(AdmissionError::HostBinding)
    );
}
