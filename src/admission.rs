//! Zero-knowledge lobby admission: one seat per credential per match, without
//! revealing which credential. This is Semaphore's construction, in Groth16 over
//! BN254 with Poseidon, as the classical baseline for oneSeat
//! (<https://micronant.com/oneseat/>).
//!
//! A player holds a secret `s`. The issuer adds the commitment `Poseidon(1, s)` to a
//! Merkle tree and ships the tree's root with the game. To take a seat in a match,
//! the player publishes
//!
//! ```text
//! nullifier = Poseidon(2, scope, s)      scope = the match, from app id and session id
//! ```
//!
//! with a proof that `s` is behind some leaf of the tree and that the nullifier was
//! computed from it. The proof also takes a binding as a public input: the TLS
//! exporter value of the connection it was made for, so it is no good on any other
//! connection. One credential always gives the same nullifier in a match, so a second
//! seat shows up as a repeat; nullifiers from different matches cannot be linked.
//!
//! The host proves a seat too, bound to its certificate, and sends every admitted
//! client the roster of all seats. A client checks every proof in it and that no
//! nullifier repeats, so a host cannot invent seats. It can still refuse players or
//! withhold the roster: being the hub of a star gives it that much.
//!
//! The Groth16 keys come from a setup specific to this circuit, and
//! [`AdmissionKeys::setup`] runs one locally. That suits tests and a prototype, but
//! whoever runs the setup can forge proofs, so a real deployment needs a ceremony.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_crypto_primitives::sponge::poseidon::{
    find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge,
};
use ark_crypto_primitives::sponge::CryptographicSponge;
use ark_ff::{PrimeField, UniformRand, Zero};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use quinn::Connection;
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{QuinnPeer, SessionId};

/// Depth of the membership tree: room for 1,024 credentials.
pub const TREE_DEPTH: usize = 10;

/// How long the host waits for a connected client to send its proof.
pub const ADMISSION_TIMEOUT: Duration = Duration::from_secs(30);

const LEAF_TAG: u64 = 1;
const NULLIFIER_TAG: u64 = 2;
const NODE_TAG: u64 = 3;
const BYTES_TAG: u64 = 4;
const EXPORTER_LABEL: &[u8] = b"EXPORTER-localnet-admission";
const MAX_REQUEST_BYTES: usize = 1024;
const MAX_ROSTER_BYTES: usize = 64 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AdmissionError {
    #[error("malformed admission message: {0}")]
    Malformed(&'static str),
    #[error("the proof does not verify")]
    InvalidProof,
    #[error("that credential already holds a seat in this match")]
    DuplicateNullifier,
    #[error("the match is full")]
    Full,
    #[error("the roster's first seat is not bound to the host's certificate")]
    HostBinding,
    #[error("the roster does not include this player's seat")]
    MissingOwnSeat,
}

// Poseidon over BN254's scalar field: width 3 (rate 2, capacity 1), x^5, 8 full and
// 57 partial rounds, constants from the reference Grain LFSR.
fn poseidon_config() -> &'static PoseidonConfig<Fr> {
    static CONFIG: OnceLock<PoseidonConfig<Fr>> = OnceLock::new();
    CONFIG.get_or_init(|| {
        let (ark, mds) =
            find_poseidon_ark_and_mds::<Fr>(Fr::MODULUS_BIT_SIZE as u64, 2, 8, 57, 0);
        PoseidonConfig::new(8, 57, 5, mds, ark, 2, 1)
    })
}

fn poseidon(inputs: &[Fr]) -> Fr {
    let mut sponge = PoseidonSponge::new(poseidon_config());
    sponge.absorb(&inputs.to_vec());
    sponge.squeeze_field_elements::<Fr>(1)[0]
}

fn poseidon_var(
    cs: ConstraintSystemRef<Fr>,
    inputs: &[FpVar<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    let mut sponge = PoseidonSpongeVar::new(cs, poseidon_config());
    sponge.absorb(&inputs.to_vec())?;
    Ok(sponge.squeeze_field_elements(1)?.remove(0))
}

/// Hashes arbitrary bytes to a field element, length first and then in 31-byte
/// chunks, each below the modulus, so distinct inputs give distinct preimages.
fn hash_bytes(bytes: &[u8]) -> Fr {
    let mut inputs = vec![Fr::from(BYTES_TAG), Fr::from(bytes.len() as u64)];
    inputs.extend(bytes.chunks(31).map(Fr::from_le_bytes_mod_order));
    poseidon(&inputs)
}

fn fe_to_bytes(fe: &Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    fe.serialize_compressed(&mut out[..])
        .expect("a BN254 scalar serializes to 32 bytes");
    out
}

/// Only the canonical encoding is accepted. Otherwise `x` and `x + p` would be two
/// different byte strings for one nullifier, and a repeat would not look like one.
fn fe_from_bytes(bytes: &[u8; 32]) -> Option<Fr> {
    Fr::deserialize_compressed(&bytes[..])
        .ok()
        .filter(|fe| fe_to_bytes(fe) == *bytes)
}

/// A player's secret. Whoever holds it can take this player's seat.
#[derive(Clone)]
pub struct Identity {
    secret: Fr,
}

impl Identity {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self {
            secret: Fr::rand(rng),
        }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        fe_to_bytes(&self.secret)
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        fe_from_bytes(bytes).map(|secret| Self { secret })
    }

    /// What the issuer adds to the group. Reveals nothing about the secret.
    pub fn commitment(&self) -> Commitment {
        Commitment(poseidon(&[Fr::from(LEAF_TAG), self.secret]))
    }

    pub fn nullifier(&self, scope: &Scope) -> Nullifier {
        Nullifier(fe_to_bytes(&poseidon(&[
            Fr::from(NULLIFIER_TAG),
            scope.0,
            self.secret,
        ])))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Commitment(Fr);

/// The match a seat is for. Every player derives it from what the host advertised,
/// before anyone joins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scope(Fr);

impl Scope {
    pub fn for_match(app_id: &str, session_id: &SessionId) -> Self {
        let mut bytes = (app_id.len() as u32).to_le_bytes().to_vec();
        bytes.extend_from_slice(app_id.as_bytes());
        bytes.extend_from_slice(session_id.0.as_bytes());
        Self(hash_bytes(&bytes))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        fe_to_bytes(&self.0)
    }
}

/// Root of the membership tree, shipped with the game.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Root(Fr);

impl Root {
    pub fn to_bytes(&self) -> [u8; 32] {
        fe_to_bytes(&self.0)
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        fe_from_bytes(bytes).map(Self)
    }
}

/// The public tag of one seat. Equal nullifiers in one match mean one credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Nullifier(pub [u8; 32]);

/// What ties a proof to the one channel it was made for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Binding(Fr);

impl Binding {
    /// The connection's TLS exporter value for this scope. Both ends of a QUIC
    /// connection compute the same value without sending it; no other connection
    /// shares it.
    pub fn for_connection(connection: &Connection, scope: &Scope) -> Result<Self> {
        let mut out = [0u8; 32];
        connection
            .export_keying_material(&mut out, EXPORTER_LABEL, &scope.to_bytes())
            .map_err(|e| anyhow!("TLS exporter unavailable: {e:?}"))?;
        Ok(Self(Fr::from_le_bytes_mod_order(&out)))
    }

    /// The host's seat is bound to the certificate every client pinned.
    pub fn for_host_certificate(cert_der: &[u8]) -> Self {
        Self(hash_bytes(cert_der))
    }
}

/// The credentials allowed in, as a Merkle tree of their commitments.
pub struct Group {
    levels: Vec<Vec<Fr>>,
}

impl Group {
    pub fn new(commitments: &[Commitment]) -> Result<Self> {
        let width = 1usize << TREE_DEPTH;
        if commitments.len() > width {
            return Err(anyhow!("a group holds at most {width} credentials"));
        }
        // Empty slots are zero, which no known secret commits to.
        let mut leaves: Vec<Fr> = commitments.iter().map(|c| c.0).collect();
        leaves.resize(width, Fr::zero());

        let mut levels = vec![leaves];
        while levels.last().unwrap().len() > 1 {
            let next = levels
                .last()
                .unwrap()
                .chunks(2)
                .map(|pair| poseidon(&[Fr::from(NODE_TAG), pair[0], pair[1]]))
                .collect();
            levels.push(next);
        }
        Ok(Self { levels })
    }

    pub fn root(&self) -> Root {
        Root(self.levels[TREE_DEPTH][0])
    }

    /// The witness a member keeps: its identity and the path from its leaf to the
    /// root. `None` if the identity is not in the group.
    pub fn credential(&self, identity: &Identity) -> Option<Credential> {
        let leaf = identity.commitment().0;
        let index = self.levels[0].iter().position(|l| *l == leaf)?;
        let siblings = (0..TREE_DEPTH)
            .map(|level| self.levels[level][(index >> level) ^ 1])
            .collect();
        Some(Credential {
            identity: identity.clone(),
            index: index as u32,
            siblings,
        })
    }
}

#[derive(Clone)]
pub struct Credential {
    identity: Identity,
    index: u32,
    siblings: Vec<Fr>,
}

impl Credential {
    pub fn nullifier(&self, scope: &Scope) -> Nullifier {
        self.identity.nullifier(scope)
    }

    /// The root this credential's path leads to.
    pub fn root(&self) -> Root {
        let mut node = self.identity.commitment().0;
        for (level, sibling) in self.siblings.iter().enumerate() {
            let (left, right) = if (self.index >> level) & 1 == 1 {
                (*sibling, node)
            } else {
                (node, *sibling)
            };
            node = poseidon(&[Fr::from(NODE_TAG), left, right]);
        }
        Root(node)
    }
}

/// The statement: the secret is behind a leaf of the tree with this root, and the
/// nullifier is the one it gives in this scope. Public inputs, in order: root, scope,
/// nullifier, binding.
#[derive(Clone)]
struct AdmissionCircuit {
    root: Fr,
    scope: Fr,
    nullifier: Fr,
    binding: Fr,
    secret: Fr,
    index: u32,
    siblings: Vec<Fr>,
}

impl AdmissionCircuit {
    /// Any values of the right shape, for the setup and for counting constraints.
    fn blank() -> Self {
        Self {
            root: Fr::zero(),
            scope: Fr::zero(),
            nullifier: Fr::zero(),
            binding: Fr::zero(),
            secret: Fr::zero(),
            index: 0,
            siblings: vec![Fr::zero(); TREE_DEPTH],
        }
    }
}

impl ConstraintSynthesizer<Fr> for AdmissionCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let root = FpVar::new_input(cs.clone(), || Ok(self.root))?;
        let scope = FpVar::new_input(cs.clone(), || Ok(self.scope))?;
        let nullifier = FpVar::new_input(cs.clone(), || Ok(self.nullifier))?;
        let binding = FpVar::new_input(cs.clone(), || Ok(self.binding))?;
        let secret = FpVar::new_witness(cs.clone(), || Ok(self.secret))?;

        let tag = |t: u64| FpVar::constant(Fr::from(t));
        let mut node = poseidon_var(cs.clone(), &[tag(LEAF_TAG), secret.clone()])?;
        for (level, sibling) in self.siblings.iter().enumerate() {
            let sibling = FpVar::new_witness(cs.clone(), || Ok(*sibling))?;
            let is_right = Boolean::new_witness(cs.clone(), || Ok((self.index >> level) & 1 == 1))?;
            let left = is_right.select(&sibling, &node)?;
            let right = is_right.select(&node, &sibling)?;
            node = poseidon_var(cs.clone(), &[tag(NODE_TAG), left, right])?;
        }
        node.enforce_equal(&root)?;

        poseidon_var(cs.clone(), &[tag(NULLIFIER_TAG), scope, secret])?.enforce_equal(&nullifier)?;

        // Semaphore constrains its signal the same way, so the binding is part of what
        // the proof attests to whatever the setup does with untouched inputs.
        let _ = binding.square()?;
        Ok(())
    }
}

/// Number of R1CS constraints in the admission circuit.
pub fn constraint_count() -> usize {
    let cs = ConstraintSystem::<Fr>::new_ref();
    AdmissionCircuit::blank()
        .generate_constraints(cs.clone())
        .expect("the blank circuit synthesizes");
    cs.num_constraints()
}

/// The Groth16 keys for the admission circuit.
#[derive(Clone)]
pub struct AdmissionKeys {
    proving: Arc<ProvingKey<Bn254>>,
    verifying: VerifyingKey<Bn254>,
}

impl AdmissionKeys {
    /// Runs the circuit-specific setup. Whoever runs it can forge proofs; see the
    /// module documentation.
    pub fn setup<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self> {
        let (proving, verifying) =
            Groth16::<Bn254>::circuit_specific_setup(AdmissionCircuit::blank(), rng)
                .map_err(|e| anyhow!("Groth16 setup failed: {e}"))?;
        Ok(Self {
            proving: Arc::new(proving),
            verifying,
        })
    }

    pub fn verifier(&self) -> Verifier {
        Verifier {
            pvk: Groth16::<Bn254>::process_vk(&self.verifying)
                .expect("a verifying key from setup prepares"),
        }
    }

    pub fn verifying_key_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.verifying
            .serialize_compressed(&mut out)
            .expect("a verifying key serializes");
        out
    }

    /// Proves a seat. Takes on the order of the circuit's size in multi-scalar
    /// multiplications, so call it off any thread that has to stay responsive.
    pub fn prove(
        &self,
        credential: &Credential,
        root: &Root,
        scope: &Scope,
        binding: &Binding,
    ) -> Result<Admission> {
        if credential.root() != *root {
            return Err(anyhow!("the credential is not in the group with this root"));
        }
        let nullifier = credential.nullifier(scope);
        let circuit = AdmissionCircuit {
            root: root.0,
            scope: scope.0,
            nullifier: fe_from_bytes(&nullifier.0).expect("nullifiers are canonical"),
            binding: binding.0,
            secret: credential.identity.secret,
            index: credential.index,
            siblings: credential.siblings.clone(),
        };
        let proof = Groth16::<Bn254>::prove(&self.proving, circuit, &mut OsRng)
            .map_err(|e| anyhow!("Groth16 proving failed: {e}"))?;
        let mut bytes = Vec::new();
        proof
            .serialize_compressed(&mut bytes)
            .expect("a proof serializes");
        Ok(Admission {
            nullifier,
            proof: bytes,
        })
    }
}

/// Checks admission proofs. Holds the prepared verifying key, nothing secret.
#[derive(Clone)]
pub struct Verifier {
    pvk: PreparedVerifyingKey<Bn254>,
}

impl Verifier {
    pub fn verify(
        &self,
        root: &Root,
        scope: &Scope,
        binding: &Binding,
        admission: &Admission,
    ) -> Result<(), AdmissionError> {
        let nullifier =
            fe_from_bytes(&admission.nullifier.0).ok_or(AdmissionError::Malformed("nullifier"))?;
        let proof = Proof::<Bn254>::deserialize_compressed(&admission.proof[..])
            .map_err(|_| AdmissionError::Malformed("proof"))?;
        let inputs = [root.0, scope.0, nullifier, binding.0];
        match Groth16::<Bn254>::verify_with_processed_vk(&self.pvk, &inputs, &proof) {
            Ok(true) => Ok(()),
            _ => Err(AdmissionError::InvalidProof),
        }
    }

    /// Checks a roster from the host: the first seat is bound to the certificate this
    /// client pinned, every proof verifies, no nullifier repeats, and this client's
    /// own seat is there.
    pub fn verify_roster(
        &self,
        root: &Root,
        scope: &Scope,
        host_cert_der: &[u8],
        own: &Nullifier,
        roster: &Roster,
    ) -> Result<(), AdmissionError> {
        let host = roster.seats.first().ok_or(AdmissionError::Malformed("empty roster"))?;
        if host.binding != fe_to_bytes(&Binding::for_host_certificate(host_cert_der).0) {
            return Err(AdmissionError::HostBinding);
        }
        let mut seen = std::collections::HashSet::new();
        for seat in &roster.seats {
            let binding = fe_from_bytes(&seat.binding)
                .map(Binding)
                .ok_or(AdmissionError::Malformed("binding"))?;
            self.verify(root, scope, &binding, &seat.admission)?;
            if !seen.insert(seat.admission.nullifier) {
                return Err(AdmissionError::DuplicateNullifier);
            }
        }
        if !seen.contains(own) {
            return Err(AdmissionError::MissingOwnSeat);
        }
        Ok(())
    }
}

/// A seat claim: the nullifier and a compressed Groth16 proof, 128 bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Admission {
    pub nullifier: Nullifier,
    pub proof: Vec<u8>,
}

/// One seat as clients see it. A client can check the proof against the binding, but
/// only the host and that seat's player can check the binding itself is genuine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seat {
    pub admission: Admission,
    pub binding: [u8; 32],
}

/// Every seat in the match; the host's comes first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roster {
    pub seats: Vec<Seat>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum Reply {
    Admitted { seat: usize },
    Refused { reason: String },
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    bincode::serde::encode_to_vec(value, bincode::config::standard())
        .context("failed to encode admission message")
}

fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    let (value, _) = bincode::serde::decode_from_slice(bytes, bincode::config::standard())
        .context("failed to decode admission message")?;
    Ok(value)
}

/// The host's side: it holds the seats and decides who joins.
pub struct HostGate {
    verifier: Verifier,
    root: Root,
    scope: Scope,
    capacity: usize,
    roster: Roster,
}

impl HostGate {
    /// Proves the host's own seat, bound to its certificate, and opens the lobby.
    pub fn new(
        keys: &AdmissionKeys,
        credential: &Credential,
        root: Root,
        scope: Scope,
        host_cert_der: &[u8],
        capacity: usize,
    ) -> Result<Self> {
        let binding = Binding::for_host_certificate(host_cert_der);
        let admission = keys.prove(credential, &root, &scope, &binding)?;
        Ok(Self {
            verifier: keys.verifier(),
            root,
            scope,
            capacity,
            roster: Roster {
                seats: vec![Seat {
                    admission,
                    binding: fe_to_bytes(&binding.0),
                }],
            },
        })
    }

    pub fn roster(&self) -> &Roster {
        &self.roster
    }

    /// Checks a claim made on `binding`'s channel and seats it if it holds.
    pub fn check(&mut self, binding: &Binding, admission: Admission) -> Result<usize, AdmissionError> {
        self.verifier.verify(&self.root, &self.scope, binding, &admission)?;
        if self
            .roster
            .seats
            .iter()
            .any(|s| s.admission.nullifier == admission.nullifier)
        {
            return Err(AdmissionError::DuplicateNullifier);
        }
        if self.roster.seats.len() >= self.capacity {
            return Err(AdmissionError::Full);
        }
        self.roster.seats.push(Seat {
            admission,
            binding: fe_to_bytes(&binding.0),
        });
        Ok(self.roster.seats.len() - 1)
    }

    /// Frees a seat when its player leaves, so the same credential can rejoin.
    pub fn release(&mut self, nullifier: &Nullifier) {
        let (host, players) = self.roster.seats.split_at_mut(1);
        if host[0].admission.nullifier == *nullifier {
            return;
        }
        let kept: Vec<Seat> = players
            .iter()
            .filter(|s| s.admission.nullifier != *nullifier)
            .cloned()
            .collect();
        self.roster.seats.truncate(1);
        self.roster.seats.extend(kept);
    }

    /// Reads a newly connected peer's claim, checks it against that connection, and
    /// replies. Returns the seat's nullifier, or why it was refused.
    pub async fn admit(&mut self, peer: &QuinnPeer) -> Result<Nullifier> {
        let (mut send, mut recv) = tokio::time::timeout(ADMISSION_TIMEOUT, peer.connection.accept_bi())
            .await
            .context("peer sent no admission proof in time")?
            .context("peer closed before sending an admission proof")?;
        let request = recv
            .read_to_end(MAX_REQUEST_BYTES)
            .await
            .context("failed to read admission proof")?;

        let outcome = match decode::<Admission>(&request) {
            Ok(admission) => {
                let nullifier = admission.nullifier;
                let binding = Binding::for_connection(&peer.connection, &self.scope)?;
                self.check(&binding, admission)
                    .map(|seat| (seat, nullifier))
                    .map_err(|e| e.to_string())
            }
            Err(_) => Err(AdmissionError::Malformed("request").to_string()),
        };

        let reply = match &outcome {
            Ok((seat, _)) => Reply::Admitted { seat: *seat },
            Err(reason) => Reply::Refused {
                reason: reason.clone(),
            },
        };
        send.write_all(&encode(&reply)?).await?;
        send.finish()?;
        // Let the reply reach the peer before the caller can close the connection.
        let _ = tokio::time::timeout(Duration::from_secs(2), send.stopped()).await;

        outcome
            .map(|(_, nullifier)| nullifier)
            .map_err(|reason| anyhow!("admission refused: {reason}"))
    }
}

/// Sends the roster to one peer on a stream of its own.
pub async fn send_roster(peer: &QuinnPeer, roster: &Roster) -> Result<()> {
    let mut send = peer.open_uni().await?;
    send.write_all(&encode(roster)?).await?;
    send.finish()?;
    Ok(())
}

/// The client's side, on a connection to the host: proves a seat bound to this
/// connection, sends it, and returns the seat number and nullifier if admitted.
pub async fn request_admission(
    peer: &QuinnPeer,
    keys: &AdmissionKeys,
    credential: &Credential,
    root: Root,
    scope: Scope,
) -> Result<(usize, Nullifier)> {
    let binding = Binding::for_connection(&peer.connection, &scope)?;
    let (keys, credential) = (keys.clone(), credential.clone());
    let admission =
        tokio::task::spawn_blocking(move || keys.prove(&credential, &root, &scope, &binding))
            .await
            .context("proving task failed")??;
    let nullifier = admission.nullifier;
    let seat = submit_admission(peer, &admission).await?;
    Ok((seat, nullifier))
}

/// Sends an already-made claim and waits for the host's answer. Exposed so tests can
/// replay a claim on a connection it was not made for.
pub async fn submit_admission(peer: &QuinnPeer, admission: &Admission) -> Result<usize> {
    let (mut send, mut recv) = peer.open_bi().await?;
    send.write_all(&encode(admission)?).await?;
    send.finish()?;
    let reply = recv
        .read_to_end(MAX_REQUEST_BYTES)
        .await
        .context("host closed before answering the admission proof")?;
    match decode::<Reply>(&reply)? {
        Reply::Admitted { seat } => Ok(seat),
        Reply::Refused { reason } => Err(anyhow!("admission refused: {reason}")),
    }
}

/// Reads the next roster the host sends.
pub async fn receive_roster(peer: &QuinnPeer) -> Result<Roster> {
    let mut recv = peer
        .connection
        .accept_uni()
        .await
        .context("host closed before sending a roster")?;
    let bytes = recv
        .read_to_end(MAX_ROSTER_BYTES)
        .await
        .context("failed to read roster")?;
    decode(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::BigInteger;

    fn satisfied(circuit: AdmissionCircuit) -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        cs.is_satisfied().unwrap()
    }

    fn honest() -> (AdmissionCircuit, Credential, Scope) {
        let mut rng = OsRng;
        let ids: Vec<_> = (0..5).map(|_| Identity::generate(&mut rng)).collect();
        let group = Group::new(&ids.iter().map(Identity::commitment).collect::<Vec<_>>()).unwrap();
        let credential = group.credential(&ids[3]).unwrap();
        let scope = Scope::for_match("test", &SessionId::new());
        let circuit = AdmissionCircuit {
            root: group.root().0,
            scope: scope.0,
            nullifier: fe_from_bytes(&credential.nullifier(&scope).0).unwrap(),
            binding: Fr::from(7u64),
            secret: credential.identity.secret,
            index: credential.index,
            siblings: credential.siblings.clone(),
        };
        (circuit, credential, scope)
    }

    #[test]
    fn honest_witness_satisfies_the_circuit() {
        assert!(satisfied(honest().0));
    }

    #[test]
    fn wrong_nullifier_or_root_does_not() {
        let (circuit, _, _) = honest();
        assert!(!satisfied(AdmissionCircuit {
            nullifier: circuit.nullifier + Fr::from(1u64),
            ..circuit.clone()
        }));
        assert!(!satisfied(AdmissionCircuit {
            root: circuit.root + Fr::from(1u64),
            ..circuit
        }));
    }

    #[test]
    fn a_credential_leads_to_its_group_root() {
        let mut rng = OsRng;
        let ids: Vec<_> = (0..3).map(|_| Identity::generate(&mut rng)).collect();
        let group = Group::new(&ids.iter().map(Identity::commitment).collect::<Vec<_>>()).unwrap();
        for id in &ids {
            assert_eq!(group.credential(id).unwrap().root(), group.root());
        }
        assert!(group.credential(&Identity::generate(&mut rng)).is_none());
    }

    #[test]
    fn nullifiers_repeat_within_a_match_and_differ_across_matches() {
        let (_, credential, scope) = honest();
        let other = Scope::for_match("test", &SessionId::new());
        assert_eq!(credential.nullifier(&scope), credential.nullifier(&scope));
        assert_ne!(credential.nullifier(&scope), credential.nullifier(&other));
    }

    #[test]
    fn non_canonical_encodings_are_refused() {
        // The modulus itself encodes zero non-canonically.
        let mut bytes = [0u8; 32];
        let modulus = Fr::MODULUS.to_bytes_le();
        bytes.copy_from_slice(&modulus);
        assert!(fe_from_bytes(&bytes).is_none());
    }
}
