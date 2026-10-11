//! Measures lobby admission: circuit size, setup, proving and verification time,
//! and what goes over the wire. Run with
//! `cargo run --release --features admission --example admission_bench`.

use std::time::{Duration, Instant};

use localnet::admission::{
    constraint_count, AdmissionKeys, Binding, Group, Identity, Scope, TREE_DEPTH,
};
use localnet::SessionId;
use rand::rngs::OsRng;

const RUNS: u32 = 20;

fn ms(d: Duration) -> String {
    format!("{:.1} ms", d.as_secs_f64() * 1e3)
}

fn main() -> anyhow::Result<()> {
    let identities: Vec<_> = (0..4).map(|_| Identity::generate(&mut OsRng)).collect();
    let started = Instant::now();
    let group = Group::new(&identities.iter().map(Identity::commitment).collect::<Vec<_>>())?;
    let tree_time = started.elapsed();

    let started = Instant::now();
    let keys = AdmissionKeys::setup(&mut OsRng)?;
    let setup_time = started.elapsed();
    let verifier = keys.verifier();

    let root = group.root();
    let scope = Scope::for_match("bench", &SessionId::new());
    let credential = group.credential(&identities[1]).unwrap();
    let binding = Binding::for_host_certificate(b"bench");

    let started = Instant::now();
    let mut admission = None;
    for _ in 0..RUNS {
        admission = Some(keys.prove(&credential, &root, &scope, &binding)?);
    }
    let prove_time = started.elapsed() / RUNS;
    let admission = admission.unwrap();

    let started = Instant::now();
    for _ in 0..RUNS {
        verifier.verify(&root, &scope, &binding, &admission)?;
    }
    let verify_time = started.elapsed() / RUNS;

    println!("tree depth           {TREE_DEPTH} (up to {} credentials)", 1 << TREE_DEPTH);
    println!("constraints          {}", constraint_count());
    println!("build tree           {}", ms(tree_time));
    println!("setup                {}", ms(setup_time));
    println!("prove                {} (mean of {RUNS})", ms(prove_time));
    println!("verify               {} (mean of {RUNS})", ms(verify_time));
    println!("proof                {} bytes", admission.proof.len());
    println!("claim on the wire    {} bytes (nullifier + proof)", 32 + admission.proof.len());
    println!("verifying key        {} bytes", keys.verifying_key_bytes().len());
    println!("4-seat lobby, client {} to verify the roster", ms(verify_time * 4));
    Ok(())
}
