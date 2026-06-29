//! Example service: run a complete FROST 2-of-3 DKG round-trip over a live,
//! self-hosted Nostr relay using `LiveNostrTransport`. This is the runnable
//! proof of sub-project A (the live transport).
//!
//! Start a relay first:
//!
//! ```text
//! docker compose -f examples/self-hosted-relay/docker-compose.yml up -d
//! export DKGKIT_TEST_RELAY=ws://127.0.0.1:7777   # optional; this is the default
//! cargo run -p nostr-transport-service
//! ```
//!
//! Each participant is an independent device: its own Nostr identity, its own
//! `LiveNostrTransport`, its own key share. Round 1 commitments broadcast in the
//! clear; Round 2 secret shares are NIP-44-encrypted to each recipient. All
//! traffic is scoped to one vault topic tag on the relay.

use dkgkit_core::{ParticipantId, SessionId};
use dkgkit_nostr::{LiveNostrTransport, LiveNostrTransportConfig, ParticipantDirectory};
use dkgkit_sdk::{create_frost_session, FrostCoordinator};
use nostr_sdk::Keys;
use std::time::{Duration, Instant};

const THRESHOLD: u16 = 2;
const PARTICIPANTS: u16 = 3;

fn relay_url() -> String {
    std::env::var("DKGKIT_TEST_RELAY").unwrap_or_else(|_| "ws://127.0.0.1:7777".to_string())
}

/// Unique per-run suffix so the relay's persisted history does not leak in.
fn unique_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

fn pid(value: u16) -> ParticipantId {
    ParticipantId::new(value).expect("participant id >= 1")
}

fn make_transport(
    vault: &str,
    self_id: u16,
    keys: Keys,
    directory: ParticipantDirectory,
) -> LiveNostrTransport {
    LiveNostrTransport::new(LiveNostrTransportConfig {
        relays: vec![relay_url()],
        vault_tag: vault.to_string(),
        self_id: pid(self_id),
        keys,
        directory,
        connect_timeout: Duration::from_secs(15),
        publish_timeout: Duration::from_secs(15),
    })
}

/// Poll a coordinator's `drain` closure until `want` items arrive or `timeout`
/// elapses (relay delivery is asynchronous).
fn collect<T>(
    coordinator: &mut FrostCoordinator<LiveNostrTransport>,
    want: usize,
    timeout: Duration,
    mut drain: impl FnMut(&mut FrostCoordinator<LiveNostrTransport>) -> anyhow::Result<Vec<T>>,
) -> anyhow::Result<Vec<T>> {
    let mut acc = Vec::new();
    let deadline = Instant::now() + timeout;
    while acc.len() < want && Instant::now() < deadline {
        acc.extend(drain(coordinator)?);
        if acc.len() < want {
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    Ok(acc)
}

fn main() -> anyhow::Result<()> {
    let vault = format!("nostr-transport-service-{}", unique_suffix());
    let session = SessionId::new(format!("{vault}-dkg"))?;
    let n = PARTICIPANTS as usize;

    // Per-device Nostr identities and the shared participant directory.
    let keys: Vec<Keys> = (0..PARTICIPANTS).map(|_| Keys::generate()).collect();
    let mut directory = ParticipantDirectory::new();
    for (idx, k) in keys.iter().enumerate() {
        directory.insert(pid(idx as u16 + 1), k.public_key());
    }

    // One transport (device) per participant, all on the same relay + vault.
    let mut coordinators: Vec<FrostCoordinator<LiveNostrTransport>> = keys
        .iter()
        .enumerate()
        .map(|(idx, k)| {
            FrostCoordinator::new(make_transport(
                &vault,
                idx as u16 + 1,
                k.clone(),
                directory.clone(),
            ))
        })
        .collect();
    for c in coordinators.iter_mut() {
        c.connect()?;
    }
    std::thread::sleep(Duration::from_millis(500)); // let subscriptions settle

    let sessions: Vec<_> = (1..=PARTICIPANTS)
        .map(|id| create_frost_session(session.0.clone(), THRESHOLD, PARTICIPANTS, id))
        .collect::<dkgkit_core::Result<_>>()?;

    // --- Round 1: each device broadcasts its public commitment. ---
    for (idx, dkg) in sessions.iter().enumerate() {
        let round1 = dkg.round1()?;
        coordinators[idx].publish_round1(session.clone(), &round1)?;
    }

    let mut round1_per_device = Vec::with_capacity(n);
    for c in coordinators.iter_mut() {
        let packages = collect(c, n, Duration::from_secs(20), |c| {
            Ok(c.drain_round1(&session)?)
        })?;
        anyhow::ensure!(
            packages.len() == n,
            "a device only collected {}/{n} round1 packages",
            packages.len()
        );
        round1_per_device.push(packages);
    }

    // --- Round 2: each device sends an (encrypted) secret share to every peer. ---
    for (idx, dkg) in sessions.iter().enumerate() {
        for package in dkg.round2(&round1_per_device[idx])? {
            coordinators[idx].publish_round2(session.clone(), &package)?;
        }
    }

    // --- Finalize: each device collects its shares and derives the group key. ---
    let mut shares = Vec::with_capacity(n);
    for (idx, dkg) in sessions.iter().enumerate() {
        let recipient = pid(idx as u16 + 1);
        let round2 = collect(&mut coordinators[idx], n, Duration::from_secs(20), |c| {
            Ok(c.drain_round2_for(&session, recipient)?)
        })?;
        anyhow::ensure!(
            round2.len() == n,
            "participant {} only collected {}/{n} round2 shares",
            recipient.0,
            round2.len()
        );
        shares.push(dkg.finalize(&round2)?);
    }

    let group_key = shares[0].group_key.clone();
    let all_match = shares.iter().all(|s| s.group_key == group_key);

    println!("nostr-transport-service: live FROST {THRESHOLD}-of-{PARTICIPANTS} DKG");
    println!("relay: {}", relay_url());
    println!("vault topic: dkgkit:{vault}");
    println!("participants completed DKG: {n}");
    println!(
        "group x-only public key: {}",
        hex::encode(group_key.xonly_public_key)
    );
    println!("all devices derived the same group key: {all_match}");
    anyhow::ensure!(all_match, "participants derived different group keys");

    for c in coordinators.iter_mut() {
        c.disconnect()?;
    }
    Ok(())
}
