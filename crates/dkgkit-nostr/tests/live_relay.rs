#![cfg(feature = "live")]

//! Integration tests for `LiveNostrTransport`. These require a running relay,
//! so they are `#[ignore]`d by default. To run them:
//!
//! ```text
//! docker compose -f examples/self-hosted-relay/docker-compose.yml up -d
//! export DKGKIT_TEST_RELAY=ws://127.0.0.1:7777
//! cargo test -p dkgkit-nostr --features live -- --ignored
//! ```

use dkgkit_core::{ParticipantId, ProtocolMessage, ProtocolMessageKind, Result, SessionId};
use dkgkit_nostr::{LiveNostrTransport, LiveNostrTransportConfig, ParticipantDirectory};
use dkgkit_transport::Transport;
use nostr_sdk::prelude::*;
use std::time::{Duration, Instant};

fn relay_url() -> Option<String> {
    std::env::var("DKGKIT_TEST_RELAY").ok()
}

/// Unique per-run suffix so the relay's persisted history from prior tests/runs
/// does not leak into a fresh subscription.
fn unique(prefix: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{prefix}-{nanos}")
}

fn collect_until(
    transport: &mut LiveNostrTransport,
    session: &SessionId,
    want: usize,
    timeout: Duration,
) -> Vec<ProtocolMessage> {
    let mut acc = Vec::new();
    let deadline = Instant::now() + timeout;
    while acc.len() < want && Instant::now() < deadline {
        let mut all = |_: &ProtocolMessage| true;
        acc.extend(transport.drain_matching(session, &mut all).unwrap());
        if acc.len() < want {
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    acc
}

fn config(
    relays: Vec<String>,
    vault_tag: &str,
    self_id: u16,
    keys: Keys,
    directory: ParticipantDirectory,
) -> LiveNostrTransportConfig {
    LiveNostrTransportConfig {
        relays,
        vault_tag: vault_tag.to_string(),
        self_id: ParticipantId::new(self_id).unwrap(),
        keys,
        directory,
        connect_timeout: Duration::from_secs(10),
        publish_timeout: Duration::from_secs(10),
    }
}

#[test]
#[ignore = "requires DKGKIT_TEST_RELAY pointing at a running relay"]
fn public_message_round_trips_over_relay() -> Result<()> {
    let Some(url) = relay_url() else {
        return Ok(());
    };
    let alice = Keys::generate();
    let bob = Keys::generate();
    let mut directory = ParticipantDirectory::new();
    directory.insert(ParticipantId::new(1)?, alice.public_key());
    directory.insert(ParticipantId::new(2)?, bob.public_key());

    let vault = unique("it-pub");
    let mut tx1 = LiveNostrTransport::new(config(
        vec![url.clone()],
        &vault,
        1,
        alice,
        directory.clone(),
    ));
    let mut tx2 = LiveNostrTransport::new(config(vec![url], &vault, 2, bob, directory));
    tx1.connect()?;
    tx2.connect()?;
    std::thread::sleep(Duration::from_millis(300)); // subscription settle

    let session = SessionId::new(unique("it-pub-dkg"))?;
    tx1.publish(ProtocolMessage::new(
        session.clone(),
        ParticipantId::new(1)?,
        ProtocolMessageKind::FrostDkgRound1,
        vec![1, 2, 3],
    ))?;

    let received = collect_until(&mut tx2, &session, 1, Duration::from_secs(10));
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].kind, ProtocolMessageKind::FrostDkgRound1);
    assert_eq!(received[0].payload, vec![1, 2, 3]);
    Ok(())
}

#[test]
#[ignore = "requires DKGKIT_TEST_RELAY pointing at a running relay"]
fn round2_is_encrypted_and_only_recipient_reads_it() -> Result<()> {
    let Some(url) = relay_url() else {
        return Ok(());
    };
    let alice = Keys::generate();
    let bob = Keys::generate();
    let eve = Keys::generate();
    let mut directory = ParticipantDirectory::new();
    directory.insert(ParticipantId::new(1)?, alice.public_key());
    directory.insert(ParticipantId::new(2)?, bob.public_key());
    directory.insert(ParticipantId::new(3)?, eve.public_key());

    let vault = unique("it-enc");
    let mut tx1 = LiveNostrTransport::new(config(
        vec![url.clone()],
        &vault,
        1,
        alice,
        directory.clone(),
    ));
    let mut tx_bob =
        LiveNostrTransport::new(config(vec![url.clone()], &vault, 2, bob, directory.clone()));
    let mut tx_eve = LiveNostrTransport::new(config(vec![url], &vault, 3, eve, directory));
    tx1.connect()?;
    tx_bob.connect()?;
    tx_eve.connect()?;
    std::thread::sleep(Duration::from_millis(300));

    let session = SessionId::new(unique("it-enc-dkg"))?;
    tx1.publish(ProtocolMessage::direct(
        session.clone(),
        ParticipantId::new(1)?,
        ParticipantId::new(2)?,
        ProtocolMessageKind::HtssDkgRound2,
        vec![42, 42, 42],
    ))?;

    let bob_got = collect_until(&mut tx_bob, &session, 1, Duration::from_secs(10));
    assert_eq!(bob_got.len(), 1);
    assert_eq!(bob_got[0].payload, vec![42, 42, 42]);

    // Eve sees the relay event but cannot decode it (decrypt fails / dropped).
    let eve_got = collect_until(&mut tx_eve, &session, 1, Duration::from_secs(3));
    assert!(eve_got.is_empty());
    Ok(())
}
