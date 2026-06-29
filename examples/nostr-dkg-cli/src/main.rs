use dkgkit_nostr::LocalNostrEventTransport;
use dkgkit_sdk::{create_frost_session, FrostCoordinator, ParticipantId};

fn main() -> anyhow::Result<()> {
    let alice = create_frost_session("nostr-local-demo", 2, 3, 1)?;
    let bob = create_frost_session("nostr-local-demo", 2, 3, 2)?;
    let carol = create_frost_session("nostr-local-demo", 2, 3, 3)?;
    let dkg_sessions = [&alice, &bob, &carol];
    let session_id = alice.config.session_id.clone();

    let mut coordinator = FrostCoordinator::new(LocalNostrEventTransport::default());
    coordinator.connect()?;

    for session in dkg_sessions {
        let round1 = session.round1()?;
        coordinator.publish_round1(session_id.clone(), &round1)?;
    }
    let nostr_round1_events = coordinator.transport().pending_len();
    let round1_packages = coordinator.drain_round1(&session_id)?;

    for session in dkg_sessions {
        for round2 in session.round2(&round1_packages)? {
            coordinator.publish_round2(session_id.clone(), &round2)?;
        }
    }
    let nostr_round2_events = coordinator.transport().pending_len();

    let alice_round2 = coordinator.drain_round2_for(&session_id, ParticipantId::new(1)?)?;
    let bob_round2 = coordinator.drain_round2_for(&session_id, ParticipantId::new(2)?)?;
    let carol_round2 = coordinator.drain_round2_for(&session_id, ParticipantId::new(3)?)?;

    let alice_share = alice.finalize(&alice_round2)?;
    let bob_share = bob.finalize(&bob_round2)?;
    let carol_share = carol.finalize(&carol_round2)?;

    anyhow::ensure!(alice_share.group_key == bob_share.group_key);
    anyhow::ensure!(bob_share.group_key == carol_share.group_key);

    println!("NostrDKG local event transport demo");
    println!("threshold: 2-of-3");
    println!("round1 Nostr envelope events published: {nostr_round1_events}");
    println!("round2 Nostr envelope events published: {nostr_round2_events}");
    println!(
        "remaining local Nostr events: {}",
        coordinator.transport().pending_len()
    );
    println!(
        "group x-only public key: {}",
        hex::encode(alice_share.group_key.xonly_public_key)
    );
    println!("all parties derived matching group keys: true");
    println!("live relay I/O: pending migration");
    Ok(())
}
