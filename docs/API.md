# DKGKit API Shape

The top-level SDK facade lives in `dkgkit-sdk`.

## Session builder

```rust
use dkgkit_sdk::DkgKitSessionBuilder;

let manifest = DkgKitSessionBuilder::new()
    .session_id("demo")
    .threshold(2, 3)
    .participant(1, Some("alice".to_string()))?
    .participant(2, Some("bob".to_string()))?
    .participant(3, Some("carol".to_string()))?
    .build_manifest()?;
```

## Bitcoin authorization message

```rust
use dkgkit_bitcoin::BitcoinAuthorizationMessage;

let authorization = BitcoinAuthorizationMessage {
    network: "signet".to_string(),
    action: "approve-payment".to_string(),
    recipient: Some("tb1...".to_string()),
    amount_sats: Some(100_000),
    memo: Some("demo payout".to_string()),
    nonce: "session-001".to_string(),
};

let digest = authorization.digest();
```

Base TSS DKG, HTSS derivative-share DKG, and threshold message signing are implemented in `dkgkit-frost`; PSBT/transaction signing remains future work.

## FROST transport coordinator

`FrostCoordinator<T: Transport>` wraps any transport and lets applications publish or drain typed FROST packages without manually editing protocol envelopes.

```rust
use dkgkit_sdk::{FrostCoordinator, MemoryTransport, Round1Package, SessionId, ParticipantId};

let session_id = SessionId::new("demo")?;
let mut coordinator = FrostCoordinator::new(MemoryTransport::default());
coordinator.connect()?;

let round1 = Round1Package {
    participant_id: ParticipantId::new(1)?,
    bytes: vec![],
};

coordinator.publish_round1(session_id.clone(), &round1)?;
let received = coordinator.drain_round1(&session_id)?;
```

Available helpers:

- `publish_round1` / `drain_round1`
- `publish_round2` / `drain_round2_for`
- `publish_htss_dkg_round1` / `drain_htss_dkg_round1`
- `publish_htss_dkg_round2` / `drain_htss_dkg_round2_for`
- `publish_nonce` / `drain_nonces`
- `publish_signature_share` / `drain_signature_shares`
- `publish_htss_nonce` / `drain_htss_nonces`
- `publish_htss_signature_share` / `drain_htss_signature_shares`

The coordinator does not implement cryptography, storage, wallet policy, or Nostr behavior. It only composes typed FROST packages with a transport.

`FrostCoordinator` uses selective transport draining, so draining nonces does not consume signature shares from the same signing session.

## HTSS DKG service entrypoints

`HtssDkgService` is the service-facing facade for the HTSS DKG primitive:

```rust
let service = HtssDkgService::new("vault-dkg", htss_config)?;
let state = service.begin_round1(participant_id)?;
let round1_message = service.round1_message(&state.package)?;
let round2_packages = service.create_round2_packages(&state, &round1_packages)?;
let (group_key, local_share) =
    service.finalize_participant(participant_id, &round1_packages, &round2_for_me)?;
```

Round 1 packages are public commitments. Round 2 packages contain secret
derivative shares and must be encrypted by the application before use on public
transports.

See `docs/SERVICE_WIRING.md` for the full app-layer flow.

## Bitcoin account child addresses

The DKG group key can be treated as an account-level key. With a service-owned
chain code, `dkgkit-bitcoin` derives non-hardened child Taproot addresses below
that account key:

```rust
let account_key = BitcoinAccountKey::new(group_key, chain_code);
let path = BitcoinDerivationPath::bip86(0, 0, 0);
let descriptor =
    taproot_child_address_descriptor_for_network(&account_key, "signet", path)?;
```

The helper derives `/change/index`. Hardened purpose, coin, and account levels
cannot be derived from public threshold key material after DKG.

## Aggregate signature verification

`dkgkit-bitcoin` provides `verify_aggregate_signature_digest` for the common Bitcoin-first message-signing path:

```rust
let verified = verify_aggregate_signature_digest(&group_key, &digest, &aggregate_signature)?;
```

The helper verifies the aggregate 64-byte BIP340 Schnorr signature against the group x-only public key and the 32-byte digest. DKGKit signs prehashed digests with `Message::raw`, so this verification path matches the SDK signing path.

## Local share custody

`LocalKeyShare.secret_share_bytes` is plaintext serialized FROST share material. DKGKit returns it so applications can choose their own custody model, but the SDK does not encrypt it at rest, upload it, back it up, or delete it from application storage.

Applications must treat this field as secret key material.

## High-level local helpers

For tests, examples, and single-process demos, `dkgkit-sdk` provides convenience helpers:

```rust
let shares = run_local_frost_dkg("demo", 2, 3)?;
let signature = sign_digest_with_shares(
    "sign-demo",
    ThresholdConfig::new(2, 3)?,
    shares[0].group_key.clone(),
    digest,
    &shares,
    vec![ParticipantId::new(1)?, ParticipantId::new(2)?],
)?;
```

These helpers are intentionally local. Multi-device applications should use `FrostDkgSession`, `FrostSigningSession`, and a `Transport` so each participant keeps its own share and nonce material on its own device.
