# Next App Build Guide

This guide is for building the next wallet service or web app on top of
DKGKit. DKGKit should be used as the cryptography, Bitcoin helper, and
protocol-envelope dependency. The app should own product state, networking,
storage, authentication, wallet policy, UX, and integrations.

Use this document with:

- `docs/SERVICE_WIRING.md` for the exact low-level DKG and signing sequence.
- `docs/API.md` for the current SDK facade.
- `examples/vault-service` for a single-process reference flow.
- `docs/SECURITY_MODEL.md` and `docs/RELEASE_CHECKLIST.md` before any custody
  claim.

Run the reference service first:

```bash
cargo run -p vault-service
```

The expected proof path is:

```text
create vault -> HTSS DKG complete -> Taproot address derived -> approval digest signed -> aggregate verifies
```

## Current DKGKit Surface

Use these crates as dependencies from the app:

```text
dkgkit-sdk        developer-facing facade and coordinator helpers
dkgkit-core       session IDs, participants, grouped policy, protocol messages
dkgkit-frost      FROST and HTSS DKG/signing primitives
dkgkit-bitcoin    Taproot address, authorization digest, signature verification
dkgkit-transport  transport trait and memory transport
dkgkit-nostr      local Nostr-style transport reference implementation
```

Typical imports:

```rust
use dkgkit_nostr::LocalNostrEventTransport;
use dkgkit_sdk::bitcoin::{
    taproot_child_address_descriptor_for_network, verify_aggregate_signature_digest,
    BitcoinAccountKey, BitcoinAuthorizationMessage, BitcoinDerivationPath,
};
use dkgkit_sdk::{
    aggregate_htss_signature_shares, hierarchical_config_from_grouped_threshold, htss_nonce,
    htss_sign_share, validate_grouped_threshold_signer_set, FrostCoordinator,
    GroupThresholdRequirement, GroupedThresholdConfig, HtssDkgService, ParticipantId,
    RankedParticipant, SessionId,
};
```

Keep out of DKGKit:

- HTTP, WebSocket, or RPC routes.
- database schema and migrations.
- user accounts, teams, device auth, and session auth.
- Nostr relay pools, subscriptions, retries, dedupe, and event signing.
- NIP-44 encryption and local device key management.
- PSBT construction, UTXO selection, fee estimation, and broadcasting.
- Arkade, Silent Payments, accounting, and webhook integrations.
- nested "TSS group controls one HTSS logical share" orchestration.

## Target App Shape

Recommended split:

```text
wallet-service/
  api/
    routes.rs
    ws.rs
    dto.rs
  domain/
    vault.rs
    dkg_session.rs
    signing_session.rs
    policy.rs
    approval.rs
  storage/
    migrations/
    models.rs
    repository.rs
  transport/
    local_relay.rs
    nostr_relay.rs
    message_router.rs
  crypto_io/
    device_keys.rs
    nip44.rs
    local_secret_store.rs
  bitcoin/
    address_book.rs
    psbt_builder.rs
    sighash.rs
    broadcaster.rs
  integrations/
    arkade.rs
    silent_payments.rs
    accounting.rs
    webhooks.rs
  web/
```

The service can be a Rust backend, a Next.js app with Rust sidecar services, or
another product shell. The important boundary is that DKGKit remains stateless:
it receives validated inputs, returns protocol packages or signatures, and does
not become the owner of product state.

## Phase 1: Local Service MVP

Goal: turn `examples/vault-service` into app modules while staying local and
single-process.

Build:

- create vault.
- construct grouped `(1,2,3)-of-(2,3,5)` policy.
- convert grouped policy to HTSS config with
  `hierarchical_config_from_grouped_threshold`.
- run HTSS DKG through `HtssDkgService`.
- use `FrostCoordinator<LocalNostrEventTransport>` as the local relay.
- derive a child Taproot address with `BitcoinAccountKey` and
  `taproot_child_address_descriptor_for_network`.
- create a `BitcoinAuthorizationMessage`.
- validate the signer set with `validate_grouped_threshold_signer_set`.
- collect public nonces, signature shares, aggregate signature, and verify it
  with `verify_aggregate_signature_digest`.

Do not build yet:

- live relay networking.
- NIP-44 encryption.
- PSBT construction.
- transaction broadcast.
- Arkade or Silent Payments.
- production device backup or recovery.
- nested TSS groups.

One local command or test should prove:

```text
vault created
all participants finalized the same group key
address descriptor produced
valid signer set accepted
invalid signer set rejected
aggregate signature verified
```

## Phase 2: Persistent Service

Add durable storage for public vault state and session progress. Keep signing
shares local to participant devices unless the backend is intentionally a
signer.

Persist:

- vault metadata.
- participant IDs, labels, ranks, and device public keys.
- grouped threshold requirements.
- DKG session status.
- protocol message metadata and payload storage.
- receive address descriptors.
- approval requests.
- signing session status.
- aggregate signature and verification result.

Do not persist plaintext:

- `HtssDkgRound1State.secret_coefficient_bytes`.
- `HtssLocalKeyShare`.
- `HtssLocalNonce.secret_nonce_bytes`.
- HTSS DKG Round 2 plaintext derivative shares.

If the server is a signer, store its local share only through a dedicated secret
store or encrypted key vault. Do not treat normal database encryption as a
complete custody boundary.

## Phase 3: Live Transport

Replace `LocalNostrEventTransport` with an app-owned relay adapter that
implements or wraps DKGKit's transport boundary.

Implement:

- relay pool connection management.
- event publishing and subscription by vault/session tags.
- conversion between relay events and `ProtocolMessage` envelopes.
- event ID dedupe and protocol payload hash dedupe.
- retries with idempotency.
- stale session expiry.
- sender, recipient, session ID, protocol version, and message kind
  preservation.

DKGKit's current `LocalNostrEventTransport` is a reference local transport. It
is not a production relay client.

## Phase 4: Secret Message Encryption

Encrypt direct secret material before it reaches public relay infrastructure.

Encrypt:

- HTSS DKG Round 2 packages.
- any future secret backup, recovery, or resharing payload.

Do not encrypt only to a server key. Encrypt each direct package to the
recipient device key. Round 1 commitments, public signing nonces, and signature
shares can be routed as protocol messages without containing local secret
coefficients or nonce secrets.

The app owns:

- device keys.
- NIP-44 or equivalent encryption.
- key rotation.
- lost-device handling.
- replay and expiry policy.

## Phase 5: Bitcoin Transaction Flow

DKGKit signs 32-byte digests. The app owns the wallet transaction flow.

Implement in the app layer:

- wallet account model.
- UTXO source.
- fee rate source.
- recipient validation.
- PSBT builder.
- policy and transaction preview.
- Taproot sighash extraction.
- signature insertion.
- broadcast.
- post-broadcast status tracking.

For the MVP, use `BitcoinAuthorizationMessage` to sign a clear, user-visible
authorization digest. For real transaction signing, the app must display the
transaction details and pass only the correct 32-byte sighash digest into
DKGKit signing.

## Phase 6: Integrations

Add integrations after the base vault flow is stable.

Possible modules:

- `integrations/arkade`
- `integrations/silent_payments`
- `integrations/accounting`
- `integrations/webhooks`

Keep integration-specific API clients, credentials, retries, and product state
outside DKGKit.

## Minimal API Routes

Use REST, WebSocket, tRPC, or server actions as appropriate. These routes are a
minimal backend shape, not DKGKit APIs.

### Vaults

```text
POST /vaults
GET  /vaults/:vault_id
GET  /vaults/:vault_id/participants
GET  /vaults/:vault_id/addresses
POST /vaults/:vault_id/addresses
```

### DKG

```text
POST /vaults/:vault_id/dkg/start
POST /vaults/:vault_id/dkg/round1
GET  /vaults/:vault_id/dkg/round1
POST /vaults/:vault_id/dkg/round2
GET  /vaults/:vault_id/dkg/round2/:participant_id
POST /vaults/:vault_id/dkg/finalize
GET  /vaults/:vault_id/dkg/status
```

### Approvals And Signing

```text
POST /vaults/:vault_id/approvals
GET  /vaults/:vault_id/approvals/:approval_id
POST /vaults/:vault_id/approvals/:approval_id/select-signers
POST /vaults/:vault_id/signing/:session_id/nonce
GET  /vaults/:vault_id/signing/:session_id/nonces
POST /vaults/:vault_id/signing/:session_id/share
GET  /vaults/:vault_id/signing/:session_id/shares
POST /vaults/:vault_id/signing/:session_id/aggregate
```

For a demo, a WebSocket can replace polling endpoints for Round 1, Round 2,
nonces, and signature shares.

## Minimal Database Tables

### `vaults`

```text
id
name
network
status
group_xonly_public_key
account_chain_code
created_by
created_at
updated_at
```

### `participants`

```text
id
vault_id
participant_id
rank
label
nostr_pubkey
device_pubkey
status
created_at
updated_at
```

### `group_requirements`

```text
id
vault_id
rank
required
total
```

### `dkg_sessions`

```text
id
vault_id
session_id
status
started_at
completed_at
expires_at
```

### `protocol_messages`

```text
id
vault_id
session_id
sender_participant_id
recipient_participant_id
message_kind
protocol_version
payload_plaintext_json
payload_ciphertext
payload_hash
transport_event_id
created_at
```

Use plaintext payload storage only for public messages or local debugging.
Store ciphertext for secret direct messages.

### `local_shares`

Only create this table if the backend is intentionally a signer:

```text
id
vault_id
participant_id
encrypted_share
key_version
created_at
updated_at
```

Normal self-custody should store `HtssLocalKeyShare` only on participant
devices.

### `addresses`

```text
id
vault_id
path
network
address
account_xonly_public_key
internal_xonly_public_key
output_xonly_public_key
child_chain_code
created_at
```

### `approvals`

```text
id
vault_id
status
action
recipient
amount_sats
memo
nonce
canonical_text
digest
created_by
created_at
expires_at
```

### `signing_sessions`

```text
id
vault_id
approval_id
session_id
status
signer_set_json
aggregate_signature
verified
created_at
completed_at
expires_at
```

## State Machines

Vault:

```text
created -> dkg_round1 -> dkg_round2 -> active -> archived
```

Approval:

```text
draft -> pending_signers -> signing -> signed -> executed
                         -> rejected
                         -> expired
```

Signing session:

```text
created -> collecting_nonces -> collecting_shares -> aggregated -> verified
                                   -> failed
                                   -> expired
```

## Core Flow Snippets

### Grouped Policy

The reference `(1,2,3)-of-(2,3,5)` policy has three ranks. Lower rank values
are higher authority.

```rust
let grouped = GroupedThresholdConfig::new(
    vec![
        RankedParticipant::new(1, 0, Some("c-level-a".to_string()))?,
        RankedParticipant::new(2, 0, Some("c-level-b".to_string()))?,
        RankedParticipant::new(3, 1, Some("manager-a".to_string()))?,
        RankedParticipant::new(4, 1, Some("manager-b".to_string()))?,
        RankedParticipant::new(5, 1, Some("manager-c".to_string()))?,
        RankedParticipant::new(6, 2, Some("operator-a".to_string()))?,
        RankedParticipant::new(7, 2, Some("operator-b".to_string()))?,
        RankedParticipant::new(8, 2, Some("operator-c".to_string()))?,
        RankedParticipant::new(9, 2, Some("operator-d".to_string()))?,
        RankedParticipant::new(10, 2, Some("operator-e".to_string()))?,
    ],
    vec![
        GroupThresholdRequirement::new(0, 1, 2)?,
        GroupThresholdRequirement::new(1, 2, 3)?,
        GroupThresholdRequirement::new(2, 3, 5)?,
    ],
)?;
let htss = hierarchical_config_from_grouped_threshold(&grouped)?;
let dkg = HtssDkgService::new("vault-dkg", htss)?;
```

### HTSS DKG

Round 1:

```rust
let state = dkg.begin_round1(participant_id)?;
coordinator.publish_htss_dkg_round1(dkg.session_id.clone(), &state.package)?;
```

Round 2:

```rust
let round1_packages = coordinator.drain_htss_dkg_round1(&dkg.session_id)?;
let round2_packages = dkg.create_round2_packages(&state, &round1_packages)?;
for package in &round2_packages {
    coordinator.publish_htss_dkg_round2(dkg.session_id.clone(), package)?;
}
```

Finalize:

```rust
let round2_for_me = coordinator.drain_htss_dkg_round2_for(&dkg.session_id, participant_id)?;
let (group_key, local_share) =
    dkg.finalize_participant(participant_id, &round1_packages, &round2_for_me)?;
```

Round 1 packages are public commitments. Round 2 packages carry secret
derivative-share material and must be encrypted for live public relays.

### Address Derivation

```rust
let account_key = BitcoinAccountKey::new(group_key, chain_code);
let path = BitcoinDerivationPath::bip86(0, 0, 0);
let descriptor =
    taproot_child_address_descriptor_for_network(&account_key, "regtest", path)?;
```

The DKG group key is treated as an account-level key, for example
`m/86'/0'/account'`. DKGKit derives only the public non-hardened
`/change/address_index` tail. Hardened purpose, coin, and account derivation
must be established before or during DKG if the product needs full BIP32
semantics.

### Approval Digest

```rust
let authorization = BitcoinAuthorizationMessage {
    network: "regtest".to_string(),
    action: "approve-payment".to_string(),
    recipient: Some(descriptor.address.clone()),
    amount_sats: Some(100_000),
    memo: Some("demo approval".to_string()),
    nonce: "approval-001".to_string(),
};
let digest = authorization.digest();
```

Store and display the canonical text behind this digest. Users should approve
human-readable fields, not a raw hash.

### HTSS Signing

```rust
validate_grouped_threshold_signer_set(&signer_set, &grouped)?;
let signing_session_id = SessionId::new("approval-001-signing")?;

let nonce = htss_nonce(signing_session_id.clone(), &local_share)?;
coordinator.publish_htss_nonce(&nonce.package)?;
let public_nonces = coordinator.drain_htss_nonces(&signing_session_id)?;

let signature_share = htss_sign_share(
    &group_key,
    digest,
    &local_share,
    &nonce,
    &public_nonces,
    &signer_set,
    &dkg.config,
)?;
coordinator.publish_htss_signature_share(&signature_share)?;

let signature_shares = coordinator.drain_htss_signature_shares(&signing_session_id)?;
let aggregate = aggregate_htss_signature_shares(
    &group_key,
    digest,
    &public_nonces,
    &signature_shares,
    &signer_set,
    &dkg.config,
)?;
let verified = verify_aggregate_signature_digest(&group_key, &digest, &aggregate)?;
```

Never reuse `HtssLocalNonce`. Create a fresh signing session and nonce set for
every digest.

## Security Rules

- Never transmit or log `HtssDkgRound1State.secret_coefficient_bytes`.
- Never transmit or log `HtssLocalNonce.secret_nonce_bytes`.
- Never publish HTSS DKG Round 2 plaintext on a public relay.
- Never reuse signing nonces.
- Always validate grouped or hierarchical signer policy before nonce creation.
- Always verify aggregate signatures before showing success.
- Treat `HtssLocalKeyShare` as long-lived secret key material.
- Treat account chain code as public metadata with integrity requirements.
- Bind every protocol package to the intended `session_id`.
- Expire stale DKG and signing sessions.
- Record enough metadata to audit who approved what, without storing plaintext
  secret material.

## Demo Cut

For a fast demo, build only:

1. local in-memory app state.
2. local relay transport or mocked live Nostr.
3. create vault form.
4. DKG progress view.
5. address display.
6. approval request view.
7. signer selection.
8. aggregate verification result.

Defer:

- production DB migrations.
- mainnet PSBT.
- live relay hardening.
- Arkade production integration.
- Silent Payments.
- nested TSS group shares.
- recovery and reshare.

## Acceptance Checklist

The next app MVP is working when:

- `cargo run -p vault-service` still succeeds in DKGKit.
- The app can create a vault with grouped `(1,2,3)-of-(2,3,5)` policy.
- All participants complete HTSS DKG and derive the same group key.
- The app derives a child Taproot address descriptor.
- An approval digest is generated from visible approval fields.
- A valid signer set signs successfully.
- An invalid signer set is rejected before nonce creation.
- The aggregate signature verifies against the group x-only public key.
- Server logs and database rows do not contain plaintext local shares,
  coefficient secrets, or nonce secrets.
- The app clearly distinguishes demo-only local transport from production relay,
  encryption, PSBT, and custody requirements.

Run before shipping changes:

```bash
cargo fmt --all
cargo test --workspace
cargo run -p vault-service
```
