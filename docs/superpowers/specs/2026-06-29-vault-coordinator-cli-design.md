# Vault Coordinator + Participant CLIs — Design Spec (Sub-project B)

Date: 2026-06-29
Status: Approved design, pre-implementation
Package: `examples/vault-cli` (reference application layer)
Depends on: sub-project A (`dkgkit-nostr` `live` feature)

## Context

Sub-project A delivered `LiveNostrTransport`: a relay-backed `Transport` with
NIP-44 round-2 encryption and a vault-scoped subscription. Sub-project B builds
the application on top: a self-hostable coordinator and participant CLIs that
create a company HTSS wallet and sign with it.

A→B→C decomposition (B is this spec):

- **A** — live Nostr transport. Done.
- **B** — coordinator + participant CLIs: DKG → wallet → idle pre-signing →
  one-round, operator-selected threshold signing of an approval digest.
- **C** — Bitcoin spend layer (PSBT, Taproot sighash, broadcast). Later.

Settled product decisions (carried from A):

- Self-hosted relay (`examples/self-hosted-relay`, `ws://127.0.0.1:7777`).
- Coordinator holds **no** key share.
- Grouped company policy `(1,2,3)-of-(2,3,5)` (C-level / managers / operators),
  configurable.
- Signet network for addresses.
- Pre-signed nonce pool uses **synchronized slots**.
- B shape: real CLIs + encrypted-at-rest store + in-memory coordinator state,
  proven by an automated in-process integration test over the live relay.

## Goal

Two binaries over the live transport:

- a **coordinator** that orchestrates a vault (DKG, address, an idle pre-signed
  nonce pool, and operator-approved signing) without ever holding a key share;
- a **participant CLI** that holds an encrypted share and device identity,
  completes DKG, pre-signs nonces during idle time, and produces a single
  signature share per approval.

Success: end-to-end over the live relay — DKG completes and all participants
derive the same group key; the coordinator derives a Taproot address; the
pre-sign pool fills; an operator approves a payment, **chooses the signers**, and
a **one-round** threshold signature aggregates and verifies; the consumed slot's
secret nonce is destroyed and reuse is refused.

## Package layout

`examples/vault-cli/` — reference application layer. It may depend freely on the
SDK and the live transport; it is not an SDK crate.

```text
examples/vault-cli/
  Cargo.toml
  src/lib.rs                  re-exports the modules below
  src/store.rs                SecretStore (encrypted at rest)
  src/control.rs              ControlMessage types + JSON mapping to ProtocolMessage
  src/slot_pool.rs            coordinator-side slot lifecycle
  src/coordinator.rs          Coordinator domain flow
  src/participant.rs          Participant domain flow
  src/bin/dkgkit-coordinator.rs   coordinator CLI (clap)
  src/bin/dkgkit-participant.rs   participant CLI (clap)
  tests/flow.rs               env-gated in-process integration test
```

## Control protocol

DKG packages, signing nonces, and signature shares use the existing
`dkgkit-core` protocol kinds. Coordination control messages ride as
`ProtocolMessageKind::Custom("dkgkit_…")` with JSON payloads, so `dkgkit-core`
is unchanged. Control kinds:

- `dkgkit_vault_manifest` — coordinator → all. Payload: grouped policy
  (participants with ranks + labels, requirements), the participant **directory**
  (`ParticipantId → nostr pubkey hex`), Bitcoin network, account chain code
  (hex), and the DKG session id. Participants ingest this to build their
  `ParticipantDirectory` and `GroupedThresholdConfig`.
- `dkgkit_dkg_ack` — participant → coordinator. Payload: `{participant_id,
  group_xonly_hex}`. The coordinator confirms all N acks carry the same x-only
  key, then marks the vault active. The coordinator stores only this **public**
  key.
- `dkgkit_slot_open` — coordinator → all. Payload: `{slot_id}`. Opens a pre-sign
  slot.
- `dkgkit_sign_request` — coordinator → all. Payload: `{slot_id, digest_hex,
  authorization fields, signer_set}`. Chosen signers produce a signature share.

Pre-signed nonces are published as the existing `HtssSigningNonce` kind, and
signature shares as `HtssSignatureShare`, both scoped to `session_id = slot_id`.
A slot id IS the signing session id, which is exactly what `htss_nonce` /
`htss_sign_share` / `aggregate_htss_signature_shares` already require.

## Identities and bootstrap

- Each participant has a Nostr device keypair (created on `init`, which prints
  the participant's npub). The operator collects the N npubs out-of-band and
  writes them into the coordinator config as the `ParticipantId → npub`
  directory before `init-vault`.
- The coordinator has its own Nostr keypair purely to sign relay events. It is
  **not** a signer, not in the directory, and not in the policy. On the
  transport it uses a reserved `self_id` (`u16::MAX`) that never collides with a
  participant id.
- All control messages are broadcast (no `recipient`) and unencrypted; only DKG
  round-2 direct shares are NIP-44-encrypted (handled by the transport). The
  coordinator only ever transports public data, so its reserved transport
  identity carries no custody meaning.

## Encrypted secret store (`store.rs`)

A per-participant file holding secret material for one vault:

- the device Nostr secret key (nsec);
- the `HtssLocalKeyShare`;
- per-slot secret nonces, each tagged `Available` or `Spent`.

Encryption: passphrase from `DKGKIT_PASSPHRASE` → **Argon2id** key derivation →
**XChaCha20-Poly1305** AEAD. On-disk format: JSON `{salt, nonce, ciphertext}`.
A wrong passphrase fails closed (AEAD authentication error). The plaintext model
is serialized with serde, encrypted, and written atomically.

API (sketch):

```rust
pub struct SecretStore { /* path + derived key + decrypted model */ }
impl SecretStore {
    pub fn open_or_init(path: &Path, passphrase: &str) -> Result<Self>;
    pub fn device_keys(&self) -> &Keys;
    pub fn set_share(&mut self, share: HtssLocalKeyShare) -> Result<()>;
    pub fn share(&self) -> Option<&HtssLocalKeyShare>;
    pub fn put_nonce(&mut self, slot_id: &str, nonce: HtssLocalNonce) -> Result<()>;
    /// Returns the nonce and atomically marks the slot Spent; errors if missing or already Spent.
    pub fn consume_nonce(&mut self, slot_id: &str) -> Result<HtssLocalNonce>;
}
```

`consume_nonce` is the consume-once guard: it errors if the slot is missing or
already `Spent`, and persists `Spent` before returning, so a crash after signing
cannot resurrect a usable nonce.

## Slot pool (`slot_pool.rs`, coordinator-side, in-memory)

Tracks each slot's lifecycle and which participants have committed a public nonce:

```text
Open ──(committed nonces satisfy grouped policy)──▶ Ready ──(used by an approval)──▶ Consumed
```

The coordinator drains `HtssSigningNonce` per open slot to learn who committed.
It keeps a target number of `Ready`/`Open` slots (default depth 3), opening new
slots as ready ones are consumed. A consumed slot id is never reused.

## Flows

### Coordinator (`coordinator.rs`)

1. `init-vault` — load coordinator config (grouped policy + directory + network +
   chain code), publish `dkgkit_vault_manifest`, open the DKG session.
2. Collect `dkgkit_dkg_ack` from all N; verify identical group x-only key; store
   the public group key + chain code; mark vault active.
3. `address` — derive a Taproot child address from the public group key via
   `BitcoinAccountKey` + `taproot_child_address_descriptor_for_network`.
4. Maintain pool — emit `dkgkit_slot_open` up to the target depth; mark slots
   `Ready` when committed nonces satisfy `validate_grouped_threshold_signer_set`.
5. `approve` — build a `BitcoinAuthorizationMessage`, compute its digest, choose a
   `Ready` slot, **list eligible committed signers and let the operator select**
   a valid set (`--signers 1,3,4,6,7,8`, validated by
   `validate_grouped_threshold_signer_set`), publish `dkgkit_sign_request`,
   collect `HtssSignatureShare` from the chosen signers, aggregate with
   `aggregate_htss_signature_shares`, verify with
   `verify_aggregate_signature_digest`, and mark the slot `Consumed`.

### Participant (`participant.rs`)

1. `init` — generate or load the device `Keys`; create the encrypted store.
2. `run`:
   - ingest `dkgkit_vault_manifest` → build `ParticipantDirectory` +
     `GroupedThresholdConfig` + HTSS config;
   - run HTSS DKG (round 1 broadcast; round 2 NIP-44-encrypted direct shares);
     store the `HtssLocalKeyShare`; publish `dkgkit_dkg_ack`;
   - idle loop:
     - on `dkgkit_slot_open` → `htss_nonce(slot_id, share)`, persist the secret
       nonce as `Available`, publish the public `HtssSigningNonce`;
     - on `dkgkit_sign_request` where self ∈ signer set → `consume_nonce(slot_id)`
       (destroys it), gather the chosen signers' public nonces for the slot,
       `htss_sign_share`, publish the `HtssSignatureShare`. Refuse if the slot's
       nonce is missing or already spent.

## Consume-once enforcement

A pre-committed nonce may sign exactly once. Enforced on both sides:

- Participant: `SecretStore::consume_nonce` marks the slot `Spent` (persisted)
  and returns the nonce exactly once; signing a missing/spent slot errors.
- Coordinator: a `Consumed` slot is never re-offered in an approval.

Reuse across two digests would leak the secret share; this is the dominant
security requirement of B.

## Defaults and configuration

- Policy: grouped `(1,2,3)-of-(2,3,5)`, configurable via the coordinator config
  file (participants, ranks, labels, per-rank requirements).
- Network: signet (address derivation only in B; spending is C).
- Relay: `DKGKIT_TEST_RELAY` or a `--relay` flag, default `ws://127.0.0.1:7777`.
- Pool depth: default 3.
- Passphrase: `DKGKIT_PASSPHRASE`.

## Error handling

- Missing/invalid manifest, directory gaps, or policy validation failures abort
  the relevant command with a clear error.
- A wrong store passphrase fails closed.
- Signing aborts before any nonce is consumed if the signer set is invalid.
- The coordinator marks an approval failed (and does not consume the slot) if
  aggregation or verification fails.

## Testing

Per project rule, the main agent writes and runs all code; subagents only draft
`.md` plans.

- Unit (no network):
  - `SecretStore` encrypt→decrypt round-trip; wrong passphrase fails.
  - `consume_nonce` returns once then refuses (consume-once).
  - `SlotPool` Open→Ready→Consumed transitions and policy-satisfaction check.
  - control-message JSON round-trips for all four `Custom` kinds.
- Integration (`tests/flow.rs`, gated by `DKGKIT_TEST_RELAY`): coordinator + N
  participants in-process over the live relay run DKG → address → pool fill →
  operator-selected one-round sign → aggregate verifies → reusing the consumed
  slot fails. Run against the Docker relay (`examples/self-hosted-relay`).
- Validation gate: `cargo fmt --all`, `cargo check --workspace`,
  `cargo test --workspace`, and the gated integration test against a relay.

## New dependencies

`clap` (CLI), `argon2` (KDF), `chacha20poly1305` (AEAD). `serde`, `serde_json`,
`hex`, `rand`, `anyhow` already in the workspace. `dkgkit-nostr` is used with the
`live` feature.

## Acceptance criteria

- `dkgkit-coordinator` and `dkgkit-participant` build and run.
- Over a live relay, N participants complete HTSS DKG and all derive the same
  group key; the coordinator confirms via `dkgkit_dkg_ack`.
- The coordinator derives a Taproot receive address from the public group key.
- The pre-sign pool reaches the target depth (synchronized slots).
- An operator approves a payment, selects a valid signer set, and a single round
  produces an aggregate signature that verifies against the group x-only key.
- An invalid signer set is rejected before any nonce is consumed.
- A consumed slot's nonce is destroyed; reusing it is refused.
- Server/coordinator state never contains plaintext shares, coefficients, or
  secret nonces; the participant store is encrypted at rest.
- Default `cargo test --workspace` passes with no relay; the integration test is
  ignored without `DKGKIT_TEST_RELAY`.

## Out of scope for B (deferred)

- Real Bitcoin transactions: PSBT, UTXO selection, sighash, broadcast (C).
- Persisted coordinator state (SQLite), device authentication/registration,
  replay/expiry policy, NIP-29 groups (a later full-product pass).
- Recovery and resharing.
