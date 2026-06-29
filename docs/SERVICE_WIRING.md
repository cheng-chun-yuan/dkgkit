# Service Wiring Spec

This document describes how an application or service should wire DKGKit into a
Bitcoin vault product while keeping DKGKit small, stateless, and auditable.

For a product-oriented build plan with routes, tables, state machines, and
milestones, see `NEXT_APP_GUIDE.md`.

DKGKit owns cryptographic and protocol primitives. The service owns storage,
authorization, relay networking, encryption, wallet policy, and product flows.

## Boundary

Keep in DKGKit:

- HTSS DKG round package types.
- HTSS DKG round 1, round 2, and finalize functions.
- HTSS signing nonce, signature share, and aggregation functions.
- grouped and hierarchical policy validation.
- transport-agnostic `ProtocolMessage` envelopes.
- local and deterministic test transports.
- stateless Bitcoin address, digest, and signature helpers.

Keep in the service:

- HTTP or WebSocket API routes.
- database schema and session lifecycle.
- Nostr relay connections, retries, dedupe, and subscriptions.
- NIP-44 or equivalent encryption for secret direct messages.
- device authentication and user authorization.
- vault/team approval workflow.
- PSBT construction, UTXO selection, transaction broadcast.
- Arkade and Silent Payments product integrations.
- nested "TSS group controls one HTSS logical share" orchestration.

## Vault Creation

Inputs:

- `vault_id`
- `session_id`
- `HierarchicalThresholdConfig` or `GroupedThresholdConfig`
- participant IDs, ranks, and labels
- Bitcoin network
- 32-byte account chain code

If the product starts from grouped policy, convert it to the HTSS config used by
the DKG and signing primitives:

```rust
let htss_config = hierarchical_config_from_grouped_threshold(&grouped_config)?;
```

Create the service facade:

```rust
let dkg = HtssDkgService::new(session_id, htss_config)?;
```

Store public vault metadata:

- `vault_id`
- `session_id`
- participant IDs, ranks, labels
- grouped requirements, if used
- Bitcoin network
- account chain code
- DKG status

Do not store plaintext `HtssLocalKeyShare` values on the server unless the
server is intentionally one of the signers and has its own secure key storage.

## HTSS DKG Round 1

Each participant device runs:

```rust
let state = dkg.begin_round1(participant_id)?;
let message = dkg.round1_message(&state.package)?;
```

Publish `message` through the service transport.

Round 1 contains public polynomial commitments. It is safe to broadcast.

Local-only secret material:

```rust
state.secret_coefficient_bytes
```

The service must keep this on the participant device or encrypted local storage.
It must not be sent to relays or other participants.

Coordinator helpers:

```rust
coordinator.publish_htss_dkg_round1(session_id.clone(), &state.package)?;
let round1_packages = coordinator.drain_htss_dkg_round1(&session_id)?;
```

## HTSS DKG Round 2

After all Round 1 packages are collected, each participant device runs:

```rust
let round2_packages = dkg.create_round2_packages(&state, &round1_packages)?;
```

For each package:

```rust
let message = dkg.round2_message(&package)?;
```

Round 2 package shape:

```text
s_i,j = f_i^(rank_j)(x_j)
```

This is secret derivative share material. In production, encrypt each Round 2
direct message to its recipient before publishing over a public relay.

Coordinator helpers:

```rust
coordinator.publish_htss_dkg_round2(session_id.clone(), &package)?;
let round2_for_me = coordinator.drain_htss_dkg_round2_for(&session_id, participant_id)?;
```

## HTSS DKG Finalize

Each participant device collects the Round 2 packages addressed to itself:

```rust
let (group_key, local_share) =
    dkg.finalize_participant(participant_id, &round1_packages, &round2_for_me)?;
```

Finalize verifies each derivative share against the sender's public
commitments:

```text
s_i,j * G == sum_k falling_factorial(k, rank_j) * x_j^(k-rank_j) * C_i,k
```

Store locally:

- `HtssLocalKeyShare`
- encrypted at rest

Store publicly:

- `group_key.xonly_public_key`
- participant/rank metadata
- completed DKG status

## Bitcoin Account Key And Addresses

DKGKit treats the DKG group key as the account-level key, for example:

```text
m/86'/0'/account'
```

The public service layer can derive only the non-hardened tail:

```text
/change/address_index
```

Create account metadata:

```rust
let account_key = BitcoinAccountKey::new(group_key.clone(), chain_code);
```

Derive a real child Taproot address:

```rust
let path = BitcoinDerivationPath::bip86(account, change, address_index);
let descriptor =
    taproot_child_address_descriptor_for_network(&account_key, "signet", path)?;
```

The descriptor includes:

- full path label
- address
- account x-only public key
- internal child x-only public key
- Taproot output x-only public key
- child chain code

Hardened path components cannot be derived from public threshold key material
after DKG. If the product needs full BIP32 hardened account derivation, that
must be established before or during DKG.

## HTSS Signing

Inputs:

- `vault_id`
- `signing_session_id`
- 32-byte digest
- signer set
- local participant share

Validate policy before creating nonces:

```rust
validate_hierarchical_signer_set(&signer_set, &htss_config)?;
```

For grouped policy:

```rust
validate_grouped_threshold_signer_set(&signer_set, &grouped_config)?;
let htss_config = hierarchical_config_from_grouped_threshold(&grouped_config)?;
```

Each signer creates a nonce:

```rust
let nonce = htss_nonce(signing_session_id.clone(), &local_share)?;
let public_nonce = nonce.package.clone();
```

Publish only `public_nonce`. Keep `nonce.secret_nonce_bytes` local and
single-use.

Each signer creates a signature share:

```rust
let signature_share = htss_sign_share(
    &group_key,
    digest,
    &local_share,
    &nonce,
    &public_nonces,
    &signer_set,
    &htss_config,
)?;
```

The coordinator aggregates:

```rust
let signature = aggregate_htss_signature_shares(
    &group_key,
    digest,
    &public_nonces,
    &signature_shares,
    &signer_set,
    &htss_config,
)?;
```

Verify:

```rust
let ok = verify_aggregate_signature_digest(&group_key, &digest, &signature)?;
```

## Current Test Evidence

Current workspace tests cover:

- exact finite-field Birkhoff interpolation.
- HTSS DKG derivative-share generation.
- derivative-share commitment verification.
- tampered HTSS DKG Round 2 rejection.
- HTSS threshold signing without reconstructing the group secret.
- grouped `(1,2,3)-of-(2,3,5)` policy validation.
- local Nostr-style relay transport for HTSS DKG packages.
- local Nostr-style relay transport for HTSS signing packages.
- BIP32 non-hardened child Taproot address derivation below a DKG account key.

Run:

```bash
cargo fmt --all
cargo test --workspace
cargo run -p vault-service
```

## Not Wired In DKGKit

These are intentionally left for the service/app layer:

- live Nostr relay networking.
- Nostr event signing and relay authentication.
- NIP-44 encryption for HTSS DKG Round 2.
- replay protection, expiry policy, and relay dedupe.
- persistent vault/session database.
- local device keystore or backup UX.
- real PSBT construction and transaction sighash production.
- child-key threshold signing tweak application.
- Arkade integration.
- Silent Payments integration.
- nested TSS committees that control logical HTSS shares.

## Recommended Service Modules

```text
wallet-service
  api/              REST or WebSocket routes
  sessions/         DKG and signing session state machine
  storage/          vault metadata, messages, address book
  transport/        Nostr relay adapter and subscriptions
  crypto_io/        NIP-44 encryption/decryption wrappers
  policy/           grouped vault policy and signer selection
  bitcoin/          PSBT, sighash, UTXO, broadcast adapters
  integrations/     Arkade, Silent Payments, accounting exports
```

DKGKit should remain a dependency of these modules, not the owner of them.
