# Release Checklist

DKGKit is intended to be an open-source SDK, not a hosted wallet or custody product. This checklist defines what is usable today and what must be completed before anyone can claim production custody readiness.

## Current developer-preview capabilities

- Run in-memory FROST DKG for local tests, examples, and demos.
- Generate matching local key shares for all participants in a DKG ceremony.
- Sign a 32-byte application digest with a selected threshold signer set.
- Aggregate threshold signature shares into a BIP340 Schnorr signature.
- Verify aggregate signatures against the FROST group x-only public key.
- Derive Bitcoin Taproot addresses from the group key.
- Encode/decode protocol messages independently of the transport layer.
- Coordinate DKG/signing packages over in-memory and local Nostr-shaped transports.

## Not production custody ready until complete

- External cryptography review of DKG, signing, aggregation, and verification flows.
- External application security review of transport handling, identity binding, replay handling, and key-share storage guidance.
- Live multi-device DKG drill over a real relay with authenticated participant identity and encrypted direct messages.
- Manual operator drill proving every device derives the same group public key and Bitcoin address.
- Backup and restore drill for every party share before any funds are received.
- Reproducible release artifacts and documented supply-chain process.
- Stable crate API policy, semantic-versioning policy, and migration guide.
- Negative test vectors for malformed DKG packages, wrong signer sets, wrong nonces, replayed messages, and invalid aggregate signatures.
- Persistent storage guidance for encrypted local key shares.
- Incident-response guidance for lost share, compromised share, relay outage, and failed ceremony.

## Explicitly out of scope for version 0.1

- PSBT signing.
- Bitcoin transaction construction or broadcasting.
- Wallet balance tracking.
- Recovery protocol.
- Resharing protocol.
- HTSS.
- ROAST.
- Mainnet custody claims.

## Release gates

### 0.1 developer preview

- Workspace formats cleanly with `cargo fmt`.
- Workspace compiles with `cargo check --workspace`.
- Workspace tests pass with `cargo test --workspace`.
- Examples run without external services.
- README and docs state the non-custody status clearly.

### 0.2 relay preview

- Real Nostr relay transport is implemented behind an explicit feature flag.
- Direct DKG/share messages are encrypted before publication to public relays.
- Relay events bind session ID, participant ID, Nostr public key, message kind, and recipient.
- Multi-device relay drill is documented and repeatable.

### 1.0 production SDK candidate

- Independent cryptography review is complete and linked from the repository.
- Independent security review is complete and linked from the repository.
- Stable API policy is documented.
- Test vectors are published.
- Release signing and provenance are documented.
- No documentation implies mainnet custody safety without the required operational controls.
