# DKGKit

Bitcoin-first threshold cryptography SDK.

DKGKit is a clean SDK extraction target inspired by the FrostDAO prototype. It is designed to provide reusable primitives for distributed key generation, threshold signing, and transport-agnostic coordination.

## Status

Developer-preview SDK. Base FROST DKG, HTSS DKG primitives, threshold signing, Bitcoin Taproot address derivation, and aggregate signature verification are implemented and covered by workspace tests.

Not production custody software. Do not use for mainnet funds until the release checklist in `docs/RELEASE_CHECKLIST.md` is complete, including external cryptography and security review.

## Architecture

```text
crates/dkgkit-core       session IDs, participants, threshold config, errors
crates/dkgkit-frost      FROST and HTSS DKG/signing API surface
crates/dkgkit-bitcoin    Bitcoin address/message-signing helpers
crates/dkgkit-transport  transport traits only
crates/dkgkit-nostr      Nostr envelope mapping, local + live (feature `live`) relay transport
crates/dkgkit-sdk        developer-facing facade
examples/nostr-dkg-cli   reference Nostr DKG CLI demo
examples/self-hosted-relay        Docker nostr-rs-relay coordination channel
examples/nostr-transport-service  live FROST DKG round-trip over a self-hosted relay
examples/bitcoin-message-signing  end-to-end DKG plus Bitcoin message signing example
```


## Current SDK Surface

- `dkgkit-core`: validated sessions, participants, manifests, protocol messages
- `dkgkit-transport`: transport trait plus in-memory transport for tests/examples
- `dkgkit-nostr`: Nostr envelope mapping, local test transport, and (feature `live`) a relay-backed `LiveNostrTransport` with NIP-44 round-2 encryption
- `dkgkit-bitcoin`: Taproot address helpers, account child address descriptors, authorization-message digesting, BIP340 verification
- `dkgkit-frost`: public DKG/signing API boundary, base TSS DKG, HTSS derivative-share DKG, threshold signer-set validation, HTSS rank validation, grouped threshold validation, Birkhoff interpolation coefficients, and HTSS threshold signing
- `dkgkit-sdk`: developer-facing facade, session builder, and `HtssDkgService` entrypoints

## Production Readiness

See `docs/RELEASE_CHECKLIST.md` for the explicit line between demo-ready SDK functionality and production custody requirements.

## Local Development

```bash
cargo fmt
cargo check --workspace
cargo test --workspace
```

## MVP Scope

Version 0.1 targets:

- FROST DKG API
- HTSS DKG API
- threshold message signing API
- aggregate signature verification API
- Bitcoin Taproot child address derivation below a DKG account key
- transport traits
- Nostr reference transport
- examples

Out of scope for 0.1:

- wallet UI
- PSBT
- transaction broadcasting
- recovery
- reshare
- ROAST
- mainnet custody claims
- live relay networking, NIP-44 encryption, PSBT orchestration, Arkade integration, Silent Payments integration, and nested TSS-over-HTSS product workflow

## Relationship to FrostDAO

FrostDAO remains the advanced prototype/reference implementation with TUI, transaction signing, HTSS, recovery, reshare, Nostr relay drills, and production-readiness evidence tooling.

DKGKit is the fresh SDK repo intended for a smaller, composable, open-source developer surface.

## Service Wiring

See `docs/SERVICE_WIRING.md` for the recommended app/service architecture, all current service-facing entrypoints, and what remains intentionally outside DKGKit.

To build the next wallet service or web app on top of DKGKit, see `docs/NEXT_APP_GUIDE.md`.

## Protocol Envelope

DKGKit uses a stable transport-agnostic protocol envelope from `dkgkit-core`. See `docs/PROTOCOL.md` for message kinds, broadcast/direct routing, and payload rules.
