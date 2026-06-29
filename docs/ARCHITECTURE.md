# DKGKit Architecture

## Principles

- Small modules
- Composable architecture
- Transport agnostic
- Bitcoin first
- SDK before application

## Layers

```text
dkgkit-core
  shared protocol types, participant IDs, threshold config, errors

dkgkit-frost
  FROST DKG/signing state machines and aggregation

dkgkit-bitcoin
  Bitcoin address and message verification helpers

dkgkit-transport
  coordination transport traits

dkgkit-nostr
  Nostr implementation of transport traits

dkgkit-sdk
  stable developer-facing facade

service/app layer
  storage, auth, Nostr relay networking, encryption, PSBT, Arkade, Silent Payments
```

Cryptographic crates must not depend on Nostr, UI frameworks, Bitcoin RPC, or application backends.

See `SERVICE_WIRING.md` for the recommended boundary between DKGKit and a
wallet service.
