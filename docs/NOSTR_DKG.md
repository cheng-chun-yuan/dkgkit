# NostrDKG

NostrDKG is the first reference coordination layer for DKGKit.

Nostr responsibilities:

- relay connection
- session discovery
- message delivery
- participant identity display

Nostr must not implement cryptography itself. It only transports protocol messages produced by DKGKit.

## Current SDK boundary

`dkgkit-nostr` currently provides deterministic mapping between DKGKit protocol messages and relay-ready event DTOs.

```rust
let event = NostrEnvelopeEvent::from_protocol_message(&message)?;
let message = event.to_protocol_message()?;
```

The event DTO includes:

- fixed DKGKit event kind
- app tag
- session tag
- sender party index
- optional recipient party index
- message kind tag
- JSON-encoded `ProtocolMessage` content

The decoder validates that tags match the encoded message content. This prevents a relay or app layer from accidentally routing a message under one room/sender/kind while the signed or serialized body says something else.

## Live relay transport status

Live Nostr relay I/O is still pending migration. The transport placeholder remains intentionally separate from the mapping layer so the cryptographic SDK does not depend on relay networking.

## Local Nostr event transport

`LocalNostrEventTransport` implements the generic `Transport` trait by storing `NostrEnvelopeEvent` values in memory.

This is useful for:

- testing Nostr event serialization
- building demos without a live relay
- verifying that app code depends only on `Transport`
- preparing for a live relay implementation without coupling apps to relay internals
- testing HTSS DKG Round 1 commitments and direct Round 2 derivative-share routing
- testing HTSS signing nonce and signature-share routing

It is not a network transport. It does not connect to a relay, sign Nostr events, encrypt DKG round 2 shares, or provide persistence.

Current tests prove that HTSS DKG and HTSS signing packages can pass through the
local Nostr event envelope and still produce a Bitcoin-verifiable Schnorr
signature. Production relay I/O and NIP-44 encryption remain service-layer
responsibilities.
