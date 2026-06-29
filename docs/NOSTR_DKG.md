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

Live Nostr relay I/O is implemented as `LiveNostrTransport` behind the
`dkgkit-nostr` `live` Cargo feature. It bridges the synchronous `Transport`
trait to the async `nostr-sdk` client on a dedicated background thread,
publishes kind-`30333` events, subscribes by the `#t = dkgkit:<vault>` topic
tag, and NIP-44-encrypts the secret round-2 direct messages while leaving public
messages (round 1, nonces, signature shares) in clear. The default build stays
dependency-light; only `--features live` pulls in `nostr-sdk` and `tokio`.

To stand up a coordination channel and prove the transport end-to-end, see
`examples/self-hosted-relay` (a Docker `nostr-rs-relay`) and
`examples/nostr-transport-service` (a full FROST DKG round-trip over the live
relay). The earlier deterministic `LocalNostrEventTransport` remains for tests
and demos without a relay.

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
