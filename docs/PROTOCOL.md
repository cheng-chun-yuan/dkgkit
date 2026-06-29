# DKGKit Protocol Envelope

DKGKit transports move serialized protocol messages. They do not understand FROST, Bitcoin, wallets, storage, or UI policy.

The reusable message envelope lives in `dkgkit-core`:

```rust
pub struct ProtocolMessage {
    pub protocol_version: String,
    pub session_id: SessionId,
    pub sender: ParticipantId,
    pub recipient: Option<ParticipantId>,
    pub kind: ProtocolMessageKind,
    pub payload: Vec<u8>,
}
```

## Protocol version

Current version:

```text
dkgkit/0.1
```

Applications should reject messages with unknown major protocol versions once a stable compatibility policy exists.

## Message kinds

Built-in message kinds:

| Kind | Purpose |
| --- | --- |
| `session_manifest` | Announces or syncs the session manifest. |
| `frost_dkg_round1` | Broadcast FROST DKG round-1 package. |
| `frost_dkg_round2` | Direct FROST DKG round-2 package. |
| `htss_dkg_round1` | Broadcast HTSS DKG polynomial commitments. |
| `htss_dkg_round2` | Direct HTSS DKG derivative share package. |
| `frost_signing_nonce` | Broadcast or direct FROST signing nonce package. |
| `frost_signature_share` | Broadcast or direct FROST signature share package. |
| `htss_signing_nonce` | Broadcast HTSS signing nonce package. |
| `htss_signature_share` | Broadcast HTSS signature share package. |
| `Custom(String)` | Application-specific extension payload. |

## Broadcast vs direct messages

A broadcast message has no recipient:

```rust
ProtocolMessage::broadcast(session_id, sender, kind, payload)
```

A direct message targets one participant:

```rust
ProtocolMessage::direct(session_id, sender, recipient, kind, payload)
```

Transport implementations should preserve `recipient` metadata even when the underlying network is public. Encryption and authentication are application or transport-extension responsibilities, not core responsibilities.

## Payload rule

`payload` is opaque bytes at the transport layer.

Recommended encoding for SDK users:

1. Serialize the typed FROST package with a deterministic encoding.
2. Put only that serialized package in `payload`.
3. Do not put wallet policy, UI text, relay metadata, or Bitcoin RPC data inside FROST payloads.

## Transport rule

A transport implementation may map the envelope to Nostr events, WebRTC data channels, libp2p messages, HTTP requests, or local memory queues, but it must not change DKG or signing semantics.

This keeps the cryptographic layer reusable and prevents Nostr from becoming a hidden dependency of the SDK.

## Default JSON wire encoding

For version `dkgkit/0.1`, the SDK provides JSON helpers for the protocol envelope:

```rust
let bytes = message.encode_json()?;
let message = ProtocolMessage::decode_json(&bytes)?;
```

This is intentionally simple for early adopters, CLIs, demos, and relay debugging. A compact binary codec can be added later without changing the transport boundary because transports still move opaque bytes.

## FROST package helpers

`dkgkit-frost` provides package-specific helpers on top of the generic envelope:

```rust
let message = round1_package.to_protocol_message(session_id)?;
let round1_package = Round1Package::from_protocol_message(&message)?;
```

Use these helpers instead of manually setting `kind`, `sender`, `recipient`, and payload bytes in application code.

Package helpers validate message semantics:

- FROST DKG round 1 is broadcast.
- FROST DKG round 2 is direct.
- HTSS DKG round 1 is broadcast.
- HTSS DKG round 2 is direct.
- FROST and HTSS signing nonces are broadcast.
- FROST and HTSS signature shares are broadcast.
- Envelope sender must match the package sender.
- Direct envelope recipient must match the package recipient.
