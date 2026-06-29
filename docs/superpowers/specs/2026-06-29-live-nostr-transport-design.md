# Live Nostr Transport — Design Spec (Sub-project A)

Date: 2026-06-29
Status: Approved design, pre-implementation
Crate: `dkgkit-nostr`

## Context: the larger goal and its decomposition

The goal is a company MPC wallet on top of DKGKit: create a threshold wallet via
DKG, and spend Bitcoin where a human chooses the signers and signing takes a
single round (nonces pre-committed during idle time). Coordination runs over a
self-hosted Nostr relay, with a self-hostable **coordinator** (holds no key
share) and **per-participant device CLIs** (hold the shares).

This is four subsystems. We build them in order, each independently shippable:

- **A — Live Nostr transport** (this spec). Real relay-backed `Transport`.
- **B — Coordinator + participant CLIs.** DKG → wallet → idle nonce pre-signing →
  one-round threshold signing of an approval digest. Depends on A.
- **C — Bitcoin spend layer.** UTXO/chain source, fee, PSBT, Taproot sighash,
  threshold-sign the sighash, broadcast. Depends on B.

Settled product decisions (apply across A/B/C):

- Self-hosted Nostr relay (e.g. `nostr-rs-relay` via Docker). Transport takes
  relay URLs, so production can point at any relay.
- Coordinator orchestrates sessions/subscriptions and holds **no** key share.
- Default grouped company policy `(1,2,3)-of-(2,3,5)` (C-level / managers /
  operators), configurable.
- Bitcoin **signet** for the spend demo (public faucet + Esplora, no local
  `bitcoind`). Regtest stays an option.
- Pre-signed nonce pool uses **synchronized slots** (see B scope below).

## A. Goal & boundary

Replace the `NotImplemented` stubs in `dkgkit-nostr` (`NostrTransport`) with a
real relay-backed transport that the existing `FrostCoordinator<T: Transport>`
drives **without any change to the `Transport` trait or the coordinator**.

In scope for A:

- Connect to configured self-hosted relays; sign and publish kind-`30333`
  events; subscribe by app + vault tags; decode events back to
  `ProtocolMessage`; dedupe; surface messages through the existing synchronous
  `drain_matching` contract.
- NIP-44 encryption for the **secret** direct messages only
  (`FrostDkgRound2`, `HtssDkgRound2`). Public messages (Round 1 commitments,
  signing nonces, signature shares) are published in clear.
- A participant directory mapping `ParticipantId` to Nostr public key, so the
  transport can encrypt direct messages to the correct recipient.
- Long-lived, idle-friendly subscription scoped at a stable **vault tag**, so one
  connected transport carries DKG, idle nonce pre-commitments, and signing for a
  whole vault across many `session_id`s.

Out of scope for A (deferred to B/C):

- Coordinator process, device-key persistence/CLI, session state machine.
- Pre-sign pool/slot lifecycle and consume-once enforcement (B).
- NIP-29 relay groups, NIP-42 relay auth.
- PSBT/UTXO/broadcast, recovery/reshare (C).

`dkgkit-frost` is **unchanged** by A. (Confirmed: `htss_nonce` takes no digest,
so nonces are precomputable; `htss_sign_share` separates nonce from digest and
computes Birkhoff coefficients from the signer set at sign time.)

## A.1 Architecture — synchronous trait over an async client

`Transport` is synchronous and poll-based (`publish`, `drain_matching`);
`nostr-sdk` is async/tokio. The transport bridges them with a dedicated
background thread that owns the runtime and the nostr `Client`. The outside
stays 100% synchronous, and this works even if the caller (sub-project B) is
itself async — no runtime-nesting hazard.

```text
caller (sync)                       background relay thread (runtime + Client)
─────────────                       ──────────────────────────────────────────
publish(msg) ──Command::Publish───▶ build+sign event, NIP-44 if secret, send_event
                  ◀──ack(Result)───
                                    subscription loop:
                                      relay event ─▶ dedupe by event id
                                                   ─▶ decrypt if marked
                                                   ─▶ envelope tag/content check
                                                   ─▶ push ProtocolMessage
drain_matching ◀── Arc<Mutex<VecDeque<ProtocolMessage>>> ──┘
disconnect() ──Command::Disconnect─▶ unsubscribe, disconnect, thread joins
```

## A.2 Public API (`dkgkit-nostr`, feature `live`)

```rust
/// Maps DKGKit participants to their Nostr public keys.
pub struct ParticipantDirectory { /* BTreeMap<ParticipantId, PublicKey> */ }

pub struct LiveNostrTransportConfig {
    pub relays: Vec<String>,           // e.g. "ws://127.0.0.1:7777"
    pub vault_tag: String,             // stable subscription scope for the vault
    pub self_id: ParticipantId,
    pub keys: Keys,                    // this device's Nostr identity
    pub directory: ParticipantDirectory,
    pub connect_timeout: Duration,
    pub publish_timeout: Duration,
    pub message_ttl: Option<Duration>, // optional NIP-40 expiry tag
}

pub struct LiveNostrTransport { /* cmd_tx, inbound buffer, thread handle, connected */ }

impl LiveNostrTransport {
    pub fn new(cfg: LiveNostrTransportConfig) -> Self;
}

impl Transport for LiveNostrTransport {
    fn connect(&mut self) -> Result<()>;
    fn disconnect(&mut self) -> Result<()>;
    fn publish(&mut self, message: ProtocolMessage) -> Result<()>;
    fn drain_matching(
        &mut self,
        session_id: &SessionId,
        predicate: &mut dyn FnMut(&ProtocolMessage) -> bool,
    ) -> Result<Vec<ProtocolMessage>>;
}
```

`drain_matching` keeps the exact buffer semantics of `MemoryTransport` /
`LocalNostrEventTransport`: drain messages matching the `session_id` and
predicate, retain the rest. Every existing `FrostCoordinator` drain helper works
unchanged.

The existing `NostrEnvelopeEvent` mapping is reused. It gains a `vault` tag
alongside the current `app`, `session`, `sender`, `recipient`, `message_kind`
tags. Routing tags stay in clear even when content is encrypted.

Implementation note: vault/topic tags are added by `LiveNostrTransport` at the
nostr-event layer (`#t = dkgkit:<vault>`); `NostrEnvelopeEvent` is unchanged. The
transport also loops a participant's own broadcast messages into its local
inbound buffer, because a relay does not echo a client's own events back and the
`FrostCoordinator` pattern drains them locally.

Subscription-filter tag (important): NIP-01 relays only index **single-letter**
tags for subscription filters, so a multi-char `vault`/`app` tag is not
filterable on a standard relay. The transport therefore also emits a
single-letter indexed tag — `["t", "dkgkit:<vault_tag>"]` (NIP-12 topic) — used
as the relay-side subscription filter. The human-readable `app`/`vault`/`session`
tags remain for validation and debugging.

## A.3 Message flow and the encryption rule

Publish:

1. Build a `NostrEnvelopeEvent` from the `ProtocolMessage` (reuse existing
   mapping). Add the `vault` tag.
2. If `kind ∈ {HtssDkgRound2, FrostDkgRound2}` **and** `recipient` is set:
   NIP-44-encrypt only the envelope `content` to the recipient's directory
   pubkey; add `["p", recipient_pubkey]` and `["encrypted","nip44"]` tags.
   Otherwise publish `content` in clear.
3. Sign the event with `keys`. Send `Command::Publish` to the thread; block up
   to `publish_timeout` for the ack.

Receive (in the thread):

1. Dedupe by event id (`HashSet<EventId>`).
2. Match `app` + `vault` tags; ignore foreign events.
3. If marked `encrypted`, NIP-44-decrypt `content` with `keys` + sender pubkey.
   If decryption fails (not addressed to me, or spam), drop silently.
4. `to_protocol_message()` re-validates the routing tags against the (decrypted)
   content — preserving the existing tamper check across encryption.
5. Push the `ProtocolMessage` into the inbound buffer.

Pre-committed nonces are ordinary public `HtssSigningNonce` messages — no
encryption, carried at the vault scope so they can be published during idle
time and drained later by slot `session_id`.

## A.4 Concurrency, lifecycle, dedupe

- `connect()` spawns the thread, builds the `Client`, adds relays, connects, and
  subscribes with a `Filter` of kind `30333` and the single-letter indexed topic
  tag `#t = "dkgkit:<vault_tag>"` (see A.2). After draining, the thread filters
  decoded messages locally by the full tag set. It blocks up to `connect_timeout`
  for a ready signal.
- Inbound buffer: `Arc<Mutex<VecDeque<ProtocolMessage>>>`. Dedupe set lives in
  the thread.
- `disconnect()` signals the thread and joins it. `Drop` disconnects
  defensively.

## A.5 Cargo, dependencies, MSRV

- Add optional deps to `dkgkit-nostr`: `nostr-sdk` (includes NIP-44) and
  `tokio` (features `rt`, `sync`, `time`, `macros`), gated behind a
  `live = ["dep:nostr-sdk", "dep:tokio"]` feature. The default build is
  unchanged and dependency-light; crypto crates stay clean.
- At implementation time, resolve the current `nostr-sdk` version with
  `cargo add nostr-sdk`, record the exact resolved version and its MSRV in the
  PR, and bump the workspace `rust-version` (currently `1.76`) to match. This is
  a known, tracked risk: `nostr-sdk`'s MSRV is newer than `1.76`.

## A.6 Error handling

- Connect and publish failures return `DkgKitError::Transport(String)`
  synchronously to the caller.
- Undecryptable, foreign, or malformed inbound events are dropped in the thread
  and never poison the inbound buffer.

## A.7 Testing strategy

Per the project rule, the main agent writes and runs all code; subagents only
produce `.md` plans.

- Always-on unit tests (feature `live`, no network):
  - NIP-44 encrypt → decrypt round-trip between two `Keys`.
  - Only the intended recipient can decrypt; a third key cannot.
  - Dedupe set rejects a repeated event id.
  - `drain_matching` buffer semantics match `MemoryTransport` (drain matches,
    retain the rest; respect session scoping and predicate).
  - Envelope `vault` tag round-trips and tag/content validation still rejects
    mismatches.
- Integration test gated by env var `DKGKIT_TEST_RELAY`
  (e.g. `ws://127.0.0.1:7777` for a local `nostr-rs-relay`): two transports,
  publish → drain round-trip including an encrypted Round 2 and a public nonce.
  Skipped when the env var is unset, so `cargo test --workspace` stays green
  without a relay.
- Validation gate before completion: `cargo fmt --all`,
  `cargo check --workspace`, `cargo test --workspace`, and the same with
  `--features live` for `dkgkit-nostr`.

## A.8 Self-hosted relay example (the coordination channel)

The "channel" for a vault is a self-hosted relay plus the vault topic tag
(`#t = dkgkit:<vault_tag>`) that scopes all of that vault's traffic. A ships two
runnable artifacts so this can be stood up and proven locally:

- `examples/self-hosted-relay/` — `docker-compose.yml` running `nostr-rs-relay`
  on `ws://127.0.0.1:7777`, a `config.toml`, and a `README.md` with start/stop
  instructions and `export DKGKIT_TEST_RELAY=ws://127.0.0.1:7777`.
- `examples/relay-smoke/` — a small Rust binary (added to the workspace) that
  builds a `LiveNostrTransport`, connects to the relay, publishes a message, and
  drains it back. This is the first end-to-end proof of A and is reused by the
  `DKGKIT_TEST_RELAY` integration test.

Run:

```bash
docker compose -f examples/self-hosted-relay/docker-compose.yml up -d
export DKGKIT_TEST_RELAY=ws://127.0.0.1:7777
cargo run -p relay-smoke --features dkgkit-nostr/live
```

## Acceptance criteria for A

- `LiveNostrTransport` implements `Transport` and is driven by an unchanged
  `FrostCoordinator`.
- With a local relay set in `DKGKIT_TEST_RELAY`, a message published by one
  transport is drained by another via the relay.
- A `HtssDkgRound2` message is NIP-44-encrypted on the wire; only the recipient
  decrypts it; routing tags remain readable.
- Public nonce messages publish and drain in clear at the vault scope.
- Default `cargo test --workspace` passes with no relay and no `live` feature.
- No secret material (round-2 plaintext, secret nonces, coefficients) is ever
  logged or published in clear.
- `docker compose -f examples/self-hosted-relay/docker-compose.yml up` starts a
  local relay, and `cargo run -p relay-smoke` publishes and drains a message
  through it.

## Forward scope captured for sub-project B (not built in A)

Pre-signing for one-round, user-chosen-signer threshold signatures:

- **Synchronized slots.** A slot is a shared slot-id. During idle time each
  participant calls `htss_nonce(slot_id, share)` and publishes the public nonce
  commitment (a public `HtssSigningNonce` at the vault scope). The slot-id is
  the `signing_session_id` the eventual signature uses — this is why the existing
  crypto needs no change.
- **Coordinator pool.** The coordinator tracks "ready" slots: slots where enough
  participants to satisfy the grouped policy have committed a nonce.
- **User chooses signers.** At payment time, a human selects the signer set from
  the participants who committed in a ready slot and who satisfy the grouped
  policy. (Valid because the nonce is not bound to the signer set.)
- **One-round signing.** The coordinator publishes the digest; each chosen signer
  performs exactly one action — `htss_sign_share` with its stored secret nonce
  for that slot — then the coordinator aggregates and verifies.
- **Consume-once (critical security requirement).** A pre-committed nonce may be
  used by exactly one signature, then destroyed. Reuse across two different
  digests leaks the secret share and thus the key. Each participant persists its
  secret nonce, marks it spent the instant it signs, and refuses reuse; the
  coordinator never re-offers a spent slot.
