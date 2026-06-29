# Examples

## Bitcoin message authorization

```bash
cargo run -p bitcoin-message-signing
```

Runs the high-level SDK helper flow:

- runs local 2-of-3 FROST DKG with `run_local_frost_dkg`
- completes 2-of-3 DKG
- derives the group x-only public key
- derives a Signet Taproot address
- builds a canonical Bitcoin authorization message
- signs the authorization digest with parties 1 and 2 via `sign_digest_with_shares`
- aggregates verified signature shares into a final Schnorr signature object
- verifies the aggregate signature against the group key and digest

This example intentionally does not build or broadcast a Bitcoin transaction. PSBT and transaction signing remain future SDK work.

## Nostr local DKG event transport

```bash
cargo run -p nostr-dkg-cli
```

Runs a local Nostr-shaped DKG flow:

- creates three FROST DKG sessions
- publishes round1 packages as `NostrEnvelopeEvent` values
- drains round1 messages back through the generic transport boundary
- publishes round2 packages as recipient-tagged Nostr envelope events
- selectively drains each recipient's round2 messages
- finalizes all parties and proves the group key matches

This example does not connect to a live relay. It demonstrates the Nostr event mapping and transport boundary that the live relay implementation will use.

## Vault Service

`examples/vault-service` executes the service wiring spec in one process:

- grouped `(1,2,3)-of-(2,3,5)` policy
- HTSS DKG over local Nostr-style transport
- Taproot child address descriptor
- Bitcoin authorization digest
- HTSS signing and aggregate verification

Run:

```bash
cargo run -p vault-service
```

Use this example as the starting point for `NEXT_APP_GUIDE.md`.
