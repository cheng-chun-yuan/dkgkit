# Contributing to DKGKit

DKGKit is intended to be a small, modular, Bitcoin-first threshold cryptography SDK.

## Project rules

- Keep cryptography independent from transports.
- Keep transports independent from UI and wallet policy.
- Prefer small crates and explicit interfaces.
- Do not add mainnet custody claims without release evidence and review.
- Add tests for every public API behavior.

## Local checks

```bash
cargo fmt
cargo check
cargo test
```

## Migration from FrostDAO

Migrate in small reviewed slices:

1. pure Bitcoin helpers
2. core/session types
3. FROST DKG test vectors
4. threshold signing APIs
5. Nostr transport
6. examples

Avoid copying TUI, storage, transaction broadcasting, recovery, reshare, or HTSS into the 0.1 SDK surface.
