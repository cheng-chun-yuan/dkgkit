# Vault Service Example

Executable service-layer sketch for `docs/SERVICE_WIRING.md`.

This example keeps DKGKit simple and puts product orchestration in the app
layer:

1. Creates a grouped `(1,2,3)-of-(2,3,5)` vault policy.
2. Converts grouped policy into HTSS rank config.
3. Runs HTSS DKG Round 1 and Round 2 through `FrostCoordinator`.
4. Uses `LocalNostrEventTransport` as a local relay-style transport.
5. Finalizes participant derivative shares.
6. Derives a BIP86-style Taproot child address below the DKG account key.
7. Builds a Bitcoin authorization digest.
8. Validates grouped signer policy.
9. Runs HTSS nonce, signature-share, and aggregate verification flow.

Run:

```bash
cargo run -p vault-service
```

This is not a production service. It intentionally omits live relay I/O,
NIP-44 encryption, persistent storage, auth, PSBT construction, Arkade, Silent
Payments, and nested TSS-over-HTSS orchestration.
