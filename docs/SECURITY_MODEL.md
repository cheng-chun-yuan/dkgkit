# Security Model

DKGKit provides threshold key-management primitives without embedding application custody policy.

## Assumptions

- Applications authenticate participants before trusting protocol messages.
- Transports may be unreliable and adversarial.
- DKG round 2 packages contain secret share material and must be encrypted before use on public transports.
- `LocalKeyShare.secret_share_bytes` is plaintext serialized secret material returned to the application.
- Applications are responsible for encrypting, storing, backing up, and deleting local share material.
- Secret nonce material stays inside `FrostSigningSession` and is consumed by `sign_share`.
- Public nonces and signature shares are safe to transport, but must still be bound to the expected session, signer set, and message digest.

## SDK boundaries

DKGKit does not provide:

- wallet storage
- device keychain integration
- cloud backup
- hardware signer policy
- operator approval workflows
- mainnet custody guarantees

These are application responsibilities.

## Non-goals for 0.1

- Mainnet transaction custody
- PSBT signing
- Wallet recovery
- Automated admin rotation
- Production signer liveness guarantees
