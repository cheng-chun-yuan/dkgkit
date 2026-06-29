# FROST API Boundary

`dkgkit-frost` exposes storage-free, transport-free API types for DKG and threshold signing.

## DKG shape

```rust
use dkgkit_sdk::create_frost_session;

let session = create_frost_session("demo", 2, 3, 1)?;
let round1 = session.round1()?;
```

Base TSS DKG is implemented with `schnorr_fun` and runs in memory without storage or transport dependencies. Base TSS signing is implemented with `schnorr_fun`: generate nonces, create signature shares, and aggregate verified shares into a final Schnorr signature.

## Signing shape

```rust
use dkgkit_sdk::{FrostSigningSession, SigningRequest};

let request = SigningRequest::new(
    session_id,
    group_key,
    message_digest,
    signer_set,
    &threshold,
)?;
let signing = FrostSigningSession::new(request);
```

`SigningRequest::new` already validates signer-set shape:

- signer count must meet threshold
- duplicate signer IDs are rejected
- signer IDs cannot exceed participant count

`SigningRequest::new_with_policy` can validate an HTSS-style hierarchical
policy before signing:

```rust
use dkgkit_sdk::{
    HierarchicalThresholdConfig, ParticipantId, RankedParticipant, SigningPolicy,
    validate_hierarchical_signer_set,
};

let policy = SigningPolicy::Hierarchical(HierarchicalThresholdConfig::new(
    3,
    vec![
        RankedParticipant::new(1, 0, Some("admin".to_string()))?,
        RankedParticipant::new(2, 1, Some("finance".to_string()))?,
        RankedParticipant::new(3, 1, Some("ops".to_string()))?,
        RankedParticipant::new(4, 2, Some("member".to_string()))?,
        RankedParticipant::new(5, 2, Some("member".to_string()))?,
    ],
)?);

let accepted = vec![
    ParticipantId::new(1)?,
    ParticipantId::new(2)?,
    ParticipantId::new(3)?,
];
let rejected = vec![
    ParticipantId::new(2)?,
    ParticipantId::new(4)?,
    ParticipantId::new(5)?,
];

if let SigningPolicy::Hierarchical(config) = &policy {
    validate_hierarchical_signer_set(&accepted, config)?;
    assert!(validate_hierarchical_signer_set(&rejected, config).is_err());
}
```

This is signer-set validation for hierarchical signing flows. Birkhoff-based
HTSS DKG and signing primitives are also available for service layers that need
ranked derivative shares.

## Birkhoff Coefficients

`dkgkit-frost` also exposes the interpolation primitive needed for math-level
HTSS signing:

```rust
use dkgkit_sdk::{
    birkhoff_interpolation_coefficients,
    birkhoff_points_from_hierarchical_signer_set,
    HierarchicalThresholdConfig,
    ParticipantId,
    RankedParticipant,
};

let config = HierarchicalThresholdConfig::new(
    3,
    vec![
        RankedParticipant::new(1, 0, Some("admin".to_string()))?,
        RankedParticipant::new(2, 1, Some("finance".to_string()))?,
        RankedParticipant::new(3, 1, Some("ops".to_string()))?,
    ],
)?;

let points = birkhoff_points_from_hierarchical_signer_set(
    &[
        ParticipantId::new(1)?,
        ParticipantId::new(2)?,
        ParticipantId::new(3)?,
    ],
    &config,
)?;
let coefficients = birkhoff_interpolation_coefficients(&points)?;
```

The coefficients reconstruct `f(0)` from derivative observations
`f^(rank_i)(x_i)`. This is the math foundation for HTSS and is used by the
local and distributed HTSS DKG/signing primitives.

Applications that need to keep the signing request and Birkhoff data together
can use `HierarchicalSigningRequest::new`, which validates the rank set and
attaches the interpolation points and coefficients to the underlying
`SigningRequest`.

For local demos and tests, `run_local_htss_keygen`,
`reconstruct_htss_secret_scalar`, and `sign_digest_with_local_htss_shares`
generate derivative shares and reconstruct/sign from a valid HTSS signer set.
This proves the Birkhoff share math end-to-end, but it is not production
threshold signing because the combiner reconstructs the secret scalar.

For a local non-reconstructing signing flow, use `htss_nonce`,
`htss_sign_share`, and `aggregate_htss_signature_shares`, or the convenience
helper `sign_digest_with_local_htss_threshold_shares`. In this path, each signer
uses its own derivative share and Birkhoff coefficient to produce a Schnorr
signature share; the aggregator verifies the final Schnorr signature without
reconstructing the group secret.

## HTSS DKG

`HtssDkgService` exposes the service-facing HTSS DKG flow:

```rust
let service = HtssDkgService::new("vault-dkg", htss_config)?;
let state = service.begin_round1(participant_id)?;
let round1_message = service.round1_message(&state.package)?;
let round2_packages = service.create_round2_packages(&state, &round1_packages)?;
let (group_key, local_share) =
    service.finalize_participant(participant_id, &round1_packages, &round2_for_me)?;
```

The lower-level functions are also exported:

- `htss_dkg_round1`
- `htss_dkg_round2`
- `finalize_htss_dkg`
- `run_distributed_htss_keygen`

Round 1 broadcasts polynomial commitments. Round 2 sends direct derivative
shares:

```text
s_i,j = f_i^(rank_j)(x_j)
```

Finalize verifies every received derivative share against the sender's public
commitments:

```text
s_i,j * G == sum_k falling_factorial(k, rank_j) * x_j^(k-rank_j) * C_i,k
```

Round 2 packages are plaintext secret material at the DKGKit boundary. A
production service must encrypt them before public transport, for example with
NIP-44 over Nostr.

## Grouped Threshold Policy

For organization-style policies such as `(1,2,3)-of-(2,3,5)`, use
`SigningPolicy::Grouped`. This is an exact per-rank quorum policy:

```rust
use dkgkit_sdk::{
    GroupThresholdRequirement, GroupedThresholdConfig, ParticipantId,
    RankedParticipant, SigningPolicy, validate_grouped_threshold_signer_set,
};

let policy = SigningPolicy::Grouped(GroupedThresholdConfig::new(
    vec![
        RankedParticipant::new(1, 0, Some("c-level-a".to_string()))?,
        RankedParticipant::new(2, 0, Some("c-level-b".to_string()))?,
        RankedParticipant::new(3, 1, Some("manager-a".to_string()))?,
        RankedParticipant::new(4, 1, Some("manager-b".to_string()))?,
        RankedParticipant::new(5, 1, Some("manager-c".to_string()))?,
        RankedParticipant::new(6, 2, Some("operator-a".to_string()))?,
        RankedParticipant::new(7, 2, Some("operator-b".to_string()))?,
        RankedParticipant::new(8, 2, Some("operator-c".to_string()))?,
        RankedParticipant::new(9, 2, Some("operator-d".to_string()))?,
        RankedParticipant::new(10, 2, Some("operator-e".to_string()))?,
    ],
    vec![
        GroupThresholdRequirement::new(0, 1, 2)?,
        GroupThresholdRequirement::new(1, 2, 3)?,
        GroupThresholdRequirement::new(2, 3, 5)?,
    ],
)?);

let valid = vec![
    ParticipantId::new(1)?,
    ParticipantId::new(3)?,
    ParticipantId::new(4)?,
    ParticipantId::new(6)?,
    ParticipantId::new(7)?,
    ParticipantId::new(8)?,
];
let invalid = vec![
    ParticipantId::new(1)?,
    ParticipantId::new(3)?,
    ParticipantId::new(6)?,
    ParticipantId::new(7)?,
    ParticipantId::new(8)?,
    ParticipantId::new(9)?,
];

if let SigningPolicy::Grouped(config) = &policy {
    validate_grouped_threshold_signer_set(&valid, config)?;
    assert!(validate_grouped_threshold_signer_set(&invalid, config).is_err());
}
```

Grouped policy combines with the existing FROST signing path by setting the
underlying threshold to the sum of required group quorums. In the example above,
that is a real `6-of-10` FROST signing session plus exact group requirements:
`1-of-2`, `2-of-3`, and `3-of-5`.

Applications can use `GroupedSigningRequest::new` to bundle the validated
grouped config with the underlying `SigningRequest`.

Grouped policies can also be used with local HTSS signing through
`run_local_grouped_htss_keygen` and
`sign_digest_with_local_grouped_htss_threshold_shares`. This enforces the exact
per-rank group requirements before running the HTSS threshold-share signing
flow.

## Protocol message helpers

FROST package types can convert themselves to and from the shared `ProtocolMessage` envelope.

```rust
let round1 = Round1Package {
    participant_id,
    bytes: vec![],
};
let message = round1.to_protocol_message(session_id.clone())?;
let decoded = Round1Package::from_protocol_message(&message)?;
```

The helpers validate envelope semantics before returning a typed package:

- DKG round 1 must be broadcast as `frost_dkg_round1`.
- DKG round 2 must be direct as `frost_dkg_round2`.
- Signing nonces must be broadcast as `frost_signing_nonce`.
- Signature shares must be broadcast as `frost_signature_share`.
- Envelope sender must match the package participant.
- Envelope recipient must match direct package recipient.
- Signing package session IDs must match the envelope session ID.

This lets transports remain simple byte movers while SDK users work with typed FROST packages.

## In-memory TSS DKG flow

```rust
let alice = create_frost_session("demo", 2, 3, 1)?;
let bob = create_frost_session("demo", 2, 3, 2)?;
let carol = create_frost_session("demo", 2, 3, 3)?;

let round1 = vec![alice.round1()?, bob.round1()?, carol.round1()?];
let round2 = vec![
    alice.round2(&round1)?,
    bob.round2(&round1)?,
    carol.round2(&round1)?,
]
.into_iter()
.flatten()
.collect::<Vec<_>>();

let alice_share = alice.finalize(&round2)?;
let bob_share = bob.finalize(&round2)?;
let carol_share = carol.finalize(&round2)?;

assert_eq!(alice_share.group_key, bob_share.group_key);
assert_eq!(bob_share.group_key, carol_share.group_key);
```

Round 2 packages contain secret share material and must be encrypted by applications before use on public transports. DKGKit keeps this responsibility outside the cryptographic core so Nostr, WebRTC, and other transports can choose their own encryption layer.

## In-memory signing flow

```rust
let request = SigningRequest::new(
    SessionId::new("sign-demo")?,
    alice_share.group_key.clone(),
    message_digest,
    vec![ParticipantId::new(1)?, ParticipantId::new(2)?],
    &ThresholdConfig::new(2, 3)?,
)?;

let alice_signing = FrostSigningSession::new(request.clone());
let bob_signing = FrostSigningSession::new(request.clone());
let aggregator = FrostSigningSession::new(request);

let nonces = vec![
    alice_signing.nonce(&alice_share)?,
    bob_signing.nonce(&bob_share)?,
];

let shares = vec![
    alice_signing.sign_share(&alice_share, &nonces)?,
    bob_signing.sign_share(&bob_share, &nonces)?,
];

let signature = aggregator.aggregate(&shares)?;
```

`SignatureSharePackage` carries the signer public nonce with the share so any aggregator can verify and combine shares without hidden storage. Secret nonce material stays inside the signer session and is consumed when `sign_share` is called.
