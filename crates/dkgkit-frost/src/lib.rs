//! FROST API surface for DKGKit.
//!
//! This crate defines the public DKG/signing boundary used by applications and
//! transports. The API is storage-free, transport-free, and Bitcoin-agnostic.
//! Base TSS DKG and signing are backed by `schnorr_fun`.

use dkgkit_core::{
    DkgKitError, GroupedThresholdConfig, HierarchicalThresholdConfig, ParticipantId,
    ProtocolMessage, ProtocolMessageKind, Result, SessionId, SigningPolicy, ThresholdConfig,
};
use rand_chacha::ChaCha20Rng;
use schnorr_fun::binonce::{Nonce, NonceKeyPair};
use schnorr_fun::frost::{
    self,
    chilldkg::simplepedpop::{self, Contributor, Coordinator, KeygenInput},
    PairedSecretShare, SharedKey,
};
use schnorr_fun::Message;
use secp256kfun::op;
use secp256kfun::prelude::*;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::Sha256;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DkgSessionConfig {
    pub session_id: SessionId,
    pub threshold: ThresholdConfig,
    pub participant_id: ParticipantId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Round1Package {
    pub participant_id: ParticipantId,
    /// Serialized `schnorr_fun::frost::chilldkg::simplepedpop::KeygenInput`.
    pub bytes: Vec<u8>,
}

impl Round1Package {
    pub fn to_protocol_message(&self, session_id: SessionId) -> Result<ProtocolMessage> {
        Ok(ProtocolMessage::broadcast(
            session_id,
            self.participant_id,
            ProtocolMessageKind::FrostDkgRound1,
            encode_payload(self)?,
        ))
    }

    pub fn from_protocol_message(message: &ProtocolMessage) -> Result<Self> {
        require_kind(message, ProtocolMessageKind::FrostDkgRound1)?;
        require_broadcast(message)?;
        let package: Self = decode_payload(&message.payload)?;
        if package.participant_id != message.sender {
            return Err(DkgKitError::Protocol(format!(
                "round1 sender mismatch: envelope={}, payload={}",
                message.sender.0, package.participant_id.0
            )));
        }
        Ok(package)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Round2Package {
    pub sender: ParticipantId,
    pub recipient: ParticipantId,
    /// Serialized secret share sent from `sender` to `recipient`.
    pub bytes: Vec<u8>,
}

impl Round2Package {
    pub fn to_protocol_message(&self, session_id: SessionId) -> Result<ProtocolMessage> {
        Ok(ProtocolMessage::direct(
            session_id,
            self.sender,
            self.recipient,
            ProtocolMessageKind::FrostDkgRound2,
            encode_payload(self)?,
        ))
    }

    pub fn from_protocol_message(message: &ProtocolMessage) -> Result<Self> {
        require_kind(message, ProtocolMessageKind::FrostDkgRound2)?;
        let package: Self = decode_payload(&message.payload)?;
        if package.sender != message.sender {
            return Err(DkgKitError::Protocol(format!(
                "round2 sender mismatch: envelope={}, payload={}",
                message.sender.0, package.sender.0
            )));
        }
        if Some(package.recipient) != message.recipient {
            return Err(DkgKitError::Protocol(
                "round2 recipient mismatch".to_string(),
            ));
        }
        Ok(package)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupKey {
    pub xonly_public_key: [u8; 32],
    /// Serialized `schnorr_fun::frost::SharedKey<EvenY>` used for FROST share verification.
    pub verification_key_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalKeyShare {
    pub participant_id: ParticipantId,
    pub group_key: GroupKey,
    /// Serialized paired secret share. This is plaintext secret material; applications must encrypt it at rest.
    pub secret_share_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningRequest {
    pub session_id: SessionId,
    pub group_key: GroupKey,
    pub message_digest: [u8; 32],
    pub signer_set: Vec<ParticipantId>,
}

impl SigningRequest {
    pub fn new(
        session_id: SessionId,
        group_key: GroupKey,
        message_digest: [u8; 32],
        signer_set: Vec<ParticipantId>,
        threshold: &ThresholdConfig,
    ) -> Result<Self> {
        validate_signer_set(&signer_set, threshold)?;
        Ok(Self {
            session_id,
            group_key,
            message_digest,
            signer_set,
        })
    }

    pub fn new_with_policy(
        session_id: SessionId,
        group_key: GroupKey,
        message_digest: [u8; 32],
        signer_set: Vec<ParticipantId>,
        policy: &SigningPolicy,
    ) -> Result<Self> {
        validate_signer_set_with_policy(&signer_set, policy)?;
        Ok(Self {
            session_id,
            group_key,
            message_digest,
            signer_set,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HierarchicalSigningRequest {
    pub request: SigningRequest,
    pub points: Vec<BirkhoffPoint>,
    pub coefficients: Vec<BirkhoffCoefficient>,
}

impl HierarchicalSigningRequest {
    pub fn new(
        session_id: SessionId,
        group_key: GroupKey,
        message_digest: [u8; 32],
        signer_set: Vec<ParticipantId>,
        config: &HierarchicalThresholdConfig,
    ) -> Result<Self> {
        let points = birkhoff_points_from_hierarchical_signer_set(&signer_set, config)?;
        let coefficients = birkhoff_interpolation_coefficients(&points)?;
        let request = SigningRequest::new_with_policy(
            session_id,
            group_key,
            message_digest,
            signer_set,
            &SigningPolicy::Hierarchical(config.clone()),
        )?;
        Ok(Self {
            request,
            points,
            coefficients,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupedSigningRequest {
    pub request: SigningRequest,
    pub config: GroupedThresholdConfig,
}

impl GroupedSigningRequest {
    pub fn new(
        session_id: SessionId,
        group_key: GroupKey,
        message_digest: [u8; 32],
        signer_set: Vec<ParticipantId>,
        config: &GroupedThresholdConfig,
    ) -> Result<Self> {
        let request = SigningRequest::new_with_policy(
            session_id,
            group_key,
            message_digest,
            signer_set,
            &SigningPolicy::Grouped(config.clone()),
        )?;
        Ok(Self {
            request,
            config: config.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoncePackage {
    pub participant_id: ParticipantId,
    pub signing_session_id: SessionId,
    pub public_nonce_bytes: Vec<u8>,
}

impl NoncePackage {
    pub fn to_protocol_message(&self) -> Result<ProtocolMessage> {
        Ok(ProtocolMessage::broadcast(
            self.signing_session_id.clone(),
            self.participant_id,
            ProtocolMessageKind::FrostSigningNonce,
            encode_payload(self)?,
        ))
    }

    pub fn from_protocol_message(message: &ProtocolMessage) -> Result<Self> {
        require_kind(message, ProtocolMessageKind::FrostSigningNonce)?;
        require_broadcast(message)?;
        let package: Self = decode_payload(&message.payload)?;
        if package.participant_id != message.sender {
            return Err(DkgKitError::Protocol(format!(
                "nonce sender mismatch: envelope={}, payload={}",
                message.sender.0, package.participant_id.0
            )));
        }
        if package.signing_session_id != message.session_id {
            return Err(DkgKitError::Protocol("nonce session mismatch".to_string()));
        }
        Ok(package)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureSharePackage {
    pub participant_id: ParticipantId,
    pub signing_session_id: SessionId,
    pub public_nonce_bytes: Vec<u8>,
    pub signature_share_bytes: Vec<u8>,
}

impl SignatureSharePackage {
    pub fn to_protocol_message(&self) -> Result<ProtocolMessage> {
        Ok(ProtocolMessage::broadcast(
            self.signing_session_id.clone(),
            self.participant_id,
            ProtocolMessageKind::FrostSignatureShare,
            encode_payload(self)?,
        ))
    }

    pub fn from_protocol_message(message: &ProtocolMessage) -> Result<Self> {
        require_kind(message, ProtocolMessageKind::FrostSignatureShare)?;
        require_broadcast(message)?;
        let package: Self = decode_payload(&message.payload)?;
        if package.participant_id != message.sender {
            return Err(DkgKitError::Protocol(format!(
                "signature share sender mismatch: envelope={}, payload={}",
                message.sender.0, package.participant_id.0
            )));
        }
        if package.signing_session_id != message.session_id {
            return Err(DkgKitError::Protocol(
                "signature share session mismatch".to_string(),
            ));
        }
        Ok(package)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregateSignature {
    /// Serialized `schnorr_fun::Signature`.
    pub signature_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BirkhoffPoint {
    pub participant_id: ParticipantId,
    pub x: u16,
    /// Derivative order for this interpolation condition. Rank 0 maps to a
    /// normal evaluation, rank 1 to a first derivative, and so on.
    pub derivative_order: u16,
}

impl BirkhoffPoint {
    pub fn new(participant_id: ParticipantId, x: u16, derivative_order: u16) -> Result<Self> {
        if x == 0 {
            return Err(DkgKitError::Protocol(
                "Birkhoff x-coordinate cannot be zero".to_string(),
            ));
        }
        Ok(Self {
            participant_id,
            x,
            derivative_order,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BirkhoffCoefficient {
    pub participant_id: ParticipantId,
    pub derivative_order: u16,
    pub coefficient_bytes: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HtssLocalKeyShare {
    pub participant_id: ParticipantId,
    pub rank: u16,
    /// Scalar bytes for the derivative share `f^(rank)(x)`. This is plaintext
    /// secret material; applications must encrypt it at rest.
    pub share_value_bytes: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HtssLocalKeySet {
    pub group_key: GroupKey,
    pub shares: Vec<HtssLocalKeyShare>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HtssDkgRound1State {
    pub package: HtssDkgRound1Package,
    /// Local-only polynomial coefficients. This must not be sent to other
    /// participants or encoded into protocol messages.
    pub secret_coefficient_bytes: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HtssDkgRound1Package {
    pub participant_id: ParticipantId,
    pub rank: u16,
    /// Compressed public commitments `[a_0*G, a_1*G, ...]`.
    pub commitment_bytes: Vec<Vec<u8>>,
}

impl HtssDkgRound1Package {
    pub fn to_protocol_message(&self, session_id: SessionId) -> Result<ProtocolMessage> {
        Ok(ProtocolMessage::broadcast(
            session_id,
            self.participant_id,
            ProtocolMessageKind::HtssDkgRound1,
            encode_payload(self)?,
        ))
    }

    pub fn from_protocol_message(message: &ProtocolMessage) -> Result<Self> {
        require_kind(message, ProtocolMessageKind::HtssDkgRound1)?;
        require_broadcast(message)?;
        let package: Self = decode_payload(&message.payload)?;
        if package.participant_id != message.sender {
            return Err(DkgKitError::Protocol(format!(
                "HTSS DKG round1 sender mismatch: envelope={}, payload={}",
                message.sender.0, package.participant_id.0
            )));
        }
        Ok(package)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HtssDkgRound2Package {
    pub sender: ParticipantId,
    pub recipient: ParticipantId,
    pub recipient_rank: u16,
    /// Scalar bytes for `f_sender^(recipient_rank)(recipient_x)`.
    pub share_value_bytes: [u8; 32],
}

impl HtssDkgRound2Package {
    pub fn to_protocol_message(&self, session_id: SessionId) -> Result<ProtocolMessage> {
        Ok(ProtocolMessage::direct(
            session_id,
            self.sender,
            self.recipient,
            ProtocolMessageKind::HtssDkgRound2,
            encode_payload(self)?,
        ))
    }

    pub fn from_protocol_message(message: &ProtocolMessage) -> Result<Self> {
        require_kind(message, ProtocolMessageKind::HtssDkgRound2)?;
        let package: Self = decode_payload(&message.payload)?;
        if package.sender != message.sender {
            return Err(DkgKitError::Protocol(format!(
                "HTSS DKG round2 sender mismatch: envelope={}, payload={}",
                message.sender.0, package.sender.0
            )));
        }
        if Some(package.recipient) != message.recipient {
            return Err(DkgKitError::Protocol(
                "HTSS DKG round2 recipient mismatch".to_string(),
            ));
        }
        Ok(package)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HtssNoncePackage {
    pub participant_id: ParticipantId,
    pub signing_session_id: SessionId,
    pub public_nonce_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HtssLocalNonce {
    pub package: HtssNoncePackage,
    /// Local-only nonce scalar. This must not be sent to other participants or
    /// encoded into protocol messages.
    pub secret_nonce_bytes: [u8; 32],
}

impl HtssNoncePackage {
    pub fn to_protocol_message(&self) -> Result<ProtocolMessage> {
        Ok(ProtocolMessage::broadcast(
            self.signing_session_id.clone(),
            self.participant_id,
            ProtocolMessageKind::HtssSigningNonce,
            encode_payload(self)?,
        ))
    }

    pub fn from_protocol_message(message: &ProtocolMessage) -> Result<Self> {
        require_kind(message, ProtocolMessageKind::HtssSigningNonce)?;
        require_broadcast(message)?;
        let package: Self = decode_payload(&message.payload)?;
        if package.participant_id != message.sender {
            return Err(DkgKitError::Protocol(format!(
                "HTSS nonce sender mismatch: envelope={}, payload={}",
                message.sender.0, package.participant_id.0
            )));
        }
        if package.signing_session_id != message.session_id {
            return Err(DkgKitError::Protocol(
                "HTSS nonce session mismatch".to_string(),
            ));
        }
        nonce_public_nonce_bytes(&package)?;
        Ok(package)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HtssSignatureSharePackage {
    pub participant_id: ParticipantId,
    pub signing_session_id: SessionId,
    pub signature_share_bytes: [u8; 32],
}

impl HtssSignatureSharePackage {
    pub fn to_protocol_message(&self) -> Result<ProtocolMessage> {
        Ok(ProtocolMessage::broadcast(
            self.signing_session_id.clone(),
            self.participant_id,
            ProtocolMessageKind::HtssSignatureShare,
            encode_payload(self)?,
        ))
    }

    pub fn from_protocol_message(message: &ProtocolMessage) -> Result<Self> {
        require_kind(message, ProtocolMessageKind::HtssSignatureShare)?;
        require_broadcast(message)?;
        let package: Self = decode_payload(&message.payload)?;
        if package.participant_id != message.sender {
            return Err(DkgKitError::Protocol(format!(
                "HTSS signature share sender mismatch: envelope={}, payload={}",
                message.sender.0, package.participant_id.0
            )));
        }
        if package.signing_session_id != message.session_id {
            return Err(DkgKitError::Protocol(
                "HTSS signature share session mismatch".to_string(),
            ));
        }
        Ok(package)
    }
}

impl AggregateSignature {
    pub fn new(signature_bytes: Vec<u8>) -> Result<Self> {
        if signature_bytes.is_empty() {
            return Err(DkgKitError::Protocol(
                "aggregate signature cannot be empty".to_string(),
            ));
        }
        Ok(Self { signature_bytes })
    }
}

pub fn encode_payload<T: Serialize>(payload: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(payload).map_err(|err| DkgKitError::Serialization(err.to_string()))
}

pub fn decode_payload<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|err| DkgKitError::Serialization(err.to_string()))
}

fn encode_binary<T: Serialize>(payload: &T) -> Result<Vec<u8>> {
    bincode::serialize(payload).map_err(|err| DkgKitError::Serialization(err.to_string()))
}

fn decode_binary<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    bincode::deserialize(bytes).map_err(|err| DkgKitError::Serialization(err.to_string()))
}

fn require_kind(message: &ProtocolMessage, expected: ProtocolMessageKind) -> Result<()> {
    if message.kind != expected {
        return Err(DkgKitError::Protocol(format!(
            "unexpected protocol message kind: expected {}, got {}",
            expected.as_str(),
            message.kind.as_str()
        )));
    }
    Ok(())
}

fn require_broadcast(message: &ProtocolMessage) -> Result<()> {
    if message.recipient.is_some() {
        return Err(DkgKitError::Protocol(
            "expected broadcast protocol message".to_string(),
        ));
    }
    Ok(())
}

pub fn validate_signer_set(signers: &[ParticipantId], threshold: &ThresholdConfig) -> Result<()> {
    if signers.len() < threshold.threshold as usize {
        return Err(DkgKitError::Protocol(format!(
            "not enough signers: have {}, need {}",
            signers.len(),
            threshold.threshold
        )));
    }
    let mut seen = BTreeSet::new();
    for signer in signers {
        if signer.0 > threshold.participants {
            return Err(DkgKitError::ParticipantOutOfRange {
                participant_id: signer.0,
                participants: threshold.participants,
            });
        }
        if !seen.insert(signer.0) {
            return Err(DkgKitError::DuplicateParticipantId(signer.0));
        }
    }
    Ok(())
}

pub fn validate_hierarchical_signer_set(
    signers: &[ParticipantId],
    config: &HierarchicalThresholdConfig,
) -> Result<()> {
    validate_signer_set(signers, &config.threshold_config()?)?;
    let mut ranks = Vec::with_capacity(signers.len());
    for signer in signers {
        let rank = config
            .rank_of(*signer)
            .ok_or(DkgKitError::MissingRankedParticipant(signer.0))?;
        ranks.push(rank.0);
    }
    ranks.sort_unstable();
    for (index, rank) in ranks
        .into_iter()
        .take(config.threshold as usize)
        .enumerate()
    {
        if rank as usize > index {
            return Err(DkgKitError::Protocol(format!(
                "hierarchical signer set violates Birkhoff rank rule at position {index}: rank {rank} > {index}"
            )));
        }
    }
    Ok(())
}

pub fn validate_grouped_threshold_signer_set(
    signers: &[ParticipantId],
    config: &GroupedThresholdConfig,
) -> Result<()> {
    validate_signer_set(signers, &config.threshold_config()?)?;

    let mut selected_by_rank = BTreeMap::<u16, u16>::new();
    for signer in signers {
        let rank = config
            .rank_of(*signer)
            .ok_or(DkgKitError::MissingRankedParticipant(signer.0))?;
        *selected_by_rank.entry(rank.0).or_default() += 1;
    }

    for requirement in &config.requirements {
        let selected = selected_by_rank
            .get(&requirement.rank.0)
            .copied()
            .unwrap_or_default();
        if selected < requirement.required {
            return Err(DkgKitError::Protocol(format!(
                "grouped threshold rank {} needs {} signer(s), got {}",
                requirement.rank.0, requirement.required, selected
            )));
        }
    }

    Ok(())
}

pub fn validate_signer_set_with_policy(
    signers: &[ParticipantId],
    policy: &SigningPolicy,
) -> Result<()> {
    match policy {
        SigningPolicy::Threshold(threshold) => validate_signer_set(signers, threshold),
        SigningPolicy::Hierarchical(config) => validate_hierarchical_signer_set(signers, config),
        SigningPolicy::Grouped(config) => validate_grouped_threshold_signer_set(signers, config),
    }
}

type PublicScalar = Scalar<Public, Zero>;

pub fn birkhoff_points_from_hierarchical_signer_set(
    signers: &[ParticipantId],
    config: &HierarchicalThresholdConfig,
) -> Result<Vec<BirkhoffPoint>> {
    validate_hierarchical_signer_set(signers, config)?;
    signers
        .iter()
        .map(|signer| {
            let rank = config
                .rank_of(*signer)
                .ok_or(DkgKitError::MissingRankedParticipant(signer.0))?;
            BirkhoffPoint::new(*signer, signer.0, rank.0)
        })
        .collect()
}

/// Compute Birkhoff interpolation coefficients for reconstructing `f(0)`.
///
/// Each point represents one observed derivative condition `f^(r)(x)`. The
/// returned coefficients satisfy:
///
/// `f(0) = sum_i coefficient_i * f^(r_i)(x_i)`
///
/// for polynomials whose degree is lower than `points.len()`, when the Birkhoff
/// system is nonsingular.
pub fn birkhoff_interpolation_coefficients(
    points: &[BirkhoffPoint],
) -> Result<Vec<BirkhoffCoefficient>> {
    if points.is_empty() {
        return Err(DkgKitError::Protocol(
            "Birkhoff point set cannot be empty".to_string(),
        ));
    }
    let n = points.len();
    let matrix = birkhoff_matrix(points)?;
    let mut transpose = vec![vec![scalar_zero(); n]; n];
    for row in 0..n {
        for col in 0..n {
            transpose[col][row] = matrix[row][col];
        }
    }
    let mut target = vec![scalar_zero(); n];
    target[0] = scalar_one();
    let coefficients = solve_scalar_system(transpose, target)?;
    Ok(points
        .iter()
        .zip(coefficients)
        .map(|(point, coefficient)| BirkhoffCoefficient {
            participant_id: point.participant_id,
            derivative_order: point.derivative_order,
            coefficient_bytes: coefficient.to_bytes(),
        })
        .collect())
}

/// Generate local HTSS shares from one in-process dealer.
///
/// This is useful for tests, demos, and as the math target for a future
/// distributed HTSS DKG. It is not a production DKG ceremony: the dealer sees
/// the polynomial and every participant share.
pub fn run_local_htss_keygen(config: &HierarchicalThresholdConfig) -> Result<HtssLocalKeySet> {
    let mut rng = rand::thread_rng();
    let schnorr = schnorr_fun::new_with_deterministic_nonces::<Sha256>();
    let initial_secret = Scalar::<Secret, NonZero>::random(&mut rng);
    let keypair = schnorr.new_keypair(initial_secret);
    let secret = keypair.secret_key().public().mark_zero();

    let mut polynomial = Vec::with_capacity(config.threshold as usize);
    polynomial.push(secret);
    for _ in 1..config.threshold {
        polynomial.push(
            Scalar::<Secret, NonZero>::random(&mut rng)
                .public()
                .mark_zero(),
        );
    }

    let shares = config
        .participants
        .iter()
        .map(|participant| {
            let value =
                polynomial_derivative_value(&polynomial, participant.id.0, participant.rank.0);
            HtssLocalKeyShare {
                participant_id: participant.id,
                rank: participant.rank.0,
                share_value_bytes: value.to_bytes(),
            }
        })
        .collect();

    Ok(HtssLocalKeySet {
        group_key: GroupKey {
            xonly_public_key: keypair.public_key().to_xonly_bytes(),
            verification_key_bytes: Vec::new(),
        },
        shares,
    })
}

pub fn htss_dkg_round1(
    participant_id: ParticipantId,
    config: &HierarchicalThresholdConfig,
) -> Result<HtssDkgRound1State> {
    let rank = config
        .rank_of(participant_id)
        .ok_or(DkgKitError::MissingRankedParticipant(participant_id.0))?;
    let mut rng = rand::thread_rng();
    let mut secret_coefficient_bytes = Vec::with_capacity(config.threshold as usize);
    let mut commitment_bytes = Vec::with_capacity(config.threshold as usize);
    for _ in 0..config.threshold {
        let coefficient = Scalar::<Secret, NonZero>::random(&mut rng);
        let commitment = g!(coefficient * G).normalize();
        secret_coefficient_bytes.push(coefficient.to_bytes());
        commitment_bytes.push(commitment.to_bytes().to_vec());
    }
    Ok(HtssDkgRound1State {
        package: HtssDkgRound1Package {
            participant_id,
            rank: rank.0,
            commitment_bytes,
        },
        secret_coefficient_bytes,
    })
}

pub fn htss_dkg_round2(
    state: &HtssDkgRound1State,
    round1_packages: &[HtssDkgRound1Package],
    config: &HierarchicalThresholdConfig,
) -> Result<Vec<HtssDkgRound2Package>> {
    validate_htss_dkg_round1_set(round1_packages, config)?;
    if !round1_packages
        .iter()
        .any(|package| package.participant_id == state.package.participant_id)
    {
        return Err(DkgKitError::Protocol(format!(
            "missing own HTSS DKG round1 package for participant {}",
            state.package.participant_id.0
        )));
    }
    if state.secret_coefficient_bytes.len() != config.threshold as usize {
        return Err(DkgKitError::Protocol(format!(
            "HTSS DKG contributor {} has {} coefficients, expected {}",
            state.package.participant_id.0,
            state.secret_coefficient_bytes.len(),
            config.threshold
        )));
    }
    let coefficients = state
        .secret_coefficient_bytes
        .iter()
        .map(|bytes| {
            Scalar::<Public, Zero>::from_bytes(*bytes).ok_or_else(|| {
                DkgKitError::Protocol(format!(
                    "invalid HTSS DKG coefficient for participant {}",
                    state.package.participant_id.0
                ))
            })
        })
        .collect::<Result<Vec<_>>>()?;

    config
        .participants
        .iter()
        .map(|recipient| {
            let share_value =
                polynomial_derivative_value(&coefficients, recipient.id.0, recipient.rank.0);
            Ok(HtssDkgRound2Package {
                sender: state.package.participant_id,
                recipient: recipient.id,
                recipient_rank: recipient.rank.0,
                share_value_bytes: share_value.to_bytes(),
            })
        })
        .collect()
}

pub fn finalize_htss_dkg(
    participant_id: ParticipantId,
    round1_packages: &[HtssDkgRound1Package],
    round2_packages: &[HtssDkgRound2Package],
    config: &HierarchicalThresholdConfig,
) -> Result<(GroupKey, HtssLocalKeyShare)> {
    let rank = config
        .rank_of(participant_id)
        .ok_or(DkgKitError::MissingRankedParticipant(participant_id.0))?;
    validate_htss_dkg_round1_set(round1_packages, config)?;
    validate_htss_dkg_round2_set(participant_id, round2_packages, config)?;

    let round1_by_sender = round1_packages
        .iter()
        .map(|package| (package.participant_id, package))
        .collect::<BTreeMap<_, _>>();
    let mut share_value = scalar_zero();
    for package in round2_packages {
        let round1 = round1_by_sender
            .get(&package.sender)
            .ok_or(DkgKitError::MissingRankedParticipant(package.sender.0))?;
        verify_htss_dkg_derivative_share(package, round1)?;
        let contribution = Scalar::<Public, Zero>::from_bytes(package.share_value_bytes)
            .ok_or_else(|| {
                DkgKitError::Protocol(format!(
                    "invalid HTSS DKG round2 share from participant {}",
                    package.sender.0
                ))
            })?;
        share_value = scalar_add(share_value, contribution);
    }

    let (xonly_public_key, negated) = htss_dkg_group_xonly_public_key(round1_packages)?;
    if negated {
        share_value = scalar_sub(scalar_zero(), share_value);
    }
    Ok((
        GroupKey {
            xonly_public_key,
            verification_key_bytes: Vec::new(),
        },
        HtssLocalKeyShare {
            participant_id,
            rank: rank.0,
            share_value_bytes: share_value.to_bytes(),
        },
    ))
}

pub fn run_distributed_htss_keygen(
    config: &HierarchicalThresholdConfig,
) -> Result<HtssLocalKeySet> {
    let states = config
        .participants
        .iter()
        .map(|participant| htss_dkg_round1(participant.id, config))
        .collect::<Result<Vec<_>>>()?;
    let round1_packages = states
        .iter()
        .map(|state| state.package.clone())
        .collect::<Vec<_>>();
    let round2_packages = states
        .iter()
        .map(|state| htss_dkg_round2(state, &round1_packages, config))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    let mut group_key = None::<GroupKey>;
    let mut shares = Vec::with_capacity(config.participants.len());
    for participant in &config.participants {
        let packages_for_participant = round2_packages
            .iter()
            .filter(|package| package.recipient == participant.id)
            .cloned()
            .collect::<Vec<_>>();
        let (participant_group_key, share) = finalize_htss_dkg(
            participant.id,
            &round1_packages,
            &packages_for_participant,
            config,
        )?;
        match &group_key {
            Some(existing)
                if existing.xonly_public_key != participant_group_key.xonly_public_key =>
            {
                return Err(DkgKitError::Protocol(
                    "HTSS DKG participants derived different group keys".to_string(),
                ));
            }
            None => group_key = Some(participant_group_key),
            _ => {}
        }
        shares.push(share);
    }

    Ok(HtssLocalKeySet {
        group_key: group_key
            .ok_or_else(|| DkgKitError::Protocol("missing HTSS DKG group key".to_string()))?,
        shares,
    })
}

pub fn reconstruct_htss_secret_scalar(
    shares: &[HtssLocalKeyShare],
    signer_set: &[ParticipantId],
    config: &HierarchicalThresholdConfig,
) -> Result<[u8; 32]> {
    let points = birkhoff_points_from_hierarchical_signer_set(signer_set, config)?;
    let coefficients = birkhoff_interpolation_coefficients(&points)?;
    let share_map = shares
        .iter()
        .map(|share| (share.participant_id, share))
        .collect::<BTreeMap<_, _>>();

    let mut secret = scalar_zero();
    for coefficient in coefficients {
        let share = share_map.get(&coefficient.participant_id).ok_or(
            DkgKitError::MissingRankedParticipant(coefficient.participant_id.0),
        )?;
        if share.rank != coefficient.derivative_order {
            return Err(DkgKitError::Protocol(format!(
                "HTSS share rank mismatch for participant {}: share rank {}, coefficient rank {}",
                share.participant_id.0, share.rank, coefficient.derivative_order
            )));
        }
        let share_value =
            Scalar::<Public, Zero>::from_bytes(share.share_value_bytes).ok_or_else(|| {
                DkgKitError::Protocol(format!(
                    "invalid HTSS share scalar for participant {}",
                    share.participant_id.0
                ))
            })?;
        let coefficient_value = Scalar::<Public, Zero>::from_bytes(coefficient.coefficient_bytes)
            .ok_or_else(|| {
            DkgKitError::Protocol(format!(
                "invalid Birkhoff coefficient scalar for participant {}",
                coefficient.participant_id.0
            ))
        })?;
        secret = scalar_add(secret, scalar_mul(coefficient_value, share_value));
    }

    Ok(secret.to_bytes())
}

/// Sign by reconstructing the HTSS secret locally from valid derivative shares.
///
/// This proves the HTSS share math end-to-end for local demos. It is not a
/// production threshold-signing protocol because the combiner reconstructs the
/// secret scalar.
pub fn sign_digest_with_local_htss_shares(
    group_key: &GroupKey,
    digest: [u8; 32],
    shares: &[HtssLocalKeyShare],
    signer_set: &[ParticipantId],
    config: &HierarchicalThresholdConfig,
) -> Result<AggregateSignature> {
    let secret_bytes = reconstruct_htss_secret_scalar(shares, signer_set, config)?;
    let secret = Scalar::<Secret, Zero>::from_bytes(secret_bytes)
        .and_then(|scalar| scalar.non_zero())
        .ok_or_else(|| DkgKitError::Protocol("reconstructed HTSS secret is zero".to_string()))?;
    let schnorr = schnorr_fun::new_with_deterministic_nonces::<Sha256>();
    let keypair = schnorr.new_keypair(secret);
    if keypair.public_key().to_xonly_bytes() != group_key.xonly_public_key {
        return Err(DkgKitError::Protocol(
            "reconstructed HTSS secret does not match group key".to_string(),
        ));
    }
    let signature = schnorr.sign(&keypair, frost_message(&digest));
    AggregateSignature::new(signature.to_bytes().to_vec())
}

pub fn htss_nonce(
    signing_session_id: SessionId,
    local_share: &HtssLocalKeyShare,
) -> Result<HtssLocalNonce> {
    let nonce = Scalar::<Secret, NonZero>::random(&mut rand::thread_rng());
    let public_nonce = g!(nonce * G).normalize();
    Ok(HtssLocalNonce {
        package: HtssNoncePackage {
            participant_id: local_share.participant_id,
            signing_session_id,
            public_nonce_bytes: public_nonce.to_bytes().to_vec(),
        },
        secret_nonce_bytes: nonce.to_bytes(),
    })
}

pub fn htss_sign_share(
    group_key: &GroupKey,
    digest: [u8; 32],
    local_share: &HtssLocalKeyShare,
    nonce: &HtssLocalNonce,
    nonces: &[HtssNoncePackage],
    signer_set: &[ParticipantId],
    config: &HierarchicalThresholdConfig,
) -> Result<HtssSignatureSharePackage> {
    if local_share.participant_id != nonce.package.participant_id {
        return Err(DkgKitError::Protocol(format!(
            "HTSS nonce participant mismatch: share {}, nonce {}",
            local_share.participant_id.0, nonce.package.participant_id.0
        )));
    }
    if !signer_set.contains(&local_share.participant_id) {
        return Err(DkgKitError::Protocol(format!(
            "participant {} is not in HTSS signer set",
            local_share.participant_id.0
        )));
    }

    let coefficients = birkhoff_interpolation_coefficients(
        &birkhoff_points_from_hierarchical_signer_set(signer_set, config)?,
    )?;
    let coefficient = coefficients
        .iter()
        .find(|coefficient| coefficient.participant_id == local_share.participant_id)
        .ok_or(DkgKitError::MissingRankedParticipant(
            local_share.participant_id.0,
        ))?;
    if local_share.rank != coefficient.derivative_order {
        return Err(DkgKitError::Protocol(format!(
            "HTSS share rank mismatch for participant {}: share rank {}, coefficient rank {}",
            local_share.participant_id.0, local_share.rank, coefficient.derivative_order
        )));
    }

    let aggregate_nonce = aggregate_htss_public_nonce(nonces, signer_set)?;
    if aggregate_nonce.signing_session_id != nonce.package.signing_session_id {
        return Err(DkgKitError::Protocol(
            "HTSS aggregate nonce session mismatch".to_string(),
        ));
    }
    let group_public_key = Point::<EvenY, Public>::from_xonly_bytes(group_key.xonly_public_key)
        .ok_or_else(|| DkgKitError::Protocol("invalid HTSS group x-only public key".to_string()))?;
    let schnorr = schnorr_fun::Schnorr::<Sha256>::verify_only();
    let challenge = schnorr.challenge(
        &aggregate_nonce.even_public_nonce,
        &group_public_key,
        frost_message(&digest),
    );

    let mut secret_nonce = Scalar::<Public, Zero>::from_bytes(nonce.secret_nonce_bytes)
        .ok_or_else(|| {
            DkgKitError::Protocol(format!(
                "invalid HTSS secret nonce scalar for participant {}",
                nonce.package.participant_id.0
            ))
        })?;
    secret_nonce.conditional_negate(aggregate_nonce.negated);
    let coefficient_value = Scalar::<Public, Zero>::from_bytes(coefficient.coefficient_bytes)
        .ok_or_else(|| {
            DkgKitError::Protocol(format!(
                "invalid Birkhoff coefficient scalar for participant {}",
                coefficient.participant_id.0
            ))
        })?;
    let share_value = Scalar::<Public, Zero>::from_bytes(local_share.share_value_bytes)
        .ok_or_else(|| {
            DkgKitError::Protocol(format!(
                "invalid HTSS share scalar for participant {}",
                local_share.participant_id.0
            ))
        })?;
    let weighted_share = scalar_mul(coefficient_value, share_value);
    let challenge_share = scalar_mul(challenge, weighted_share);
    let signature_share = scalar_add(secret_nonce, challenge_share);
    Ok(HtssSignatureSharePackage {
        participant_id: local_share.participant_id,
        signing_session_id: nonce.package.signing_session_id.clone(),
        signature_share_bytes: signature_share.to_bytes(),
    })
}

pub fn aggregate_htss_signature_shares(
    group_key: &GroupKey,
    digest: [u8; 32],
    nonces: &[HtssNoncePackage],
    shares: &[HtssSignatureSharePackage],
    signer_set: &[ParticipantId],
    config: &HierarchicalThresholdConfig,
) -> Result<AggregateSignature> {
    validate_hierarchical_signer_set(signer_set, config)?;
    validate_htss_nonce_set(nonces, signer_set)?;
    validate_htss_signature_share_set(shares, signer_set)?;
    let aggregate_nonce = aggregate_htss_public_nonce(nonces, signer_set)?;
    let mut s = scalar_zero();
    for share in shares {
        let share_value = Scalar::<Public, Zero>::from_bytes(share.signature_share_bytes)
            .ok_or_else(|| {
                DkgKitError::Protocol(format!(
                    "invalid HTSS signature share scalar for participant {}",
                    share.participant_id.0
                ))
            })?;
        s = scalar_add(s, share_value);
    }
    let signature = schnorr_fun::Signature {
        R: aggregate_nonce.even_public_nonce,
        s,
    };
    let group_public_key = Point::<EvenY, Public>::from_xonly_bytes(group_key.xonly_public_key)
        .ok_or_else(|| DkgKitError::Protocol("invalid HTSS group x-only public key".to_string()))?;
    let schnorr = schnorr_fun::Schnorr::<Sha256>::verify_only();
    if !schnorr.verify(&group_public_key, frost_message(&digest), &signature) {
        return Err(DkgKitError::Protocol(
            "HTSS aggregate signature verification failed".to_string(),
        ));
    }
    AggregateSignature::new(signature.to_bytes().to_vec())
}

pub fn sign_digest_with_local_htss_threshold_shares(
    group_key: &GroupKey,
    digest: [u8; 32],
    shares: &[HtssLocalKeyShare],
    signer_set: &[ParticipantId],
    config: &HierarchicalThresholdConfig,
) -> Result<AggregateSignature> {
    let selected_shares = signer_set
        .iter()
        .map(|participant_id| {
            shares
                .iter()
                .find(|share| share.participant_id == *participant_id)
                .ok_or(DkgKitError::MissingRankedParticipant(participant_id.0))
        })
        .collect::<Result<Vec<_>>>()?;
    let signing_session_id = SessionId::new("local-htss-threshold-signing")?;
    let nonces = selected_shares
        .iter()
        .map(|share| htss_nonce(signing_session_id.clone(), share))
        .collect::<Result<Vec<_>>>()?;
    let public_nonces = nonces
        .iter()
        .map(|nonce| nonce.package.clone())
        .collect::<Vec<_>>();
    let signature_shares = selected_shares
        .iter()
        .zip(nonces.iter())
        .map(|(share, nonce)| {
            htss_sign_share(
                group_key,
                digest,
                share,
                nonce,
                &public_nonces,
                signer_set,
                config,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    aggregate_htss_signature_shares(
        group_key,
        digest,
        &public_nonces,
        &signature_shares,
        signer_set,
        config,
    )
}

pub fn hierarchical_config_from_grouped_threshold(
    config: &GroupedThresholdConfig,
) -> Result<HierarchicalThresholdConfig> {
    HierarchicalThresholdConfig::new(config.required_signer_count(), config.participants.clone())
}

pub fn run_local_grouped_htss_keygen(config: &GroupedThresholdConfig) -> Result<HtssLocalKeySet> {
    run_local_htss_keygen(&hierarchical_config_from_grouped_threshold(config)?)
}

pub fn sign_digest_with_local_grouped_htss_threshold_shares(
    group_key: &GroupKey,
    digest: [u8; 32],
    shares: &[HtssLocalKeyShare],
    signer_set: &[ParticipantId],
    config: &GroupedThresholdConfig,
) -> Result<AggregateSignature> {
    validate_grouped_threshold_signer_set(signer_set, config)?;
    sign_digest_with_local_htss_threshold_shares(
        group_key,
        digest,
        shares,
        signer_set,
        &hierarchical_config_from_grouped_threshold(config)?,
    )
}

struct AggregateHtssNonce {
    signing_session_id: SessionId,
    even_public_nonce: Point<EvenY, Public, NonZero>,
    negated: bool,
}

fn aggregate_htss_public_nonce(
    nonces: &[HtssNoncePackage],
    signer_set: &[ParticipantId],
) -> Result<AggregateHtssNonce> {
    validate_htss_nonce_set(nonces, signer_set)?;
    let signing_session_id = nonces
        .first()
        .ok_or_else(|| DkgKitError::Protocol("missing HTSS nonce set".to_string()))?
        .signing_session_id
        .clone();
    let mut aggregate = Point::<NonNormal, Public, Zero>::zero();
    for nonce in nonces {
        let public_nonce =
            Point::<Normal, Public, NonZero>::from_bytes(nonce_public_nonce_bytes(nonce)?)
                .ok_or_else(|| {
                    DkgKitError::Protocol(format!(
                        "invalid HTSS public nonce for participant {}",
                        nonce.participant_id.0
                    ))
                })?;
        aggregate += public_nonce;
    }
    let (even_public_nonce, negated) = aggregate
        .normalize()
        .non_zero()
        .ok_or_else(|| DkgKitError::Protocol("HTSS aggregate nonce cannot be zero".to_string()))?
        .into_point_with_even_y();
    Ok(AggregateHtssNonce {
        signing_session_id,
        even_public_nonce,
        negated,
    })
}

fn nonce_public_nonce_bytes(nonce: &HtssNoncePackage) -> Result<[u8; 33]> {
    nonce.public_nonce_bytes.as_slice().try_into().map_err(|_| {
        DkgKitError::Protocol(format!(
            "HTSS public nonce for participant {} must be 33 bytes",
            nonce.participant_id.0
        ))
    })
}

fn validate_htss_nonce_set(
    nonces: &[HtssNoncePackage],
    signer_set: &[ParticipantId],
) -> Result<()> {
    let mut seen = BTreeSet::new();
    let mut session_id = None::<SessionId>;
    for nonce in nonces {
        if !signer_set.contains(&nonce.participant_id) {
            return Err(DkgKitError::Protocol(format!(
                "HTSS nonce participant {} is not in signer set",
                nonce.participant_id.0
            )));
        }
        if !seen.insert(nonce.participant_id) {
            return Err(DkgKitError::DuplicateParticipantId(nonce.participant_id.0));
        }
        match &session_id {
            Some(existing) if existing != &nonce.signing_session_id => {
                return Err(DkgKitError::Protocol(
                    "HTSS nonce session mismatch".to_string(),
                ));
            }
            None => session_id = Some(nonce.signing_session_id.clone()),
            _ => {}
        }
    }
    if seen.len() != signer_set.len() {
        return Err(DkgKitError::Protocol(format!(
            "HTSS nonce set mismatch: have {}, need {}",
            seen.len(),
            signer_set.len()
        )));
    }
    Ok(())
}

fn validate_htss_signature_share_set(
    shares: &[HtssSignatureSharePackage],
    signer_set: &[ParticipantId],
) -> Result<()> {
    let mut seen = BTreeSet::new();
    let mut session_id = None::<SessionId>;
    for share in shares {
        if !signer_set.contains(&share.participant_id) {
            return Err(DkgKitError::Protocol(format!(
                "HTSS signature share participant {} is not in signer set",
                share.participant_id.0
            )));
        }
        if !seen.insert(share.participant_id) {
            return Err(DkgKitError::DuplicateParticipantId(share.participant_id.0));
        }
        match &session_id {
            Some(existing) if existing != &share.signing_session_id => {
                return Err(DkgKitError::Protocol(
                    "HTSS signature share session mismatch".to_string(),
                ));
            }
            None => session_id = Some(share.signing_session_id.clone()),
            _ => {}
        }
    }
    if seen.len() != signer_set.len() {
        return Err(DkgKitError::Protocol(format!(
            "HTSS signature share set mismatch: have {}, need {}",
            seen.len(),
            signer_set.len()
        )));
    }
    Ok(())
}

fn birkhoff_matrix(points: &[BirkhoffPoint]) -> Result<Vec<Vec<PublicScalar>>> {
    let n = points.len();
    points
        .iter()
        .map(|point| {
            (0..n)
                .map(|degree| {
                    derivative_basis_scalar(degree as u16, point.derivative_order, point.x)
                })
                .collect()
        })
        .collect()
}

fn derivative_basis_scalar(degree: u16, derivative_order: u16, x: u16) -> Result<PublicScalar> {
    if derivative_order > degree {
        return Ok(scalar_zero());
    }
    let mut coefficient = scalar_one();
    for factor in (degree - derivative_order + 1)..=degree {
        coefficient = scalar_mul(coefficient, scalar_from_u32(factor as u32));
    }
    Ok(scalar_mul(
        coefficient,
        scalar_pow(scalar_from_u32(x as u32), degree - derivative_order),
    ))
}

fn polynomial_derivative_value(
    coefficients: &[PublicScalar],
    x: u16,
    derivative_order: u16,
) -> PublicScalar {
    coefficients
        .iter()
        .enumerate()
        .map(|(degree, coefficient)| {
            scalar_mul(
                *coefficient,
                derivative_basis_scalar(degree as u16, derivative_order, x)
                    .expect("valid derivative basis"),
            )
        })
        .fold(scalar_zero(), scalar_add)
}

fn solve_scalar_system(
    mut matrix: Vec<Vec<PublicScalar>>,
    mut target: Vec<PublicScalar>,
) -> Result<Vec<PublicScalar>> {
    let n = matrix.len();
    if target.len() != n || matrix.iter().any(|row| row.len() != n) {
        return Err(DkgKitError::Protocol(
            "Birkhoff linear system must be square".to_string(),
        ));
    }

    for col in 0..n {
        let pivot = (col..n)
            .find(|row| !matrix[*row][col].is_zero())
            .ok_or_else(|| {
                DkgKitError::Protocol("singular Birkhoff interpolation system".to_string())
            })?;
        if pivot != col {
            matrix.swap(pivot, col);
            target.swap(pivot, col);
        }

        let pivot_inverse = matrix[col][col]
            .non_zero()
            .ok_or_else(|| {
                DkgKitError::Protocol("singular Birkhoff interpolation pivot".to_string())
            })?
            .invert()
            .mark_zero();
        for entry in matrix[col].iter_mut().skip(col) {
            *entry = scalar_mul(*entry, pivot_inverse);
        }
        target[col] = scalar_mul(target[col], pivot_inverse);

        for row in 0..n {
            if row == col {
                continue;
            }
            let factor = matrix[row][col];
            if factor.is_zero() {
                continue;
            }
            for inner_col in col..n {
                matrix[row][inner_col] = scalar_sub(
                    matrix[row][inner_col],
                    scalar_mul(factor, matrix[col][inner_col]),
                );
            }
            target[row] = scalar_sub(target[row], scalar_mul(factor, target[col]));
        }
    }

    Ok(target)
}

fn validate_htss_dkg_round1_set(
    round1_packages: &[HtssDkgRound1Package],
    config: &HierarchicalThresholdConfig,
) -> Result<()> {
    let mut seen = BTreeSet::new();
    for package in round1_packages {
        if !seen.insert(package.participant_id) {
            return Err(DkgKitError::DuplicateParticipantId(
                package.participant_id.0,
            ));
        }
        let expected_rank =
            config
                .rank_of(package.participant_id)
                .ok_or(DkgKitError::MissingRankedParticipant(
                    package.participant_id.0,
                ))?;
        if package.rank != expected_rank.0 {
            return Err(DkgKitError::Protocol(format!(
                "HTSS DKG round1 rank mismatch for participant {}: got {}, expected {}",
                package.participant_id.0, package.rank, expected_rank.0
            )));
        }
        if package.commitment_bytes.len() != config.threshold as usize {
            return Err(DkgKitError::Protocol(format!(
                "HTSS DKG round1 participant {} has {} commitments, expected {}",
                package.participant_id.0,
                package.commitment_bytes.len(),
                config.threshold
            )));
        }
        for commitment in &package.commitment_bytes {
            htss_dkg_commitment_point(commitment)?;
        }
    }
    if seen.len() != config.participants.len() {
        return Err(DkgKitError::Protocol(format!(
            "HTSS DKG round1 set mismatch: have {}, need {}",
            seen.len(),
            config.participants.len()
        )));
    }
    Ok(())
}

fn validate_htss_dkg_round2_set(
    participant_id: ParticipantId,
    round2_packages: &[HtssDkgRound2Package],
    config: &HierarchicalThresholdConfig,
) -> Result<()> {
    let expected_rank = config
        .rank_of(participant_id)
        .ok_or(DkgKitError::MissingRankedParticipant(participant_id.0))?;
    let mut seen = BTreeSet::new();
    for package in round2_packages {
        if package.recipient != participant_id {
            return Err(DkgKitError::Protocol(format!(
                "HTSS DKG round2 package for participant {} cannot finalize participant {}",
                package.recipient.0, participant_id.0
            )));
        }
        if package.recipient_rank != expected_rank.0 {
            return Err(DkgKitError::Protocol(format!(
                "HTSS DKG round2 recipient rank mismatch for participant {}: got {}, expected {}",
                participant_id.0, package.recipient_rank, expected_rank.0
            )));
        }
        config
            .rank_of(package.sender)
            .ok_or(DkgKitError::MissingRankedParticipant(package.sender.0))?;
        if !seen.insert(package.sender) {
            return Err(DkgKitError::DuplicateParticipantId(package.sender.0));
        }
    }
    if seen.len() != config.participants.len() {
        return Err(DkgKitError::Protocol(format!(
            "HTSS DKG round2 set for participant {} mismatch: have {}, need {}",
            participant_id.0,
            seen.len(),
            config.participants.len()
        )));
    }
    Ok(())
}

fn verify_htss_dkg_derivative_share(
    package: &HtssDkgRound2Package,
    round1: &HtssDkgRound1Package,
) -> Result<()> {
    if package.sender != round1.participant_id {
        return Err(DkgKitError::Protocol(
            "HTSS DKG derivative share sender mismatch".to_string(),
        ));
    }
    let share_value =
        Scalar::<Public, Zero>::from_bytes(package.share_value_bytes).ok_or_else(|| {
            DkgKitError::Protocol(format!(
                "invalid HTSS DKG derivative share from participant {}",
                package.sender.0
            ))
        })?;
    let mut expected = Point::<NonNormal, Public, Zero>::zero();
    for (degree, commitment_bytes) in round1.commitment_bytes.iter().enumerate() {
        let basis =
            derivative_basis_scalar(degree as u16, package.recipient_rank, package.recipient.0)?;
        if basis.is_zero() {
            continue;
        }
        let commitment = htss_dkg_commitment_point(commitment_bytes)?;
        expected += g!(basis * commitment);
    }
    let actual = g!(share_value * G).normalize();
    if actual.to_bytes() != expected.normalize().to_bytes() {
        return Err(DkgKitError::Protocol(format!(
            "HTSS DKG derivative share from participant {} failed commitment verification",
            package.sender.0
        )));
    }
    Ok(())
}

fn htss_dkg_group_xonly_public_key(
    round1_packages: &[HtssDkgRound1Package],
) -> Result<([u8; 32], bool)> {
    let mut aggregate = Point::<NonNormal, Public, Zero>::zero();
    for package in round1_packages {
        let first_commitment = package.commitment_bytes.first().ok_or_else(|| {
            DkgKitError::Protocol(format!(
                "HTSS DKG participant {} missing constant commitment",
                package.participant_id.0
            ))
        })?;
        aggregate += htss_dkg_commitment_point(first_commitment)?;
    }
    let (even_public_key, negated) = aggregate
        .normalize()
        .non_zero()
        .ok_or_else(|| DkgKitError::Protocol("HTSS DKG group key cannot be zero".to_string()))?
        .into_point_with_even_y();
    Ok((even_public_key.to_xonly_bytes(), negated))
}

fn htss_dkg_commitment_point(bytes: &[u8]) -> Result<Point<Normal, Public, NonZero>> {
    let bytes: [u8; 33] = bytes.try_into().map_err(|_| {
        DkgKitError::Protocol(format!(
            "HTSS DKG commitment must be 33 bytes, got {}",
            bytes.len()
        ))
    })?;
    Point::<Normal, Public, NonZero>::from_bytes(bytes)
        .ok_or_else(|| DkgKitError::Protocol("invalid HTSS DKG commitment point".to_string()))
}

fn scalar_zero() -> PublicScalar {
    Scalar::<Public, Zero>::default()
}

fn scalar_one() -> PublicScalar {
    scalar_from_u32(1)
}

fn scalar_from_u32(value: u32) -> PublicScalar {
    Scalar::<Secret, Zero>::from(value).public()
}

fn scalar_mul(left: PublicScalar, right: PublicScalar) -> PublicScalar {
    op::scalar_mul(left, right).public()
}

fn scalar_sub(left: PublicScalar, right: PublicScalar) -> PublicScalar {
    op::scalar_sub(left, right).public()
}

fn scalar_add(left: PublicScalar, right: PublicScalar) -> PublicScalar {
    op::scalar_add(left, right).public()
}

fn scalar_pow(base: PublicScalar, exponent: u16) -> PublicScalar {
    let mut value = scalar_one();
    for _ in 0..exponent {
        value = scalar_mul(value, base);
    }
    value
}

struct PendingSecretShare {
    recipient: ParticipantId,
    bytes: Vec<u8>,
}

struct DkgRuntime {
    _contributor: Contributor,
    pending_secret_shares: Vec<PendingSecretShare>,
    round1_packages: BTreeMap<ParticipantId, Round1Package>,
}

pub struct FrostDkgSession {
    pub config: DkgSessionConfig,
    runtime: RefCell<Option<DkgRuntime>>,
}

impl FrostDkgSession {
    pub fn new(config: DkgSessionConfig) -> Self {
        Self {
            config,
            runtime: RefCell::new(None),
        }
    }

    pub fn round1(&self) -> Result<Round1Package> {
        let frost = frost::new_with_deterministic_nonces::<Sha256>();
        let share_indices: BTreeSet<_> = (1..=self.config.threshold.participants)
            .map(|i| Scalar::from(i as u32).non_zero().expect("nonzero"))
            .collect();
        let mut rng = rand::thread_rng();
        let (contributor, keygen_input, secret_shares) = Contributor::gen_keygen_input(
            &frost.schnorr,
            self.config.threshold.threshold as u32,
            &share_indices,
            self.config.participant_id.0 as u32 - 1,
            &mut rng,
        );

        let package = Round1Package {
            participant_id: self.config.participant_id,
            bytes: encode_binary(&keygen_input)?,
        };

        let pending_secret_shares = secret_shares
            .into_iter()
            .map(|(index, share)| {
                Ok(PendingSecretShare {
                    recipient: participant_id_from_scalar_bytes(&index.to_bytes())?,
                    bytes: encode_binary(&share)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let mut round1_packages = BTreeMap::new();
        round1_packages.insert(package.participant_id, package.clone());
        *self.runtime.borrow_mut() = Some(DkgRuntime {
            _contributor: contributor,
            pending_secret_shares,
            round1_packages,
        });

        Ok(package)
    }

    pub fn round2(&self, round1_packages: &[Round1Package]) -> Result<Vec<Round2Package>> {
        self.validate_round1_set(round1_packages)?;
        let mut runtime_ref = self.runtime.borrow_mut();
        let runtime = runtime_ref.as_mut().ok_or(DkgKitError::Protocol(
            "round1 must be called before round2".to_string(),
        ))?;
        runtime.round1_packages = round1_packages
            .iter()
            .cloned()
            .map(|package| (package.participant_id, package))
            .collect();
        self.aggregate_keygen_inputs(round1_packages)?;

        Ok(runtime
            .pending_secret_shares
            .iter()
            .map(|share| Round2Package {
                sender: self.config.participant_id,
                recipient: share.recipient,
                bytes: share.bytes.clone(),
            })
            .collect())
    }

    pub fn finalize(&self, round2_packages: &[Round2Package]) -> Result<LocalKeyShare> {
        let runtime_ref = self.runtime.borrow();
        let runtime = runtime_ref.as_ref().ok_or(DkgKitError::Protocol(
            "round1 and round2 must be called before finalize".to_string(),
        ))?;
        if runtime.round1_packages.len() != self.config.threshold.participants as usize {
            return Err(DkgKitError::Protocol(format!(
                "missing round1 packages: have {}, need {}",
                runtime.round1_packages.len(),
                self.config.threshold.participants
            )));
        }

        let mut shares_for_me = Vec::new();
        let mut seen_senders = BTreeSet::new();
        for package in round2_packages
            .iter()
            .filter(|package| package.recipient == self.config.participant_id)
        {
            if !seen_senders.insert(package.sender) {
                return Err(DkgKitError::DuplicateParticipantId(package.sender.0));
            }
            let share: Scalar<Secret, Zero> = decode_binary(&package.bytes)?;
            shares_for_me.push(share);
        }
        if shares_for_me.len() != self.config.threshold.participants as usize {
            return Err(DkgKitError::Protocol(format!(
                "missing round2 shares for participant {}: have {}, need {}",
                self.config.participant_id.0,
                shares_for_me.len(),
                self.config.threshold.participants
            )));
        }

        let round1_packages: Vec<Round1Package> =
            runtime.round1_packages.values().cloned().collect();
        let agg_input = self.aggregate_keygen_inputs(&round1_packages)?;
        let frost = frost::new_with_deterministic_nonces::<Sha256>();
        let my_share_index = participant_share_index(self.config.participant_id);
        let secret_share = simplepedpop::collect_secret_inputs(my_share_index, shares_for_me);
        let paired_share =
            simplepedpop::receive_secret_share(&frost.schnorr, &agg_input, secret_share).map_err(
                |err| DkgKitError::Protocol(format!("share verification failed: {err:?}")),
            )?;
        let shared_key = agg_input.shared_key();
        let xonly_paired_share = paired_share
            .non_zero()
            .ok_or_else(|| DkgKitError::Protocol("paired share is zero".to_string()))?
            .into_xonly();
        let xonly_shared_key = shared_key
            .non_zero()
            .ok_or_else(|| DkgKitError::Protocol("shared key is zero".to_string()))?
            .into_xonly();

        Ok(LocalKeyShare {
            participant_id: self.config.participant_id,
            group_key: GroupKey {
                xonly_public_key: xonly_shared_key.public_key().to_xonly_bytes(),
                verification_key_bytes: encode_binary(&xonly_shared_key)?,
            },
            secret_share_bytes: encode_binary(&xonly_paired_share)?,
        })
    }

    fn validate_round1_set(&self, round1_packages: &[Round1Package]) -> Result<()> {
        if round1_packages.len() != self.config.threshold.participants as usize {
            return Err(DkgKitError::ParticipantCountMismatch {
                expected: self.config.threshold.participants,
                actual: round1_packages.len(),
            });
        }
        let mut seen = BTreeSet::new();
        for package in round1_packages {
            if package.participant_id.0 > self.config.threshold.participants {
                return Err(DkgKitError::ParticipantOutOfRange {
                    participant_id: package.participant_id.0,
                    participants: self.config.threshold.participants,
                });
            }
            if !seen.insert(package.participant_id) {
                return Err(DkgKitError::DuplicateParticipantId(
                    package.participant_id.0,
                ));
            }
        }
        Ok(())
    }

    fn aggregate_keygen_inputs(
        &self,
        round1_packages: &[Round1Package],
    ) -> Result<simplepedpop::AggKeygenInput> {
        let frost = frost::new_with_deterministic_nonces::<Sha256>();
        let mut coordinator = Coordinator::new(
            self.config.threshold.threshold as u32,
            self.config.threshold.participants as u32,
        );
        for package in round1_packages {
            let keygen_input: KeygenInput = decode_binary(&package.bytes)?;
            coordinator
                .add_input(
                    &frost.schnorr,
                    package.participant_id.0 as u32 - 1,
                    keygen_input,
                )
                .map_err(|err| DkgKitError::Protocol(format!("invalid round1 input: {err}")))?;
        }
        coordinator
            .finish()
            .ok_or_else(|| DkgKitError::Protocol("coordinator missing round1 inputs".to_string()))
    }
}

fn participant_id_from_scalar_bytes(bytes: &[u8; 32]) -> Result<ParticipantId> {
    let value = u32::from_be_bytes(bytes[28..32].try_into().expect("slice length"));
    let value = u16::try_from(value).map_err(|_| DkgKitError::InvalidParticipantId(u16::MAX))?;
    ParticipantId::new(value)
}

fn participant_share_index(participant_id: ParticipantId) -> Scalar<Public, NonZero> {
    Scalar::<Secret, Zero>::from(participant_id.0 as u32)
        .public()
        .non_zero()
        .expect("participant index cannot be zero")
}

fn frost_message(message_digest: &[u8; 32]) -> Message<'_> {
    Message::raw(message_digest)
}

fn nonces_to_map(
    nonces: &[NoncePackage],
    request: &SigningRequest,
) -> Result<BTreeMap<Scalar<Public, NonZero>, Nonce>> {
    let mut map = BTreeMap::new();
    for nonce in nonces {
        if nonce.signing_session_id != request.session_id {
            return Err(DkgKitError::Protocol("nonce session mismatch".to_string()));
        }
        if !request.signer_set.contains(&nonce.participant_id) {
            return Err(DkgKitError::Protocol(format!(
                "nonce participant {} is not in signer set",
                nonce.participant_id.0
            )));
        }
        let public_nonce: Nonce = decode_binary(&nonce.public_nonce_bytes)?;
        if map
            .insert(participant_share_index(nonce.participant_id), public_nonce)
            .is_some()
        {
            return Err(DkgKitError::DuplicateParticipantId(nonce.participant_id.0));
        }
    }
    if map.len() != request.signer_set.len() {
        return Err(DkgKitError::Protocol(format!(
            "nonce set mismatch: have {}, need {}",
            map.len(),
            request.signer_set.len()
        )));
    }
    Ok(map)
}

fn validate_signature_share_set(
    shares: &[SignatureSharePackage],
    request: &SigningRequest,
) -> Result<()> {
    let mut seen = BTreeSet::new();
    for share in shares {
        if share.signing_session_id != request.session_id {
            return Err(DkgKitError::Protocol(
                "signature share session mismatch".to_string(),
            ));
        }
        if !request.signer_set.contains(&share.participant_id) {
            return Err(DkgKitError::Protocol(format!(
                "signature share participant {} is not in signer set",
                share.participant_id.0
            )));
        }
        if !seen.insert(share.participant_id) {
            return Err(DkgKitError::DuplicateParticipantId(share.participant_id.0));
        }
    }
    if seen.len() != request.signer_set.len() {
        return Err(DkgKitError::Protocol(format!(
            "signature share set mismatch: have {}, need {}",
            seen.len(),
            request.signer_set.len()
        )));
    }
    Ok(())
}

#[derive(Debug)]
pub struct FrostSigningSession {
    pub request: SigningRequest,
    nonce_runtime: RefCell<Option<NonceKeyPair>>,
}

impl FrostSigningSession {
    pub fn new(request: SigningRequest) -> Self {
        Self {
            request,
            nonce_runtime: RefCell::new(None),
        }
    }

    pub fn nonce(&self, local_share: &LocalKeyShare) -> Result<NoncePackage> {
        if local_share.group_key != self.request.group_key {
            return Err(DkgKitError::Protocol(
                "local share group key does not match signing request".to_string(),
            ));
        }
        let paired_share: PairedSecretShare<EvenY> =
            decode_binary(&local_share.secret_share_bytes)?;
        let frost = frost::new_with_synthetic_nonces::<Sha256, rand::rngs::ThreadRng>();
        let mut nonce_rng: ChaCha20Rng =
            frost.seed_nonce_rng(paired_share, self.request.session_id.0.as_bytes());
        let nonce = frost.gen_nonce(&mut nonce_rng);
        let package = NoncePackage {
            participant_id: local_share.participant_id,
            signing_session_id: self.request.session_id.clone(),
            public_nonce_bytes: encode_binary(&nonce.public())?,
        };
        *self.nonce_runtime.borrow_mut() = Some(nonce);
        Ok(package)
    }

    pub fn sign_share(
        &self,
        local_share: &LocalKeyShare,
        nonces: &[NoncePackage],
    ) -> Result<SignatureSharePackage> {
        if local_share.group_key != self.request.group_key {
            return Err(DkgKitError::Protocol(
                "local share group key does not match signing request".to_string(),
            ));
        }
        if !self
            .request
            .signer_set
            .contains(&local_share.participant_id)
        {
            return Err(DkgKitError::Protocol(format!(
                "participant {} is not in signer set",
                local_share.participant_id.0
            )));
        }
        let nonce = self.nonce_runtime.borrow_mut().take().ok_or_else(|| {
            DkgKitError::Protocol("nonce must be generated before sign_share".to_string())
        })?;
        let own_public_nonce_bytes = nonces
            .iter()
            .find(|package| package.participant_id == local_share.participant_id)
            .ok_or_else(|| DkgKitError::Protocol("missing local public nonce".to_string()))?
            .public_nonce_bytes
            .clone();
        let paired_share: PairedSecretShare<EvenY> =
            decode_binary(&local_share.secret_share_bytes)?;
        let shared_key: SharedKey<EvenY> =
            decode_binary(&self.request.group_key.verification_key_bytes)?;
        let nonces_map = nonces_to_map(nonces, &self.request)?;
        let frost = frost::new_with_deterministic_nonces::<Sha256>();
        let message = frost_message(&self.request.message_digest);
        let coord_session = frost.coordinator_sign_session(&shared_key, nonces_map, message);
        let sign_session = frost.party_sign_session(
            shared_key.public_key(),
            coord_session.parties().clone(),
            coord_session.agg_binonce(),
            message,
        );
        let sig_share = sign_session.sign(&paired_share, nonce);
        Ok(SignatureSharePackage {
            participant_id: local_share.participant_id,
            signing_session_id: self.request.session_id.clone(),
            public_nonce_bytes: own_public_nonce_bytes,
            signature_share_bytes: encode_binary(&sig_share)?,
        })
    }

    pub fn aggregate(&self, shares: &[SignatureSharePackage]) -> Result<AggregateSignature> {
        validate_signature_share_set(shares, &self.request)?;
        let shared_key: SharedKey<EvenY> =
            decode_binary(&self.request.group_key.verification_key_bytes)?;
        let nonces = shares
            .iter()
            .map(|share| NoncePackage {
                participant_id: share.participant_id,
                signing_session_id: share.signing_session_id.clone(),
                public_nonce_bytes: share.public_nonce_bytes.clone(),
            })
            .collect::<Vec<_>>();
        let nonces_map = nonces_to_map(&nonces, &self.request)?;
        let frost = frost::new_with_deterministic_nonces::<Sha256>();
        let message = frost_message(&self.request.message_digest);
        let coord_session = frost.coordinator_sign_session(&shared_key, nonces_map, message);
        let mut sig_shares = BTreeMap::new();
        for share in shares {
            let sig_share: Scalar<Public, Zero> = decode_binary(&share.signature_share_bytes)?;
            sig_shares.insert(participant_share_index(share.participant_id), sig_share);
        }
        let signature = coord_session
            .verify_and_combine_signature_shares(&shared_key, sig_shares)
            .map_err(|err| {
                DkgKitError::Protocol(format!("signature share verification failed: {err:?}"))
            })?;
        AggregateSignature::new(encode_binary(&signature)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dkgkit_core::{GroupThresholdRequirement, RankedParticipant};
    use schnorr_fun::Signature;

    fn pid(value: u16) -> ParticipantId {
        ParticipantId::new(value).unwrap()
    }

    fn session(participant_id: u16) -> FrostDkgSession {
        FrostDkgSession::new(DkgSessionConfig {
            session_id: SessionId::new("dkg-demo").unwrap(),
            threshold: ThresholdConfig::new(2, 3).unwrap(),
            participant_id: pid(participant_id),
        })
    }

    fn htss_config() -> HierarchicalThresholdConfig {
        HierarchicalThresholdConfig::new(
            3,
            vec![
                RankedParticipant::new(1, 0, Some("ceo".to_string())).unwrap(),
                RankedParticipant::new(2, 1, Some("cfo".to_string())).unwrap(),
                RankedParticipant::new(3, 1, Some("finance".to_string())).unwrap(),
                RankedParticipant::new(4, 2, Some("operator-a".to_string())).unwrap(),
                RankedParticipant::new(5, 2, Some("operator-b".to_string())).unwrap(),
            ],
        )
        .unwrap()
    }

    fn grouped_config_123_of_235() -> GroupedThresholdConfig {
        GroupedThresholdConfig::new(
            vec![
                RankedParticipant::new(1, 0, Some("c-level-a".to_string())).unwrap(),
                RankedParticipant::new(2, 0, Some("c-level-b".to_string())).unwrap(),
                RankedParticipant::new(3, 1, Some("manager-a".to_string())).unwrap(),
                RankedParticipant::new(4, 1, Some("manager-b".to_string())).unwrap(),
                RankedParticipant::new(5, 1, Some("manager-c".to_string())).unwrap(),
                RankedParticipant::new(6, 2, Some("operator-a".to_string())).unwrap(),
                RankedParticipant::new(7, 2, Some("operator-b".to_string())).unwrap(),
                RankedParticipant::new(8, 2, Some("operator-c".to_string())).unwrap(),
                RankedParticipant::new(9, 2, Some("operator-d".to_string())).unwrap(),
                RankedParticipant::new(10, 2, Some("operator-e".to_string())).unwrap(),
            ],
            vec![
                GroupThresholdRequirement::new(0, 1, 2).unwrap(),
                GroupThresholdRequirement::new(1, 2, 3).unwrap(),
                GroupThresholdRequirement::new(2, 3, 5).unwrap(),
            ],
        )
        .unwrap()
    }

    fn coefficient_scalar(coefficient: &BirkhoffCoefficient) -> PublicScalar {
        Scalar::<Public, Zero>::from_bytes(coefficient.coefficient_bytes).unwrap()
    }

    fn reconstruct_f0(
        points: &[BirkhoffPoint],
        interpolation_coefficients: &[BirkhoffCoefficient],
        polynomial_coefficients: &[PublicScalar],
    ) -> PublicScalar {
        points
            .iter()
            .zip(interpolation_coefficients)
            .map(|(point, interpolation_coefficient)| {
                scalar_mul(
                    coefficient_scalar(interpolation_coefficient),
                    polynomial_derivative_value(
                        polynomial_coefficients,
                        point.x,
                        point.derivative_order,
                    ),
                )
            })
            .fold(scalar_zero(), scalar_add)
    }

    fn run_dkg() -> Vec<LocalKeyShare> {
        let sessions = [session(1), session(2), session(3)];
        let round1_packages = sessions
            .iter()
            .map(|session| session.round1().unwrap())
            .collect::<Vec<_>>();
        let round2_packages = sessions
            .iter()
            .flat_map(|session| session.round2(&round1_packages).unwrap())
            .collect::<Vec<_>>();
        sessions
            .iter()
            .map(|session| session.finalize(&round2_packages).unwrap())
            .collect::<Vec<_>>()
    }

    #[test]
    fn signer_set_requires_threshold() {
        let threshold = ThresholdConfig::new(2, 3).unwrap();
        assert!(validate_signer_set(&[pid(1)], &threshold).is_err());
        assert!(validate_signer_set(&[pid(1), pid(2)], &threshold).is_ok());
    }

    #[test]
    fn signer_set_rejects_duplicates_and_out_of_range() {
        let threshold = ThresholdConfig::new(2, 3).unwrap();
        assert!(matches!(
            validate_signer_set(&[pid(1), pid(1)], &threshold).unwrap_err(),
            DkgKitError::DuplicateParticipantId(1)
        ));
        assert!(matches!(
            validate_signer_set(&[pid(1), pid(4)], &threshold).unwrap_err(),
            DkgKitError::ParticipantOutOfRange {
                participant_id: 4,
                participants: 3
            }
        ));
    }

    #[test]
    fn hierarchical_signer_set_accepts_rank_valid_sets() {
        let config = htss_config();
        assert!(validate_hierarchical_signer_set(&[pid(1), pid(2), pid(3)], &config).is_ok());
        assert!(validate_hierarchical_signer_set(&[pid(1), pid(2), pid(4)], &config).is_ok());
    }

    #[test]
    fn hierarchical_signer_set_rejects_missing_high_authority() {
        let config = htss_config();
        let err = validate_hierarchical_signer_set(&[pid(2), pid(4), pid(5)], &config).unwrap_err();
        assert!(err.to_string().contains("Birkhoff rank rule"));
    }

    #[test]
    fn signing_request_can_validate_against_hierarchical_policy() {
        let shares = run_dkg();
        let config = HierarchicalThresholdConfig::new(
            2,
            vec![
                RankedParticipant::new(1, 0, Some("admin".to_string())).unwrap(),
                RankedParticipant::new(2, 1, Some("operator".to_string())).unwrap(),
                RankedParticipant::new(3, 1, Some("operator".to_string())).unwrap(),
            ],
        )
        .unwrap();
        let policy = SigningPolicy::Hierarchical(config);
        let request = SigningRequest::new_with_policy(
            SessionId::new("sign-demo").unwrap(),
            shares[0].group_key.clone(),
            [2u8; 32],
            vec![pid(1), pid(2)],
            &policy,
        )
        .unwrap();
        assert_eq!(request.signer_set, vec![pid(1), pid(2)]);
        assert!(SigningRequest::new_with_policy(
            SessionId::new("sign-demo-2").unwrap(),
            shares[0].group_key.clone(),
            [2u8; 32],
            vec![pid(2), pid(3)],
            &policy,
        )
        .is_err());
    }

    #[test]
    fn grouped_threshold_signer_set_accepts_123_of_235() {
        let config = grouped_config_123_of_235();
        assert!(validate_grouped_threshold_signer_set(
            &[pid(1), pid(3), pid(4), pid(6), pid(7), pid(8)],
            &config
        )
        .is_ok());
    }

    #[test]
    fn grouped_threshold_signer_set_rejects_short_group_despite_enough_total_signers() {
        let config = grouped_config_123_of_235();
        let err = validate_grouped_threshold_signer_set(
            &[pid(1), pid(3), pid(6), pid(7), pid(8), pid(9)],
            &config,
        )
        .unwrap_err();
        assert!(err.to_string().contains("rank 1 needs 2"));
    }

    #[test]
    fn signing_request_can_validate_against_grouped_policy() {
        let group_key = GroupKey {
            xonly_public_key: [1u8; 32],
            verification_key_bytes: vec![1, 2, 3],
        };
        let policy = SigningPolicy::Grouped(grouped_config_123_of_235());
        assert!(SigningRequest::new_with_policy(
            SessionId::new("grouped-demo").unwrap(),
            group_key.clone(),
            [4u8; 32],
            vec![pid(1), pid(3), pid(4), pid(6), pid(7), pid(8)],
            &policy,
        )
        .is_ok());
        assert!(SigningRequest::new_with_policy(
            SessionId::new("grouped-demo-reject").unwrap(),
            group_key,
            [4u8; 32],
            vec![pid(1), pid(3), pid(6), pid(7), pid(8), pid(9)],
            &policy,
        )
        .is_err());
    }

    #[test]
    fn grouped_signing_request_carries_grouped_config() {
        let group_key = GroupKey {
            xonly_public_key: [1u8; 32],
            verification_key_bytes: vec![1, 2, 3],
        };
        let config = grouped_config_123_of_235();
        let request = GroupedSigningRequest::new(
            SessionId::new("grouped-request-demo").unwrap(),
            group_key,
            [5u8; 32],
            vec![pid(1), pid(3), pid(4), pid(6), pid(7), pid(8)],
            &config,
        )
        .unwrap();
        assert_eq!(request.request.signer_set.len(), 6);
        assert_eq!(request.config.required_signer_count(), 6);
    }

    #[test]
    fn hierarchical_signing_request_carries_birkhoff_coefficients() {
        let shares = run_dkg();
        let config = HierarchicalThresholdConfig::new(
            2,
            vec![
                RankedParticipant::new(1, 0, Some("admin".to_string())).unwrap(),
                RankedParticipant::new(2, 1, Some("operator".to_string())).unwrap(),
                RankedParticipant::new(3, 1, Some("operator".to_string())).unwrap(),
            ],
        )
        .unwrap();
        let request = HierarchicalSigningRequest::new(
            SessionId::new("htss-sign-demo").unwrap(),
            shares[0].group_key.clone(),
            [3u8; 32],
            vec![pid(1), pid(2)],
            &config,
        )
        .unwrap();
        assert_eq!(request.request.signer_set, vec![pid(1), pid(2)]);
        assert_eq!(request.points.len(), 2);
        assert_eq!(request.coefficients.len(), 2);
    }

    #[test]
    fn birkhoff_coefficients_match_standard_lagrange_for_rank_zero_points() {
        let points = vec![
            BirkhoffPoint::new(pid(1), 1, 0).unwrap(),
            BirkhoffPoint::new(pid(2), 2, 0).unwrap(),
        ];
        let interpolation_coefficients = birkhoff_interpolation_coefficients(&points).unwrap();
        let polynomial_coefficients = vec![scalar_from_u32(5), scalar_from_u32(7)];
        assert_eq!(
            reconstruct_f0(
                &points,
                &interpolation_coefficients,
                &polynomial_coefficients
            ),
            polynomial_coefficients[0]
        );
    }

    #[test]
    fn birkhoff_coefficients_reconstruct_ranked_derivative_system() {
        let points = vec![
            BirkhoffPoint::new(pid(1), 1, 0).unwrap(),
            BirkhoffPoint::new(pid(2), 2, 1).unwrap(),
            BirkhoffPoint::new(pid(3), 3, 1).unwrap(),
        ];
        let interpolation_coefficients = birkhoff_interpolation_coefficients(&points).unwrap();
        let polynomial_coefficients =
            vec![scalar_from_u32(11), scalar_from_u32(5), scalar_from_u32(2)];
        assert_eq!(
            reconstruct_f0(
                &points,
                &interpolation_coefficients,
                &polynomial_coefficients
            ),
            polynomial_coefficients[0]
        );
    }

    #[test]
    fn birkhoff_coefficients_reject_singular_low_authority_system() {
        let points = vec![
            BirkhoffPoint::new(pid(1), 1, 1).unwrap(),
            BirkhoffPoint::new(pid(2), 2, 1).unwrap(),
            BirkhoffPoint::new(pid(3), 3, 2).unwrap(),
        ];
        let err = birkhoff_interpolation_coefficients(&points).unwrap_err();
        assert!(err.to_string().contains("singular Birkhoff"));
    }

    #[test]
    fn local_htss_keygen_reconstructs_secret_for_valid_rank_set() {
        let config = htss_config();
        let keyset = run_local_htss_keygen(&config).unwrap();
        let signer_set = vec![pid(1), pid(2), pid(4)];
        let secret_bytes =
            reconstruct_htss_secret_scalar(&keyset.shares, &signer_set, &config).unwrap();
        let secret = Scalar::<Secret, Zero>::from_bytes(secret_bytes)
            .unwrap()
            .non_zero()
            .unwrap();
        let schnorr = schnorr_fun::new_with_deterministic_nonces::<Sha256>();
        let keypair = schnorr.new_keypair(secret);
        assert_eq!(
            keypair.public_key().to_xonly_bytes(),
            keyset.group_key.xonly_public_key
        );
    }

    #[test]
    fn local_htss_reconstruction_rejects_invalid_rank_set() {
        let config = htss_config();
        let keyset = run_local_htss_keygen(&config).unwrap();
        let err =
            reconstruct_htss_secret_scalar(&keyset.shares, &[pid(2), pid(4), pid(5)], &config)
                .unwrap_err();
        assert!(err.to_string().contains("Birkhoff rank rule"));
    }

    #[test]
    fn local_htss_shares_sign_digest_that_verifies_against_group_key() {
        let config = htss_config();
        let keyset = run_local_htss_keygen(&config).unwrap();
        let digest = [12u8; 32];
        let signature = sign_digest_with_local_htss_shares(
            &keyset.group_key,
            digest,
            &keyset.shares,
            &[pid(1), pid(2), pid(4)],
            &config,
        )
        .unwrap();
        let signature_bytes: [u8; 64] = signature.signature_bytes.try_into().unwrap();
        let signature = Signature::from_bytes(signature_bytes).unwrap();
        let public_key =
            Point::<EvenY, Public>::from_xonly_bytes(keyset.group_key.xonly_public_key).unwrap();
        let schnorr = schnorr_fun::Schnorr::<Sha256>::verify_only();
        assert!(schnorr.verify(&public_key, frost_message(&digest), &signature));
    }

    #[test]
    fn local_htss_threshold_shares_sign_without_reconstructing_secret() {
        let config = htss_config();
        let keyset = run_local_htss_keygen(&config).unwrap();
        let digest = [14u8; 32];
        let signature = sign_digest_with_local_htss_threshold_shares(
            &keyset.group_key,
            digest,
            &keyset.shares,
            &[pid(1), pid(2), pid(4)],
            &config,
        )
        .unwrap();
        let signature_bytes: [u8; 64] = signature.signature_bytes.try_into().unwrap();
        let signature = Signature::from_bytes(signature_bytes).unwrap();
        let public_key =
            Point::<EvenY, Public>::from_xonly_bytes(keyset.group_key.xonly_public_key).unwrap();
        let schnorr = schnorr_fun::Schnorr::<Sha256>::verify_only();
        assert!(schnorr.verify(&public_key, frost_message(&digest), &signature));
    }

    #[test]
    fn distributed_htss_dkg_derives_derivative_shares_that_sign() {
        let config = htss_config();
        let keyset = run_distributed_htss_keygen(&config).unwrap();
        let signer_set = vec![pid(1), pid(2), pid(4)];
        let digest = [24u8; 32];
        let signature = sign_digest_with_local_htss_threshold_shares(
            &keyset.group_key,
            digest,
            &keyset.shares,
            &signer_set,
            &config,
        )
        .unwrap();
        let signature_bytes: [u8; 64] = signature.signature_bytes.try_into().unwrap();
        let signature = Signature::from_bytes(signature_bytes).unwrap();
        let public_key =
            Point::<EvenY, Public>::from_xonly_bytes(keyset.group_key.xonly_public_key).unwrap();
        let schnorr = schnorr_fun::Schnorr::<Sha256>::verify_only();
        assert!(schnorr.verify(&public_key, frost_message(&digest), &signature));
    }

    #[test]
    fn distributed_htss_dkg_rejects_tampered_derivative_share() {
        let config = htss_config();
        let states = config
            .participants
            .iter()
            .map(|participant| htss_dkg_round1(participant.id, &config))
            .collect::<Result<Vec<_>>>()
            .unwrap();
        let round1_packages = states
            .iter()
            .map(|state| state.package.clone())
            .collect::<Vec<_>>();
        let mut round2_for_one = states
            .iter()
            .map(|state| htss_dkg_round2(state, &round1_packages, &config))
            .collect::<Result<Vec<_>>>()
            .unwrap()
            .into_iter()
            .flatten()
            .filter(|package| package.recipient == pid(1))
            .collect::<Vec<_>>();
        round2_for_one[0].share_value_bytes = scalar_add(
            Scalar::<Public, Zero>::from_bytes(round2_for_one[0].share_value_bytes).unwrap(),
            scalar_one(),
        )
        .to_bytes();

        let err =
            finalize_htss_dkg(pid(1), &round1_packages, &round2_for_one, &config).unwrap_err();
        assert!(err.to_string().contains("failed commitment verification"));
    }

    #[test]
    fn local_htss_nonce_share_and_aggregate_flow_verifies() {
        let config = htss_config();
        let keyset = run_local_htss_keygen(&config).unwrap();
        let signer_set = vec![pid(1), pid(2), pid(4)];
        let digest = [15u8; 32];
        let signing_session_id = SessionId::new("htss-share-flow").unwrap();
        let selected_shares = signer_set
            .iter()
            .map(|participant_id| {
                keyset
                    .shares
                    .iter()
                    .find(|share| share.participant_id == *participant_id)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let nonces = selected_shares
            .iter()
            .map(|share| htss_nonce(signing_session_id.clone(), share).unwrap())
            .collect::<Vec<_>>();
        let public_nonces = nonces
            .iter()
            .map(|nonce| nonce.package.clone())
            .collect::<Vec<_>>();
        let shares = selected_shares
            .iter()
            .zip(nonces.iter())
            .map(|(share, nonce)| {
                htss_sign_share(
                    &keyset.group_key,
                    digest,
                    share,
                    nonce,
                    &public_nonces,
                    &signer_set,
                    &config,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let signature = aggregate_htss_signature_shares(
            &keyset.group_key,
            digest,
            &public_nonces,
            &shares,
            &signer_set,
            &config,
        )
        .unwrap();
        assert_eq!(signature.signature_bytes.len(), 64);
    }

    #[test]
    fn local_grouped_htss_threshold_shares_sign_valid_123_of_235() {
        let config = grouped_config_123_of_235();
        let keyset = run_local_grouped_htss_keygen(&config).unwrap();
        let signer_set = vec![pid(1), pid(3), pid(4), pid(6), pid(7), pid(8)];
        let digest = [17u8; 32];
        let signature = sign_digest_with_local_grouped_htss_threshold_shares(
            &keyset.group_key,
            digest,
            &keyset.shares,
            &signer_set,
            &config,
        )
        .unwrap();
        let signature_bytes: [u8; 64] = signature.signature_bytes.try_into().unwrap();
        let signature = Signature::from_bytes(signature_bytes).unwrap();
        let public_key =
            Point::<EvenY, Public>::from_xonly_bytes(keyset.group_key.xonly_public_key).unwrap();
        let schnorr = schnorr_fun::Schnorr::<Sha256>::verify_only();
        assert!(schnorr.verify(&public_key, frost_message(&digest), &signature));
    }

    #[test]
    fn local_grouped_htss_rejects_short_group_before_signing() {
        let config = grouped_config_123_of_235();
        let keyset = run_local_grouped_htss_keygen(&config).unwrap();
        let signer_set = vec![pid(1), pid(3), pid(6), pid(7), pid(8), pid(9)];
        let err = sign_digest_with_local_grouped_htss_threshold_shares(
            &keyset.group_key,
            [18u8; 32],
            &keyset.shares,
            &signer_set,
            &config,
        )
        .unwrap_err();
        assert!(err.to_string().contains("rank 1 needs 2"));
    }

    #[test]
    fn signing_request_validates_signer_set() {
        let threshold = ThresholdConfig::new(2, 3).unwrap();
        let shares = run_dkg();
        let request = SigningRequest::new(
            SessionId::new("sign-demo").unwrap(),
            shares[0].group_key.clone(),
            [1u8; 32],
            vec![pid(1), pid(2)],
            &threshold,
        )
        .unwrap();
        assert_eq!(request.signer_set.len(), 2);
    }

    #[test]
    fn round1_package_round_trips_through_protocol_message() {
        let session_id = SessionId::new("dkg-demo").unwrap();
        let package = Round1Package {
            participant_id: pid(1),
            bytes: vec![1, 2, 3],
        };
        let message = package.to_protocol_message(session_id).unwrap();
        assert_eq!(message.kind, ProtocolMessageKind::FrostDkgRound1);
        assert_eq!(
            Round1Package::from_protocol_message(&message).unwrap(),
            package
        );
    }

    #[test]
    fn round2_package_round_trips_through_direct_protocol_message() {
        let session_id = SessionId::new("dkg-demo").unwrap();
        let package = Round2Package {
            sender: pid(1),
            recipient: pid(2),
            bytes: vec![4, 5, 6],
        };
        let message = package.to_protocol_message(session_id).unwrap();
        assert_eq!(message.kind, ProtocolMessageKind::FrostDkgRound2);
        assert_eq!(message.recipient, Some(pid(2)));
        assert_eq!(
            Round2Package::from_protocol_message(&message).unwrap(),
            package
        );
    }

    #[test]
    fn package_decoder_rejects_wrong_kind() {
        let package = Round1Package {
            participant_id: pid(1),
            bytes: vec![1],
        };
        let message = ProtocolMessage::broadcast(
            SessionId::new("dkg-demo").unwrap(),
            pid(1),
            ProtocolMessageKind::FrostSignatureShare,
            encode_payload(&package).unwrap(),
        );
        assert!(Round1Package::from_protocol_message(&message).is_err());
    }

    #[test]
    fn signing_packages_round_trip_through_protocol_messages() {
        let nonce = NoncePackage {
            participant_id: pid(1),
            signing_session_id: SessionId::new("sign-demo").unwrap(),
            public_nonce_bytes: vec![7, 8],
        };
        let nonce_message = nonce.to_protocol_message().unwrap();
        assert_eq!(
            NoncePackage::from_protocol_message(&nonce_message).unwrap(),
            nonce
        );

        let share = SignatureSharePackage {
            participant_id: pid(2),
            signing_session_id: SessionId::new("sign-demo").unwrap(),
            public_nonce_bytes: vec![7],
            signature_share_bytes: vec![9, 10],
        };
        let share_message = share.to_protocol_message().unwrap();
        assert_eq!(
            SignatureSharePackage::from_protocol_message(&share_message).unwrap(),
            share
        );
    }

    #[test]
    fn htss_signing_packages_round_trip_through_protocol_messages() {
        let nonce = HtssNoncePackage {
            participant_id: pid(1),
            signing_session_id: SessionId::new("htss-sign-demo").unwrap(),
            public_nonce_bytes: vec![2; 33],
        };
        let nonce_message = nonce.to_protocol_message().unwrap();
        assert_eq!(nonce_message.kind, ProtocolMessageKind::HtssSigningNonce);
        assert_eq!(
            HtssNoncePackage::from_protocol_message(&nonce_message).unwrap(),
            nonce
        );

        let share = HtssSignatureSharePackage {
            participant_id: pid(2),
            signing_session_id: SessionId::new("htss-sign-demo").unwrap(),
            signature_share_bytes: [4; 32],
        };
        let share_message = share.to_protocol_message().unwrap();
        assert_eq!(share_message.kind, ProtocolMessageKind::HtssSignatureShare);
        assert_eq!(
            HtssSignatureSharePackage::from_protocol_message(&share_message).unwrap(),
            share
        );
    }

    #[test]
    fn frost_dkg_sessions_derive_same_group_key() {
        let local_shares = run_dkg();
        assert_eq!(local_shares.len(), 3);
        assert_eq!(local_shares[0].group_key, local_shares[1].group_key);
        assert_eq!(local_shares[1].group_key, local_shares[2].group_key);
        assert!(local_shares
            .iter()
            .all(|share| !share.secret_share_bytes.is_empty()));
    }

    #[test]
    fn frost_signing_sessions_aggregate_valid_signature() {
        let local_shares = run_dkg();
        let threshold = ThresholdConfig::new(2, 3).unwrap();
        let request = SigningRequest::new(
            SessionId::new("sign-demo").unwrap(),
            local_shares[0].group_key.clone(),
            [42u8; 32],
            vec![pid(1), pid(2)],
            &threshold,
        )
        .unwrap();
        let signing_1 = FrostSigningSession::new(request.clone());
        let signing_2 = FrostSigningSession::new(request.clone());
        let aggregator = FrostSigningSession::new(request);
        let nonces = vec![
            signing_1.nonce(&local_shares[0]).unwrap(),
            signing_2.nonce(&local_shares[1]).unwrap(),
        ];
        let shares = vec![
            signing_1.sign_share(&local_shares[0], &nonces).unwrap(),
            signing_2.sign_share(&local_shares[1], &nonces).unwrap(),
        ];
        let aggregate = aggregator.aggregate(&shares).unwrap();
        assert!(!aggregate.signature_bytes.is_empty());
    }
}
