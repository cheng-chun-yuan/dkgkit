//! Core DKGKit protocol types.
//!
//! `dkgkit-core` contains protocol-agnostic identifiers, participant models,
//! threshold configuration, session manifests, and shared errors. It must not
//! depend on Bitcoin, Nostr, FROST implementation details, storage, or UI code.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const DKGKIT_PROTOCOL_VERSION: &str = "dkgkit/0.1";

pub type Result<T> = std::result::Result<T, DkgKitError>;

#[derive(Debug, thiserror::Error)]
pub enum DkgKitError {
    #[error("invalid threshold config: threshold={threshold}, participants={participants}")]
    InvalidThreshold { threshold: u16, participants: u16 },
    #[error("invalid participant id: {0}")]
    InvalidParticipantId(u16),
    #[error("participant count mismatch: expected {expected}, got {actual}")]
    ParticipantCountMismatch { expected: u16, actual: usize },
    #[error("duplicate participant id: {0}")]
    DuplicateParticipantId(u16),
    #[error("participant id {participant_id} exceeds configured participant count {participants}")]
    ParticipantOutOfRange {
        participant_id: u16,
        participants: u16,
    },
    #[error("missing ranked participant id: {0}")]
    MissingRankedParticipant(u16),
    #[error("session id cannot be empty")]
    EmptySessionId,
    #[error("protocol message kind cannot be empty")]
    EmptyMessageKind,
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("feature not implemented yet: {0}")]
    NotImplemented(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub String);

impl SessionId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(DkgKitError::EmptySessionId);
        }
        Ok(Self(value))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ParticipantId(pub u16);

impl ParticipantId {
    pub fn new(value: u16) -> Result<Self> {
        if value == 0 {
            return Err(DkgKitError::InvalidParticipantId(value));
        }
        Ok(Self(value))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdConfig {
    pub threshold: u16,
    pub participants: u16,
}

impl ThresholdConfig {
    pub fn new(threshold: u16, participants: u16) -> Result<Self> {
        if threshold == 0 || participants == 0 || threshold > participants {
            return Err(DkgKitError::InvalidThreshold {
                threshold,
                participants,
            });
        }
        Ok(Self {
            threshold,
            participants,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Participant {
    pub id: ParticipantId,
    pub label: Option<String>,
}

impl Participant {
    pub fn new(id: u16, label: impl Into<Option<String>>) -> Result<Self> {
        Ok(Self {
            id: ParticipantId::new(id)?,
            label: label.into(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Rank(pub u16);

impl Rank {
    pub fn new(value: u16) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RankedParticipant {
    pub id: ParticipantId,
    /// Lower rank values represent higher authority. Rank 0 is the highest level.
    pub rank: Rank,
    pub label: Option<String>,
}

impl RankedParticipant {
    pub fn new(id: u16, rank: u16, label: impl Into<Option<String>>) -> Result<Self> {
        Ok(Self {
            id: ParticipantId::new(id)?,
            rank: Rank::new(rank),
            label: label.into(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HierarchicalThresholdConfig {
    pub threshold: u16,
    pub participants: Vec<RankedParticipant>,
}

impl HierarchicalThresholdConfig {
    pub fn new(threshold: u16, participants: Vec<RankedParticipant>) -> Result<Self> {
        let participant_count =
            u16::try_from(participants.len()).map_err(|_| DkgKitError::InvalidThreshold {
                threshold,
                participants: u16::MAX,
            })?;
        ThresholdConfig::new(threshold, participant_count)?;
        let mut seen = BTreeSet::new();
        for participant in &participants {
            if !seen.insert(participant.id.0) {
                return Err(DkgKitError::DuplicateParticipantId(participant.id.0));
            }
        }
        Ok(Self {
            threshold,
            participants,
        })
    }

    pub fn participant_count(&self) -> u16 {
        self.participants.len() as u16
    }

    pub fn threshold_config(&self) -> Result<ThresholdConfig> {
        ThresholdConfig::new(self.threshold, self.participant_count())
    }

    pub fn rank_of(&self, participant_id: ParticipantId) -> Option<Rank> {
        self.participants
            .iter()
            .find(|participant| participant.id == participant_id)
            .map(|participant| participant.rank)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupThresholdRequirement {
    pub rank: Rank,
    pub required: u16,
    pub total: u16,
}

impl GroupThresholdRequirement {
    pub fn new(rank: u16, required: u16, total: u16) -> Result<Self> {
        if required == 0 || total == 0 || required > total {
            return Err(DkgKitError::InvalidThreshold {
                threshold: required,
                participants: total,
            });
        }
        Ok(Self {
            rank: Rank::new(rank),
            required,
            total,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupedThresholdConfig {
    pub participants: Vec<RankedParticipant>,
    pub requirements: Vec<GroupThresholdRequirement>,
}

impl GroupedThresholdConfig {
    pub fn new(
        participants: Vec<RankedParticipant>,
        requirements: Vec<GroupThresholdRequirement>,
    ) -> Result<Self> {
        if participants.is_empty() || requirements.is_empty() {
            return Err(DkgKitError::InvalidThreshold {
                threshold: 0,
                participants: participants.len() as u16,
            });
        }

        let mut seen_participants = BTreeSet::new();
        for participant in &participants {
            if !seen_participants.insert(participant.id.0) {
                return Err(DkgKitError::DuplicateParticipantId(participant.id.0));
            }
        }

        let mut seen_ranks = BTreeSet::new();
        for requirement in &requirements {
            if !seen_ranks.insert(requirement.rank.0) {
                return Err(DkgKitError::Protocol(format!(
                    "duplicate grouped threshold rank: {}",
                    requirement.rank.0
                )));
            }
            let actual_total = participants
                .iter()
                .filter(|participant| participant.rank == requirement.rank)
                .count();
            if actual_total != requirement.total as usize {
                return Err(DkgKitError::Protocol(format!(
                    "grouped threshold rank {} total mismatch: declared {}, found {}",
                    requirement.rank.0, requirement.total, actual_total
                )));
            }
        }

        for participant in &participants {
            if !seen_ranks.contains(&participant.rank.0) {
                return Err(DkgKitError::Protocol(format!(
                    "missing grouped threshold requirement for rank {}",
                    participant.rank.0
                )));
            }
        }

        Ok(Self {
            participants,
            requirements,
        })
    }

    pub fn participant_count(&self) -> u16 {
        self.participants.len() as u16
    }

    pub fn required_signer_count(&self) -> u16 {
        self.requirements
            .iter()
            .map(|requirement| requirement.required)
            .sum()
    }

    pub fn threshold_config(&self) -> Result<ThresholdConfig> {
        ThresholdConfig::new(self.required_signer_count(), self.participant_count())
    }

    pub fn rank_of(&self, participant_id: ParticipantId) -> Option<Rank> {
        self.participants
            .iter()
            .find(|participant| participant.id == participant_id)
            .map(|participant| participant.rank)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigningPolicy {
    Threshold(ThresholdConfig),
    Hierarchical(HierarchicalThresholdConfig),
    Grouped(GroupedThresholdConfig),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionConfig {
    pub session_id: SessionId,
    pub threshold: ThresholdConfig,
    pub participants: Vec<Participant>,
}

impl SessionConfig {
    pub fn new(
        session_id: impl Into<String>,
        threshold: u16,
        participant_count: u16,
        participants: Vec<Participant>,
    ) -> Result<Self> {
        let threshold = ThresholdConfig::new(threshold, participant_count)?;
        if participants.len() != participant_count as usize {
            return Err(DkgKitError::ParticipantCountMismatch {
                expected: participant_count,
                actual: participants.len(),
            });
        }
        let mut seen = BTreeSet::new();
        for participant in &participants {
            if participant.id.0 > participant_count {
                return Err(DkgKitError::ParticipantOutOfRange {
                    participant_id: participant.id.0,
                    participants: participant_count,
                });
            }
            if !seen.insert(participant.id.0) {
                return Err(DkgKitError::DuplicateParticipantId(participant.id.0));
            }
        }
        Ok(Self {
            session_id: SessionId::new(session_id)?,
            threshold,
            participants,
        })
    }

    pub fn participant(&self, id: ParticipantId) -> Option<&Participant> {
        self.participants
            .iter()
            .find(|participant| participant.id == id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionPhase {
    Created,
    Round1,
    Round2,
    Finalized,
    Signing,
    Complete,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionManifest {
    pub config: SessionConfig,
    pub protocol: String,
    pub protocol_version: String,
    pub phase: SessionPhase,
}

impl SessionManifest {
    pub fn frost_v1(config: SessionConfig) -> Self {
        Self {
            config,
            protocol: "frost".to_string(),
            protocol_version: "0.1".to_string(),
            phase: SessionPhase::Created,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolMessageKind {
    SessionManifest,
    FrostDkgRound1,
    FrostDkgRound2,
    HtssDkgRound1,
    HtssDkgRound2,
    FrostSigningNonce,
    FrostSignatureShare,
    HtssSigningNonce,
    HtssSignatureShare,
    Custom(String),
}

impl ProtocolMessageKind {
    pub fn custom(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(DkgKitError::EmptyMessageKind);
        }
        Ok(Self::Custom(value))
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::SessionManifest => "session_manifest",
            Self::FrostDkgRound1 => "frost_dkg_round1",
            Self::FrostDkgRound2 => "frost_dkg_round2",
            Self::HtssDkgRound1 => "htss_dkg_round1",
            Self::HtssDkgRound2 => "htss_dkg_round2",
            Self::FrostSigningNonce => "frost_signing_nonce",
            Self::FrostSignatureShare => "frost_signature_share",
            Self::HtssSigningNonce => "htss_signing_nonce",
            Self::HtssSignatureShare => "htss_signature_share",
            Self::Custom(value) => value.as_str(),
        }
    }
}

impl From<&str> for ProtocolMessageKind {
    fn from(value: &str) -> Self {
        match value {
            "session_manifest" => Self::SessionManifest,
            "frost_dkg_round1" | "round1" => Self::FrostDkgRound1,
            "frost_dkg_round2" | "round2" => Self::FrostDkgRound2,
            "htss_dkg_round1" => Self::HtssDkgRound1,
            "htss_dkg_round2" => Self::HtssDkgRound2,
            "frost_signing_nonce" | "nonce" => Self::FrostSigningNonce,
            "frost_signature_share" | "signature_share" => Self::FrostSignatureShare,
            "htss_signing_nonce" => Self::HtssSigningNonce,
            "htss_signature_share" => Self::HtssSignatureShare,
            other => Self::Custom(other.to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolMessage {
    pub protocol_version: String,
    pub session_id: SessionId,
    pub sender: ParticipantId,
    pub recipient: Option<ParticipantId>,
    pub kind: ProtocolMessageKind,
    pub payload: Vec<u8>,
}

impl ProtocolMessage {
    pub fn new(
        session_id: SessionId,
        sender: ParticipantId,
        kind: impl Into<ProtocolMessageKind>,
        payload: Vec<u8>,
    ) -> Self {
        Self::broadcast(session_id, sender, kind, payload)
    }

    pub fn broadcast(
        session_id: SessionId,
        sender: ParticipantId,
        kind: impl Into<ProtocolMessageKind>,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            protocol_version: DKGKIT_PROTOCOL_VERSION.to_string(),
            session_id,
            sender,
            recipient: None,
            kind: kind.into(),
            payload,
        }
    }

    pub fn direct(
        session_id: SessionId,
        sender: ParticipantId,
        recipient: ParticipantId,
        kind: impl Into<ProtocolMessageKind>,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            protocol_version: DKGKIT_PROTOCOL_VERSION.to_string(),
            session_id,
            sender,
            recipient: Some(recipient),
            kind: kind.into(),
            payload,
        }
    }

    pub fn is_for(&self, participant_id: ParticipantId) -> bool {
        self.recipient
            .map(|recipient| recipient == participant_id)
            .unwrap_or(true)
    }

    pub fn encode_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|err| DkgKitError::Serialization(err.to_string()))
    }

    pub fn decode_json(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|err| DkgKitError::Serialization(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn participant(id: u16) -> Participant {
        Participant::new(id, Some(format!("party-{id}"))).unwrap()
    }

    fn ranked(id: u16, rank: u16) -> RankedParticipant {
        RankedParticipant::new(id, rank, Some(format!("party-{id}"))).unwrap()
    }

    #[test]
    fn threshold_config_rejects_impossible_shapes() {
        assert!(ThresholdConfig::new(0, 3).is_err());
        assert!(ThresholdConfig::new(4, 3).is_err());
        assert!(ThresholdConfig::new(2, 3).is_ok());
    }

    #[test]
    fn hierarchical_threshold_config_allows_shared_ranks() {
        let config = HierarchicalThresholdConfig::new(
            3,
            vec![ranked(1, 0), ranked(2, 1), ranked(3, 1), ranked(4, 2)],
        )
        .unwrap();
        assert_eq!(config.participant_count(), 4);
        assert_eq!(
            config.rank_of(ParticipantId::new(3).unwrap()),
            Some(Rank(1))
        );
        assert_eq!(config.threshold_config().unwrap().threshold, 3);
    }

    #[test]
    fn hierarchical_threshold_config_rejects_duplicate_participants() {
        let err =
            HierarchicalThresholdConfig::new(2, vec![ranked(1, 0), ranked(1, 1)]).unwrap_err();
        assert!(matches!(err, DkgKitError::DuplicateParticipantId(1)));
    }

    #[test]
    fn grouped_threshold_config_supports_per_rank_quorums() {
        let config = GroupedThresholdConfig::new(
            vec![
                ranked(1, 0),
                ranked(2, 0),
                ranked(3, 1),
                ranked(4, 1),
                ranked(5, 1),
            ],
            vec![
                GroupThresholdRequirement::new(1, 2, 3).unwrap(),
                GroupThresholdRequirement::new(0, 1, 2).unwrap(),
            ],
        )
        .unwrap();
        assert_eq!(config.participant_count(), 5);
        assert_eq!(config.required_signer_count(), 3);
        assert_eq!(config.threshold_config().unwrap().threshold, 3);
        assert_eq!(
            config.rank_of(ParticipantId::new(4).unwrap()),
            Some(Rank(1))
        );
    }

    #[test]
    fn grouped_threshold_config_rejects_declared_total_mismatch() {
        let err = GroupedThresholdConfig::new(
            vec![ranked(1, 0), ranked(2, 0)],
            vec![GroupThresholdRequirement::new(1, 2, 3).unwrap()],
        )
        .unwrap_err();
        assert!(err.to_string().contains("total mismatch"));
    }

    #[test]
    fn session_config_rejects_duplicate_participants() {
        let err = SessionConfig::new(
            "demo",
            2,
            3,
            vec![participant(1), participant(1), participant(3)],
        )
        .unwrap_err();
        assert!(matches!(err, DkgKitError::DuplicateParticipantId(1)));
    }

    #[test]
    fn session_manifest_defaults_to_frost_created() {
        let config = SessionConfig::new(
            "demo",
            2,
            3,
            vec![participant(1), participant(2), participant(3)],
        )
        .unwrap();
        let manifest = SessionManifest::frost_v1(config);
        assert_eq!(manifest.protocol, "frost");
        assert_eq!(manifest.phase, SessionPhase::Created);
    }

    #[test]
    fn protocol_message_defaults_to_broadcast_current_version() {
        let message = ProtocolMessage::new(
            SessionId::new("demo").unwrap(),
            ParticipantId::new(1).unwrap(),
            ProtocolMessageKind::FrostDkgRound1,
            vec![1, 2, 3],
        );
        assert_eq!(message.protocol_version, DKGKIT_PROTOCOL_VERSION);
        assert_eq!(message.kind.as_str(), "frost_dkg_round1");
        assert!(message.recipient.is_none());
        assert!(message.is_for(ParticipantId::new(2).unwrap()));
    }

    #[test]
    fn direct_protocol_message_targets_one_participant() {
        let message = ProtocolMessage::direct(
            SessionId::new("demo").unwrap(),
            ParticipantId::new(1).unwrap(),
            ParticipantId::new(2).unwrap(),
            ProtocolMessageKind::FrostDkgRound2,
            vec![9],
        );
        assert!(message.is_for(ParticipantId::new(2).unwrap()));
        assert!(!message.is_for(ParticipantId::new(3).unwrap()));
    }

    #[test]
    fn protocol_message_json_round_trips() {
        let message = ProtocolMessage::direct(
            SessionId::new("demo").unwrap(),
            ParticipantId::new(1).unwrap(),
            ParticipantId::new(2).unwrap(),
            ProtocolMessageKind::FrostSignatureShare,
            vec![1, 2, 3, 4],
        );
        let encoded = message.encode_json().unwrap();
        let decoded = ProtocolMessage::decode_json(&encoded).unwrap();
        assert_eq!(decoded, message);
    }
}
