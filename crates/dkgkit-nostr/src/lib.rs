//! Nostr reference transport helpers for DKGKit.
//!
//! This crate keeps Nostr-specific event mapping outside the cryptographic core.
//! Live relay I/O can be layered on top of the deterministic envelope mapping
//! implemented here.

use dkgkit_core::{
    DkgKitError, ParticipantId, ProtocolMessage, ProtocolMessageKind, Result, SessionId,
};
use dkgkit_transport::Transport;
use serde::{Deserialize, Serialize};

pub const DKGKIT_NOSTR_EVENT_KIND: u64 = 30333;
pub const DKGKIT_NOSTR_APP_TAG: &str = "dkgkit";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NostrEnvelopeEvent {
    pub kind: u64,
    pub app: String,
    pub session_id: String,
    pub sender: u16,
    pub recipient: Option<u16>,
    pub message_kind: String,
    pub content: String,
}

impl NostrEnvelopeEvent {
    pub fn from_protocol_message(message: &ProtocolMessage) -> Result<Self> {
        let content = String::from_utf8(message.encode_json()?)
            .map_err(|err| DkgKitError::Serialization(err.to_string()))?;
        Ok(Self {
            kind: DKGKIT_NOSTR_EVENT_KIND,
            app: DKGKIT_NOSTR_APP_TAG.to_string(),
            session_id: message.session_id.0.clone(),
            sender: message.sender.0,
            recipient: message.recipient.map(|recipient| recipient.0),
            message_kind: message.kind.as_str().to_string(),
            content,
        })
    }

    pub fn to_protocol_message(&self) -> Result<ProtocolMessage> {
        self.validate_metadata()?;
        let message = ProtocolMessage::decode_json(self.content.as_bytes())?;
        if message.session_id.0 != self.session_id {
            return Err(DkgKitError::Protocol(
                "Nostr event session tag does not match message content".to_string(),
            ));
        }
        if message.sender.0 != self.sender {
            return Err(DkgKitError::Protocol(
                "Nostr event sender tag does not match message content".to_string(),
            ));
        }
        if message.recipient.map(|recipient| recipient.0) != self.recipient {
            return Err(DkgKitError::Protocol(
                "Nostr event recipient tag does not match message content".to_string(),
            ));
        }
        if message.kind.as_str() != self.message_kind {
            return Err(DkgKitError::Protocol(
                "Nostr event kind tag does not match message content".to_string(),
            ));
        }
        Ok(message)
    }

    pub fn tags(&self) -> Vec<Vec<String>> {
        let mut tags = vec![
            vec!["app".to_string(), self.app.clone()],
            vec!["session".to_string(), self.session_id.clone()],
            vec!["sender".to_string(), self.sender.to_string()],
            vec!["message_kind".to_string(), self.message_kind.clone()],
        ];
        if let Some(recipient) = self.recipient {
            tags.push(vec!["recipient".to_string(), recipient.to_string()]);
        }
        tags
    }

    fn validate_metadata(&self) -> Result<()> {
        if self.kind != DKGKIT_NOSTR_EVENT_KIND {
            return Err(DkgKitError::Protocol(format!(
                "unexpected Nostr event kind: expected {}, got {}",
                DKGKIT_NOSTR_EVENT_KIND, self.kind
            )));
        }
        if self.app != DKGKIT_NOSTR_APP_TAG {
            return Err(DkgKitError::Protocol(format!(
                "unexpected Nostr app tag: expected {}, got {}",
                DKGKIT_NOSTR_APP_TAG, self.app
            )));
        }
        SessionId::new(self.session_id.clone())?;
        ParticipantId::new(self.sender)?;
        if let Some(recipient) = self.recipient {
            ParticipantId::new(recipient)?;
        }
        if matches!(ProtocolMessageKind::from(self.message_kind.as_str()), ProtocolMessageKind::Custom(ref value) if value.trim().is_empty())
        {
            return Err(DkgKitError::EmptyMessageKind);
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct NostrTransportConfig {
    pub relays: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct NostrTransport {
    pub config: NostrTransportConfig,
}

impl NostrTransport {
    pub fn new(config: NostrTransportConfig) -> Self {
        Self { config }
    }
}

impl Transport for NostrTransport {
    fn connect(&mut self) -> Result<()> {
        Err(DkgKitError::NotImplemented(
            "Nostr relay transport migration",
        ))
    }

    fn disconnect(&mut self) -> Result<()> {
        Ok(())
    }

    fn publish(&mut self, _message: ProtocolMessage) -> Result<()> {
        Err(DkgKitError::NotImplemented("Nostr publish migration"))
    }

    fn drain_matching(
        &mut self,
        _session_id: &SessionId,
        _predicate: &mut dyn FnMut(&ProtocolMessage) -> bool,
    ) -> Result<Vec<ProtocolMessage>> {
        Err(DkgKitError::NotImplemented(
            "Nostr subscribe/drain migration",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dkgkit_core::{GroupThresholdRequirement, RankedParticipant};
    use dkgkit_frost::{
        aggregate_htss_signature_shares, finalize_htss_dkg,
        hierarchical_config_from_grouped_threshold, htss_dkg_round1, htss_dkg_round2, htss_nonce,
        htss_sign_share, run_local_grouped_htss_keygen, validate_grouped_threshold_signer_set,
        HtssDkgRound1Package, HtssDkgRound2Package, HtssLocalKeySet, HtssNoncePackage,
        HtssSignatureSharePackage,
    };

    fn message() -> ProtocolMessage {
        ProtocolMessage::direct(
            SessionId::new("room-1").unwrap(),
            ParticipantId::new(1).unwrap(),
            ParticipantId::new(2).unwrap(),
            ProtocolMessageKind::FrostDkgRound2,
            vec![1, 2, 3],
        )
    }

    fn pid(value: u16) -> ParticipantId {
        ParticipantId::new(value).unwrap()
    }

    fn grouped_config_123_of_235() -> dkgkit_core::GroupedThresholdConfig {
        dkgkit_core::GroupedThresholdConfig::new(
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

    #[test]
    fn nostr_envelope_event_round_trips_protocol_message() {
        let message = message();
        let event = NostrEnvelopeEvent::from_protocol_message(&message).unwrap();
        assert_eq!(event.kind, DKGKIT_NOSTR_EVENT_KIND);
        assert_eq!(event.tags().len(), 5);
        assert_eq!(event.to_protocol_message().unwrap(), message);
    }

    #[test]
    fn nostr_envelope_rejects_mismatched_metadata() {
        let message = message();
        let mut event = NostrEnvelopeEvent::from_protocol_message(&message).unwrap();
        event.sender = 3;
        assert!(event.to_protocol_message().is_err());
    }

    #[test]
    fn local_nostr_event_transport_publishes_tags_and_drains_protocol_messages() {
        let message = message();
        let session_id = message.session_id.clone();
        let mut transport = LocalNostrEventTransport::default();
        transport.connect().unwrap();
        transport.publish(message.clone()).unwrap();

        assert_eq!(transport.pending_len(), 1);
        assert_eq!(transport.events()[0].tags().len(), 5);

        let mut only_round2 =
            |message: &ProtocolMessage| message.kind == ProtocolMessageKind::FrostDkgRound2;
        let drained = transport
            .drain_matching(&session_id, &mut only_round2)
            .unwrap();
        assert_eq!(drained, vec![message]);
        assert_eq!(transport.pending_len(), 0);
    }

    #[test]
    fn local_nostr_event_transport_preserves_non_matching_events() {
        let message = message();
        let session_id = message.session_id.clone();
        let mut transport = LocalNostrEventTransport::default();
        transport.publish(message).unwrap();

        let mut only_nonces =
            |message: &ProtocolMessage| message.kind == ProtocolMessageKind::FrostSigningNonce;
        let drained = transport
            .drain_matching(&session_id, &mut only_nonces)
            .unwrap();
        assert!(drained.is_empty());
        assert_eq!(transport.pending_len(), 1);
    }

    #[test]
    fn local_nostr_event_transport_runs_htss_dkg_derivative_share_flow() {
        let config =
            hierarchical_config_from_grouped_threshold(&grouped_config_123_of_235()).unwrap();
        let dkg_session_id = SessionId::new("nostr-htss-dkg").unwrap();
        let states = config
            .participants
            .iter()
            .map(|participant| htss_dkg_round1(participant.id, &config))
            .collect::<Result<Vec<_>>>()
            .unwrap();

        let mut relay = LocalNostrEventTransport::default();
        relay.connect().unwrap();
        for state in &states {
            relay
                .publish(
                    state
                        .package
                        .to_protocol_message(dkg_session_id.clone())
                        .unwrap(),
                )
                .unwrap();
        }
        assert_eq!(relay.pending_len(), config.participants.len());
        assert!(relay.events().iter().all(|event| {
            event.kind == DKGKIT_NOSTR_EVENT_KIND
                && event.message_kind == ProtocolMessageKind::HtssDkgRound1.as_str()
        }));

        let mut only_htss_dkg_round1 =
            |message: &ProtocolMessage| message.kind == ProtocolMessageKind::HtssDkgRound1;
        let round1_packages = relay
            .drain_matching(&dkg_session_id, &mut only_htss_dkg_round1)
            .unwrap()
            .iter()
            .map(HtssDkgRound1Package::from_protocol_message)
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert_eq!(round1_packages.len(), config.participants.len());

        for state in &states {
            for package in htss_dkg_round2(state, &round1_packages, &config).unwrap() {
                relay
                    .publish(package.to_protocol_message(dkg_session_id.clone()).unwrap())
                    .unwrap();
            }
        }
        assert_eq!(
            relay.pending_len(),
            config.participants.len() * config.participants.len()
        );

        let mut shares = Vec::with_capacity(config.participants.len());
        let mut group_key = None;
        for participant in &config.participants {
            let recipient = participant.id;
            let mut only_recipient_round2 = |message: &ProtocolMessage| {
                message.kind == ProtocolMessageKind::HtssDkgRound2 && message.is_for(recipient)
            };
            let round2_packages = relay
                .drain_matching(&dkg_session_id, &mut only_recipient_round2)
                .unwrap()
                .iter()
                .map(HtssDkgRound2Package::from_protocol_message)
                .collect::<Result<Vec<_>>>()
                .unwrap();
            let (participant_group_key, share) =
                finalize_htss_dkg(recipient, &round1_packages, &round2_packages, &config).unwrap();
            if let Some(existing_group_key) = &group_key {
                assert_eq!(existing_group_key, &participant_group_key);
            } else {
                group_key = Some(participant_group_key);
            }
            shares.push(share);
        }
        assert_eq!(relay.pending_len(), 0);

        let keyset = HtssLocalKeySet {
            group_key: group_key.unwrap(),
            shares,
        };
        let signing_session_id = SessionId::new("nostr-htss-dkg-sign").unwrap();
        let signer_set = vec![pid(1), pid(3), pid(4), pid(6), pid(7), pid(8)];
        let digest = [25u8; 32];
        let selected_shares = signer_set
            .iter()
            .map(|participant_id| {
                keyset
                    .shares
                    .iter()
                    .find(|share| share.participant_id == *participant_id)
                    .cloned()
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let local_nonces = selected_shares
            .iter()
            .map(|share| htss_nonce(signing_session_id.clone(), share))
            .collect::<Result<Vec<_>>>()
            .unwrap();
        let public_nonces = local_nonces
            .iter()
            .map(|nonce| nonce.package.clone())
            .collect::<Vec<_>>();
        let signature_shares = selected_shares
            .iter()
            .zip(local_nonces.iter())
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
            })
            .collect::<Result<Vec<_>>>()
            .unwrap();
        let signature = aggregate_htss_signature_shares(
            &keyset.group_key,
            digest,
            &public_nonces,
            &signature_shares,
            &signer_set,
            &config,
        )
        .unwrap();
        assert!(dkgkit_bitcoin::verify_aggregate_signature_digest(
            &keyset.group_key,
            &digest,
            &signature
        )
        .unwrap());
    }

    #[test]
    fn local_nostr_event_transport_runs_grouped_htss_123_of_235_signing() {
        let config = grouped_config_123_of_235();
        let hierarchical_config = hierarchical_config_from_grouped_threshold(&config).unwrap();
        let keyset = run_local_grouped_htss_keygen(&config).unwrap();
        let signing_session_id = SessionId::new("nostr-grouped-htss-sign").unwrap();
        let signer_set = vec![pid(1), pid(3), pid(4), pid(6), pid(7), pid(8)];
        let digest = [23u8; 32];

        validate_grouped_threshold_signer_set(&signer_set, &config).unwrap();
        let err = validate_grouped_threshold_signer_set(
            &[pid(1), pid(3), pid(6), pid(7), pid(8), pid(9)],
            &config,
        )
        .unwrap_err();
        assert!(err.to_string().contains("rank 1 needs 2"));

        let selected_shares = signer_set
            .iter()
            .map(|participant_id| {
                keyset
                    .shares
                    .iter()
                    .find(|share| share.participant_id == *participant_id)
                    .cloned()
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let local_nonces = selected_shares
            .iter()
            .map(|share| htss_nonce(signing_session_id.clone(), share))
            .collect::<Result<Vec<_>>>()
            .unwrap();

        let mut relay = LocalNostrEventTransport::default();
        relay.connect().unwrap();
        for nonce in &local_nonces {
            relay
                .publish(nonce.package.to_protocol_message().unwrap())
                .unwrap();
        }
        assert_eq!(relay.pending_len(), signer_set.len());
        assert!(relay.events().iter().all(|event| {
            event.kind == DKGKIT_NOSTR_EVENT_KIND
                && event.message_kind == ProtocolMessageKind::HtssSigningNonce.as_str()
        }));

        let mut only_htss_nonces =
            |message: &ProtocolMessage| message.kind == ProtocolMessageKind::HtssSigningNonce;
        let public_nonces = relay
            .drain_matching(&signing_session_id, &mut only_htss_nonces)
            .unwrap()
            .iter()
            .map(HtssNoncePackage::from_protocol_message)
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert_eq!(public_nonces.len(), signer_set.len());
        assert_eq!(relay.pending_len(), 0);

        for (share, nonce) in selected_shares.iter().zip(local_nonces.iter()) {
            let signature_share = htss_sign_share(
                &keyset.group_key,
                digest,
                share,
                nonce,
                &public_nonces,
                &signer_set,
                &hierarchical_config,
            )
            .unwrap();
            relay
                .publish(signature_share.to_protocol_message().unwrap())
                .unwrap();
        }

        let mut only_htss_signature_shares =
            |message: &ProtocolMessage| message.kind == ProtocolMessageKind::HtssSignatureShare;
        let signature_shares = relay
            .drain_matching(&signing_session_id, &mut only_htss_signature_shares)
            .unwrap()
            .iter()
            .map(HtssSignatureSharePackage::from_protocol_message)
            .collect::<Result<Vec<_>>>()
            .unwrap();
        let signature = aggregate_htss_signature_shares(
            &keyset.group_key,
            digest,
            &public_nonces,
            &signature_shares,
            &signer_set,
            &hierarchical_config,
        )
        .unwrap();

        assert!(dkgkit_bitcoin::verify_aggregate_signature_digest(
            &keyset.group_key,
            &digest,
            &signature
        )
        .unwrap());
    }
}

#[derive(Debug, Default, Clone)]
pub struct LocalNostrEventTransport {
    connected: bool,
    events: Vec<NostrEnvelopeEvent>,
}

impl LocalNostrEventTransport {
    pub fn events(&self) -> &[NostrEnvelopeEvent] {
        &self.events
    }

    pub fn pending_len(&self) -> usize {
        self.events.len()
    }
}

impl Transport for LocalNostrEventTransport {
    fn connect(&mut self) -> Result<()> {
        self.connected = true;
        Ok(())
    }

    fn disconnect(&mut self) -> Result<()> {
        self.connected = false;
        Ok(())
    }

    fn publish(&mut self, message: ProtocolMessage) -> Result<()> {
        self.events
            .push(NostrEnvelopeEvent::from_protocol_message(&message)?);
        Ok(())
    }

    fn drain_matching(
        &mut self,
        session_id: &SessionId,
        predicate: &mut dyn FnMut(&ProtocolMessage) -> bool,
    ) -> Result<Vec<ProtocolMessage>> {
        let mut drained = Vec::new();
        let mut kept = Vec::new();
        for event in self.events.drain(..) {
            let message = event.to_protocol_message()?;
            if &message.session_id == session_id && predicate(&message) {
                drained.push(message);
            } else {
                kept.push(event);
            }
        }
        self.events = kept;
        Ok(drained)
    }
}
