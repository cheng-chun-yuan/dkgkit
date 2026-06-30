//! Developer-facing DKGKit SDK facade.

pub use dkgkit_bitcoin as bitcoin;
pub use dkgkit_core::{
    DkgKitError, GroupThresholdRequirement, GroupedThresholdConfig, HierarchicalThresholdConfig,
    Participant, ParticipantId, ProtocolMessage, ProtocolMessageKind, Rank, RankedParticipant,
    Result, SessionConfig, SessionId, SessionManifest, SessionPhase, SigningPolicy,
    ThresholdConfig, DKGKIT_PROTOCOL_VERSION,
};
pub use dkgkit_frost::{
    aggregate_htss_signature_shares, aggregate_htss_signature_shares_for_output,
    birkhoff_interpolation_coefficients, birkhoff_points_from_hierarchical_signer_set,
    decode_payload, encode_payload, finalize_htss_dkg, hierarchical_config_from_grouped_threshold,
    htss_dkg_round1, htss_dkg_round2, htss_nonce, htss_sign_share, htss_sign_share_for_output,
    reconstruct_htss_secret_scalar, run_distributed_htss_keygen, run_local_grouped_htss_keygen,
    run_local_htss_keygen, sign_digest_with_local_grouped_htss_threshold_shares,
    sign_digest_with_local_grouped_htss_threshold_shares_for_output,
    sign_digest_with_local_htss_shares, sign_digest_with_local_htss_threshold_shares,
    validate_grouped_threshold_signer_set, validate_hierarchical_signer_set, validate_signer_set,
    validate_signer_set_with_policy, AggregateSignature, BirkhoffCoefficient, BirkhoffPoint,
    DkgSessionConfig, FrostDkgSession, FrostSigningSession, GroupKey, GroupedSigningRequest,
    HierarchicalSigningRequest, HtssDkgRound1Package, HtssDkgRound1State, HtssDkgRound2Package,
    HtssLocalKeySet, HtssLocalKeyShare, HtssLocalNonce, HtssNoncePackage,
    HtssSignatureSharePackage, LocalKeyShare, NoncePackage, Round1Package, Round2Package,
    SignatureSharePackage, SigningRequest,
};
pub use dkgkit_transport::{MemoryTransport, Transport};

#[derive(Debug, Default)]
pub struct DkgKitSessionBuilder {
    session_id: Option<String>,
    threshold: Option<u16>,
    participant_count: Option<u16>,
    participants: Vec<Participant>,
    local_participant_id: Option<u16>,
}

impl DkgKitSessionBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn session_id(mut self, value: impl Into<String>) -> Self {
        self.session_id = Some(value.into());
        self
    }

    pub fn threshold(mut self, threshold: u16, participant_count: u16) -> Self {
        self.threshold = Some(threshold);
        self.participant_count = Some(participant_count);
        self
    }

    pub fn participant(mut self, id: u16, label: impl Into<Option<String>>) -> Result<Self> {
        self.participants.push(Participant::new(id, label)?);
        Ok(self)
    }

    pub fn local_participant(mut self, id: u16) -> Self {
        self.local_participant_id = Some(id);
        self
    }

    pub fn build_manifest(self) -> Result<SessionManifest> {
        let config = SessionConfig::new(
            self.session_id.unwrap_or_else(|| "default".to_string()),
            self.threshold.unwrap_or(0),
            self.participant_count.unwrap_or(0),
            self.participants,
        )?;
        Ok(SessionManifest::frost_v1(config))
    }

    pub fn build_frost_session(self) -> Result<FrostDkgSession> {
        let local_participant_id = ParticipantId::new(self.local_participant_id.unwrap_or(0))?;
        let manifest = self.build_manifest()?;
        let config = DkgSessionConfig {
            session_id: manifest.config.session_id,
            threshold: manifest.config.threshold,
            participant_id: local_participant_id,
        };
        Ok(FrostDkgSession::new(config))
    }
}

pub fn create_frost_session(
    session_id: impl Into<String>,
    threshold: u16,
    participants: u16,
    participant_id: u16,
) -> Result<FrostDkgSession> {
    let config = DkgSessionConfig {
        session_id: SessionId::new(session_id)?,
        threshold: ThresholdConfig::new(threshold, participants)?,
        participant_id: ParticipantId::new(participant_id)?,
    };
    Ok(FrostDkgSession::new(config))
}

#[derive(Debug, Clone)]
pub struct HtssDkgService {
    pub session_id: SessionId,
    pub config: HierarchicalThresholdConfig,
}

impl HtssDkgService {
    pub fn new(session_id: impl Into<String>, config: HierarchicalThresholdConfig) -> Result<Self> {
        Ok(Self {
            session_id: SessionId::new(session_id)?,
            config,
        })
    }

    pub fn begin_round1(&self, participant_id: ParticipantId) -> Result<HtssDkgRound1State> {
        htss_dkg_round1(participant_id, &self.config)
    }

    pub fn round1_message(&self, package: &HtssDkgRound1Package) -> Result<ProtocolMessage> {
        package.to_protocol_message(self.session_id.clone())
    }

    pub fn create_round2_packages(
        &self,
        state: &HtssDkgRound1State,
        round1_packages: &[HtssDkgRound1Package],
    ) -> Result<Vec<HtssDkgRound2Package>> {
        htss_dkg_round2(state, round1_packages, &self.config)
    }

    pub fn round2_message(&self, package: &HtssDkgRound2Package) -> Result<ProtocolMessage> {
        package.to_protocol_message(self.session_id.clone())
    }

    pub fn finalize_participant(
        &self,
        participant_id: ParticipantId,
        round1_packages: &[HtssDkgRound1Package],
        round2_packages: &[HtssDkgRound2Package],
    ) -> Result<(GroupKey, HtssLocalKeyShare)> {
        finalize_htss_dkg(
            participant_id,
            round1_packages,
            round2_packages,
            &self.config,
        )
    }

    pub fn run_local_rehearsal(&self) -> Result<HtssLocalKeySet> {
        run_distributed_htss_keygen(&self.config)
    }
}

#[derive(Debug)]
pub struct FrostCoordinator<T> {
    transport: T,
}

impl<T: Transport> FrostCoordinator<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn into_inner(self) -> T {
        self.transport
    }

    pub fn connect(&mut self) -> Result<()> {
        self.transport.connect()
    }

    pub fn disconnect(&mut self) -> Result<()> {
        self.transport.disconnect()
    }

    pub fn publish_round1(&mut self, session_id: SessionId, package: &Round1Package) -> Result<()> {
        self.transport
            .publish(package.to_protocol_message(session_id)?)
    }

    pub fn publish_round2(&mut self, session_id: SessionId, package: &Round2Package) -> Result<()> {
        self.transport
            .publish(package.to_protocol_message(session_id)?)
    }

    pub fn publish_htss_dkg_round1(
        &mut self,
        session_id: SessionId,
        package: &HtssDkgRound1Package,
    ) -> Result<()> {
        self.transport
            .publish(package.to_protocol_message(session_id)?)
    }

    pub fn publish_htss_dkg_round2(
        &mut self,
        session_id: SessionId,
        package: &HtssDkgRound2Package,
    ) -> Result<()> {
        self.transport
            .publish(package.to_protocol_message(session_id)?)
    }

    pub fn publish_nonce(&mut self, package: &NoncePackage) -> Result<()> {
        self.transport.publish(package.to_protocol_message()?)
    }

    pub fn publish_signature_share(&mut self, package: &SignatureSharePackage) -> Result<()> {
        self.transport.publish(package.to_protocol_message()?)
    }

    pub fn publish_htss_nonce(&mut self, package: &HtssNoncePackage) -> Result<()> {
        self.transport.publish(package.to_protocol_message()?)
    }

    pub fn publish_htss_signature_share(
        &mut self,
        package: &HtssSignatureSharePackage,
    ) -> Result<()> {
        self.transport.publish(package.to_protocol_message()?)
    }

    pub fn drain_round1(&mut self, session_id: &SessionId) -> Result<Vec<Round1Package>> {
        let mut only_round1 =
            |message: &ProtocolMessage| message.kind == ProtocolMessageKind::FrostDkgRound1;
        let messages = self
            .transport
            .drain_matching(session_id, &mut only_round1)?;
        messages
            .into_iter()
            .map(|message| Round1Package::from_protocol_message(&message))
            .collect()
    }

    pub fn drain_round2_for(
        &mut self,
        session_id: &SessionId,
        recipient: ParticipantId,
    ) -> Result<Vec<Round2Package>> {
        let mut only_target_round2 = |message: &ProtocolMessage| {
            message.kind == ProtocolMessageKind::FrostDkgRound2 && message.is_for(recipient)
        };
        let messages = self
            .transport
            .drain_matching(session_id, &mut only_target_round2)?;
        messages
            .into_iter()
            .map(|message| Round2Package::from_protocol_message(&message))
            .collect()
    }

    pub fn drain_htss_dkg_round1(
        &mut self,
        session_id: &SessionId,
    ) -> Result<Vec<HtssDkgRound1Package>> {
        let mut only_round1 =
            |message: &ProtocolMessage| message.kind == ProtocolMessageKind::HtssDkgRound1;
        let messages = self
            .transport
            .drain_matching(session_id, &mut only_round1)?;
        messages
            .into_iter()
            .map(|message| HtssDkgRound1Package::from_protocol_message(&message))
            .collect()
    }

    pub fn drain_htss_dkg_round2_for(
        &mut self,
        session_id: &SessionId,
        recipient: ParticipantId,
    ) -> Result<Vec<HtssDkgRound2Package>> {
        let mut only_target_round2 = |message: &ProtocolMessage| {
            message.kind == ProtocolMessageKind::HtssDkgRound2 && message.is_for(recipient)
        };
        let messages = self
            .transport
            .drain_matching(session_id, &mut only_target_round2)?;
        messages
            .into_iter()
            .map(|message| HtssDkgRound2Package::from_protocol_message(&message))
            .collect()
    }

    pub fn drain_nonces(&mut self, signing_session_id: &SessionId) -> Result<Vec<NoncePackage>> {
        let mut only_nonces =
            |message: &ProtocolMessage| message.kind == ProtocolMessageKind::FrostSigningNonce;
        let messages = self
            .transport
            .drain_matching(signing_session_id, &mut only_nonces)?;
        messages
            .into_iter()
            .map(|message| NoncePackage::from_protocol_message(&message))
            .collect()
    }

    pub fn drain_signature_shares(
        &mut self,
        signing_session_id: &SessionId,
    ) -> Result<Vec<SignatureSharePackage>> {
        let mut only_signature_shares =
            |message: &ProtocolMessage| message.kind == ProtocolMessageKind::FrostSignatureShare;
        let messages = self
            .transport
            .drain_matching(signing_session_id, &mut only_signature_shares)?;
        messages
            .into_iter()
            .map(|message| SignatureSharePackage::from_protocol_message(&message))
            .collect()
    }

    pub fn drain_htss_nonces(
        &mut self,
        signing_session_id: &SessionId,
    ) -> Result<Vec<HtssNoncePackage>> {
        let mut only_htss_nonces =
            |message: &ProtocolMessage| message.kind == ProtocolMessageKind::HtssSigningNonce;
        let messages = self
            .transport
            .drain_matching(signing_session_id, &mut only_htss_nonces)?;
        messages
            .into_iter()
            .map(|message| HtssNoncePackage::from_protocol_message(&message))
            .collect()
    }

    pub fn drain_htss_signature_shares(
        &mut self,
        signing_session_id: &SessionId,
    ) -> Result<Vec<HtssSignatureSharePackage>> {
        let mut only_htss_signature_shares =
            |message: &ProtocolMessage| message.kind == ProtocolMessageKind::HtssSignatureShare;
        let messages = self
            .transport
            .drain_matching(signing_session_id, &mut only_htss_signature_shares)?;
        messages
            .into_iter()
            .map(|message| HtssSignatureSharePackage::from_protocol_message(&message))
            .collect()
    }
}

pub type MemoryFrostCoordinator = FrostCoordinator<MemoryTransport>;

/// Run a complete in-memory TSS FROST DKG ceremony for local demos and tests.
///
/// This helper does not use networking, storage, backup, or encryption.
/// Applications that coordinate across devices should use `FrostDkgSession`
/// plus a `Transport`.
pub fn run_local_frost_dkg(
    session_id: impl Into<String>,
    threshold: u16,
    participants: u16,
) -> Result<Vec<LocalKeyShare>> {
    let session_id = session_id.into();
    let sessions = (1..=participants)
        .map(|participant_id| {
            create_frost_session(session_id.clone(), threshold, participants, participant_id)
        })
        .collect::<Result<Vec<_>>>()?;
    let round1 = sessions
        .iter()
        .map(|session| session.round1())
        .collect::<Result<Vec<_>>>()?;
    let round2 = sessions
        .iter()
        .map(|session| session.round2(&round1))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    sessions
        .iter()
        .map(|session| session.finalize(&round2))
        .collect()
}

/// Sign a 32-byte digest with a selected threshold set of local shares.
///
/// This is a convenience helper for local demos and SDK tests. Multi-device
/// apps should exchange `NoncePackage` and `SignatureSharePackage` values over
/// a transport.
pub fn sign_digest_with_shares(
    signing_session_id: impl Into<String>,
    threshold: ThresholdConfig,
    group_key: GroupKey,
    digest: [u8; 32],
    local_shares: &[LocalKeyShare],
    signer_set: Vec<ParticipantId>,
) -> Result<AggregateSignature> {
    validate_signer_set(&signer_set, &threshold)?;
    let signing_session_id = SessionId::new(signing_session_id)?;
    let request = SigningRequest::new(
        signing_session_id,
        group_key,
        digest,
        signer_set.clone(),
        &threshold,
    )?;
    let selected_shares = signer_set
        .iter()
        .map(|participant_id| {
            local_shares
                .iter()
                .find(|share| share.participant_id == *participant_id)
                .cloned()
                .ok_or_else(|| {
                    DkgKitError::Protocol(format!(
                        "missing local share for signer {}",
                        participant_id.0
                    ))
                })
        })
        .collect::<Result<Vec<_>>>()?;
    let signing_sessions = selected_shares
        .iter()
        .map(|_| FrostSigningSession::new(request.clone()))
        .collect::<Vec<_>>();
    let nonces = signing_sessions
        .iter()
        .zip(selected_shares.iter())
        .map(|(session, share)| session.nonce(share))
        .collect::<Result<Vec<_>>>()?;
    let signature_shares = signing_sessions
        .iter()
        .zip(selected_shares.iter())
        .map(|(session, share)| session.sign_share(share, &nonces))
        .collect::<Result<Vec<_>>>()?;
    FrostSigningSession::new(request).aggregate(&signature_shares)
}

pub fn sign_digest_with_shares_and_policy(
    signing_session_id: impl Into<String>,
    policy: SigningPolicy,
    group_key: GroupKey,
    digest: [u8; 32],
    local_shares: &[LocalKeyShare],
    signer_set: Vec<ParticipantId>,
) -> Result<AggregateSignature> {
    validate_signer_set_with_policy(&signer_set, &policy)?;
    let signing_session_id = SessionId::new(signing_session_id)?;
    let request = SigningRequest::new_with_policy(
        signing_session_id,
        group_key,
        digest,
        signer_set.clone(),
        &policy,
    )?;
    let selected_shares = signer_set
        .iter()
        .map(|participant_id| {
            local_shares
                .iter()
                .find(|share| share.participant_id == *participant_id)
                .cloned()
                .ok_or_else(|| {
                    DkgKitError::Protocol(format!(
                        "missing local share for signer {}",
                        participant_id.0
                    ))
                })
        })
        .collect::<Result<Vec<_>>>()?;
    let signing_sessions = selected_shares
        .iter()
        .map(|_| FrostSigningSession::new(request.clone()))
        .collect::<Vec<_>>();
    let nonces = signing_sessions
        .iter()
        .zip(selected_shares.iter())
        .map(|(session, share)| session.nonce(share))
        .collect::<Result<Vec<_>>>()?;
    let signature_shares = signing_sessions
        .iter()
        .zip(selected_shares.iter())
        .map(|(session, share)| session.sign_share(share, &nonces))
        .collect::<Result<Vec<_>>>()?;
    FrostSigningSession::new(request).aggregate(&signature_shares)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(value: u16) -> ParticipantId {
        ParticipantId::new(value).unwrap()
    }

    #[test]
    fn builder_creates_manifest() {
        let manifest = DkgKitSessionBuilder::new()
            .session_id("demo")
            .threshold(2, 3)
            .participant(1, Some("alice".to_string()))
            .unwrap()
            .participant(2, Some("bob".to_string()))
            .unwrap()
            .participant(3, Some("carol".to_string()))
            .unwrap()
            .build_manifest()
            .unwrap();
        assert_eq!(manifest.config.threshold.threshold, 2);
        assert_eq!(manifest.config.participants.len(), 3);
    }

    #[test]
    fn frost_coordinator_publishes_and_drains_round1_packages() {
        let session_id = SessionId::new("dkg-demo").unwrap();
        let mut coordinator = FrostCoordinator::new(MemoryTransport::default());
        coordinator.connect().unwrap();
        coordinator
            .publish_round1(
                session_id.clone(),
                &Round1Package {
                    participant_id: pid(1),
                    bytes: vec![1, 2, 3],
                },
            )
            .unwrap();

        let packages = coordinator.drain_round1(&session_id).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].participant_id, pid(1));
        assert_eq!(packages[0].bytes, vec![1, 2, 3]);
    }

    #[test]
    fn frost_coordinator_filters_round2_by_recipient() {
        let session_id = SessionId::new("dkg-demo").unwrap();
        let mut coordinator = FrostCoordinator::new(MemoryTransport::default());
        coordinator
            .publish_round2(
                session_id.clone(),
                &Round2Package {
                    sender: pid(1),
                    recipient: pid(2),
                    bytes: vec![2],
                },
            )
            .unwrap();
        coordinator
            .publish_round2(
                session_id.clone(),
                &Round2Package {
                    sender: pid(1),
                    recipient: pid(3),
                    bytes: vec![3],
                },
            )
            .unwrap();

        let packages = coordinator.drain_round2_for(&session_id, pid(2)).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].recipient, pid(2));
    }

    #[test]
    fn htss_dkg_service_entrypoints_publish_drain_and_finalize() {
        let config = HierarchicalThresholdConfig::new(
            2,
            vec![
                RankedParticipant::new(1, 0, Some("admin".to_string())).unwrap(),
                RankedParticipant::new(2, 1, Some("ops-a".to_string())).unwrap(),
                RankedParticipant::new(3, 1, Some("ops-b".to_string())).unwrap(),
            ],
        )
        .unwrap();
        let service = HtssDkgService::new("sdk-htss-dkg-entrypoint", config).unwrap();
        let states = service
            .config
            .participants
            .iter()
            .map(|participant| service.begin_round1(participant.id))
            .collect::<Result<Vec<_>>>()
            .unwrap();
        let mut coordinator = FrostCoordinator::new(MemoryTransport::default());
        for state in &states {
            coordinator
                .publish_htss_dkg_round1(service.session_id.clone(), &state.package)
                .unwrap();
        }
        let round1_packages = coordinator
            .drain_htss_dkg_round1(&service.session_id)
            .unwrap();
        assert_eq!(round1_packages.len(), 3);

        for state in &states {
            for package in service
                .create_round2_packages(state, &round1_packages)
                .unwrap()
            {
                coordinator
                    .publish_htss_dkg_round2(service.session_id.clone(), &package)
                    .unwrap();
            }
        }
        let round2_for_one = coordinator
            .drain_htss_dkg_round2_for(&service.session_id, pid(1))
            .unwrap();
        let (group_key, share) = service
            .finalize_participant(pid(1), &round1_packages, &round2_for_one)
            .unwrap();
        assert_eq!(share.participant_id, pid(1));

        let account_key = bitcoin::BitcoinAccountKey::new(group_key.clone(), [42u8; 32]);
        let descriptor = bitcoin::taproot_child_address_descriptor_for_network(
            &account_key,
            "regtest",
            bitcoin::BitcoinDerivationPath::bip86(0, 0, 0),
        )
        .unwrap();
        assert_eq!(descriptor.path.display_path(), "m/86'/0'/0'/0/0");
        assert!(descriptor.address.starts_with("bcrt1p"));
        assert_eq!(descriptor.account_xonly_public_key_hex.len(), 64);
        assert_ne!(
            descriptor.internal_xonly_public_key_hex,
            descriptor.account_xonly_public_key_hex
        );
    }

    #[test]
    fn high_level_helpers_run_dkg_and_sign_digest() {
        let shares = run_local_frost_dkg("sdk-demo", 2, 3).unwrap();
        assert_eq!(shares.len(), 3);
        assert_eq!(shares[0].group_key, shares[1].group_key);

        let signature = sign_digest_with_shares(
            "sdk-sign",
            ThresholdConfig::new(2, 3).unwrap(),
            shares[0].group_key.clone(),
            [9u8; 32],
            &shares,
            vec![pid(1), pid(2)],
        )
        .unwrap();
        assert_eq!(signature.signature_bytes.len(), 64);
    }

    #[test]
    fn high_level_helper_can_enforce_hierarchical_policy() {
        let shares = run_local_frost_dkg("sdk-htss-demo", 2, 3).unwrap();
        let policy = SigningPolicy::Hierarchical(
            HierarchicalThresholdConfig::new(
                2,
                vec![
                    RankedParticipant::new(1, 0, Some("admin".to_string())).unwrap(),
                    RankedParticipant::new(2, 1, Some("operator-a".to_string())).unwrap(),
                    RankedParticipant::new(3, 1, Some("operator-b".to_string())).unwrap(),
                ],
            )
            .unwrap(),
        );

        let signature = sign_digest_with_shares_and_policy(
            "sdk-htss-sign",
            policy.clone(),
            shares[0].group_key.clone(),
            [7u8; 32],
            &shares,
            vec![pid(1), pid(2)],
        )
        .unwrap();
        assert_eq!(signature.signature_bytes.len(), 64);

        let err = sign_digest_with_shares_and_policy(
            "sdk-htss-sign-reject",
            policy,
            shares[0].group_key.clone(),
            [7u8; 32],
            &shares,
            vec![pid(2), pid(3)],
        )
        .unwrap_err();
        assert!(err.to_string().contains("Birkhoff rank rule"));
    }

    #[test]
    fn sdk_exports_birkhoff_points_for_hierarchical_signer_set() {
        let config = HierarchicalThresholdConfig::new(
            3,
            vec![
                RankedParticipant::new(1, 0, Some("admin".to_string())).unwrap(),
                RankedParticipant::new(2, 1, Some("finance".to_string())).unwrap(),
                RankedParticipant::new(3, 1, Some("ops".to_string())).unwrap(),
            ],
        )
        .unwrap();
        let points =
            birkhoff_points_from_hierarchical_signer_set(&[pid(1), pid(2), pid(3)], &config)
                .unwrap();
        let coefficients = birkhoff_interpolation_coefficients(&points).unwrap();
        assert_eq!(coefficients.len(), 3);
        assert_eq!(coefficients[0].participant_id, pid(1));
    }

    #[test]
    fn sdk_exports_hierarchical_signing_request() {
        let shares = run_local_frost_dkg("sdk-hierarchical-request-demo", 2, 3).unwrap();
        let config = HierarchicalThresholdConfig::new(
            2,
            vec![
                RankedParticipant::new(1, 0, Some("admin".to_string())).unwrap(),
                RankedParticipant::new(2, 1, Some("operator-a".to_string())).unwrap(),
                RankedParticipant::new(3, 1, Some("operator-b".to_string())).unwrap(),
            ],
        )
        .unwrap();
        let request = HierarchicalSigningRequest::new(
            SessionId::new("sdk-hierarchical-request-sign").unwrap(),
            shares[0].group_key.clone(),
            [8u8; 32],
            vec![pid(1), pid(2)],
            &config,
        )
        .unwrap();
        assert_eq!(request.coefficients.len(), 2);
    }

    #[test]
    fn sdk_exports_local_htss_keygen_and_signing() {
        let config = HierarchicalThresholdConfig::new(
            3,
            vec![
                RankedParticipant::new(1, 0, Some("admin".to_string())).unwrap(),
                RankedParticipant::new(2, 1, Some("finance".to_string())).unwrap(),
                RankedParticipant::new(3, 1, Some("ops".to_string())).unwrap(),
                RankedParticipant::new(4, 2, Some("operator".to_string())).unwrap(),
            ],
        )
        .unwrap();
        let keyset = run_local_htss_keygen(&config).unwrap();
        let digest = [13u8; 32];
        let signature = sign_digest_with_local_htss_shares(
            &keyset.group_key,
            digest,
            &keyset.shares,
            &[pid(1), pid(2), pid(4)],
            &config,
        )
        .unwrap();
        assert!(
            bitcoin::verify_aggregate_signature_digest(&keyset.group_key, &digest, &signature)
                .unwrap()
        );
    }

    #[test]
    fn sdk_exports_local_htss_threshold_share_signing() {
        let config = HierarchicalThresholdConfig::new(
            3,
            vec![
                RankedParticipant::new(1, 0, Some("admin".to_string())).unwrap(),
                RankedParticipant::new(2, 1, Some("finance".to_string())).unwrap(),
                RankedParticipant::new(3, 1, Some("ops".to_string())).unwrap(),
                RankedParticipant::new(4, 2, Some("operator".to_string())).unwrap(),
            ],
        )
        .unwrap();
        let keyset = run_local_htss_keygen(&config).unwrap();
        let digest = [16u8; 32];
        let signature = sign_digest_with_local_htss_threshold_shares(
            &keyset.group_key,
            digest,
            &keyset.shares,
            &[pid(1), pid(2), pid(4)],
            &config,
        )
        .unwrap();
        assert!(
            bitcoin::verify_aggregate_signature_digest(&keyset.group_key, &digest, &signature)
                .unwrap()
        );
    }

    #[test]
    fn high_level_helper_can_enforce_grouped_threshold_policy() {
        let shares = run_local_frost_dkg("sdk-grouped-demo", 6, 10).unwrap();
        let policy = SigningPolicy::Grouped(
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
            .unwrap(),
        );

        let signature = sign_digest_with_shares_and_policy(
            "sdk-grouped-sign",
            policy.clone(),
            shares[0].group_key.clone(),
            [10u8; 32],
            &shares,
            vec![pid(1), pid(3), pid(4), pid(6), pid(7), pid(8)],
        )
        .unwrap();
        assert_eq!(signature.signature_bytes.len(), 64);

        let err = sign_digest_with_shares_and_policy(
            "sdk-grouped-sign-reject",
            policy,
            shares[0].group_key.clone(),
            [10u8; 32],
            &shares,
            vec![pid(1), pid(3), pid(6), pid(7), pid(8), pid(9)],
        )
        .unwrap_err();
        assert!(err.to_string().contains("rank 1 needs 2"));
    }

    #[test]
    fn sdk_can_sign_grouped_policy_with_local_htss_threshold_shares() {
        let config = GroupedThresholdConfig::new(
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
        .unwrap();
        let keyset = run_local_grouped_htss_keygen(&config).unwrap();
        let signer_set = vec![pid(1), pid(3), pid(4), pid(6), pid(7), pid(8)];
        let digest = [19u8; 32];
        let signature = sign_digest_with_local_grouped_htss_threshold_shares(
            &keyset.group_key,
            digest,
            &keyset.shares,
            &signer_set,
            &config,
        )
        .unwrap();
        assert!(
            bitcoin::verify_aggregate_signature_digest(&keyset.group_key, &digest, &signature)
                .unwrap()
        );
    }

    #[test]
    fn sdk_exports_grouped_signing_request() {
        let shares = run_local_frost_dkg("sdk-grouped-request-demo", 6, 10).unwrap();
        let config = GroupedThresholdConfig::new(
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
        .unwrap();
        let request = GroupedSigningRequest::new(
            SessionId::new("sdk-grouped-request-sign").unwrap(),
            shares[0].group_key.clone(),
            [11u8; 32],
            vec![pid(1), pid(3), pid(4), pid(6), pid(7), pid(8)],
            &config,
        )
        .unwrap();
        assert_eq!(request.config.required_signer_count(), 6);
    }

    #[test]
    fn frost_coordinator_publishes_and_drains_signing_packages() {
        let signing_session_id = SessionId::new("sign-demo").unwrap();
        let mut coordinator = FrostCoordinator::new(MemoryTransport::default());
        coordinator
            .publish_nonce(&NoncePackage {
                participant_id: pid(1),
                signing_session_id: signing_session_id.clone(),
                public_nonce_bytes: vec![7],
            })
            .unwrap();
        coordinator
            .publish_signature_share(&SignatureSharePackage {
                participant_id: pid(2),
                signing_session_id: signing_session_id.clone(),
                public_nonce_bytes: vec![7],
                signature_share_bytes: vec![8],
            })
            .unwrap();

        let nonces = coordinator.drain_nonces(&signing_session_id).unwrap();
        assert_eq!(nonces.len(), 1);
        assert_eq!(nonces[0].participant_id, pid(1));

        let shares = coordinator
            .drain_signature_shares(&signing_session_id)
            .unwrap();
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].participant_id, pid(2));
    }

    #[test]
    fn frost_coordinator_publishes_and_drains_htss_signing_packages() {
        let signing_session_id = SessionId::new("htss-sign-demo").unwrap();
        let mut coordinator = FrostCoordinator::new(MemoryTransport::default());
        coordinator
            .publish_htss_nonce(&HtssNoncePackage {
                participant_id: pid(1),
                signing_session_id: signing_session_id.clone(),
                public_nonce_bytes: vec![2; 33],
            })
            .unwrap();
        coordinator
            .publish_htss_signature_share(&HtssSignatureSharePackage {
                participant_id: pid(2),
                signing_session_id: signing_session_id.clone(),
                signature_share_bytes: [4; 32],
            })
            .unwrap();

        let nonces = coordinator.drain_htss_nonces(&signing_session_id).unwrap();
        assert_eq!(nonces.len(), 1);
        assert_eq!(nonces[0].participant_id, pid(1));

        let shares = coordinator
            .drain_htss_signature_shares(&signing_session_id)
            .unwrap();
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].participant_id, pid(2));
    }
}

#[cfg(test)]
mod bitcoin_integration_tests {
    use super::*;

    #[test]
    fn bitcoin_authorization_signature_verifies_against_frost_group_key() -> Result<()> {
        let threshold = ThresholdConfig::new(2, 3)?;
        let shares = run_local_frost_dkg("sdk-bitcoin-verification-dkg", 2, 3)?;
        let group_key = shares[0].group_key.clone();
        let authorization = bitcoin::BitcoinAuthorizationMessage {
            network: "signet".to_string(),
            action: "approve-payment".to_string(),
            recipient: Some("tb1ptestrecipient".to_string()),
            amount_sats: Some(25_000),
            memo: Some("sdk integration test".to_string()),
            nonce: "sdk-bitcoin-verification-001".to_string(),
        };
        let digest = authorization.digest();
        let signature = sign_digest_with_shares(
            "sdk-bitcoin-verification-signing",
            threshold,
            group_key.clone(),
            digest,
            &shares,
            vec![ParticipantId::new(1)?, ParticipantId::new(3)?],
        )?;

        assert!(
            bitcoin::verify_aggregate_signature_digest(&group_key, &digest, &signature).unwrap()
        );
        Ok(())
    }
}
