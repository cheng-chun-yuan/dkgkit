use dkgkit_nostr::LocalNostrEventTransport;
use dkgkit_sdk::bitcoin::{
    taproot_child_address_descriptor_for_network, verify_aggregate_signature_digest,
    BitcoinAccountKey, BitcoinAuthorizationMessage, BitcoinDerivationPath,
};
use dkgkit_sdk::{
    aggregate_htss_signature_shares, hierarchical_config_from_grouped_threshold, htss_nonce,
    htss_sign_share, validate_grouped_threshold_signer_set, FrostCoordinator, GroupKey,
    GroupThresholdRequirement, GroupedThresholdConfig, HtssDkgRound1State, HtssDkgService,
    HtssLocalKeyShare, HtssSignatureSharePackage, ParticipantId, RankedParticipant, Result,
    SessionId,
};
use std::collections::BTreeMap;

struct InMemoryVaultService {
    vault_id: String,
    network: String,
    chain_code: [u8; 32],
    grouped_config: GroupedThresholdConfig,
    dkg: HtssDkgService,
    coordinator: FrostCoordinator<LocalNostrEventTransport>,
    round1_states: BTreeMap<ParticipantId, HtssDkgRound1State>,
    local_shares: BTreeMap<ParticipantId, HtssLocalKeyShare>,
    group_key: Option<GroupKey>,
}

impl InMemoryVaultService {
    fn new(
        vault_id: impl Into<String>,
        dkg_session_id: impl Into<String>,
        network: impl Into<String>,
        chain_code: [u8; 32],
        grouped_config: GroupedThresholdConfig,
    ) -> Result<Self> {
        let htss_config = hierarchical_config_from_grouped_threshold(&grouped_config)?;
        Ok(Self {
            vault_id: vault_id.into(),
            network: network.into(),
            chain_code,
            grouped_config,
            dkg: HtssDkgService::new(dkg_session_id, htss_config)?,
            coordinator: FrostCoordinator::new(LocalNostrEventTransport::default()),
            round1_states: BTreeMap::new(),
            local_shares: BTreeMap::new(),
            group_key: None,
        })
    }

    fn connect_transport(&mut self) -> Result<()> {
        self.coordinator.connect()
    }

    fn run_htss_dkg(&mut self) -> Result<()> {
        for participant in &self.dkg.config.participants {
            let state = self.dkg.begin_round1(participant.id)?;
            self.coordinator
                .publish_htss_dkg_round1(self.dkg.session_id.clone(), &state.package)?;
            self.round1_states.insert(participant.id, state);
        }

        let round1_packages = self
            .coordinator
            .drain_htss_dkg_round1(&self.dkg.session_id)?;

        for state in self.round1_states.values() {
            for package in self.dkg.create_round2_packages(state, &round1_packages)? {
                // Production services must encrypt this direct message before
                // publishing over public relay infrastructure.
                self.coordinator
                    .publish_htss_dkg_round2(self.dkg.session_id.clone(), &package)?;
            }
        }

        for participant in &self.dkg.config.participants {
            let round2_for_participant = self
                .coordinator
                .drain_htss_dkg_round2_for(&self.dkg.session_id, participant.id)?;
            let (group_key, local_share) = self.dkg.finalize_participant(
                participant.id,
                &round1_packages,
                &round2_for_participant,
            )?;
            match &self.group_key {
                Some(existing) if existing.xonly_public_key != group_key.xonly_public_key => {
                    return Err(dkgkit_sdk::DkgKitError::Protocol(
                        "participants derived different group keys".to_string(),
                    ));
                }
                None => self.group_key = Some(group_key),
                _ => {}
            }
            self.local_shares.insert(participant.id, local_share);
        }

        Ok(())
    }

    fn derive_receive_address(
        &self,
        account: u32,
        change: u32,
        address_index: u32,
    ) -> anyhow::Result<dkgkit_sdk::bitcoin::BitcoinAddressDescriptor> {
        let group_key = self
            .group_key
            .clone()
            .ok_or_else(|| anyhow::anyhow!("vault DKG is not finalized"))?;
        let account_key = BitcoinAccountKey::new(group_key, self.chain_code);
        let path = BitcoinDerivationPath::bip86(account, change, address_index);
        taproot_child_address_descriptor_for_network(&account_key, &self.network, path)
    }

    fn sign_authorization(
        &mut self,
        signing_session_id: impl Into<String>,
        authorization: &BitcoinAuthorizationMessage,
        signer_set: Vec<ParticipantId>,
    ) -> anyhow::Result<HtssSignatureSharePackage> {
        validate_grouped_threshold_signer_set(&signer_set, &self.grouped_config)?;
        let group_key = self
            .group_key
            .clone()
            .ok_or_else(|| anyhow::anyhow!("vault DKG is not finalized"))?;
        let signing_session_id = SessionId::new(signing_session_id)?;
        let digest = authorization.digest();

        let selected_shares = signer_set
            .iter()
            .map(|participant_id| {
                self.local_shares
                    .get(participant_id)
                    .cloned()
                    .ok_or_else(|| {
                        anyhow::anyhow!("missing local share for signer {}", participant_id.0)
                    })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        let local_nonces = selected_shares
            .iter()
            .map(|share| htss_nonce(signing_session_id.clone(), share))
            .collect::<Result<Vec<_>>>()?;
        for nonce in &local_nonces {
            self.coordinator.publish_htss_nonce(&nonce.package)?;
        }
        let public_nonces = self.coordinator.drain_htss_nonces(&signing_session_id)?;

        for (share, nonce) in selected_shares.iter().zip(local_nonces.iter()) {
            let signature_share = htss_sign_share(
                &group_key,
                digest,
                share,
                nonce,
                &public_nonces,
                &signer_set,
                &self.dkg.config,
            )?;
            self.coordinator
                .publish_htss_signature_share(&signature_share)?;
        }

        let signature_shares = self
            .coordinator
            .drain_htss_signature_shares(&signing_session_id)?;
        let aggregate = aggregate_htss_signature_shares(
            &group_key,
            digest,
            &public_nonces,
            &signature_shares,
            &signer_set,
            &self.dkg.config,
        )?;
        let verified = verify_aggregate_signature_digest(&group_key, &digest, &aggregate)?;
        anyhow::ensure!(verified, "aggregate signature failed Bitcoin verification");

        signature_shares
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("no signature shares produced"))
    }
}

fn grouped_config_123_of_235() -> Result<GroupedThresholdConfig> {
    GroupedThresholdConfig::new(
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
    )
}

fn pid(value: u16) -> Result<ParticipantId> {
    ParticipantId::new(value)
}

fn main() -> anyhow::Result<()> {
    let mut service = InMemoryVaultService::new(
        "treasury-demo",
        "treasury-demo-dkg",
        "regtest",
        [42u8; 32],
        grouped_config_123_of_235()?,
    )?;
    service.connect_transport()?;
    service.run_htss_dkg()?;

    let address = service.derive_receive_address(0, 0, 0)?;
    let authorization = BitcoinAuthorizationMessage {
        network: "regtest".to_string(),
        action: "approve-payment".to_string(),
        recipient: Some(address.address.clone()),
        amount_sats: Some(100_000),
        memo: Some("vault-service spec execution".to_string()),
        nonce: "approval-001".to_string(),
    };
    let signer_set = vec![pid(1)?, pid(3)?, pid(4)?, pid(6)?, pid(7)?, pid(8)?];
    let first_share =
        service.sign_authorization("treasury-demo-signing", &authorization, signer_set.clone())?;

    let group_key = service.group_key.as_ref().expect("DKG finalized");
    println!("Vault service spec execution");
    println!("vault id: {}", service.vault_id);
    println!(
        "group x-only public key: {}",
        hex::encode(group_key.xonly_public_key)
    );
    println!("receive path: {}", address.path.display_path());
    println!("receive address: {}", address.address);
    println!(
        "signers: {:?}",
        signer_set.iter().map(|id| id.0).collect::<Vec<_>>()
    );
    println!(
        "authorization digest: {}",
        hex::encode(authorization.digest())
    );
    println!(
        "first signature share participant: {}",
        first_share.participant_id.0
    );
    println!("aggregate signature verified: true");
    println!(
        "remaining local relay events: {}",
        service.coordinator.transport().pending_len()
    );
    Ok(())
}
