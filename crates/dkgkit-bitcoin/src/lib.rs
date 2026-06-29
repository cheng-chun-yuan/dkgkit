//! Bitcoin helpers for DKGKit.
//!
//! This crate intentionally avoids wallet storage, RPC, UTXO selection, PSBT,
//! and broadcasting. It provides reusable Bitcoin-facing helpers for SDK users.

use anyhow::{anyhow, Context, Result};
use bitcoin::bip32::{ChainCode, ChildNumber, Fingerprint, Xpub};
use bitcoin::secp256k1::{
    schnorr::Signature, Message, Parity, Secp256k1, XOnlyPublicKey as SecpXOnlyPublicKey,
};
use bitcoin::{key::TapTweak, Address, Network, NetworkKind, XOnlyPublicKey};
use dkgkit_frost::{AggregateSignature, GroupKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A human-readable Bitcoin authorization request suitable for threshold message signing.
///
/// Applications can sign the digest returned by [`BitcoinAuthorizationMessage::digest`]
/// with a DKG/FROST group key, then verify the aggregate BIP340 signature against the
/// same group x-only public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitcoinAuthorizationMessage {
    pub network: String,
    pub action: String,
    pub recipient: Option<String>,
    pub amount_sats: Option<u64>,
    pub memo: Option<String>,
    pub nonce: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitcoinDerivationPath {
    pub purpose: u32,
    pub coin_type: u32,
    pub account: u32,
    pub change: u32,
    pub address_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitcoinAccountKey {
    pub group_key: GroupKey,
    pub chain_code: [u8; 32],
}

impl BitcoinAccountKey {
    pub fn new(group_key: GroupKey, chain_code: [u8; 32]) -> Self {
        Self {
            group_key,
            chain_code,
        }
    }
}

impl BitcoinDerivationPath {
    /// BIP86-style Taproot receive path for Bitcoin mainnet.
    pub fn bip86(account: u32, change: u32, address_index: u32) -> Self {
        Self {
            purpose: 86,
            coin_type: 0,
            account,
            change,
            address_index,
        }
    }

    /// BIP44-style account path descriptor. Taproot output derivation is still
    /// handled separately; this type is the stable service boundary.
    pub fn bip44(account: u32, change: u32, address_index: u32) -> Self {
        Self {
            purpose: 44,
            coin_type: 0,
            account,
            change,
            address_index,
        }
    }

    pub fn display_path(&self) -> String {
        format!(
            "m/{}'/{}'/{}'/{}/{}",
            self.purpose, self.coin_type, self.account, self.change, self.address_index
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitcoinAddressDescriptor {
    pub path: BitcoinDerivationPath,
    pub network: String,
    pub address: String,
    pub account_xonly_public_key_hex: String,
    pub internal_xonly_public_key_hex: String,
    pub xonly_public_key_hex: String,
    pub chain_code_hex: String,
}

impl BitcoinAuthorizationMessage {
    /// Deterministic text form for display and signing.
    pub fn canonical_text(&self) -> String {
        format!(
            "DKGKit Bitcoin Authorization\nnetwork={}\naction={}\nrecipient={}\namount_sats={}\nmemo={}\nnonce={}",
            self.network,
            self.action,
            self.recipient.as_deref().unwrap_or(""),
            self.amount_sats.map(|value| value.to_string()).unwrap_or_default(),
            self.memo.as_deref().unwrap_or(""),
            self.nonce,
        )
    }

    /// SHA256 digest of the canonical text.
    ///
    /// FROST implementations should sign this 32-byte digest, not an ambiguous UI string.
    pub fn digest(&self) -> [u8; 32] {
        sha256(self.canonical_text().as_bytes())
    }
}

/// Compute SHA256 bytes for an application message.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Decode a lowercase or uppercase 32-byte x-only public key from hex.
pub fn parse_xonly_public_key_hex(hex_text: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_text).context("x-only public key must be hex")?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("x-only public key must be exactly 32 bytes"))
}

/// Derive a BIP341 Taproot address from a DKG/FROST group key.
pub fn taproot_address(group_key: &GroupKey, network: Network) -> Result<Address> {
    let xonly = XOnlyPublicKey::from_slice(&group_key.xonly_public_key)
        .map_err(|err| anyhow!("invalid x-only public key: {err}"))?;
    Ok(Address::p2tr_tweaked(
        xonly.dangerous_assume_tweaked(),
        network,
    ))
}

/// Build a service-facing root address descriptor for the current group key.
///
/// This helper intentionally does not derive child public keys. Services that
/// need BIP32-style receive addresses should use
/// [`taproot_child_address_descriptor`] with a [`BitcoinAccountKey`].
pub fn taproot_address_descriptor(
    group_key: &GroupKey,
    network: Network,
    path: BitcoinDerivationPath,
) -> Result<BitcoinAddressDescriptor> {
    let address = taproot_address(group_key, network)?;
    Ok(BitcoinAddressDescriptor {
        path,
        network: format!("{network:?}"),
        address: address.to_string(),
        account_xonly_public_key_hex: hex::encode(group_key.xonly_public_key),
        internal_xonly_public_key_hex: hex::encode(group_key.xonly_public_key),
        xonly_public_key_hex: hex::encode(group_key.xonly_public_key),
        chain_code_hex: String::new(),
    })
}

pub fn taproot_address_descriptor_for_network(
    group_key: &GroupKey,
    network: &str,
    path: BitcoinDerivationPath,
) -> Result<BitcoinAddressDescriptor> {
    let network = parse_network(network)?;
    taproot_address_descriptor(group_key, network, path)
}

/// Derive a real BIP32 non-hardened child address below a DKG account key.
///
/// The DKG group key is treated as the account-level key, for example
/// `m/86'/0'/account'`. This function derives only the public non-hardened
/// tail `/{change}/{address_index}`. Hardened purpose/coin/account levels
/// cannot be derived from public threshold key material after DKG.
pub fn taproot_child_address_descriptor(
    account_key: &BitcoinAccountKey,
    network: Network,
    path: BitcoinDerivationPath,
) -> Result<BitcoinAddressDescriptor> {
    let secp = Secp256k1::verification_only();
    let account_xonly = SecpXOnlyPublicKey::from_slice(&account_key.group_key.xonly_public_key)
        .map_err(|err| anyhow!("invalid account x-only public key: {err}"))?;
    let account_public_key = account_xonly.public_key(Parity::Even);
    let mut xpub = Xpub {
        network: NetworkKind::from(network),
        depth: 3,
        parent_fingerprint: Fingerprint::default(),
        child_number: ChildNumber::from_hardened_idx(path.account)
            .map_err(|err| anyhow!("invalid account index: {err}"))?,
        public_key: account_public_key,
        chain_code: ChainCode::from(account_key.chain_code),
    };
    for index in [path.change, path.address_index] {
        xpub = xpub
            .ckd_pub(
                &secp,
                ChildNumber::from_normal_idx(index)
                    .map_err(|err| anyhow!("invalid child index: {err}"))?,
            )
            .map_err(|err| anyhow!("failed to derive public child key: {err}"))?;
    }

    let internal_xonly = XOnlyPublicKey::from(xpub.public_key);
    let (output_key, _) = internal_xonly.tap_tweak(&secp, None);
    let output_xonly = output_key.to_x_only_public_key();
    let address = Address::p2tr_tweaked(output_key, network);
    Ok(BitcoinAddressDescriptor {
        path,
        network: format!("{network:?}"),
        address: address.to_string(),
        account_xonly_public_key_hex: hex::encode(account_key.group_key.xonly_public_key),
        internal_xonly_public_key_hex: internal_xonly.to_string(),
        xonly_public_key_hex: output_xonly.to_string(),
        chain_code_hex: hex::encode(xpub.chain_code),
    })
}

pub fn taproot_child_address_descriptor_for_network(
    account_key: &BitcoinAccountKey,
    network: &str,
    path: BitcoinDerivationPath,
) -> Result<BitcoinAddressDescriptor> {
    let network = parse_network(network)?;
    taproot_child_address_descriptor(account_key, network, path)
}

pub fn parse_network(network: &str) -> Result<Network> {
    match network {
        "bitcoin" | "mainnet" => Ok(Network::Bitcoin),
        "testnet" => Ok(Network::Testnet),
        "testnet4" => Ok(Network::Testnet4),
        "signet" => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        other => Err(anyhow!("unsupported Bitcoin network: {other}")),
    }
}

/// Derive a BIP341 Taproot address from a 32-byte x-only public key hex string.
pub fn taproot_address_from_xonly_hex(xonly_hex: &str, network: Network) -> Result<Address> {
    let group_key = GroupKey {
        xonly_public_key: parse_xonly_public_key_hex(xonly_hex)?,
        verification_key_bytes: Vec::new(),
    };
    taproot_address(&group_key, network)
}

/// Verify a BIP340 Schnorr signature over a 32-byte digest.
pub fn verify_schnorr_digest(
    xonly_public_key: &[u8; 32],
    digest: &[u8; 32],
    signature: &[u8; 64],
) -> Result<bool> {
    let secp = Secp256k1::verification_only();
    let public_key = SecpXOnlyPublicKey::from_slice(xonly_public_key)
        .map_err(|err| anyhow!("invalid x-only public key: {err}"))?;
    let message = Message::from_digest(*digest);
    let signature = Signature::from_slice(signature)
        .map_err(|err| anyhow!("invalid Schnorr signature: {err}"))?;
    Ok(secp
        .verify_schnorr(&signature, &message, &public_key)
        .is_ok())
}

/// Verify an aggregate FROST signature over a 32-byte digest using the group key.
pub fn verify_aggregate_signature_digest(
    group_key: &GroupKey,
    digest: &[u8; 32],
    signature: &AggregateSignature,
) -> Result<bool> {
    let signature_bytes: [u8; 64] = signature
        .signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("aggregate signature must be exactly 64 bytes"))?;
    verify_schnorr_digest(&group_key.xonly_public_key, digest, &signature_bytes)
}

/// Verify a BIP340 Schnorr signature over a digest using hex inputs.
pub fn verify_schnorr_digest_hex(
    xonly_public_key_hex: &str,
    digest_hex: &str,
    signature_hex: &str,
) -> Result<bool> {
    let public_key = parse_xonly_public_key_hex(xonly_public_key_hex)?;
    let digest: [u8; 32] = hex::decode(digest_hex)
        .context("digest must be hex")?
        .try_into()
        .map_err(|_| anyhow!("digest must be exactly 32 bytes"))?;
    let signature: [u8; 64] = hex::decode(signature_hex)
        .context("signature must be hex")?
        .try_into()
        .map_err(|_| anyhow!("signature must be exactly 64 bytes"))?;
    verify_schnorr_digest(&public_key, &digest, &signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_message_digest_is_stable() {
        let message = BitcoinAuthorizationMessage {
            network: "signet".to_string(),
            action: "approve-payment".to_string(),
            recipient: Some("tb1ptest".to_string()),
            amount_sats: Some(100_000),
            memo: Some("designer payout".to_string()),
            nonce: "demo-001".to_string(),
        };
        assert_eq!(
            message.digest(),
            sha256(message.canonical_text().as_bytes())
        );
        assert!(message.canonical_text().contains("network=signet"));
    }

    #[test]
    fn xonly_hex_requires_32_bytes() {
        assert!(parse_xonly_public_key_hex("00").is_err());
        assert!(parse_xonly_public_key_hex(&"11".repeat(32)).is_ok());
    }

    #[test]
    fn taproot_child_address_descriptor_derives_distinct_public_children() {
        let secp = Secp256k1::new();
        let secret_key = bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &secret_key);
        let (xonly_public_key, _) = keypair.x_only_public_key();
        let account_key = BitcoinAccountKey::new(
            GroupKey {
                xonly_public_key: xonly_public_key.serialize(),
                verification_key_bytes: Vec::new(),
            },
            [7u8; 32],
        );
        let first = taproot_child_address_descriptor_for_network(
            &account_key,
            "regtest",
            BitcoinDerivationPath::bip86(0, 0, 0),
        )
        .unwrap();
        let second = taproot_child_address_descriptor_for_network(
            &account_key,
            "regtest",
            BitcoinDerivationPath::bip86(0, 0, 1),
        )
        .unwrap();
        assert_eq!(first.path.display_path(), "m/86'/0'/0'/0/0");
        assert!(first.address.starts_with("bcrt1p"));
        assert_ne!(first.address, second.address);
        assert_ne!(
            first.internal_xonly_public_key_hex,
            first.account_xonly_public_key_hex
        );
    }
}
