//! Bitcoin helpers for DKGKit.
//!
//! This crate intentionally avoids wallet storage, RPC, UTXO selection, PSBT,
//! and broadcasting. It provides reusable Bitcoin-facing helpers for SDK users.

use anyhow::{anyhow, ensure, Context, Result};
use bitcoin::bip32::{ChainCode, ChildNumber, Fingerprint, Xpub};
use bitcoin::hashes::{sha512, Hash as _, HashEngine as _, Hmac, HmacEngine};
use bitcoin::secp256k1::{
    schnorr::Signature, Message, Parity, Scalar as SecpScalar, Secp256k1, SecretKey,
    XOnlyPublicKey as SecpXOnlyPublicKey,
};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::TapTweakHash;
use bitcoin::{
    absolute::LockTime, consensus, key::TapTweak, transaction::Version, Address, Amount, Network,
    NetworkKind, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    XOnlyPublicKey,
};
use dkgkit_frost::{AggregateSignature, GroupKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::str::FromStr;

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

/// The additive key tweak between a vault group key `P` and the Taproot output
/// key that locks one of its BIP86 child receive addresses.
///
/// The output key is `Q = A·P + B·G`, where `A = ±1` (the parity of the BIP32
/// child times the parity of the tweaked output, both x-only lifts) and `B` is
/// the additive scalar combining the BIP32 child tweak and the BIP341 taproot
/// tweak. A threshold signer that can sign for `P` can spend the address by
/// signing the spend sighash under `Q` with these values (see
/// `dkgkit_frost::sign_digest_with_local_grouped_htss_threshold_shares_for_output`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaprootKeyTweak {
    /// x-only output key the address commits to (BIP341 key-path spend key).
    pub output_xonly: [u8; 32],
    /// Additive tweak `B`, big-endian scalar bytes.
    pub tweak: [u8; 32],
    /// Whether the `P` term is negated (`A == -1`).
    pub negate_key: bool,
}

/// Derive the [`TaprootKeyTweak`] for a vault's BIP86 child receive address so a
/// group-key threshold signer can produce a real key-path spend signature.
pub fn taproot_child_key_tweak(
    account_key: &BitcoinAccountKey,
    network: &str,
    path: BitcoinDerivationPath,
) -> Result<TaprootKeyTweak> {
    let network = parse_network(network)?;
    let secp = Secp256k1::verification_only();
    let account_xonly = SecpXOnlyPublicKey::from_slice(&account_key.group_key.xonly_public_key)
        .map_err(|err| anyhow!("invalid account x-only public key: {err}"))?;
    let account_public_key = account_xonly.public_key(Parity::Even);

    // Authoritative child point via the same Xpub path used to build the address.
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
    let child_public_key = xpub.public_key;
    let (internal_xonly, child_parity) = child_public_key.x_only_public_key();
    let child_was_odd = child_parity == Parity::Odd;

    // BIP32 additive tweak t_bip32 = Σ IL, recomputed over the same path. Each
    // IL = HMAC-SHA512(chain_code, ser_compressed(parent) || index)[..32].
    let mut chain_code = account_key.chain_code;
    let mut parent = account_public_key;
    let mut bip32_tweak: Option<SecretKey> = None;
    for index in [path.change, path.address_index] {
        let mut engine = HmacEngine::<sha512::Hash>::new(&chain_code);
        engine.input(&parent.serialize());
        engine.input(&index.to_be_bytes());
        let i = Hmac::<sha512::Hash>::from_engine(engine).to_byte_array();
        let il: [u8; 32] = i[..32].try_into().expect("32-byte IL");
        let il_scalar =
            SecpScalar::from_be_bytes(il).map_err(|err| anyhow!("invalid BIP32 tweak: {err}"))?;
        parent = parent
            .add_exp_tweak(&secp, &il_scalar)
            .map_err(|err| anyhow!("BIP32 point derivation failed: {err}"))?;
        chain_code = i[32..].try_into().expect("32-byte chain code");
        bip32_tweak = Some(match bip32_tweak {
            None => {
                SecretKey::from_slice(&il).map_err(|err| anyhow!("invalid BIP32 tweak: {err}"))?
            }
            Some(acc) => acc
                .add_tweak(&il_scalar)
                .map_err(|err| anyhow!("BIP32 tweak accumulation failed: {err}"))?,
        });
    }
    let bip32_tweak = bip32_tweak.ok_or_else(|| anyhow!("empty derivation path"))?;
    ensure!(
        parent == child_public_key,
        "recomputed BIP32 child does not match the Xpub derivation"
    );

    // BIP341 taproot tweak t_tap and the output key parity.
    let tap_tweak = TapTweakHash::from_key_and_tweak(internal_xonly, None).to_scalar();
    let (output_key, output_parity) = internal_xonly.tap_tweak(&secp, None);
    let output_was_odd = output_parity == Parity::Odd;
    let output_xonly = output_key.to_x_only_public_key().serialize();

    // B = s_out·(s_c·t_bip32 + t_tap).
    let inner = if child_was_odd {
        bip32_tweak.negate()
    } else {
        bip32_tweak
    };
    let inner = inner
        .add_tweak(&tap_tweak)
        .map_err(|err| anyhow!("taproot tweak accumulation failed: {err}"))?;
    let tweak_secret = if output_was_odd {
        inner.negate()
    } else {
        inner
    };

    Ok(TaprootKeyTweak {
        output_xonly,
        tweak: tweak_secret.secret_bytes(),
        negate_key: child_was_odd ^ output_was_odd,
    })
}

/// The [`TaprootKeyTweak`] for a BIP-352 silent-payment output funded against a
/// vault group key. The output key is the BIP341 key-path spend key of
/// `P = B_spend + k·G`, where `B_spend` is the vault group key (even-Y lift) and
/// `k` is the per-payment silent-payment tweak scalar (32 big-endian bytes). A
/// grouped threshold signer for the group key can spend the resulting output via
/// [`dkgkit_frost::sign_digest_with_local_grouped_htss_threshold_shares_for_output`]
/// with these values.
///
/// Venue-agnostic: whether `P` locks an on-chain UTXO or an Arkade VTXO `userPK`,
/// the spend is the same BIP340 key-path Schnorr signature over the same taproot
/// key — so the FROST quorum signs an Arkade `VTXO(P)` exactly as it would an
/// on-chain output. This mirrors [`taproot_child_key_tweak`] with the BIP32 child
/// tweak replaced by the silent-payment tweak `k`.
pub fn silent_payment_output_tweak(group_key: &GroupKey, k: [u8; 32]) -> Result<TaprootKeyTweak> {
    let secp = Secp256k1::verification_only();
    let account_xonly = SecpXOnlyPublicKey::from_slice(&group_key.xonly_public_key)
        .map_err(|err| anyhow!("invalid group x-only public key: {err}"))?;
    let p_even = account_xonly.public_key(Parity::Even);

    // Inner additive tweak k — the silent-payment per-output tweak scalar.
    let k_secret = SecretKey::from_slice(&k)
        .map_err(|err| anyhow!("invalid silent-payment tweak scalar: {err}"))?;
    let k_scalar = SecpScalar::from_be_bytes(k)
        .map_err(|err| anyhow!("invalid silent-payment tweak scalar: {err}"))?;

    // Internal key P_sp = B_spend(even) + k·G.
    let internal_point = p_even
        .add_exp_tweak(&secp, &k_scalar)
        .map_err(|err| anyhow!("silent-payment point derivation failed: {err}"))?;
    let (internal_xonly, internal_parity) = internal_point.x_only_public_key();
    let internal_was_odd = internal_parity == Parity::Odd;

    // BIP341 taproot tweak (key-path only, no script tree) and output parity.
    let tap_tweak = TapTweakHash::from_key_and_tweak(internal_xonly, None).to_scalar();
    let (output_key, output_parity) = internal_xonly.tap_tweak(&secp, None);
    let output_was_odd = output_parity == Parity::Odd;
    let output_xonly = output_key.to_x_only_public_key().serialize();

    // B = s_out·(s_internal·k + t_tap).
    let inner = if internal_was_odd {
        k_secret.negate()
    } else {
        k_secret
    };
    let inner = inner
        .add_tweak(&tap_tweak)
        .map_err(|err| anyhow!("taproot tweak accumulation failed: {err}"))?;
    let tweak_secret = if output_was_odd {
        inner.negate()
    } else {
        inner
    };

    Ok(TaprootKeyTweak {
        output_xonly,
        tweak: tweak_secret.secret_bytes(),
        negate_key: internal_was_odd ^ output_was_odd,
    })
}

/// The [`TaprootKeyTweak`] for signing under a silent-payment leaf key
/// `P = B_spend + k·G` *directly* (x-only), with NO BIP341 output tweak.
///
/// Arkade VTXOs use a NUMS taproot internal key and are spent collaboratively via
/// the forfeit tapscript leaf (`checkSig(P) && checkSig(server)`), so the
/// recipient signs the leaf sighash under the leaf pubkey `P` itself — not a
/// taproot-tweaked output key. A grouped HTSS quorum for the vault group key
/// `B_spend` produces that signature by applying the per-payment tweak `k`. Use
/// [`silent_payment_output_tweak`] instead for a BIP341 key-path output.
pub fn silent_payment_leaf_tweak(group_key: &GroupKey, k: [u8; 32]) -> Result<TaprootKeyTweak> {
    let secp = Secp256k1::verification_only();
    let account_xonly = SecpXOnlyPublicKey::from_slice(&group_key.xonly_public_key)
        .map_err(|err| anyhow!("invalid group x-only public key: {err}"))?;
    let p_even = account_xonly.public_key(Parity::Even);

    let k_secret = SecretKey::from_slice(&k)
        .map_err(|err| anyhow!("invalid silent-payment tweak scalar: {err}"))?;
    let k_scalar = SecpScalar::from_be_bytes(k)
        .map_err(|err| anyhow!("invalid silent-payment tweak scalar: {err}"))?;

    // Leaf key P = B_spend(even) + k·G; sign under its x-only form.
    let p_point = p_even
        .add_exp_tweak(&secp, &k_scalar)
        .map_err(|err| anyhow!("silent-payment point derivation failed: {err}"))?;
    let (p_xonly, p_parity) = p_point.x_only_public_key();
    let p_was_odd = p_parity == Parity::Odd;

    // even-Y(P): if P is odd-Y, negate both the key term and k.
    let tweak_secret = if p_was_odd {
        k_secret.negate()
    } else {
        k_secret
    };
    Ok(TaprootKeyTweak {
        output_xonly: p_xonly.serialize(),
        tweak: tweak_secret.secret_bytes(),
        negate_key: p_was_odd,
    })
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

/// A vault UTXO to spend in a Taproot key-path transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaprootSpendInput {
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
}

/// A destination output for a Taproot spend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaprootSpendOutput {
    pub address: String,
    pub value_sats: u64,
}

/// Build an unsigned P2TR key-path spend and the BIP341 (SIGHASH_DEFAULT) sighash
/// for each input. Every input must be a UTXO locked by `vault_address` (the same
/// Taproot output key). Sign the returned sighashes with the vault's tweaked
/// threshold key, then pass the signatures to [`finalize_taproot_keyspend`].
pub fn taproot_keyspend_sighashes(
    network: &str,
    vault_address: &str,
    inputs: &[TaprootSpendInput],
    outputs: &[TaprootSpendOutput],
) -> Result<(String, Vec<[u8; 32]>)> {
    ensure!(!inputs.is_empty(), "a spend needs at least one input");
    ensure!(!outputs.is_empty(), "a spend needs at least one output");
    let net = parse_network(network)?;
    let vault_script_pubkey = Address::from_str(vault_address)
        .map_err(|err| anyhow!("invalid vault address: {err}"))?
        .require_network(net)
        .map_err(|err| anyhow!("vault address network mismatch: {err}"))?
        .script_pubkey();

    let tx_inputs = inputs
        .iter()
        .map(|input| {
            Ok(TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_str(&input.txid)
                        .map_err(|err| anyhow!("invalid input txid: {err}"))?,
                    vout: input.vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let tx_outputs = outputs
        .iter()
        .map(|output| {
            let script_pubkey = Address::from_str(&output.address)
                .map_err(|err| anyhow!("invalid output address: {err}"))?
                .require_network(net)
                .map_err(|err| anyhow!("output address network mismatch: {err}"))?
                .script_pubkey();
            Ok(TxOut {
                value: Amount::from_sat(output.value_sats),
                script_pubkey,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let unsigned = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: tx_inputs,
        output: tx_outputs,
    };
    // Every input is locked by the same vault output key, so the prevouts share a
    // script pubkey and only differ in value.
    let prevouts = inputs
        .iter()
        .map(|input| TxOut {
            value: Amount::from_sat(input.value_sats),
            script_pubkey: vault_script_pubkey.clone(),
        })
        .collect::<Vec<_>>();
    let mut cache = SighashCache::new(&unsigned);
    let mut sighashes = Vec::with_capacity(inputs.len());
    for index in 0..inputs.len() {
        let sighash = cache
            .taproot_key_spend_signature_hash(
                index,
                &Prevouts::All(&prevouts),
                TapSighashType::Default,
            )
            .map_err(|err| anyhow!("taproot sighash failed: {err}"))?;
        sighashes.push(sighash.to_byte_array());
    }
    Ok((consensus::encode::serialize_hex(&unsigned), sighashes))
}

/// Attach key-path witnesses to the unsigned transaction returned by
/// [`taproot_keyspend_sighashes`] and produce the broadcastable raw hex + txid.
/// `signatures` are the 64-byte BIP340 aggregate signatures, one per input in
/// order (SIGHASH_DEFAULT, so each witness is exactly the 64-byte signature).
pub fn finalize_taproot_keyspend(
    unsigned_tx_hex: &str,
    signatures: &[[u8; 64]],
) -> Result<(String, String)> {
    let mut tx: Transaction = consensus::encode::deserialize_hex(unsigned_tx_hex)
        .map_err(|err| anyhow!("invalid unsigned transaction: {err}"))?;
    ensure!(
        tx.input.len() == signatures.len(),
        "expected {} signatures, got {}",
        tx.input.len(),
        signatures.len()
    );
    for (input, signature) in tx.input.iter_mut().zip(signatures) {
        let mut witness = Witness::new();
        witness.push(signature);
        input.witness = witness;
    }
    let raw_hex = consensus::encode::serialize_hex(&tx);
    let txid = tx.compute_txid().to_string();
    Ok((raw_hex, txid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use dkgkit_core::{
        GroupThresholdRequirement, GroupedThresholdConfig, ParticipantId, RankedParticipant,
    };
    use dkgkit_frost::{
        run_local_grouped_htss_keygen,
        sign_digest_with_local_grouped_htss_threshold_shares_for_output, HtssLocalKeySet,
    };

    /// A 1/2 + 2/3 + 3/5 grouped HTSS vault, matching the btech demo policy.
    fn demo_grouped_keyset() -> (GroupedThresholdConfig, HtssLocalKeySet) {
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
        (config, keyset)
    }

    fn demo_signer_set() -> Vec<ParticipantId> {
        [1, 3, 4, 6, 7, 8]
            .into_iter()
            .map(|id| ParticipantId::new(id).unwrap())
            .collect()
    }

    #[test]
    fn taproot_keyspend_witness_verifies_under_output_key() {
        let (config, keyset) = demo_grouped_keyset();
        let account = BitcoinAccountKey::new(keyset.group_key.clone(), [42u8; 32]);
        let path = BitcoinDerivationPath::bip86(0, 0, 0);
        let vault_address =
            taproot_child_address_descriptor_for_network(&account, "regtest", path.clone())
                .unwrap()
                .address;
        let tweak = taproot_child_key_tweak(&account, "regtest", path).unwrap();

        // Spend a 500-BTC UTXO: 1 BTC out, the rest back as change minus fee.
        let inputs = vec![TaprootSpendInput {
            txid: "ab".repeat(32),
            vout: 1,
            value_sats: 50_000_000_000,
        }];
        let outputs = vec![
            TaprootSpendOutput {
                address: vault_address.clone(),
                value_sats: 100_000_000,
            },
            TaprootSpendOutput {
                address: vault_address.clone(),
                value_sats: 49_899_990_000,
            },
        ];
        let (unsigned_hex, sighashes) =
            taproot_keyspend_sighashes("regtest", &vault_address, &inputs, &outputs).unwrap();
        assert_eq!(sighashes.len(), 1);

        let signature = sign_digest_with_local_grouped_htss_threshold_shares_for_output(
            &keyset.group_key,
            sighashes[0],
            tweak.output_xonly,
            tweak.tweak,
            tweak.negate_key,
            &keyset.shares,
            &demo_signer_set(),
            &config,
        )
        .unwrap();
        let sig_bytes: [u8; 64] = signature.signature_bytes.try_into().unwrap();

        // The witness signature must verify against the address output key over
        // the BIP341 sighash — i.e. it is a valid key-path spend.
        let secp = Secp256k1::new();
        let sig = Signature::from_slice(&sig_bytes).unwrap();
        let message = Message::from_digest(sighashes[0]);
        let output_xonly = SecpXOnlyPublicKey::from_slice(&tweak.output_xonly).unwrap();
        assert!(secp.verify_schnorr(&sig, &message, &output_xonly).is_ok());

        let (raw_hex, txid) = finalize_taproot_keyspend(&unsigned_hex, &[sig_bytes]).unwrap();
        assert!(!txid.is_empty());
        let tx: Transaction = consensus::encode::deserialize_hex(&raw_hex).unwrap();
        assert_eq!(tx.input[0].witness.len(), 1);
        assert_eq!(tx.input[0].witness.to_vec()[0].len(), 64);
    }

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
    fn taproot_child_spend_signature_validates_under_address_output_key() {
        let (config, keyset) = demo_grouped_keyset();
        let account = BitcoinAccountKey::new(keyset.group_key.clone(), [42u8; 32]);
        let path = BitcoinDerivationPath::bip86(0, 0, 0);

        let descriptor =
            taproot_child_address_descriptor_for_network(&account, "regtest", path.clone())
                .unwrap();
        let tweak = taproot_child_key_tweak(&account, "regtest", path).unwrap();

        // The derived output key must equal the one the receive address commits to.
        assert_eq!(
            hex::encode(tweak.output_xonly),
            descriptor.xonly_public_key_hex
        );

        // Public-key relation: A·P + B·G == even-Y output key.
        let secp = Secp256k1::new();
        let account_xonly =
            SecpXOnlyPublicKey::from_slice(&keyset.group_key.xonly_public_key).unwrap();
        let p = account_xonly.public_key(Parity::Even);
        let p_term = if tweak.negate_key { p.negate(&secp) } else { p };
        let q = p_term
            .add_exp_tweak(&secp, &SecpScalar::from_be_bytes(tweak.tweak).unwrap())
            .unwrap();
        let (q_xonly, q_parity) = q.x_only_public_key();
        assert_eq!(q_xonly.serialize(), tweak.output_xonly);
        assert_eq!(q_parity, Parity::Even);

        // Threshold-sign a digest for the output key and verify it like Bitcoin Core.
        let signer_set = [1, 3, 4, 6, 7, 8]
            .into_iter()
            .map(|id| ParticipantId::new(id).unwrap())
            .collect::<Vec<_>>();
        let digest = [0x5au8; 32];
        let signature = sign_digest_with_local_grouped_htss_threshold_shares_for_output(
            &keyset.group_key,
            digest,
            tweak.output_xonly,
            tweak.tweak,
            tweak.negate_key,
            &keyset.shares,
            &signer_set,
            &config,
        )
        .unwrap();

        let signature_bytes: [u8; 64] = signature.signature_bytes.try_into().unwrap();
        let signature = Signature::from_slice(&signature_bytes).unwrap();
        let message = Message::from_digest(digest);
        let output_xonly = SecpXOnlyPublicKey::from_slice(&tweak.output_xonly).unwrap();
        assert!(secp
            .verify_schnorr(&signature, &message, &output_xonly)
            .is_ok());
    }

    #[test]
    fn silent_payment_spend_signature_validates_under_output_key() {
        let (config, keyset) = demo_grouped_keyset();
        // An arbitrary silent-payment per-output tweak scalar k.
        let k = [0x11u8; 32];
        let tweak = silent_payment_output_tweak(&keyset.group_key, k).unwrap();

        let secp = Secp256k1::new();
        let account_xonly =
            SecpXOnlyPublicKey::from_slice(&keyset.group_key.xonly_public_key).unwrap();
        let p = account_xonly.public_key(Parity::Even);

        // Public-key relation: A·P + B·G == even-Y output key.
        let p_term = if tweak.negate_key { p.negate(&secp) } else { p };
        let q = p_term
            .add_exp_tweak(&secp, &SecpScalar::from_be_bytes(tweak.tweak).unwrap())
            .unwrap();
        let (q_xonly, q_parity) = q.x_only_public_key();
        assert_eq!(q_xonly.serialize(), tweak.output_xonly);
        assert_eq!(q_parity, Parity::Even);

        // Output key equals taproot(B_spend + k·G) computed independently.
        let internal = p
            .add_exp_tweak(&secp, &SecpScalar::from_be_bytes(k).unwrap())
            .unwrap();
        let (internal_xonly, _) = internal.x_only_public_key();
        let (expected_output, _) = internal_xonly.tap_tweak(&secp, None);
        assert_eq!(
            expected_output.to_x_only_public_key().serialize(),
            tweak.output_xonly
        );

        // Grouped HTSS threshold-sign for the output key and verify like Bitcoin Core.
        let signer_set = [1, 3, 4, 6, 7, 8]
            .into_iter()
            .map(|id| ParticipantId::new(id).unwrap())
            .collect::<Vec<_>>();
        let digest = [0x5au8; 32];
        let signature = sign_digest_with_local_grouped_htss_threshold_shares_for_output(
            &keyset.group_key,
            digest,
            tweak.output_xonly,
            tweak.tweak,
            tweak.negate_key,
            &keyset.shares,
            &signer_set,
            &config,
        )
        .unwrap();

        let signature_bytes: [u8; 64] = signature.signature_bytes.try_into().unwrap();
        let signature = Signature::from_slice(&signature_bytes).unwrap();
        let message = Message::from_digest(digest);
        let output_xonly = SecpXOnlyPublicKey::from_slice(&tweak.output_xonly).unwrap();
        assert!(secp
            .verify_schnorr(&signature, &message, &output_xonly)
            .is_ok());
    }

    #[test]
    fn silent_payment_leaf_signature_validates_under_leaf_key() {
        let (config, keyset) = demo_grouped_keyset();
        let k = [0x22u8; 32];
        let tweak = silent_payment_leaf_tweak(&keyset.group_key, k).unwrap();

        let secp = Secp256k1::new();
        let account_xonly =
            SecpXOnlyPublicKey::from_slice(&keyset.group_key.xonly_public_key).unwrap();
        let p = account_xonly.public_key(Parity::Even);

        // output_xonly is the x-only of the leaf key P = B_spend(even) + k·G.
        let leaf = p
            .add_exp_tweak(&secp, &SecpScalar::from_be_bytes(k).unwrap())
            .unwrap();
        let (leaf_xonly, _) = leaf.x_only_public_key();
        assert_eq!(leaf_xonly.serialize(), tweak.output_xonly);

        // A·P + B·G == even-Y leaf key (no taproot tweak).
        let p_term = if tweak.negate_key { p.negate(&secp) } else { p };
        let q = p_term
            .add_exp_tweak(&secp, &SecpScalar::from_be_bytes(tweak.tweak).unwrap())
            .unwrap();
        let (q_xonly, q_parity) = q.x_only_public_key();
        assert_eq!(q_xonly.serialize(), tweak.output_xonly);
        assert_eq!(q_parity, Parity::Even);

        // Grouped HTSS threshold-sign a leaf sighash; verify under the leaf key.
        let signer_set = [1, 3, 4, 6, 7, 8]
            .into_iter()
            .map(|id| ParticipantId::new(id).unwrap())
            .collect::<Vec<_>>();
        let digest = [0x7bu8; 32];
        let signature = sign_digest_with_local_grouped_htss_threshold_shares_for_output(
            &keyset.group_key,
            digest,
            tweak.output_xonly,
            tweak.tweak,
            tweak.negate_key,
            &keyset.shares,
            &signer_set,
            &config,
        )
        .unwrap();
        let signature_bytes: [u8; 64] = signature.signature_bytes.try_into().unwrap();
        let signature = Signature::from_slice(&signature_bytes).unwrap();
        let message = Message::from_digest(digest);
        let leaf_key = SecpXOnlyPublicKey::from_slice(&tweak.output_xonly).unwrap();
        assert!(secp.verify_schnorr(&signature, &message, &leaf_key).is_ok());
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
