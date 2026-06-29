use bitcoin::Network;
use dkgkit_bitcoin::{
    taproot_address_from_xonly_hex, verify_aggregate_signature_digest, BitcoinAuthorizationMessage,
};
use dkgkit_sdk::{run_local_frost_dkg, sign_digest_with_shares, ParticipantId, ThresholdConfig};

fn main() -> anyhow::Result<()> {
    let local_shares = run_local_frost_dkg("demo-dkg", 2, 3)?;
    let group_key = local_shares[0].group_key.clone();
    let group_key_hex = hex::encode(group_key.xonly_public_key);
    let address = taproot_address_from_xonly_hex(&group_key_hex, Network::Signet)?;

    let authorization = BitcoinAuthorizationMessage {
        network: "signet".to_string(),
        action: "approve-payment".to_string(),
        recipient: Some("tb1p...demo-recipient".to_string()),
        amount_sats: Some(100_000),
        memo: Some("hackathon demo payout".to_string()),
        nonce: "demo-session-001".to_string(),
    };
    let digest = authorization.digest();

    let aggregate = sign_digest_with_shares(
        "demo-signing",
        ThresholdConfig::new(2, 3)?,
        group_key,
        digest,
        &local_shares,
        vec![ParticipantId::new(1)?, ParticipantId::new(2)?],
    )?;
    let verified =
        verify_aggregate_signature_digest(&local_shares[0].group_key, &digest, &aggregate)?;
    anyhow::ensure!(
        verified,
        "aggregate signature did not verify against group key"
    );

    println!("DKGKit Bitcoin message signing demo");
    println!("threshold: 2-of-3");
    println!("group x-only public key: {group_key_hex}");
    println!("group Signet Taproot address: {address}");
    println!("message to sign:\n{}", authorization.canonical_text());
    println!("message digest: {}", hex::encode(digest));
    println!("signers: party 1, party 2");
    println!("aggregate signature verifies: {verified}");
    println!(
        "aggregate signature bytes: {}",
        aggregate.signature_bytes.len()
    );
    println!(
        "aggregate signature hex: {}",
        hex::encode(aggregate.signature_bytes)
    );
    Ok(())
}
