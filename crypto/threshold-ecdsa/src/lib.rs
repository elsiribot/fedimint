//! Threshold ECDSA for Fedimint federations, wrapping the audited
//! [`cggmp21`] implementation (CGGMP21 protocol, Kudelski-audited).
//!
//! This crate is transport-agnostic: protocol runners take a
//! [`round_based::MpcParty`], and the caller supplies message delivery.
//! It must not depend on fedimint-core; consensus/p2p wiring lives in the
//! server module that consumes this crate.

use anyhow::Context as _;
use sha3::{Digest as _, Keccak256};

/// The only curve this crate supports.
pub type Curve = cggmp21::supported_curves::Secp256k1;

/// Run the CGGMP21 distributed key generation as party `i` of `n`,
/// with signing threshold `t`. HD derivation is always enabled so the
/// resulting share can sign for SLIP-10-derived child keys (per-deposit
/// addresses) without re-running DKG.
///
/// `eid` must be unique per protocol execution and identical across all
/// parties. The transport behind `party` must be authenticated, and
/// point-to-point messages encrypted (cggmp21 requirement).
pub async fn run_keygen<M>(
    eid: cggmp21::ExecutionId<'_>,
    i: u16,
    t: u16,
    n: u16,
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
    party: M,
) -> anyhow::Result<cggmp21::IncompleteKeyShare<Curve>>
where
    M: round_based::Mpc<
            ProtocolMessage = cggmp21::keygen::ThresholdMsg<
                Curve,
                cggmp21::security_level::SecurityLevel128,
                sha2::Sha256,
            >,
        >,
{
    cggmp21::keygen::<Curve>(eid, i, n)
        .set_threshold(t)
        .hd_wallet(true)
        .start(rng, party)
        .await
        .context("cggmp21 keygen failed")
}

/// A guardian's complete signing share: DKG core share + auxiliary info
/// (Paillier keys, ring-Pedersen parameters). Serde-serializable for
/// storage in the guardian database.
pub type KeyShare = cggmp21::KeyShare<Curve>;

/// Run auxiliary-info generation (Paillier setup). `pregenerated` primes
/// are expensive to produce — generate them ahead of time (they are
/// consumed by this call).
pub async fn run_aux_gen<M>(
    eid: cggmp21::ExecutionId<'_>,
    i: u16,
    n: u16,
    pregenerated: cggmp21::PregeneratedPrimes,
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
    party: M,
) -> anyhow::Result<cggmp21::key_share::AuxInfo>
where
    M: round_based::Mpc<
            ProtocolMessage = cggmp21::key_refresh::AuxOnlyMsg<
                sha2::Sha256,
                cggmp21::security_level::SecurityLevel128,
            >,
        >,
{
    cggmp21::aux_info_gen(eid, i, n, pregenerated)
        .start(rng, party)
        .await
        .context("cggmp21 aux info generation failed")
}

/// Combine a DKG core share with aux info into a full, validated key share.
pub fn assemble_key_share(
    core: cggmp21::IncompleteKeyShare<Curve>,
    aux: cggmp21::key_share::AuxInfo,
) -> anyhow::Result<KeyShare> {
    cggmp21::KeyShare::from_parts((core, aux)).context("key share validation failed")
}

/// Convert the group public key (a curve point) to the workspace's
/// canonical `secp256k1::PublicKey`.
pub fn group_public_key(share: &KeyShare) -> anyhow::Result<secp256k1::PublicKey> {
    use cggmp21::key_share::AnyKeyShare as _;

    let compressed = share.shared_public_key().to_bytes(true);
    secp256k1::PublicKey::from_slice(&compressed)
        .context("group public key is not a valid secp256k1 point")
}

fn convert_signature(
    sig: cggmp21::Signature<Curve>,
) -> anyhow::Result<secp256k1::ecdsa::Signature> {
    let mut compact = [0u8; 64];
    compact[..32].copy_from_slice(&sig.r.to_be_bytes());
    compact[32..].copy_from_slice(&sig.s.to_be_bytes());
    let mut sig = secp256k1::ecdsa::Signature::from_compact(&compact)
        .context("cggmp21 produced an invalid compact signature")?;
    // EVM (and the secp256k1 crate's verify) require low-s form.
    sig.normalize_s();
    Ok(sig)
}

/// Sign a 32-byte digest with a t-subset of guardians.
///
/// * `i` — this party's index within `signers` (0..t)
/// * `signers` — keygen indexes of the t participating parties (all parties
///   must pass the identical slice)
/// * `derivation_path` — optional SLIP-10 non-hardened path; when set, the
///   signature is valid for the derived child public key instead of the group
///   key
/// * `digest` — the prehashed message (e.g. keccak256 of an EVM tx)
#[allow(clippy::too_many_arguments)]
pub async fn run_signing<M>(
    eid: cggmp21::ExecutionId<'_>,
    i: u16,
    signers: &[u16],
    share: &KeyShare,
    derivation_path: Option<&[u32]>,
    digest: [u8; 32],
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
    party: M,
) -> anyhow::Result<secp256k1::ecdsa::Signature>
where
    M: round_based::Mpc<ProtocolMessage = cggmp21::signing::msg::Msg<Curve, sha2::Sha256>>,
{
    let data = cggmp21::DataToSign::from_scalar(
        cggmp21::generic_ec::Scalar::from_be_bytes_mod_order(digest),
    );
    let mut builder = cggmp21::signing(eid, i, signers, share);
    if let Some(path) = derivation_path {
        builder = builder
            .set_derivation_path(path.iter().copied())
            .context("invalid derivation path")?;
    }
    let sig = builder
        .sign(rng, party, data)
        .await
        .context("cggmp21 signing failed")?;
    convert_signature(sig)
}

/// The standard Ethereum address of a secp256k1 public key: the last 20
/// bytes of keccak256 over the 64-byte uncompressed point (i.e. the
/// uncompressed SEC1 encoding with its leading `0x04` prefix stripped).
pub fn evm_address(pk: &secp256k1::PublicKey) -> [u8; 20] {
    let uncompressed = pk.serialize_uncompressed();
    let hash = Keccak256::digest(&uncompressed[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    address
}

/// Derive the child public key for a non-hardened SLIP-10 `path`.
///
/// A signature produced by [`run_signing`] with `derivation_path: Some(path)`
/// verifies against this key (and not against the group key returned by
/// [`group_public_key`]). This lets the USDT module derive a per-deposit EVM
/// address from `(group key, path)` up front, and later sign for that exact
/// address using the same guardian shares.
pub fn derived_public_key(share: &KeyShare, path: &[u32]) -> anyhow::Result<secp256k1::PublicKey> {
    let child = share
        .derive_child_public_key::<hd_wallet::Slip10, _>(path.iter().copied())
        .map_err(|err| anyhow::anyhow!("child key derivation failed: {err}"))?;
    let compressed = child.public_key.to_bytes(true);
    secp256k1::PublicKey::from_slice(&compressed)
        .context("derived key is not a valid secp256k1 point")
}

#[cfg(test)]
mod tests;
