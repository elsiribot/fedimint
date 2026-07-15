//! Threshold ECDSA for Fedimint federations, wrapping the audited
//! [`cggmp21`] implementation (CGGMP21 protocol, Kudelski-audited).
//!
//! This crate is transport-agnostic: protocol runners take a
//! [`round_based::MpcParty`], and the caller supplies message delivery.
//! It must not depend on fedimint-core; consensus/p2p wiring lives in the
//! server module that consumes this crate.

use anyhow::Context as _;

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

#[cfg(test)]
mod tests;
