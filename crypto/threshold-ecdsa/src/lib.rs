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

#[cfg(test)]
mod tests;
