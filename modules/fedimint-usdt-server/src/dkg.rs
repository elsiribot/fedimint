//! Distributed key generation for the USDT module.
//!
//! Drives the `cggmp21` keygen and aux-info-generation protocols over the
//! federation's config-gen peer channel ([`PeerHandleOps::exchange_bytes`]).
//! `cggmp21`'s synchronous state machines are `!Send`, so each protocol runs
//! on a dedicated OS thread via
//! [`fedimint_threshold_ecdsa::transport::spawn_protocol`]; only round
//! payloads (`Vec<u8>`) and the final `Send` output cross back to this
//! (`Send`) async function.

use std::collections::BTreeMap;

use anyhow::{Context as _, anyhow, ensure};
use cggmp21::ExecutionId;
use fedimint_core::PeerId;
use fedimint_server_core::ConfigGenModuleArgs;
use fedimint_server_core::config::{PeerHandleOps, PeerHandleOpsExt as _};
use fedimint_threshold_ecdsa::transport::{
    EncryptedRoundCodec, drive_over_exchange, spawn_protocol,
};
use fedimint_threshold_ecdsa::{Curve, assemble_key_share, group_public_key};
use fedimint_usdt_common::UsdtGenParams;
use rand::rngs::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest as _, Sha256};

use crate::config::{UsdtConfig, UsdtConfigConsensus, UsdtConfigLocal, UsdtConfigPrivate};

/// Domain-separation prefix for the keygen sub-protocol's `ExecutionId`,
/// folded into a hash of every party's exchanged MPC-transport encryption
/// public key (see [`derive_eid`]).
const KEYGEN_EID_PREFIX: &[u8] = b"usdt-dkg-keygen-v0";
/// Domain-separation prefix for the aux-info-gen sub-protocol's
/// `ExecutionId`. Must differ from [`KEYGEN_EID_PREFIX`]: reusing an eid
/// across cggmp21 protocol executions is unsound.
const AUX_EID_PREFIX: &[u8] = b"usdt-dkg-aux-v0";

/// Derive a 32-byte execution id deterministically from `prefix` and every
/// party's static MPC-transport encryption public key, in party-index
/// order. Every guardian computes the identical value from the same
/// exchanged public keys, so no additional coordination round is needed to
/// agree on an eid, while it stays unique to this federation and this
/// sub-protocol.
fn derive_eid(prefix: &[u8], ordered_enc_pks: &[PublicKey]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prefix);
    for pk in ordered_enc_pks {
        hasher.update(pk.serialize());
    }
    hasher.finalize().into()
}

/// Services one all-to-all round of a cggmp21 protocol over the config-gen
/// peer channel: broadcasts `payload` to every peer and reorders the
/// resulting `BTreeMap<PeerId, _>` into the `Vec` indexed by cggmp21 party
/// index (`peer_ids[i]` is party `i`'s `PeerId`), matching the index space
/// [`spawn_protocol`]/[`drive_over_exchange`] use.
async fn service_round(
    peers: &(dyn PeerHandleOps + Send + Sync),
    peer_ids: &[PeerId],
    payload: Vec<u8>,
) -> anyhow::Result<Vec<Vec<u8>>> {
    let responses = peers.exchange_bytes(payload).await?;
    peer_ids
        .iter()
        .map(|peer| {
            responses
                .get(peer)
                .cloned()
                .with_context(|| format!("missing DKG round payload from peer {peer}"))
        })
        .collect()
}

/// This guardian's resolved party assignment: its index among the
/// federation's parties (in the sorted-`PeerId` order every guardian
/// agrees on) and every party's static MPC-transport encryption public
/// key, in that same order.
struct PartyAssignment {
    peer_ids: Vec<PeerId>,
    my_index: u16,
    n: u16,
    threshold: u16,
    ordered_enc_pks: Vec<PublicKey>,
    enc_pk_map: BTreeMap<PeerId, PublicKey>,
}

/// Exchange every guardian's static MPC-transport encryption public key and
/// resolve our own party assignment from the result.
///
/// `distributed_gen` isn't handed our own `PeerId` directly, so we recover
/// it here: our entry in the map [`PeerHandleOpsExt::exchange_encodable`]
/// returns is the one keyed under our own public key.
async fn resolve_party_assignment(
    peers: &(dyn PeerHandleOps + Send + Sync),
    our_enc_pk: PublicKey,
) -> anyhow::Result<PartyAssignment> {
    let peer_ids: Vec<PeerId> = peers.num_peers().peer_ids().collect();
    let n = u16::try_from(peer_ids.len())
        .expect("federation sizes fit in u16 in every supported deployment");
    let threshold = u16::try_from(peers.num_peers().threshold())
        .expect("federation sizes fit in u16 in every supported deployment");

    let enc_pk_map: BTreeMap<PeerId, PublicKey> = peers.exchange_encodable(our_enc_pk).await?;

    // Guard against a misbehaving (or buggy) peer submitting another peer's
    // MPC-transport encryption public key: since our own party index below is
    // resolved by matching `our_enc_pk` against the values in this map, a
    // duplicate value could make us (or another honest peer) resolve to the
    // wrong party index. Every peer's encryption key must be unique.
    let distinct_enc_pks: std::collections::BTreeSet<[u8; 33]> =
        enc_pk_map.values().map(PublicKey::serialize).collect();
    ensure!(
        distinct_enc_pks.len() == enc_pk_map.len(),
        "duplicate MPC encryption key found among peers during USDT DKG party assignment; \
         each peer must submit a distinct encryption key"
    );

    let our_peer = *enc_pk_map
        .iter()
        .find(|(_, pk)| **pk == our_enc_pk)
        .map(|(peer, _)| peer)
        .context("our own MPC encryption public key is missing from the exchange result")?;
    let my_index = u16::try_from(
        peer_ids
            .iter()
            .position(|peer| *peer == our_peer)
            .context("our peer id is missing from the sorted peer id list")?,
    )
    .expect("federation sizes fit in u16 in every supported deployment");

    let ordered_enc_pks: Vec<PublicKey> = peer_ids
        .iter()
        .map(|peer| {
            enc_pk_map
                .get(peer)
                .copied()
                .with_context(|| format!("missing MPC encryption public key for peer {peer}"))
        })
        .collect::<anyhow::Result<_>>()?;

    Ok(PartyAssignment {
        peer_ids,
        my_index,
        n,
        threshold,
        ordered_enc_pks,
        enc_pk_map,
    })
}

/// Run cggmp21 keygen off-thread, serviced over `peers.exchange_bytes` via
/// [`service_round`].
async fn run_keygen(
    peers: &(dyn PeerHandleOps + Send + Sync),
    assignment: &PartyAssignment,
    mpc_encryption_sk: SecretKey,
    eid: [u8; 32],
) -> anyhow::Result<cggmp21::IncompleteKeyShare<Curve>> {
    let PartyAssignment {
        peer_ids,
        my_index,
        n,
        threshold,
        ordered_enc_pks,
        ..
    } = assignment;
    let (my_index, n, threshold) = (*my_index, *n, *threshold);

    tracing::info!(
        target: "fedimint_usdt",
        n,
        my_index,
        threshold,
        "starting USDT DKG keygen phase"
    );

    let codec = EncryptedRoundCodec::new(
        my_index,
        mpc_encryption_sk,
        ordered_enc_pks.clone(),
        eid.to_vec(),
    );
    let handle = spawn_protocol::<cggmp21::IncompleteKeyShare<Curve>, _, _>(
        my_index,
        n,
        move |mut chan| async move {
            let mut rng = OsRng;
            let execution_id = ExecutionId::new(&eid);
            let sm = cggmp21::keygen::<Curve>(execution_id, my_index, n)
                .set_threshold(threshold)
                .hd_wallet(true)
                .into_state_machine(&mut rng);
            drive_over_exchange(sm, &codec, &mut chan)
                .await?
                .map_err(|e| anyhow!("cggmp21 keygen failed: {e}"))
        },
    );

    // `peers` (a `&dyn ... + Send + Sync`, `Copy`) and `peer_ids` are
    // captured by the outer `move` closure and copied into each round's
    // owned `async move` block, so `drive`'s `FnMut(Vec<u8>) -> Fut` bound
    // is satisfied without any `Arc<Mutex<_>>` — no per-round state needs
    // sharing, only this shared, `Copy` reference pair.
    handle
        .drive(move |payload| async move { service_round(peers, peer_ids, payload).await })
        .await
        .context("driving cggmp21 keygen over the config-gen peer channel")
}

/// Run cggmp21 aux-info generation (Paillier + ring-Pedersen setup)
/// off-thread, serviced over `peers.exchange_bytes` via [`service_round`].
/// Must run with a different `eid` from [`run_keygen`]'s, though it reuses
/// the same static MPC-transport encryption keypair for its round codec.
async fn run_aux_gen(
    peers: &(dyn PeerHandleOps + Send + Sync),
    assignment: &PartyAssignment,
    mpc_encryption_sk: SecretKey,
    eid: [u8; 32],
) -> anyhow::Result<cggmp21::key_share::AuxInfo> {
    let PartyAssignment {
        peer_ids,
        my_index,
        n,
        ordered_enc_pks,
        ..
    } = assignment;
    let (my_index, n) = (*my_index, *n);

    tracing::info!(
        target: "fedimint_usdt",
        n,
        my_index,
        "starting USDT DKG aux-gen phase"
    );

    let codec = EncryptedRoundCodec::new(
        my_index,
        mpc_encryption_sk,
        ordered_enc_pks.clone(),
        eid.to_vec(),
    );
    let handle = spawn_protocol::<cggmp21::key_share::AuxInfo, _, _>(
        my_index,
        n,
        move |mut chan| async move {
            let mut rng = OsRng;
            let execution_id = ExecutionId::new(&eid);
            let primes = cggmp21::PregeneratedPrimes::generate(&mut rng);
            let sm = cggmp21::aux_info_gen(execution_id, my_index, n, primes)
                .into_state_machine(&mut rng);
            drive_over_exchange(sm, &codec, &mut chan)
                .await?
                .map_err(|e| anyhow!("cggmp21 aux-info generation failed: {e}"))
        },
    );

    handle
        .drive(move |payload| async move { service_round(peers, peer_ids, payload).await })
        .await
        .context("driving cggmp21 aux-info generation over the config-gen peer channel")
}

/// Runs the USDT module's distributed key generation: cggmp21 keygen,
/// followed by aux-info generation (Paillier + ring-Pedersen setup),
/// assembled into one complete guardian key share.
///
/// This is an untrusted protocol: no single guardian (nor any coalition
/// below the signing threshold) ever sees the full signing key. Contrast
/// with [`crate::UsdtInit::trusted_dealer_gen`], which reconstructs the full
/// secret in one place and is test/dev-only.
pub(crate) async fn distributed_gen(
    peers: &(dyn PeerHandleOps + Send + Sync),
    args: &ConfigGenModuleArgs,
    params: &UsdtGenParams,
) -> anyhow::Result<UsdtConfig> {
    let secp = Secp256k1::new();
    let mpc_encryption_sk = SecretKey::new(&mut OsRng);
    let our_enc_pk = mpc_encryption_sk.public_key(&secp);

    let assignment = resolve_party_assignment(peers, our_enc_pk).await?;

    // Deterministic, federation-unique execution ids for the two
    // sub-protocols below, derived from the exchanged encryption keys so
    // every guardian agrees on them without any extra coordination round.
    let eid_keygen = derive_eid(KEYGEN_EID_PREFIX, &assignment.ordered_enc_pks);
    let eid_aux = derive_eid(AUX_EID_PREFIX, &assignment.ordered_enc_pks);

    let core = run_keygen(peers, &assignment, mpc_encryption_sk, eid_keygen).await?;
    let aux = run_aux_gen(peers, &assignment, mpc_encryption_sk, eid_aux).await?;

    let key_share = assemble_key_share(core, aux)?;
    let group_public_key = group_public_key(&key_share)?;

    Ok(UsdtConfig {
        private: UsdtConfigPrivate {
            key_share,
            mpc_encryption_sk,
            // This guardian's own RPC endpoint is not exchanged with peers
            // (each guardian's is its own); default to localhost for
            // dev/test the same way trusted-dealer-gen does. Later
            // phases/ops override via config.
            local: UsdtConfigLocal {
                evm_rpc_url: crate::config::default_evm_rpc_url(),
                broadcaster_private_key: None,
            },
        },
        consensus: UsdtConfigConsensus {
            group_public_key,
            mpc_encryption_pks: assignment.enc_pk_map,
            threshold: assignment.threshold,
            network: args.network,
            usdt_contract: params.usdt_contract,
            chain_id: params.chain_id,
            confirmation_depth: params.confirmation_depth,
            entry_point: params.entry_point,
            account_factory: params.account_factory,
            simple_account_impl: params.simple_account_impl,
            check_ttl_blocks: params.check_ttl_blocks,
            broadcaster_min_balance_wei: params.broadcaster_min_balance_wei,
        },
    })
}
