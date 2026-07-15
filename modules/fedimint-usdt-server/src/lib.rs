#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

use std::collections::BTreeMap;

use anyhow::{bail, ensure};
use async_trait::async_trait;
use fedimint_core::config::{
    ServerModuleConfig, ServerModuleConsensusConfig, TypedServerModuleConfig,
    TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{DatabaseTransaction, DatabaseVersion};
use fedimint_core::envs::{FM_ENABLE_MODULE_USDT_ENV, is_env_var_set_opt};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    ApiEndpoint, ApiVersion, CORE_CONSENSUS_VERSION, CoreConsensusVersion, InputMeta,
    ModuleConsensusVersion, ModuleInit, SupportedModuleApiVersions, TransactionItemAmounts,
    api_endpoint,
};
use fedimint_core::{InPoint, NumPeersExt, OutPoint, PeerId};
use fedimint_server_core::config::PeerHandleOps;
use fedimint_server_core::migration::ServerModuleDbMigrationFn;
use fedimint_server_core::{
    ConfigGenModuleArgs, EnvVarDoc, ServerModule, ServerModuleInit, ServerModuleInitArgs,
};
use fedimint_threshold_ecdsa::group_public_key;
pub use fedimint_usdt_common as common;
use fedimint_usdt_common::config::UsdtClientConfig;
use fedimint_usdt_common::endpoint_constants::GROUP_PUBLIC_KEY_ENDPOINT;
use fedimint_usdt_common::{
    MODULE_CONSENSUS_VERSION, UsdtCommonInit, UsdtConsensusItem, UsdtInput, UsdtInputError,
    UsdtModuleTypes, UsdtOutput, UsdtOutputError, UsdtOutputOutcome,
};
use rand::rngs::OsRng;
use strum::IntoEnumIterator;

use crate::config::{UsdtConfig, UsdtConfigConsensus, UsdtConfigPrivate};
use crate::db::DbKeyPrefix;

mod dkg;

pub mod config;
pub mod db;

/// Generates the module
#[derive(Debug, Clone)]
pub struct UsdtInit;

impl ModuleInit for UsdtInit {
    type Common = UsdtCommonInit;

    /// Dumps all database items for debugging
    async fn dump_database(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        let items: BTreeMap<String, Box<dyn erased_serde::Serialize + Send>> = BTreeMap::new();
        let filtered_prefixes = DbKeyPrefix::iter().filter(|f| {
            prefix_names.is_empty() || prefix_names.contains(&f.to_string().to_lowercase())
        });

        // No consensus state is persisted yet; nothing to dump for any prefix.
        for table in filtered_prefixes {
            match table {
                DbKeyPrefix::Reserved => {}
            }
        }

        Box::new(items.into_iter())
    }
}

/// Implementation of server module non-consensus functions
#[async_trait]
impl ServerModuleInit for UsdtInit {
    type Module = Usdt;

    /// Returns the version of this module
    fn versions(&self, _core: CoreConsensusVersion) -> &[ModuleConsensusVersion] {
        &[MODULE_CONSENSUS_VERSION]
    }

    fn supported_api_versions(&self) -> SupportedModuleApiVersions {
        SupportedModuleApiVersions::from_raw(
            (CORE_CONSENSUS_VERSION.major, CORE_CONSENSUS_VERSION.minor),
            (
                MODULE_CONSENSUS_VERSION.major,
                MODULE_CONSENSUS_VERSION.minor,
            ),
            &[(0, 0)],
        )
    }

    fn is_enabled_by_default(&self) -> bool {
        is_env_var_set_opt(FM_ENABLE_MODULE_USDT_ENV).unwrap_or(false)
    }

    fn get_documented_env_vars(&self) -> Vec<EnvVarDoc> {
        vec![EnvVarDoc {
            name: FM_ENABLE_MODULE_USDT_ENV,
            description: "Set to 1/true to enable the USDT-on-EVM module (experimental). Disabled by default.",
        }]
    }

    /// Initialize the module
    async fn init(&self, args: &ServerModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        Ok(Usdt::new(args.cfg().to_typed()?))
    }

    /// Generates configs for all peers in a trusted manner for testing.
    ///
    /// This reconstructs the full threshold-ECDSA secret in one place (the
    /// `cggmp21` "trusted dealer"), which is only appropriate for
    /// development/test federations. Production federations must run
    /// [`ServerModuleInit::distributed_gen`] instead.
    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        args: &ConfigGenModuleArgs,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        let num_peers = peers.to_num_peers();
        let n = u16::try_from(num_peers.total())
            .expect("federation sizes fit in u16 in every supported deployment");
        let threshold = u16::try_from(num_peers.threshold())
            .expect("federation sizes fit in u16 in every supported deployment");

        let shares = cggmp21::trusted_dealer::builder::<fedimint_threshold_ecdsa::Curve, _>(n)
            .set_threshold(Some(threshold))
            .hd_wallet(true)
            .generate_shares(&mut OsRng)
            .expect("trusted dealer share generation failed");

        let group_public_key =
            group_public_key(&shares[0]).expect("dealer-generated share has a valid group key");

        let secp = secp256k1::Secp256k1::new();
        let mpc_encryption_keys: BTreeMap<PeerId, (secp256k1::SecretKey, secp256k1::PublicKey)> =
            peers
                .iter()
                .map(|&peer| (peer, secp.generate_keypair(&mut OsRng)))
                .collect();
        let mpc_encryption_pks: BTreeMap<PeerId, secp256k1::PublicKey> = mpc_encryption_keys
            .iter()
            .map(|(&peer, (_, pk))| (peer, *pk))
            .collect();

        peers
            .iter()
            .enumerate()
            .map(|(index, &peer)| {
                let cfg = UsdtConfig {
                    private: UsdtConfigPrivate {
                        key_share: shares[index].clone(),
                        mpc_encryption_sk: mpc_encryption_keys[&peer].0,
                    },
                    consensus: UsdtConfigConsensus {
                        group_public_key,
                        mpc_encryption_pks: mpc_encryption_pks.clone(),
                        threshold,
                        network: args.network,
                    },
                };

                (peer, cfg.to_erased())
            })
            .collect()
    }

    /// Generates configs for all peers in an untrusted manner
    async fn distributed_gen(
        &self,
        peers: &(dyn PeerHandleOps + Send + Sync),
        args: &ConfigGenModuleArgs,
    ) -> anyhow::Result<ServerModuleConfig> {
        let config = dkg::distributed_gen(peers, args).await?;
        Ok(config.to_erased())
    }

    /// Converts the consensus config into the client config
    fn get_client_config(
        &self,
        config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<UsdtClientConfig> {
        let config = UsdtConfigConsensus::from_erased(config)?;
        Ok(UsdtClientConfig {
            group_public_key: config.group_public_key,
            network: config.network,
        })
    }

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()> {
        let config = config.to_typed::<UsdtConfig>()?;

        ensure!(
            group_public_key(&config.private.key_share)? == config.consensus.group_public_key,
            "This guardian's key share does not aggregate to the consensus group public key"
        );

        let secp = secp256k1::Secp256k1::new();
        let our_mpc_pk = config.private.mpc_encryption_sk.public_key(&secp);
        ensure!(
            config.consensus.mpc_encryption_pks.get(identity) == Some(&our_mpc_pk),
            "This guardian's MPC encryption public key does not match the consensus configuration"
        );

        Ok(())
    }

    /// DB migrations to move from old to newer versions
    fn get_database_migrations(
        &self,
    ) -> BTreeMap<DatabaseVersion, ServerModuleDbMigrationFn<Usdt>> {
        BTreeMap::new()
    }
}

/// USDT-on-EVM module
#[derive(Debug)]
pub struct Usdt {
    pub cfg: UsdtConfig,
}

/// Implementation of consensus for the server module
#[async_trait]
impl ServerModule for Usdt {
    /// Define the consensus types
    type Common = UsdtModuleTypes;
    type Init = UsdtInit;

    async fn consensus_proposal(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<UsdtConsensusItem> {
        Vec::new()
    }

    async fn process_consensus_item<'a, 'b>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'b>,
        _consensus_item: UsdtConsensusItem,
        _peer_id: PeerId,
    ) -> anyhow::Result<()> {
        // WARNING: `process_consensus_item` should return an `Err` for items that do
        // not change any internal consensus state. Failure to do so, will result in an
        // (potentially significantly) increased consensus history size.
        bail!("The usdt module does not use consensus items yet");
    }

    async fn process_input<'a, 'b, 'c>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'c>,
        _input: &'b UsdtInput,
        _in_point: InPoint,
    ) -> Result<InputMeta, UsdtInputError> {
        Err(UsdtInputError::NotSupported)
    }

    async fn process_output<'a, 'b>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'b>,
        _output: &'a UsdtOutput,
        _out_point: OutPoint,
    ) -> Result<TransactionItemAmounts, UsdtOutputError> {
        Err(UsdtOutputError::NotSupported)
    }

    async fn output_status(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _out_point: OutPoint,
    ) -> Option<UsdtOutputOutcome> {
        None
    }

    async fn audit(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _audit: &mut Audit,
        _module_instance_id: ModuleInstanceId,
    ) {
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        vec![api_endpoint! {
            GROUP_PUBLIC_KEY_ENDPOINT,
            ApiVersion::new(0, 0),
            async |module: &Usdt, _context, _params: ()| -> secp256k1::PublicKey {
                Ok(module.cfg.consensus.group_public_key)
            }
        }]
    }
}

impl Usdt {
    /// Create new module instance
    pub fn new(cfg: UsdtConfig) -> Usdt {
        Usdt { cfg }
    }
}

#[cfg(test)]
mod tests {
    use fedimint_core::PeerId;
    use fedimint_core::bitcoin::Network;

    use super::*;

    const NUM_PEERS: u16 = 4;

    #[test]
    fn trusted_dealer_gen_produces_consistent_valid_configs() {
        let peers = (0..NUM_PEERS).map(PeerId::from).collect::<Vec<_>>();
        let args = ConfigGenModuleArgs {
            network: Network::Regtest,
            disable_base_fees: false,
        };

        let server_cfgs = UsdtInit.trusted_dealer_gen(&peers, &args);
        assert_eq!(server_cfgs.len(), usize::from(NUM_PEERS));

        let typed_cfgs = server_cfgs
            .iter()
            .map(|(peer, cfg)| {
                (
                    *peer,
                    cfg.clone()
                        .to_typed::<UsdtConfig>()
                        .expect("config was just generated by the same configgen"),
                )
            })
            .collect::<BTreeMap<_, _>>();

        let group_public_key = typed_cfgs[&peers[0]].consensus.group_public_key;
        for cfg in typed_cfgs.values() {
            assert_eq!(cfg.consensus.group_public_key, group_public_key);
            assert_eq!(cfg.consensus.threshold, 3);
            assert_eq!(
                fedimint_threshold_ecdsa::group_public_key(&cfg.private.key_share)
                    .expect("valid key share"),
                group_public_key
            );
        }

        for peer in &peers {
            UsdtInit
                .validate_config(peer, server_cfgs[peer].clone())
                .expect("dealer-generated config must validate for every peer");
        }
    }
}

/// Acceptance test for real distributed key generation (`distributed_gen`):
/// runs the actual N-party cggmp21 keygen + aux-info-gen over a hermetic
/// fake config-gen peer channel, then proves the resulting key shares are
/// genuinely usable by running one 3-of-4 threshold signature and verifying
/// it against the group key with the independent `secp256k1` crate.
#[cfg(test)]
mod distributed_gen_tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use cggmp21::ExecutionId;
    use fedimint_core::bitcoin::Network;
    use fedimint_core::{NumPeers, NumPeersExt as _, PeerId};
    use fedimint_threshold_ecdsa::Curve;
    use fedimint_threshold_ecdsa::transport::{
        EncryptedRoundCodec, drive_over_exchange, in_memory_mesh,
    };
    use rand::rngs::OsRng;
    use tokio::sync::Notify;

    use super::*;

    const N: u16 = 4;
    const T: u16 = 3;

    /// Shared state for [`FakeDkgNetwork`]: one entry per logical round
    /// (keyed by a per-peer, monotonically increasing round counter), each
    /// holding the payload every peer has submitted so far for that round.
    /// A round is complete once all `total` peers have submitted.
    struct DkgCoordinator {
        rounds: std::sync::Mutex<HashMap<u64, BTreeMap<PeerId, Vec<u8>>>>,
        notify: Notify,
        total: usize,
    }

    /// A hermetic, in-memory [`PeerHandleOps`] impl for N peers sharing one
    /// [`DkgCoordinator`]: `exchange_bytes` is an all-to-all round barrier —
    /// it submits this peer's payload for "its next round" and blocks until
    /// every peer has submitted for that same round, then returns all of
    /// them. Each `FakeDkgNetwork` tracks its own round counter, so
    /// `distributed_gen`'s sequential keygen-then-aux-gen round series (each
    /// itself many rounds) is serviced correctly without any explicit round
    /// numbering in the `exchange_bytes` API itself.
    struct FakeDkgNetwork {
        coordinator: Arc<DkgCoordinator>,
        my_peer: PeerId,
        num_peers: NumPeers,
        next_round: AtomicU64,
    }

    #[async_trait::async_trait]
    impl PeerHandleOps for FakeDkgNetwork {
        fn num_peers(&self) -> NumPeers {
            self.num_peers
        }

        async fn run_dkg_g1(
            &self,
        ) -> anyhow::Result<(Vec<bls12_381::G1Projective>, bls12_381::Scalar)> {
            unimplemented!("usdt DKG does not use run_dkg_g1")
        }

        async fn run_dkg_g2(
            &self,
        ) -> anyhow::Result<(Vec<bls12_381::G2Projective>, bls12_381::Scalar)> {
            unimplemented!("usdt DKG does not use run_dkg_g2")
        }

        async fn exchange_bytes(&self, data: Vec<u8>) -> anyhow::Result<BTreeMap<PeerId, Vec<u8>>> {
            let round = self.next_round.fetch_add(1, Ordering::SeqCst);

            {
                let mut rounds = self
                    .coordinator
                    .rounds
                    .lock()
                    .expect("coordinator mutex poisoned");
                let entry = rounds.entry(round).or_default();
                entry.insert(self.my_peer, data);
                if entry.len() == self.coordinator.total {
                    // Every peer has submitted for this round: wake everyone
                    // (including peers that haven't called `notified()` yet;
                    // see the loop below for why that is still race-free).
                    self.coordinator.notify.notify_waiters();
                }
            }

            loop {
                // Register as a waiter *before* checking the round's
                // completion, using `enable()` so a `notify_waiters()` that
                // races with our check (fired by another peer between our
                // check and our `.await` below) is not missed. Without this,
                // a peer could check the map (not yet complete), then miss
                // the one-shot `notify_waiters()` fired immediately after by
                // the peer that completes the round, and hang forever.
                let notified = self.coordinator.notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();

                {
                    let rounds = self
                        .coordinator
                        .rounds
                        .lock()
                        .expect("coordinator mutex poisoned");
                    if let Some(entry) = rounds.get(&round)
                        && entry.len() == self.coordinator.total
                    {
                        return Ok(entry.clone());
                    }
                }

                notified.await;
            }
        }
    }

    /// Runs `UsdtInit::distributed_gen` concurrently for all of `peer_ids`
    /// over a shared, hermetic [`FakeDkgNetwork`] coordinator, returning
    /// every guardian's typed config.
    async fn run_distributed_gen_for_all_peers(peer_ids: &[PeerId]) -> Vec<UsdtConfig> {
        let coordinator = Arc::new(DkgCoordinator {
            rounds: std::sync::Mutex::new(HashMap::new()),
            notify: Notify::new(),
            total: peer_ids.len(),
        });
        let args = ConfigGenModuleArgs {
            network: Network::Regtest,
            disable_base_fees: false,
        };

        let mut tasks = Vec::with_capacity(peer_ids.len());
        for &peer in peer_ids {
            let net = FakeDkgNetwork {
                coordinator: coordinator.clone(),
                my_peer: peer,
                num_peers: peer_ids.to_num_peers(),
                next_round: AtomicU64::new(0),
            };
            // This module has no other way to obtain N concurrent, `Send`
            // `distributed_gen` futures than spawning them onto the
            // multi-thread runtime: each one blocks (via `PeerHandleOps`)
            // on the others' progress, so they cannot be `.await`ed
            // sequentially on one task.
            // nosemgrep: ban-tokio-spawn
            tasks.push(tokio::spawn(async move {
                UsdtInit.distributed_gen(&net, &args).await
            }));
        }

        let mut configs = Vec::with_capacity(peer_ids.len());
        for t in tasks {
            configs.push(
                t.await
                    .expect("distributed_gen task must not panic")
                    .expect("distributed_gen must succeed")
                    .to_typed::<UsdtConfig>()
                    .expect("config was just generated by the same distributed_gen"),
            );
        }
        configs
    }

    /// Asserts every guardian's config agrees on the group key/threshold,
    /// each guardian's own key share aggregates to that group key, and each
    /// config passes `validate_config` under its own `PeerId`.
    fn assert_configs_consistent_and_valid(peer_ids: &[PeerId], configs: &[UsdtConfig]) {
        let group_public_key = configs[0].consensus.group_public_key;
        for cfg in configs {
            assert_eq!(
                cfg.consensus.group_public_key, group_public_key,
                "all guardians must agree on the DKG group public key"
            );
            assert_eq!(cfg.consensus.threshold, T);
            assert_eq!(
                fedimint_threshold_ecdsa::group_public_key(&cfg.private.key_share)
                    .expect("valid key share"),
                group_public_key,
                "each guardian's own key share must aggregate to the group key"
            );
        }

        for peer in peer_ids {
            UsdtInit
                .validate_config(peer, configs[peer.to_usize()].clone().to_erased())
                .expect("distributed_gen output must validate for every guardian");
        }
    }

    /// Runs a real `T`-of-`N` threshold signature over `shares` (a fresh
    /// mesh + fresh MPC-transport encryption keys for the signing
    /// sub-protocol, independent of the DKG's), returning the raw cggmp21
    /// signatures.
    ///
    /// cggmp21's synchronous signing state machine is `!Send` (like
    /// keygen/aux-gen; see `threshold-ecdsa`'s
    /// `keygen_and_signing_over_exchange_transport` test), so the signer
    /// tasks are scheduled cooperatively on one thread via `LocalSet`
    /// instead of `tokio::spawn`.
    async fn run_threshold_signing(
        shares: &[fedimint_threshold_ecdsa::KeyShare],
        signers: [u16; T as usize],
        digest: [u8; 32],
    ) -> Vec<cggmp21::Signature<Curve>> {
        let secp = secp256k1::Secp256k1::new();
        let signer_secret_keys: Vec<secp256k1::SecretKey> = (0..signers.len())
            .map(|i| {
                let mut bytes = [7u8; 32];
                bytes[31] = u8::try_from(i + 1).expect("fewer than 256 signers in this test");
                secp256k1::SecretKey::from_slice(&bytes).expect("valid scalar")
            })
            .collect();
        let signer_public_keys: Vec<secp256k1::PublicKey> = signer_secret_keys
            .iter()
            .map(|sk| sk.public_key(&secp))
            .collect();

        let data = cggmp21::DataToSign::from_scalar(
            cggmp21::generic_ec::Scalar::from_be_bytes_mod_order(digest),
        );
        let eid_signing = ExecutionId::new(b"usdt-server-distributed-gen-test-signing");

        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let meshes = in_memory_mesh(T);
                let mut handles = Vec::with_capacity(usize::from(T));
                for (pos, mut mesh) in meshes.into_iter().enumerate() {
                    let pos = u16::try_from(pos).expect("T fits in u16");
                    let keygen_index = signers[usize::from(pos)];
                    let codec = EncryptedRoundCodec::new(
                        pos,
                        signer_secret_keys[usize::from(pos)],
                        signer_public_keys.clone(),
                        eid_signing.as_bytes().to_vec(),
                    );
                    let share = shares[usize::from(keygen_index)].clone();
                    handles.push(tokio::task::spawn_local(async move {
                        let mut rng = OsRng;
                        let sm = cggmp21::signing(eid_signing, pos, &signers, &share)
                            .sign_sync(&mut rng, data);
                        drive_over_exchange(sm, &codec, &mut mesh).await
                    }));
                }
                let mut signatures = Vec::with_capacity(usize::from(T));
                for h in handles {
                    signatures.push(
                        h.await
                            .expect("signer task must not panic")
                            .expect("driving signing over the mesh")
                            .expect("cggmp21 signing"),
                    );
                }
                signatures
            })
            .await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn distributed_gen_produces_working_threshold_signing_key() {
        let peer_ids: Vec<PeerId> = (0..N).map(PeerId::from).collect();

        let configs = run_distributed_gen_for_all_peers(&peer_ids).await;
        assert_configs_consistent_and_valid(&peer_ids, &configs);
        let group_public_key = configs[0].consensus.group_public_key;

        // Strongest possible acceptance: prove the DKG output is genuine
        // signing material by running a real 3-of-4 threshold signature over
        // the shares and verifying it against the group key.
        let shares: Vec<fedimint_threshold_ecdsa::KeyShare> = configs
            .iter()
            .map(|cfg| cfg.private.key_share.clone())
            .collect();
        let digest: [u8; 32] = {
            use sha2::{Digest, Sha256};
            Sha256::digest(b"usdt distributed_gen acceptance test").into()
        };
        let signatures = run_threshold_signing(&shares, [0, 1, 3], digest).await;

        // Independent verification: convert the raw (r, s) scalars to the
        // workspace's canonical secp256k1 signature type (same compact +
        // normalize_s conversion `fedimint_threshold_ecdsa::run_signing`
        // uses internally) and check against the group key.
        let msg = secp256k1::Message::from_digest(digest);
        let verifier = secp256k1::Secp256k1::verification_only();
        for sig in &signatures {
            let mut compact = [0u8; 64];
            compact[..32].copy_from_slice(&sig.r.to_be_bytes());
            compact[32..].copy_from_slice(&sig.s.to_be_bytes());
            let mut ecdsa_sig = secp256k1::ecdsa::Signature::from_compact(&compact)
                .expect("cggmp21 produced a valid compact signature");
            ecdsa_sig.normalize_s();
            verifier
                .verify_ecdsa(&msg, &ecdsa_sig, &group_public_key)
                .expect(
                    "signature produced from the DKG-generated shares must verify against the DKG group key",
                );
        }
    }
}
