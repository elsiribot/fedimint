#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::bail;
use api::UsdtFederationApi;
use db::{ClaimKeyKey, ClaimKeyPrefixAll, DbKeyPrefix};
use fedimint_api_client::api::DynModuleApi;
use fedimint_client_module::db::ClientModuleMigrationFn;
use fedimint_client_module::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client_module::module::recovery::NoModuleBackup;
use fedimint_client_module::module::{ClientContext, ClientModule, IClientModule};
use fedimint_client_module::sm::Context;
use fedimint_client_module::transaction::{ClientInput, ClientInputBundle, TransactionBuilder};
use fedimint_core::core::{Decoder, ModuleKind, OperationId};
use fedimint_core::db::{
    Database, DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::module::{
    AmountUnit, Amounts, ApiVersion, ModuleCommon, ModuleInit, MultiApiVersion,
};
use fedimint_core::runtime::{Instant, sleep};
use fedimint_core::secp256k1::rand::thread_rng;
use fedimint_core::secp256k1::{self, Keypair};
use fedimint_core::{Amount, apply, async_trait_maybe_send, push_db_pair_items};
pub use fedimint_usdt_common as common;
use fedimint_usdt_common::config::UsdtClientConfig;
use fedimint_usdt_common::{
    EvmAddress, KIND, USDT_UNIT, UsdtAmount, UsdtCommonInit, UsdtInput, UsdtInputV0,
    UsdtModuleTypes,
};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use states::UsdtStateMachine;
use strum::IntoEnumIterator;

pub mod api;
pub mod db;
pub mod states;

/// Cap on the exponential backoff [`UsdtClientModule::check_and_claim`] waits
/// between `deposit_status` polls.
const CHECK_AND_CLAIM_MAX_BACKOFF: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub struct UsdtClientModule {
    cfg: UsdtClientConfig,
    client_ctx: ClientContext<Self>,
    db: Database,
    module_api: DynModuleApi,
}

/// Data needed by the state machine
#[derive(Debug, Clone)]
pub struct UsdtClientContext {
    pub usdt_decoder: Decoder,
}

// TODO: Boiler-plate
impl Context for UsdtClientContext {
    const KIND: Option<ModuleKind> = None;
}

/// Metadata recorded in the client's operation log for a deposit-claim
/// transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UsdtOperationMeta {
    Claim {
        account: EvmAddress,
        amount: UsdtAmount,
    },
}

#[apply(async_trait_maybe_send!)]
impl ClientModule for UsdtClientModule {
    type Init = UsdtClientInit;
    type Common = UsdtModuleTypes;
    type Backup = NoModuleBackup;
    type ModuleStateMachineContext = UsdtClientContext;
    type States = UsdtStateMachine;

    fn context(&self) -> Self::ModuleStateMachineContext {
        UsdtClientContext {
            usdt_decoder: self.decoder(),
        }
    }

    // The usdt module charges no client-side fee on claim inputs (mirroring
    // the server's `process_input`, which always returns `fees:
    // Amounts::ZERO`): the transaction-balancing framework calls this for
    // every input in a transaction being built (`Client::finalize_and_submit_
    // transaction` sums `input_fee`/`output_fee` across all modules involved
    // to compute the primary module's balancing output), not only when this
    // module happens to be the primary one, so it must return `Some` for the
    // only real input variant (`UsdtInput::V0`) rather than `unreachable!()`.
    fn input_fee(
        &self,
        _amount: &Amounts,
        _input: &<Self::Common as ModuleCommon>::Input,
    ) -> Option<Amounts> {
        Some(Amounts::ZERO)
    }

    // This module never constructs a `UsdtOutput` client-side (the server's
    // `process_output` unconditionally returns `UsdtOutputError::
    // NotSupported`), so this is never called in practice; `unreachable!()`
    // documents that invariant rather than guessing at a fee for a variant
    // that can't occur.
    fn output_fee(
        &self,
        _amount: &Amounts,
        _output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<Amounts> {
        unreachable!()
    }

    // USDT-denominated e-cash balance lives in the USDT-`mintv2` instance (the
    // primary module the client routes to for `USDT_UNIT`, see
    // `Client::primary_module_for_unit`), not in this module's own database, so
    // this module's own balance stays zero for every unit.
    async fn get_balance(&self, _dbtx: &mut DatabaseTransaction<'_>, _unit: AmountUnit) -> Amount {
        Amount::ZERO
    }
}

impl UsdtClientModule {
    /// The deposit address this federation watches for `claim_pubkey`.
    ///
    /// PROVISIONAL (Phase 5): detection-only; signing custody reconciled in
    /// Phase 7.
    #[must_use]
    pub fn deposit_address(&self, claim_pubkey: &secp256k1::PublicKey) -> EvmAddress {
        fedimint_usdt_common::config::derive_deposit_account(&self.cfg, claim_pubkey)
    }

    /// Generates a fresh claim keypair, persists it keyed by its derived
    /// deposit address, and returns both so the caller can hand the address
    /// out and later drive [`Self::check_and_claim`] with the keypair.
    pub async fn allocate_deposit(&self) -> anyhow::Result<(Keypair, EvmAddress)> {
        // Phase 9: deterministic-from-seed derivation for recovery; Phase 5 stores a
        // random per-deposit key.
        let claim_keypair = Keypair::new(secp256k1::SECP256K1, &mut thread_rng());
        let account = self.deposit_address(&claim_keypair.public_key());

        let mut dbtx = self.db.begin_transaction().await;
        dbtx.insert_entry(&ClaimKeyKey(account), &claim_keypair)
            .await;
        dbtx.commit_tx().await;

        Ok((claim_keypair, account))
    }

    /// Asks the federation to start watching `claim_keypair`'s deposit
    /// address, polls until a credited deposit becomes claimable (or
    /// `deadline` elapses), then submits a fedimint transaction claiming it.
    ///
    /// The claimed funds are absorbed directly into the transaction's
    /// implicit funding, which the USDT-`mintv2` primary module (routed to by
    /// `USDT_UNIT`) balances by minting e-cash notes; no explicit output is
    /// added here.
    pub async fn check_and_claim(
        &self,
        claim_keypair: &Keypair,
        deadline: Duration,
    ) -> anyhow::Result<()> {
        let claim_pk = claim_keypair.public_key();

        // Enqueues this guardian's local deposit-checker task; the derived account
        // is deterministic, so it does not matter which guardian's response we use
        // here.
        let checked = self.module_api.check_deposit(claim_pk).await?;

        let deadline_at = Instant::now() + deadline;
        let mut backoff = Duration::from_millis(250);

        let (account, claimable) = loop {
            let status = self.module_api.deposit_status(claim_pk).await?;

            if status.claimable.0 > 0 {
                break (status.account, status.claimable);
            }

            if Instant::now() >= deadline_at {
                bail!(
                    "Deposit to {} was not claimable before the deadline (enqueued={})",
                    checked.account,
                    checked.enqueued
                );
            }

            sleep(backoff).await;
            backoff = (backoff * 2).min(CHECK_AND_CLAIM_MAX_BACKOFF);
        };

        let input = ClientInput {
            input: UsdtInput::V0(UsdtInputV0 {
                account,
                amount: claimable,
            }),
            keys: vec![*claim_keypair],
            amounts: Amounts::new_custom(USDT_UNIT, Amount::from_msats(claimable.0)),
        };

        let operation_id = OperationId::new_random();
        let tx = TransactionBuilder::new().with_inputs(
            self.client_ctx
                .make_client_inputs(ClientInputBundle::new_no_sm(vec![input])),
        );

        self.client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                KIND.as_str(),
                move |_range| UsdtOperationMeta::Claim {
                    account,
                    amount: claimable,
                },
                tx,
            )
            .await?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct UsdtClientInit;

// TODO: Boilerplate-code
impl ModuleInit for UsdtClientInit {
    type Common = UsdtCommonInit;

    async fn dump_database(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        let mut items: BTreeMap<String, Box<dyn erased_serde::Serialize + Send>> = BTreeMap::new();
        let filtered_prefixes = DbKeyPrefix::iter().filter(|f| {
            prefix_names.is_empty() || prefix_names.contains(&f.to_string().to_lowercase())
        });

        for table in filtered_prefixes {
            match table {
                DbKeyPrefix::ClaimKey => {
                    push_db_pair_items!(
                        dbtx,
                        ClaimKeyPrefixAll,
                        ClaimKeyKey,
                        Keypair,
                        items,
                        "Usdt Claim Keys"
                    );
                }
            }
        }

        Box::new(items.into_iter())
    }
}

/// Generates the client module
#[apply(async_trait_maybe_send!)]
impl ClientModuleInit for UsdtClientInit {
    type Module = UsdtClientModule;

    fn supported_api_versions(&self) -> MultiApiVersion {
        MultiApiVersion::try_from_iter([ApiVersion { major: 0, minor: 0 }])
            .expect("no version conflicts")
    }

    async fn init(&self, args: &ClientModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        Ok(UsdtClientModule {
            cfg: args.cfg().clone(),
            client_ctx: args.context(),
            db: args.db().clone(),
            module_api: args.module_api().clone(),
        })
    }

    fn get_database_migrations(&self) -> BTreeMap<DatabaseVersion, ClientModuleMigrationFn> {
        BTreeMap::new()
    }
}
