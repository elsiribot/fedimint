#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use std::collections::{BTreeMap, BTreeSet};
#[cfg(feature = "cli")]
use std::ffi;
use std::time::Duration;

use anyhow::{Context as _, bail};
use api::UsdtFederationApi;
use db::{ClaimKeyKey, ClaimKeyPrefixAll, DbKeyPrefix};
use fedimint_api_client::api::DynModuleApi;
use fedimint_client_module::db::ClientModuleMigrationFn;
use fedimint_client_module::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client_module::module::recovery::NoModuleBackup;
use fedimint_client_module::module::{ClientContext, ClientModule, IClientModule};
use fedimint_client_module::sm::Context;
use fedimint_client_module::transaction::{
    ClientInput, ClientInputBundle, ClientOutput, ClientOutputBundle, TransactionBuilder,
};
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
use fedimint_core::{
    Amount, OutPointRange, PeerId, apply, async_trait_maybe_send, push_db_pair_items,
};
pub use fedimint_usdt_common as common;
use fedimint_usdt_common::config::UsdtClientConfig;
use fedimint_usdt_common::{
    CheckDepositResponse, DepositStatusResponse, EvmAddress, KIND, PoolStateResponse,
    SigningSessionId, USDT_UNIT, UsdtAmount, UsdtCommonInit, UsdtInput, UsdtInputV0,
    UsdtModuleTypes, UsdtOutput, UsdtOutputV0, UserOpStatusResponse, WithdrawFeeQuoteResponse,
};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use states::UsdtStateMachine;
use strum::IntoEnumIterator;

pub mod api;
#[cfg(feature = "cli")]
mod cli;
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

/// Metadata recorded in the client's operation log for a deposit-claim or
/// withdrawal transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UsdtOperationMeta {
    Claim {
        account: EvmAddress,
        amount: UsdtAmount,
    },
    /// Phase 8, Task 1: the DEBIT/QUEUE half of a withdrawal only -- no
    /// state machine is attached (see [`UsdtClientModule::withdraw`]), so
    /// this operation log entry is not currently advanced past submission.
    /// Task 4 adds full state-machine-tracked lifecycle metadata.
    Withdraw {
        recipient: EvmAddress,
        amount: UsdtAmount,
        max_fee: UsdtAmount,
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

    // Phase 8, Task 1: `UsdtOutput::V0` (a withdrawal) now really is
    // constructed client-side (see `Self::withdraw`); its fee is exactly
    // its own `max_fee` field -- the transaction-balancing framework calls
    // this for every output in a transaction being built
    // (`Client::finalize_and_submit_transaction` sums `input_fee`/
    // `output_fee` across all modules involved to compute the primary
    // module's balancing input), and that sum must match what the server's
    // `process_output` reports back as `TransactionItemAmounts` (`amounts:
    // amount, fees: max_fee`) for the transaction to balance. Only `V0` is a
    // variant this client (or any client on this consensus version) ever
    // constructs or observes as its own; `None` for `Default` mirrors this
    // trait method's documented contract ("only happens if a future version
    // of Fedimint introduces a new output variant").
    fn output_fee(
        &self,
        _amount: &Amounts,
        output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<Amounts> {
        match output {
            UsdtOutput::V0(withdrawal) => Some(Amounts::new_custom(
                USDT_UNIT,
                Amount::from_msats(withdrawal.max_fee.0),
            )),
            UsdtOutput::Default { .. } => None,
        }
    }

    // USDT-denominated e-cash balance lives in the USDT-`mintv2` instance (the
    // primary module the client routes to for `USDT_UNIT`, see
    // `Client::primary_module_for_unit`), not in this module's own database, so
    // this module's own balance stays zero for every unit.
    async fn get_balance(&self, _dbtx: &mut DatabaseTransaction<'_>, _unit: AmountUnit) -> Amount {
        Amount::ZERO
    }

    #[cfg(feature = "cli")]
    async fn handle_cli_command(
        &self,
        args: &[ffi::OsString],
    ) -> anyhow::Result<serde_json::Value> {
        cli::handle_cli_command(self, args).await
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

    /// Enqueues this guardian's local deposit-checker task to start watching
    /// `claim_pk`'s deposit address (thin wrapper around the federation API
    /// call; see [`UsdtFederationApi::check_deposit`]).
    pub async fn check_deposit(
        &self,
        claim_pk: secp256k1::PublicKey,
    ) -> anyhow::Result<CheckDepositResponse> {
        Ok(self.module_api.check_deposit(claim_pk).await?)
    }

    /// Reports the credited/claimed/claimable state of `claim_pk`'s deposit
    /// account (thin wrapper around the federation API call; see
    /// [`UsdtFederationApi::deposit_status`]).
    pub async fn deposit_status(
        &self,
        claim_pk: secp256k1::PublicKey,
    ) -> anyhow::Result<DepositStatusResponse> {
        Ok(self.module_api.deposit_status(claim_pk).await?)
    }

    /// This federation's peer ids, for callers (e.g. `signing_session_status`
    /// pollers) that need to iterate over every guardian individually rather
    /// than going through a threshold-agreed `request_current_consensus`
    /// call.
    #[must_use]
    pub fn all_peers(&self) -> BTreeSet<PeerId> {
        self.module_api.all_peers().clone()
    }

    /// Test-only (Phase 6a acceptance): triggers a threshold-ECDSA signing
    /// session for `digest` over the whole federation by queueing it on a
    /// single, arbitrary guardian (thin wrapper around
    /// [`UsdtFederationApi::debug_start_signing`]; see that trait method's
    /// doc comment for why calling just one guardian is enough).
    pub async fn debug_start_signing(&self, digest: [u8; 32]) -> anyhow::Result<()> {
        let peer = *self
            .module_api
            .all_peers()
            .iter()
            .next()
            .context("federation has no peers")?;
        Ok(self.module_api.debug_start_signing(peer, digest).await?)
    }

    /// Queries `peer`'s in-memory view of `session_id`'s outcome (thin
    /// wrapper around [`UsdtFederationApi::signing_session_status`]; see
    /// that trait method's doc comment for why the caller must poll across
    /// peers rather than trusting a single response).
    pub async fn signing_session_status(
        &self,
        peer: PeerId,
        session_id: SigningSessionId,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(self
            .module_api
            .signing_session_status(peer, session_id)
            .await?)
    }

    /// Test-only (Phase 6b Task 4 degraded-federation acceptance harness):
    /// toggles `peer`'s local suppression of `MpcRound` proposals for
    /// attempt-0 signing sessions (thin wrapper around
    /// [`UsdtFederationApi::debug_suppress_attempt0_round`]; see that trait
    /// method's doc comment).
    pub async fn debug_suppress_attempt0_round(
        &self,
        peer: PeerId,
        suppress: bool,
    ) -> anyhow::Result<()> {
        Ok(self
            .module_api
            .debug_suppress_attempt0_round(peer, suppress)
            .await?)
    }

    /// Reports `peer`'s consensus view of the pool `SimpleAccount`'s
    /// derived address and swept-in USDT balance (thin wrapper around
    /// [`UsdtFederationApi::pool_state`]; Phase 7, Task 5 diagnostic).
    pub async fn pool_state(&self, peer: PeerId) -> anyhow::Result<PoolStateResponse> {
        Ok(self.module_api.pool_state(peer).await?)
    }

    /// Reports `peer`'s consensus view of a `UserOp`'s lifecycle stage
    /// (thin wrapper around [`UsdtFederationApi::userop_status`]; Phase 7,
    /// Task 5 diagnostic).
    pub async fn userop_status(
        &self,
        peer: PeerId,
        op_hash: [u8; 32],
    ) -> anyhow::Result<UserOpStatusResponse> {
        Ok(self.module_api.userop_status(peer, op_hash).await?)
    }

    /// Looks up the claim keypair persisted by [`Self::allocate_deposit`] for
    /// `claim_pk`'s derived deposit account.
    async fn load_claim_keypair(
        &self,
        claim_pk: &secp256k1::PublicKey,
    ) -> anyhow::Result<(EvmAddress, Keypair)> {
        let account = self.deposit_address(claim_pk);

        let mut dbtx = self.db.begin_transaction_nc().await;
        let claim_keypair = dbtx
            .get_value(&ClaimKeyKey(account))
            .await
            .context("No claim key found for this deposit address; run `deposit-address` first")?;

        Ok((account, claim_keypair))
    }

    /// One-shot claim for `claim_pk`'s deposit account: reads the current
    /// [`Self::deposit_status`] (no polling, unlike [`Self::check_and_claim`])
    /// and, if there is a nonzero claimable balance, submits the claim
    /// transaction using the keypair [`Self::allocate_deposit`] persisted for
    /// `claim_pk`. Returns the claimed amount.
    ///
    /// Callers should have already called [`Self::check_deposit`] (to enqueue
    /// the deposit-checker task) and waited for the federation to observe and
    /// credit the on-chain transfer; use [`Self::deposit_status`] to poll for
    /// that.
    pub async fn claim(&self, claim_pk: secp256k1::PublicKey) -> anyhow::Result<UsdtAmount> {
        let (account, claim_keypair) = self.load_claim_keypair(&claim_pk).await?;
        let status = self.module_api.deposit_status(claim_pk).await?;

        if status.claimable.0 == 0 {
            bail!(
                "Nothing claimable yet for {account} (credited={}, claimed={}); \
                 run `check-deposit` and wait for the deposit checker, or poll `deposit-status`",
                status.credited.0,
                status.claimed.0,
            );
        }

        self.submit_claim(&claim_keypair, account, status.claimable)
            .await?;

        Ok(status.claimable)
    }

    /// Asks the federation to start watching `claim_keypair`'s deposit
    /// address, polls until a credited deposit becomes claimable (or
    /// `deadline` elapses), then submits a fedimint transaction claiming it.
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
                    "Deposit to {} was not claimable before the deadline",
                    checked.account,
                );
            }

            sleep(backoff).await;
            backoff = (backoff * 2).min(CHECK_AND_CLAIM_MAX_BACKOFF);
        };

        self.submit_claim(claim_keypair, account, claimable).await
    }

    /// Builds and submits the transaction claiming `amount` from `account`,
    /// funding it with `claim_keypair`. Shared by [`Self::check_and_claim`]
    /// (which polls until an amount is claimable) and [`Self::claim`] (which
    /// takes a single already-known claimable amount).
    ///
    /// The claimed funds are absorbed directly into the transaction's
    /// implicit funding, which the USDT-`mintv2` primary module (routed to by
    /// `USDT_UNIT`) balances by minting e-cash notes; no explicit output is
    /// added here.
    async fn submit_claim(
        &self,
        claim_keypair: &Keypair,
        account: EvmAddress,
        amount: UsdtAmount,
    ) -> anyhow::Result<()> {
        let input = ClientInput {
            input: UsdtInput::V0(UsdtInputV0 { account, amount }),
            keys: vec![*claim_keypair],
            amounts: Amounts::new_custom(USDT_UNIT, Amount::from_msats(amount.0)),
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
                move |_range| UsdtOperationMeta::Claim { account, amount },
                tx,
            )
            .await?;

        Ok(())
    }

    /// Reports the federation's current withdrawal fee quote: the minimum
    /// `max_fee` a `withdraw` of `amount` must offer right now (Phase 8,
    /// Task 1). Thin wrapper around [`UsdtFederationApi::withdraw_fee_quote`]
    /// (threshold-agreement -- every guardian answers identically, since the
    /// quote is derived from consensus DB).
    pub async fn withdraw_fee_quote(
        &self,
        amount: UsdtAmount,
    ) -> anyhow::Result<WithdrawFeeQuoteResponse> {
        Ok(self.module_api.withdraw_fee_quote(amount).await?)
    }

    /// Submits a withdrawal output transaction, burning `amount + max_fee`
    /// of `USDT_UNIT`-denominated e-cash (auto-funded from the USDT-`mintv2`
    /// primary module's existing notes, mirroring [`Self::submit_claim`]'s
    /// implicit-funding pattern but on the output side) and enqueueing an
    /// on-chain payout of `amount` to `recipient` (Phase 8, Task 1's
    /// DEBIT/QUEUE half; Task 2 batches queued withdrawals into an
    /// MPC-signed `UserOp`).
    ///
    /// Callers are responsible for choosing `max_fee` (typically from
    /// [`Self::withdraw_fee_quote`]) -- the server's `process_output`
    /// rejects the output if `max_fee` is below its own fresh fee-vote-
    /// median-derived quote at the point the transaction is processed.
    ///
    /// No state machine is attached to the output
    /// (`ClientOutputBundle::new_no_sm`): nothing here tracks the
    /// withdrawal's lifecycle client-side past submission yet -- poll the
    /// server's `output_status` endpoint (`Some` once queued) in the
    /// meantime. Task 4 adds a full state-machine-tracked operation
    /// (Queued -> Signing -> Submitted -> Confirmed/Failed), a
    /// `withdraw_fee_quote`-driven default `max_fee`, and `fedimint-cli`
    /// wiring; this is deliberately minimal scaffolding so Phase 8's
    /// server-side debit/queue/fee-median logic (this task) can be
    /// exercised end to end over a real transaction.
    pub async fn withdraw(
        &self,
        recipient: EvmAddress,
        amount: UsdtAmount,
        max_fee: UsdtAmount,
    ) -> anyhow::Result<OutPointRange> {
        let output = ClientOutputBundle::new_no_sm(vec![ClientOutput {
            output: UsdtOutput::V0(UsdtOutputV0 {
                recipient,
                amount,
                max_fee,
            }),
            amounts: Amounts::new_custom(USDT_UNIT, Amount::from_msats(amount.0)),
        }]);
        let output = self.client_ctx.make_client_outputs(output);

        let operation_id = OperationId::new_random();
        let tx = TransactionBuilder::new().with_outputs(output);

        let range = self
            .client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                KIND.as_str(),
                move |_range| UsdtOperationMeta::Withdraw {
                    recipient,
                    amount,
                    max_fee,
                },
                tx,
            )
            .await?;

        Ok(range)
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
