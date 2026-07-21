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
use db::{
    ClaimKeyKey, ClaimKeyPrefixAll, DbKeyPrefix, NextDepositIndexKey, NextDepositIndexPrefixAll,
};
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
use fedimint_core::secp256k1::{self, Keypair, SECP256K1};
use fedimint_core::{
    Amount, OutPoint, OutPointRange, PeerId, apply, async_trait_maybe_send, push_db_pair_items,
};
use fedimint_derive_secret::{ChildId, DerivableSecret};
pub use fedimint_usdt_common as common;
use fedimint_usdt_common::config::UsdtClientConfig;
use fedimint_usdt_common::{
    CheckDepositResponse, DepositStatusResponse, EvmAddress, KIND, PoolStateResponse,
    SigningSessionId, USDT_UNIT, UsdtAmount, UsdtCommonInit, UsdtInput, UsdtInputV0,
    UsdtModuleTypes, UsdtOutput, UsdtOutputV0, UserOpStatusResponse, WithdrawFeeQuoteResponse,
    WithdrawalStatus, WithdrawalStatusResponse,
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

/// Cap on the exponential backoff
/// [`UsdtClientModule::await_withdrawal_confirmed`] waits between
/// `withdrawal_status` polls, mirroring [`CHECK_AND_CLAIM_MAX_BACKOFF`].
const AWAIT_WITHDRAWAL_CONFIRMED_MAX_BACKOFF: Duration = Duration::from_secs(5);

/// Namespaces deposit claim keys under the module root secret: every deposit
/// claim key is derived as `module_root_secret.child_key(
/// DEPOSIT_CLAIM_KEY_CHILD).child_key(ChildId(index))` (see
/// [`UsdtClientModule::claim_keypair_for_index`]). Distinguishing this from any
/// future key type derived from the same module root secret.
const DEPOSIT_CLAIM_KEY_CHILD: ChildId = ChildId(0);

#[derive(Debug)]
pub struct UsdtClientModule {
    cfg: UsdtClientConfig,
    client_ctx: ClientContext<Self>,
    db: Database,
    module_api: DynModuleApi,
    /// This module's root secret, from which all deposit claim keys are
    /// deterministically derived (see
    /// [`Self::claim_keypair_for_index`]). Persisting nothing but an index in
    /// the client DB makes deposits seed-recoverable via
    /// [`Self::recover_deposits`].
    module_root_secret: DerivableSecret,
}

/// Summary returned by [`UsdtClientModule::recover_deposits`]: the deposit
/// claim keys a seed-only rescan of the federation rediscovered, restored into
/// the client DB.
#[derive(Debug, Clone, Serialize)]
pub struct RecoverySummary {
    /// Number of deposit accounts rediscovered (indices the federation reports
    /// as having been credited).
    pub recovered: usize,
    /// Sum of `credited` across every rediscovered account.
    pub total_credited: UsdtAmount,
    /// Sum of `claimable` (i.e. `credited - claimed`) across every
    /// rediscovered account -- what a follow-up `claim` per account can still
    /// pull into e-cash.
    pub total_claimable: UsdtAmount,
    /// One entry per rediscovered account.
    pub accounts: Vec<RecoveredAccount>,
}

/// A single deposit account rediscovered by
/// [`UsdtClientModule::recover_deposits`].
#[derive(Debug, Clone, Serialize)]
pub struct RecoveredAccount {
    /// The seed-derivation index this account's claim key lives at.
    pub index: u64,
    /// The derived deposit account (EVM address) the federation watches.
    pub account: EvmAddress,
    /// The public key of the (re-derived, re-stored) claim keypair.
    pub claim_pk: secp256k1::PublicKey,
    /// USDT the federation has credited to this account so far.
    pub credited: UsdtAmount,
    /// USDT still claimable (`credited - claimed`) on this account.
    pub claimable: UsdtAmount,
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

    /// The deterministic claim keypair for seed-derivation `index`, derived
    /// purely from `module_root_secret` (see [`DEPOSIT_CLAIM_KEY_CHILD`]).
    ///
    /// Deterministic: the same module root secret and `index` always yield the
    /// same keypair, and distinct indices yield distinct keypairs. This is what
    /// makes deposits seed-recoverable -- [`Self::recover_deposits`] walks the
    /// indices from `0` and re-derives each key without touching the client DB.
    #[must_use]
    fn claim_keypair_static(module_root_secret: &DerivableSecret, index: u64) -> Keypair {
        module_root_secret
            .child_key(DEPOSIT_CLAIM_KEY_CHILD)
            .child_key(ChildId(index))
            .to_secp_key(SECP256K1)
    }

    /// The deterministic claim keypair for seed-derivation `index` under this
    /// module's root secret (see [`Self::claim_keypair_static`]).
    #[must_use]
    fn claim_keypair_for_index(&self, index: u64) -> Keypair {
        Self::claim_keypair_static(&self.module_root_secret, index)
    }

    /// Derives the next seed-indexed claim keypair, persists it keyed by its
    /// derived deposit address, and returns both so the caller can hand the
    /// address out and later drive [`Self::check_and_claim`] with the keypair.
    ///
    /// The claim key is deterministic from the module root secret and a
    /// monotonically-increasing per-deposit index (persisted as
    /// [`NextDepositIndexKey`]), so a deposit is recoverable from the seed
    /// alone even if the client DB is lost: [`Self::recover_deposits`] rescans
    /// the federation by index and re-derives the same keys.
    pub async fn allocate_deposit(&self) -> anyhow::Result<(Keypair, EvmAddress)> {
        let mut dbtx = self.db.begin_transaction().await;

        let index = dbtx
            .get_value(&NextDepositIndexKey)
            .await
            .unwrap_or_default();
        let claim_keypair = self.claim_keypair_for_index(index);
        let account = self.deposit_address(&claim_keypair.public_key());

        dbtx.insert_entry(&NextDepositIndexKey, &(index + 1)).await;
        dbtx.insert_entry(&ClaimKeyKey(account), &claim_keypair)
            .await;
        dbtx.commit_tx().await;

        Ok((claim_keypair, account))
    }

    /// Rescans the federation from the seed alone to rediscover deposits whose
    /// client-DB state was lost, re-storing each rediscovered claim key so the
    /// existing [`Self::claim`]/[`Self::check_and_claim`] path can then be run
    /// per account.
    ///
    /// Gap-limit scan: walks seed-derivation indices from `0`, deriving
    /// [`Self::claim_keypair_for_index`] and querying the federation's
    /// `deposit_status` for each. An index whose account has been credited
    /// (`credited > 0`) is treated as used -- its claim key is re-stored
    /// ([`ClaimKeyKey`]) and recorded -- and resets the consecutive-miss
    /// counter; an uncredited index increments it. The scan stops after
    /// `gap_limit` consecutive misses.
    ///
    /// After scanning, [`NextDepositIndexKey`] is advanced to one past the
    /// highest used index seen, so future [`Self::allocate_deposit`] calls do
    /// not collide with recovered deposits (left untouched if none were found).
    ///
    /// This does NOT auto-claim: recovery is deliberately read-mostly plus
    /// key-restoring, so the caller decides when to run [`Self::claim`] per
    /// account with a nonzero `claimable`. This explicit rescan (plus its CLI
    /// `recover` subcommand) is the module's recovery path; the module uses
    /// [`NoModuleBackup`], so it is not wired into the client's global
    /// `recover()` flow -- doing so is a possible follow-up.
    pub async fn recover_deposits(&self, gap_limit: u64) -> anyhow::Result<RecoverySummary> {
        let mut accounts = Vec::new();
        let mut total_credited = UsdtAmount(0);
        let mut total_claimable = UsdtAmount(0);
        let mut highest_used_index: Option<u64> = None;
        let mut consecutive_misses = 0u64;

        let mut index = 0u64;
        while consecutive_misses < gap_limit {
            let claim_keypair = self.claim_keypair_for_index(index);
            let claim_pk = claim_keypair.public_key();
            let status = self.module_api.deposit_status(claim_pk).await?;

            if status.credited.0 > 0 {
                let mut dbtx = self.db.begin_transaction().await;
                dbtx.insert_entry(&ClaimKeyKey(status.account), &claim_keypair)
                    .await;
                dbtx.commit_tx().await;

                total_credited.0 = total_credited.0.saturating_add(status.credited.0);
                total_claimable.0 = total_claimable.0.saturating_add(status.claimable.0);
                accounts.push(RecoveredAccount {
                    index,
                    account: status.account,
                    claim_pk,
                    credited: status.credited,
                    claimable: status.claimable,
                });

                highest_used_index = Some(index);
                consecutive_misses = 0;
            } else {
                consecutive_misses += 1;
            }

            index += 1;
        }

        if let Some(highest) = highest_used_index {
            let mut dbtx = self.db.begin_transaction().await;
            dbtx.insert_entry(&NextDepositIndexKey, &(highest + 1))
                .await;
            dbtx.commit_tx().await;
        }

        Ok(RecoverySummary {
            recovered: accounts.len(),
            total_credited,
            total_claimable,
            accounts,
        })
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

    /// The `OutPoint` of the withdrawal output enqueued by a call to
    /// [`Self::withdraw`], given the `OutPointRange` it returned (Phase 8,
    /// Task 3). The withdrawal output is always at `out_idx` 0 of `range`'s
    /// `txid` (see [`Self::withdraw`]'s doc comment for why: it is the sole
    /// output added there, before the primary module appends its mint-change
    /// outputs). Pass the result to [`Self::withdrawal_status`] or
    /// [`Self::await_withdrawal_confirmed`] to track the withdrawal.
    #[must_use]
    pub fn withdrawal_out_point(range: &OutPointRange) -> OutPoint {
        OutPoint {
            txid: range.txid(),
            out_idx: 0,
        }
    }

    /// Reports `out_point`'s consensus-agreed withdrawal lifecycle stage
    /// (thin wrapper around [`UsdtFederationApi::withdrawal_status`]; Phase
    /// 8, Task 3). See [`Self::withdrawal_out_point`] for how to derive
    /// `out_point` from [`Self::withdraw`]'s return value.
    pub async fn withdrawal_status(
        &self,
        out_point: OutPoint,
    ) -> anyhow::Result<WithdrawalStatusResponse> {
        Ok(self.module_api.withdrawal_status(out_point).await?)
    }

    /// Polls [`Self::withdrawal_status`] until `out_point` reaches a
    /// terminal state (`Confirmed`/`Failed`) or `deadline` elapses,
    /// mirroring [`Self::check_and_claim`]'s exponential-backoff polling
    /// loop. Returns the confirmed block on success; `Err` on `Failed`, an
    /// elapsed deadline, or an API error.
    pub async fn await_withdrawal_confirmed(
        &self,
        out_point: OutPoint,
        deadline: Duration,
    ) -> anyhow::Result<u64> {
        let deadline_at = Instant::now() + deadline;
        let mut backoff = Duration::from_millis(250);

        loop {
            match self.module_api.withdrawal_status(out_point).await?.status {
                WithdrawalStatus::Confirmed { block } => return Ok(block),
                WithdrawalStatus::Failed { reason } => {
                    bail!("withdrawal {out_point} failed: {reason}");
                }
                WithdrawalStatus::Unknown
                | WithdrawalStatus::Queued
                | WithdrawalStatus::Signing { .. }
                | WithdrawalStatus::Submitted { .. } => {}
            }

            if Instant::now() >= deadline_at {
                bail!("withdrawal {out_point} was not confirmed before the deadline");
            }

            sleep(backoff).await;
            backoff = (backoff * 2).min(AWAIT_WITHDRAWAL_CONFIRMED_MAX_BACKOFF);
        }
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
    ///
    /// Before returning, this awaits the withdrawal transaction being
    /// accepted into consensus -- both guaranteeing the server-side
    /// `process_output` has run (so the withdrawal's server-side state
    /// exists) by the time this returns, and surfacing a consensus-level
    /// rejection (e.g. a stale `max_fee` below the fee-vote-median quote at
    /// processing time) as an `Err` rather than a silently successful `Ok`.
    /// This uses the same proven `transaction_updates(..).await_tx_accepted`
    /// pattern as e.g. `fedimint-ln-client` / `fedimint-wallet-client`.
    ///
    /// It does NOT additionally await the transaction's mint-change
    /// reissuance settling back into the client's spendable balance: callers
    /// issuing withdrawals back-to-back should poll their own
    /// `USDT_UNIT` balance (`Client::get_balance_for_unit`) down to the
    /// expected post-burn value between calls, so the next withdrawal's
    /// implicit funding sees the reissued change (the USDT-`mintv2` primary
    /// module funds each withdrawal by spending notes and reissuing change
    /// asynchronously). This mirrors this module's own claim path
    /// (`submit_claim`), which likewise submits and lets the caller poll for
    /// the effect rather than blocking on the primary module's output state
    /// machines here.
    ///
    /// Returns the `OutPointRange` of the transaction's mint-change outputs
    /// (empty if the funding was exact). The withdrawal output itself is
    /// always at `out_idx` 0 of the returned range's `txid` (it is the sole
    /// output added here, before the primary module appends its change), so
    /// its `OutPoint` is `OutPoint { txid: range.txid(), out_idx: 0 }`.
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

        // Await consensus acceptance of the withdrawal tx: this both
        // guarantees `process_output` has run (so the server-side
        // `WithdrawalState` exists) and turns a consensus-level rejection
        // (e.g. a stale `max_fee`) into an `Err` instead of a silently
        // successful return.
        self.client_ctx
            .transaction_updates(operation_id)
            .await
            .await_tx_accepted(range.txid())
            .await
            .map_err(|err| anyhow::anyhow!("withdrawal transaction was rejected: {err}"))?;

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
                DbKeyPrefix::NextDepositIndex => {
                    push_db_pair_items!(
                        dbtx,
                        NextDepositIndexPrefixAll,
                        NextDepositIndexKey,
                        u64,
                        items,
                        "Usdt Next Deposit Index"
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
            module_root_secret: args.module_root_secret().clone(),
        })
    }

    fn get_database_migrations(&self) -> BTreeMap<DatabaseVersion, ClientModuleMigrationFn> {
        BTreeMap::new()
    }
}

#[cfg(test)]
mod tests {
    use fedimint_derive_secret::DerivableSecret;

    use super::UsdtClientModule;

    /// The deposit claim-key derivation must be deterministic from the seed:
    /// the same module root secret and index always yields the same key, and
    /// distinct indices yield distinct keys. This is the invariant
    /// [`UsdtClientModule::recover_deposits`] relies on to rediscover deposits
    /// from the seed alone.
    #[test]
    fn claim_keypair_is_deterministic_from_seed() {
        let secret = DerivableSecret::new_root(b"usdt-recovery-test-seed", b"salt");

        // Same secret + same index => identical key.
        for index in [0u64, 1, 2, 7, 100, u64::MAX] {
            let a = UsdtClientModule::claim_keypair_static(&secret, index);
            let b = UsdtClientModule::claim_keypair_static(&secret, index);
            assert_eq!(
                a, b,
                "claim key for index {index} must be reproducible from the seed"
            );
        }

        // Distinct indices => distinct keys.
        let keys: Vec<_> = (0..16u64)
            .map(|index| UsdtClientModule::claim_keypair_static(&secret, index).public_key())
            .collect();
        for (i, ki) in keys.iter().enumerate() {
            for (j, kj) in keys.iter().enumerate() {
                if i != j {
                    assert_ne!(
                        ki, kj,
                        "indices {i} and {j} must derive distinct claim keys"
                    );
                }
            }
        }

        // A different root secret => a different key at the same index.
        let other = DerivableSecret::new_root(b"a-different-seed", b"salt");
        assert_ne!(
            UsdtClientModule::claim_keypair_static(&secret, 0),
            UsdtClientModule::claim_keypair_static(&other, 0),
            "a different seed must derive a different claim key"
        );
    }
}
