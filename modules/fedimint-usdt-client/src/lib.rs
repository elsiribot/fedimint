#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use std::collections::{BTreeMap, BTreeSet};
#[cfg(feature = "cli")]
use std::ffi;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, bail};
use api::UsdtFederationApi;
use db::{
    ClaimKeyKey, ClaimKeyPrefixAll, DbKeyPrefix, NextDepositIndexKey, NextDepositIndexPrefixAll,
    NextRefundIndexKey, NextRefundIndexPrefixAll, RefundKeyKey, RefundKeyPrefixAll,
};
use fedimint_api_client::api::DynModuleApi;
use fedimint_client_module::db::ClientModuleMigrationFn;
use fedimint_client_module::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client_module::module::recovery::NoModuleBackup;
use fedimint_client_module::module::{ClientContext, ClientModule, IClientModule};
use fedimint_client_module::sm::Context;
use fedimint_client_module::transaction::{
    ClientInput, ClientInputBundle, ClientOutput, ClientOutputBundle, ClientOutputSM,
    TransactionBuilder,
};
use fedimint_core::core::{Decoder, ModuleKind, OperationId};
use fedimint_core::db::{
    AutocommitError, Database, DatabaseTransaction, DatabaseVersion,
    IDatabaseTransactionOpsCoreTyped,
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
    BootstrapState, CheckDepositResponse, DepositFeeQuoteResponse, DepositStatusResponse,
    EvmAddress, KIND, PoolStateResponse, RefundStatusResponse, StatusResponse, USDT_UNIT,
    UsdtAmount, UsdtCommonInit, UsdtInput, UsdtInputV0, UsdtModuleTypes, UsdtOutput, UsdtOutputV0,
    UserOpStatusResponse, WithdrawFeeQuoteResponse, WithdrawalStatus, WithdrawalStatusResponse,
    usdt_amount,
};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use states::{UsdtStateMachine, WithdrawalRefundCommon, WithdrawalRefundState};
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
/// [`UsdtClientModule::claim_keypair_for_index`]). This distinguishes deposit
/// claim keys from any future key type derived from the same module root
/// secret.
const DEPOSIT_CLAIM_KEY_CHILD: ChildId = ChildId(0);

/// Namespaces withdrawal refund keys under the module root secret (security
/// finding 09): every refund key is derived as `module_root_secret.child_key(
/// REFUND_KEY_CHILD).child_key(ChildId(index))` (see
/// [`UsdtClientModule::refund_keypair_for_index`]). A distinct child from
/// [`DEPOSIT_CLAIM_KEY_CHILD`] so refund keys can never collide with deposit
/// claim keys derived from the same seed.
const REFUND_KEY_CHILD: ChildId = ChildId(1);

/// Shared by [`UsdtClientModule::deposit_fee_quote`]/
/// [`UsdtClientModule::withdraw_fee_quote`] (misc #4, finding 06's
/// client-confusion facet): the exact message a caller sees when the
/// federation has no `FeeVote` median yet (or the quote overflowed).
const FEE_QUOTE_UNAVAILABLE_MESSAGE: &str =
    "fee quote not available yet (federation has no current fee estimate); try again shortly";

/// Bails with [`FEE_QUOTE_UNAVAILABLE_MESSAGE`] unless `available`,
/// otherwise passes `quote` through unchanged. Factored out of
/// [`UsdtClientModule::deposit_fee_quote`]/
/// [`UsdtClientModule::withdraw_fee_quote`] into a pure, synchronous
/// function so the availability guard is unit-testable without a live
/// federation/`DynModuleApi`.
fn ensure_fee_quote_available<T>(quote: T, available: bool) -> anyhow::Result<T> {
    if !available {
        bail!(FEE_QUOTE_UNAVAILABLE_MESSAGE);
    }
    Ok(quote)
}

/// Default client-side sanity threshold for a federation fee quote (security
/// finding 07): when the caller gives no explicit `--max-fee`/
/// `--max-deposit-fee` cap, a fee quote exceeding this percentage of the
/// transferred amount is treated as abnormal and blocked by
/// [`check_fee_cap`] unless `--accept-high-fee` is set.
const FEE_SANITY_PERCENT: u64 = 25;

/// Client-side fee-cap guard (security finding 07): decides whether
/// `quote_fee` -- a federation-supplied withdrawal `max_fee` quote or
/// deposit `fee` quote -- is acceptable to submit against a transfer of
/// `amount`. A malicious/compromised threshold federation (or a skewed
/// fee-vote median) can otherwise quote up to ~100% of a deposit/withdrawal
/// as "fee"; this is the client's only independent check before that quote
/// is ever signed over.
///
/// - If `explicit_cap` is `Some`, it is a hard ceiling: `quote_fee` exceeding
///   it always bails, regardless of `accept_high_fee` (an explicit cap cannot
///   be overridden by the bypass flag).
/// - Otherwise, `quote_fee` exceeding `FEE_SANITY_PERCENT`% of `amount` bails
///   unless `accept_high_fee` is set.
///
/// `cap_flag` names the caller's explicit-cap CLI flag (`--max-fee` for
/// withdrawals, `--max-deposit-fee` for claims) purely for the error
/// message.
///
/// Pure and synchronous (no network/DB/wall-clock access, wasm-safe) so it
/// is unit-testable without a live federation. Callers MUST invoke this
/// BEFORE any irreversible submit -- burning e-cash for a withdrawal or
/// minting e-cash net of a deposit fee for a claim -- so a rejection never
/// leaves a signed/submitted transaction behind.
fn check_fee_cap(
    quote_fee: UsdtAmount,
    amount: UsdtAmount,
    explicit_cap: Option<UsdtAmount>,
    accept_high_fee: bool,
    cap_flag: &str,
) -> anyhow::Result<()> {
    if let Some(cap) = explicit_cap {
        if quote_fee.0 > cap.0 {
            bail!("federation fee quote {quote_fee} exceeds your {cap_flag} {cap}; not submitting");
        }
        return Ok(());
    }

    if accept_high_fee {
        return Ok(());
    }

    // u128 throughout: `amount.0 * FEE_SANITY_PERCENT` would overflow a u64
    // for amounts near u64::MAX.
    let threshold = u128::from(amount.0) * u128::from(FEE_SANITY_PERCENT) / 100;
    if u128::from(quote_fee.0) > threshold {
        let pct = if amount.0 == 0 {
            // No denominator to express a ratio against; any nonzero fee on
            // a zero amount is unconditionally abnormal.
            u128::from(quote_fee.0).saturating_mul(100)
        } else {
            u128::from(quote_fee.0) * 100 / u128::from(amount.0)
        };
        bail!(
            "federation fee quote {quote_fee} is {pct}% of the amount, above the \
             {FEE_SANITY_PERCENT}% sanity threshold; re-run with {cap_flag} <cap> or \
             --accept-high-fee to proceed"
        );
    }

    Ok(())
}

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

/// Result of a single [`UsdtClientModule::claim`] call: the gross
/// (on-chain-credited) amount claimed and the deposit fee actually charged
/// against it (per [`UsdtClientModule::deposit_fee_quote`] at submission
/// time), so callers can report the real e-cash issued (`claimed - fee`)
/// without re-fetching a possibly-since-changed quote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ClaimResult {
    /// The gross (on-chain-credited) amount claimed.
    pub claimed: UsdtAmount,
    /// The deposit fee charged against `claimed` (see [`UsdtInputV0::fee`]).
    pub fee: UsdtAmount,
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
    /// The federation module API, so the withdrawal refund state machine can
    /// poll `withdrawal_status`/`refund_status` (security finding 09).
    pub module_api: DynModuleApi,
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
        /// The deposit fee charged (per [`UsdtClientModule::deposit_fee_quote`]
        /// at submission time), mirroring [`Self::Withdraw`]'s `max_fee`. The
        /// e-cash actually issued to the claimant is `amount - fee`.
        fee: UsdtAmount,
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
            module_api: self.module_api.clone(),
        }
    }

    // A claim input DOES charge a real deposit fee (see `Self::submit_claim`),
    // but it is never reported through this trait method: unlike
    // `output_fee` below, whose `max_fee` must be ADDED on top of the
    // withdrawal output's own `amounts` for the transaction-balancing
    // framework to fund it correctly, a claim input's fee is baked directly
    // into its own `ClientInput.amounts`, which `submit_claim` already sets
    // to the NET `amount - fee` (mirroring the server's `process_input`,
    // which declares the input GROSS -- `amounts: amount, fees: fee` -- so
    // the two sides balance in `USDT_UNIT`: `amount >= (amount - fee) +
    // fee`). Reporting `fee` again here would double-count it and starve the
    // primary module's minted change by `fee`. The transaction-balancing
    // framework calls this for every input in a transaction being built
    // (`Client::finalize_and_submit_transaction` sums `input_fee`/
    // `output_fee` across all modules involved to compute the primary
    // module's balancing output), not only when this module happens to be
    // the primary one, so it must return `Some` for the only real input
    // variant (`UsdtInput::V0`) rather than `unreachable!()`.
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
                usdt_amount(withdrawal.max_fee),
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
    /// This module's client configuration (the consensus-agreed EVM
    /// addresses/network this federation is configured for). Exposed so
    /// integration tests can read the config-gen'd `account_factory`/
    /// `simple_account_impl` (Part A derives these deterministically from
    /// `entry_point`, so they are no longer known ahead of config-gen) when
    /// scripting readiness.
    #[must_use]
    pub fn config(&self) -> &UsdtClientConfig {
        &self.cfg
    }

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

    /// The deterministic withdrawal-refund keypair for seed-derivation `index`,
    /// derived purely from `module_root_secret` under [`REFUND_KEY_CHILD`]
    /// (security finding 09). Mirrors [`Self::claim_keypair_static`]: the same
    /// seed and `index` always yield the same keypair, and distinct indices
    /// yield distinct keypairs, so a refund key is (in principle)
    /// seed-recoverable.
    #[must_use]
    fn refund_keypair_static(module_root_secret: &DerivableSecret, index: u64) -> Keypair {
        module_root_secret
            .child_key(REFUND_KEY_CHILD)
            .child_key(ChildId(index))
            .to_secp_key(SECP256K1)
    }

    /// The deterministic withdrawal-refund keypair for seed-derivation `index`
    /// under this module's root secret (see [`Self::refund_keypair_static`]).
    #[must_use]
    fn refund_keypair_for_index(&self, index: u64) -> Keypair {
        Self::refund_keypair_static(&self.module_root_secret, index)
    }

    /// Atomically reads and increments the [`NextRefundIndexKey`] counter,
    /// returning the index to derive a fresh withdrawal refund keypair at
    /// (security finding 09). Mirrors [`Self::allocate_deposit`]'s
    /// counter-bump pattern.
    async fn allocate_refund_index(&self) -> anyhow::Result<u64> {
        self.db
            .autocommit(
                |dbtx, _| {
                    Box::pin(async {
                        let index = dbtx
                            .get_value(&NextRefundIndexKey)
                            .await
                            .unwrap_or_default();
                        dbtx.insert_entry(&NextRefundIndexKey, &index.saturating_add(1))
                            .await;
                        Ok::<_, anyhow::Error>(index)
                    })
                },
                None,
            )
            .await
            .map_err(|e| match e {
                AutocommitError::ClosureError { error, .. } => error,
                AutocommitError::CommitFailed { last_error, .. } => {
                    anyhow::anyhow!("Commit to DB failed: {last_error}")
                }
            })
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
        // Readiness gate (Part C): refuse to hand out a new deposit address
        // unless the federation reports `Ready`, so a user is never told to
        // deposit into a federation that cannot yet honor the full
        // deposit->claim->sweep->withdraw lifecycle. Only the ADVERTISEMENT of
        // new addresses is gated -- claim/withdraw/pool-state stay ungated (a
        // credited deposit is already backed in its own account).
        let status = self.module_api.status().await?;
        if status.state != BootstrapState::Ready {
            bail!(
                "federation not ready to accept deposits (state: {:?}); \
                 entry_point_ok={}, factory_ok={}, impl_ok={}, funded_guardians={}, \
                 healthy_guardians={}, threshold={}",
                status.state,
                status.entry_point_ok,
                status.factory_ok,
                status.impl_ok,
                status.funded_guardians,
                status.healthy_guardians,
                status.threshold,
            );
        }

        // Read-modify-write of the `NextDepositIndexKey` counter (plus the
        // matching `ClaimKeyKey` write) in one atomic, retried unit: a bare
        // `begin_transaction`/`commit_tx` pair would let two concurrent
        // `allocate_deposit` calls read the same index and hand out colliding
        // deposit addresses/claim keys (and `commit_tx` could panic on the
        // write conflict). `autocommit` retries the closure until it commits
        // cleanly. Mirrors the standard fedimint counter pattern (e.g.
        // `fedimint-mint-client`'s note-index bumps).
        self.db
            .autocommit(
                |dbtx, _| {
                    Box::pin(async {
                        let index = dbtx
                            .get_value(&NextDepositIndexKey)
                            .await
                            .unwrap_or_default();
                        let claim_keypair = self.claim_keypair_for_index(index);
                        let account = self.deposit_address(&claim_keypair.public_key());

                        dbtx.insert_entry(&NextDepositIndexKey, &index.saturating_add(1))
                            .await;
                        dbtx.insert_entry(&ClaimKeyKey(account), &claim_keypair)
                            .await;

                        Ok::<_, anyhow::Error>((claim_keypair, account))
                    })
                },
                None,
            )
            .await
            .map_err(|e| match e {
                AutocommitError::ClosureError { error, .. } => error,
                AutocommitError::CommitFailed { last_error, .. } => {
                    anyhow::anyhow!("Commit to DB failed: {last_error}")
                }
            })
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
    ///
    /// # Known limitation
    ///
    /// This rediscovers only deposits the federation has already CREDITED (a
    /// [`Self::check_deposit`] -> observe -> credit must have happened for the
    /// account); a funded-but-never-checked deposit at scan time reports
    /// `credited == 0` and is skipped. Such funds are not lost -- re-running
    /// `check-deposit` for the address and re-scanning finds them once the
    /// federation credits the deposit.
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
            // Never LOWER the counter: on a partially-intact DB the existing
            // `NextDepositIndexKey` may already sit above `highest + 1` (e.g.
            // allocations that were never funded), and regressing it would
            // reuse indices/addresses. Take the max of the two.
            let existing = dbtx.get_value(&NextDepositIndexKey).await.unwrap_or(0);
            dbtx.insert_entry(
                &NextDepositIndexKey,
                &existing.max(highest.saturating_add(1)),
            )
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
    /// call; see [`UsdtFederationApi::check_deposit`]). The response's
    /// `ready` field (security finding 13's r2 facet) reports whether the
    /// federation was actually ready to start watching -- if `false`, no
    /// guardian enqueued anything and the caller should wait and retry
    /// (mirrors [`Self::allocate_deposit`]'s own readiness gate).
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

    /// This federation's peer ids, for callers that need to iterate over
    /// every guardian individually rather than going through a
    /// threshold-agreed `request_current_consensus` call.
    #[must_use]
    pub fn all_peers(&self) -> BTreeSet<PeerId> {
        self.module_api.all_peers().clone()
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

    /// Reports the federation's consensus-agreed readiness state (Part C):
    /// `AwaitingInfra`/`Ready`/`Degraded`, plus the per-condition tally (thin
    /// wrapper around [`UsdtFederationApi::status`]). Threshold-agreement --
    /// every guardian answers identically, since it is derived from consensus
    /// DB. [`Self::allocate_deposit`] gates on this reporting `Ready`.
    pub async fn status(&self) -> anyhow::Result<StatusResponse> {
        Ok(self.module_api.status().await?)
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
    /// `claim_pk`. Returns a [`ClaimResult`] carrying both the claimed
    /// (gross, on-chain-credited) amount and the deposit fee actually
    /// charged against it -- the e-cash issued is `claimed - fee`.
    ///
    /// Callers should have already called [`Self::check_deposit`] (to enqueue
    /// the deposit-checker task) and waited for the federation to observe and
    /// credit the on-chain transfer; use [`Self::deposit_status`] to poll for
    /// that.
    ///
    /// `max_deposit_fee`/`accept_high_fee` are the security finding 07 fee
    /// cap: `max_deposit_fee` is an explicit hard ceiling on the federation's
    /// deposit fee quote (checked in [`Self::submit_claim`] via
    /// [`check_fee_cap`]); if `None`, the default `FEE_SANITY_PERCENT` sanity
    /// guard applies instead unless `accept_high_fee` is set. See
    /// [`check_fee_cap`] for the exact semantics.
    ///
    /// # Errors
    ///
    /// Returns an `Err` -- BEFORE any e-cash is minted -- if the federation's
    /// deposit fee quote exceeds `max_deposit_fee`, or (when
    /// `max_deposit_fee` is `None` and `accept_high_fee` is `false`) exceeds
    /// the default sanity threshold.
    pub async fn claim(
        &self,
        claim_pk: secp256k1::PublicKey,
        max_deposit_fee: Option<UsdtAmount>,
        accept_high_fee: bool,
    ) -> anyhow::Result<ClaimResult> {
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

        let fee = self
            .submit_claim(
                &claim_keypair,
                account,
                status.claimable,
                max_deposit_fee,
                accept_high_fee,
            )
            .await?;

        Ok(ClaimResult {
            claimed: status.claimable,
            fee,
        })
    }

    /// Reports the federation's current deposit fee quote: the minimum `fee`
    /// a `UsdtInput::V0` claiming a credited deposit must offer right now
    /// (mirroring [`Self::withdraw_fee_quote`]). Thin wrapper around
    /// [`UsdtFederationApi::deposit_fee_quote`] (threshold-agreement --
    /// every guardian answers identically, since the quote is derived from
    /// consensus DB).
    ///
    /// # Errors
    ///
    /// Returns an `Err` if the response's `available` is `false` (misc #4,
    /// finding 06's client-confusion facet): the federation has no
    /// `FeeVote` median yet (or the quote overflowed), so the response's
    /// `fee` is a non-authoritative `UsdtAmount(0)` placeholder that MUST
    /// NOT be submitted against. Every caller of this wrapper (`claim` via
    /// [`Self::submit_claim`], `fedimint-cli`'s `deposit-fee-quote`/`claim`)
    /// therefore inherits this bail rather than silently claiming for `0`
    /// fee and hitting `process_input`'s `NoFeeQuoteAvailable` rejection
    /// later.
    pub async fn deposit_fee_quote(&self) -> anyhow::Result<DepositFeeQuoteResponse> {
        let quote = self.module_api.deposit_fee_quote().await?;
        let available = quote.available;
        ensure_fee_quote_available(quote, available)
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
        if !checked.ready {
            bail!(
                "federation infrastructure not ready yet (deposit to {} is not being watched); \
                 try again after bootstrap completes",
                checked.account,
            );
        }

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

        // No caller-facing cap flags on this polling convenience method (it
        // predates the CLI's `--max-deposit-fee`/`--accept-high-fee` and is
        // only used by [`Self::claim`]'s callers indirectly via tests) --
        // `accept_high_fee: true` preserves its prior unrestricted-quote
        // behavior rather than silently starting to enforce the finding-07
        // default sanity guard here.
        self.submit_claim(claim_keypair, account, claimable, None, true)
            .await?;

        Ok(())
    }

    /// Builds and submits the transaction claiming `amount` from `account`,
    /// funding it with `claim_keypair`. Shared by [`Self::check_and_claim`]
    /// (which polls until an amount is claimable) and [`Self::claim`] (which
    /// takes a single already-known claimable amount). Returns the deposit
    /// fee charged (per [`Self::deposit_fee_quote`]).
    ///
    /// The claimed funds are absorbed directly into the transaction's
    /// implicit funding, which the USDT-`mintv2` primary module (routed to by
    /// `USDT_UNIT`) balances by minting e-cash notes; no explicit output is
    /// added here. The e-cash minted is the NET `amount - fee` (see
    /// [`Self::claim_input`]).
    ///
    /// Applies the security finding 07 [`check_fee_cap`] guard against the
    /// freshly fetched quote BEFORE building the claim input or submitting
    /// anything -- see `max_deposit_fee`/`accept_high_fee` on [`Self::claim`]
    /// for the semantics.
    async fn submit_claim(
        &self,
        claim_keypair: &Keypair,
        account: EvmAddress,
        amount: UsdtAmount,
        max_deposit_fee: Option<UsdtAmount>,
        accept_high_fee: bool,
    ) -> anyhow::Result<UsdtAmount> {
        let quote = self.deposit_fee_quote().await?;
        let fee = quote.fee;

        check_fee_cap(
            fee,
            amount,
            max_deposit_fee,
            accept_high_fee,
            "--max-deposit-fee",
        )?;

        let input = Self::claim_input(claim_keypair, account, amount, fee)?;

        let operation_id = OperationId::new_random();
        let tx = TransactionBuilder::new().with_inputs(
            self.client_ctx
                .make_client_inputs(ClientInputBundle::new_no_sm(vec![input])),
        );

        let range = self
            .client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                KIND.as_str(),
                move |_range| UsdtOperationMeta::Claim {
                    account,
                    amount,
                    fee,
                },
                tx,
            )
            .await?;

        // Await the primary-module (USDT-denominated `mintv2`) e-cash issuance
        // so `claim` returns only once the e-cash is actually in hand -- the
        // issuance is a blind-signature round-trip driven by the output state
        // machine, which completes strictly AFTER
        // `finalize_and_submit_transaction` returns (that only submits the tx).
        // The unit-aware await (`..._for_unit(USDT_UNIT)`) is required because
        // this module's e-cash is USDT-, not Bitcoin-denominated: the default
        // `await_primary_module_outputs` resolves the primary module for
        // `AmountUnit::BITCOIN` and would not cover our USDT-denominated
        // `mintv2` primary module.
        self.client_ctx
            .await_primary_module_outputs_for_unit(
                operation_id,
                range.into_iter().collect(),
                USDT_UNIT,
            )
            .await?;

        Ok(fee)
    }

    /// Builds the `ClientInput` claiming `amount` from `account` with
    /// `claim_keypair`, charging `fee` (per [`Self::deposit_fee_quote`]) via
    /// NET issuance rather than an explicit [`ClientModule::input_fee`] (see
    /// that trait method's doc comment on this module's impl for why): the
    /// input's own [`UsdtInputV0::fee`] carries the fee the server verifies
    /// against its own quote, while `amounts` is set to `amount - fee` so
    /// the USDT-`mintv2` primary module mints exactly that much e-cash. The
    /// server's `process_input` declares the input GROSS (`amounts: amount,
    /// fees: fee`), so the two sides balance in `USDT_UNIT`.
    ///
    /// A pure, synchronous helper (no network/DB access) so the guard and
    /// the resulting `ClientInput` are unit-testable without a live
    /// federation.
    ///
    /// # Errors
    ///
    /// Returns an `Err` if `fee` would consume all or more of `amount`
    /// (mirroring the server's `UsdtInputError::FeeExceedsAmount`
    /// rejection, but caught locally before ever building/submitting the
    /// transaction, mirroring how `fedimint-wallet-client` skips
    /// uneconomical peg-ins below the deposit fee).
    fn claim_input(
        claim_keypair: &Keypair,
        account: EvmAddress,
        amount: UsdtAmount,
        fee: UsdtAmount,
    ) -> anyhow::Result<ClientInput<UsdtInput>> {
        if amount.0 <= fee.0 {
            bail!("deposit {amount} does not cover the {fee} deposit fee");
        }

        Ok(ClientInput {
            input: UsdtInput::V0(UsdtInputV0 {
                account,
                amount,
                fee,
            }),
            keys: vec![*claim_keypair],
            amounts: Amounts::new_custom(USDT_UNIT, usdt_amount(UsdtAmount(amount.0 - fee.0))),
        })
    }

    /// Reports the federation's current withdrawal fee quote: the minimum
    /// `max_fee` a `withdraw` of `amount` must offer right now (Phase 8,
    /// Task 1). Thin wrapper around [`UsdtFederationApi::withdraw_fee_quote`]
    /// (threshold-agreement -- every guardian answers identically, since the
    /// quote is derived from consensus DB).
    ///
    /// # Errors
    ///
    /// Mirrors [`Self::deposit_fee_quote`]'s `available` handling: returns
    /// an `Err` rather than a `UsdtAmount(0)` placeholder when the
    /// federation has no fresh quote yet.
    pub async fn withdraw_fee_quote(
        &self,
        amount: UsdtAmount,
    ) -> anyhow::Result<WithdrawFeeQuoteResponse> {
        let quote = self.module_api.withdraw_fee_quote(amount).await?;
        let available = quote.available;
        ensure_fee_quote_available(quote, available)
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
        // Derive a fresh, seed-deterministic refund keypair (security finding
        // 09) and commit its PUBLIC key in the withdrawal output. If the
        // withdrawal ever fails terminally, the server reissues its e-cash as
        // a refund claimable ONLY by this key -- so only this client can
        // recover it. The SECRET stays local (embedded in the attached state
        // machine and persisted under `RefundKeyKey` below).
        let refund_index = self.allocate_refund_index().await?;
        let refund_keypair = self.refund_keypair_for_index(refund_index);
        let refund_pubkey = refund_keypair.public_key();

        let operation_id = OperationId::new_random();

        // A state machine, generated once the output's `OutPoint` is known,
        // that watches this withdrawal and claims the reissued e-cash refund
        // if it fails (see `UsdtStateMachine`).
        let sm_gen = {
            move |out_point_range: OutPointRange| {
                let out_point = OutPoint {
                    txid: out_point_range.txid(),
                    out_idx: 0,
                };
                vec![UsdtStateMachine {
                    common: WithdrawalRefundCommon {
                        operation_id,
                        txid: out_point_range.txid(),
                        out_point,
                        refund_keypair,
                    },
                    state: WithdrawalRefundState::Pending,
                }]
            }
        };

        let output = ClientOutputBundle::new(
            vec![ClientOutput {
                output: UsdtOutput::V0(UsdtOutputV0 {
                    recipient,
                    amount,
                    max_fee,
                    refund_pubkey,
                }),
                amounts: Amounts::new_custom(USDT_UNIT, usdt_amount(amount)),
            }],
            vec![ClientOutputSM {
                state_machines: Arc::new(sm_gen),
            }],
        );
        let output = self.client_ctx.make_client_outputs(output);

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

        // Persist the refund keypair keyed by the withdrawal's `OutPoint` so a
        // restarted client (or the CLI) can look it up (security finding 09).
        // The withdrawal output is always at `out_idx` 0 (see
        // `withdrawal_out_point`).
        let out_point = Self::withdrawal_out_point(&range);
        let mut dbtx = self.db.begin_transaction().await;
        dbtx.insert_entry(&RefundKeyKey(out_point), &refund_keypair)
            .await;
        dbtx.commit_tx().await;

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

    /// Reports the live refund record for a terminally-failed withdrawal
    /// (security finding 09): `Some((amount, reason))` for the reissued e-cash
    /// the refund state machine will claim (or has claimed), or `None` if the
    /// withdrawal never failed or its refund was already claimed and settled.
    /// Thin wrapper around [`UsdtFederationApi::refund_status`].
    pub async fn refund_status(&self, out_point: OutPoint) -> anyhow::Result<RefundStatusResponse> {
        Ok(self.module_api.refund_status(out_point).await?)
    }

    /// Polls the withdrawal at `out_point` until it reaches a terminal outcome
    /// (paid on-chain, or terminally failed and refunded) or `deadline`
    /// elapses (security finding 09), reporting the three cases distinctly.
    /// Complements [`Self::await_withdrawal_confirmed`], which only ever
    /// treats a failure as an error; here a failure resolves to
    /// [`WithdrawalOutcome::Refunded`] with the reissued amount and reason.
    /// The refund claim itself is driven by the attached state machine, so a
    /// caller only needs to poll their `USDT_UNIT` balance for the reissued
    /// e-cash to arrive after this returns `Refunded`.
    pub async fn await_withdrawal_outcome(
        &self,
        out_point: OutPoint,
        deadline: Duration,
    ) -> anyhow::Result<WithdrawalOutcome> {
        let deadline_at = Instant::now() + deadline;
        let mut backoff = Duration::from_millis(250);

        loop {
            match self.module_api.withdrawal_status(out_point).await?.status {
                WithdrawalStatus::Confirmed { block } => {
                    return Ok(WithdrawalOutcome::Paid { block });
                }
                WithdrawalStatus::Failed { reason } => {
                    // Report the refunded amount if the refund record is still
                    // live; if it was already claimed, report `None` amount.
                    let amount = self
                        .module_api
                        .refund_status(out_point)
                        .await?
                        .refund
                        .map(|info| info.amount);
                    return Ok(WithdrawalOutcome::Refunded { amount, reason });
                }
                WithdrawalStatus::Unknown
                | WithdrawalStatus::Queued
                | WithdrawalStatus::Signing { .. }
                | WithdrawalStatus::Submitted { .. } => {}
            }

            if Instant::now() >= deadline_at {
                bail!(
                    "withdrawal {out_point} did not reach a terminal outcome before the deadline"
                );
            }

            sleep(backoff).await;
            backoff = (backoff * 2).min(AWAIT_WITHDRAWAL_CONFIRMED_MAX_BACKOFF);
        }
    }
}

/// The terminal outcome of a withdrawal as reported by
/// [`UsdtClientModule::await_withdrawal_outcome`] (security finding 09).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum WithdrawalOutcome {
    /// The withdrawal was paid out on-chain at `block`.
    Paid { block: u64 },
    /// The withdrawal failed terminally and its e-cash was reissued as a
    /// refund. `amount` is the reissued e-cash (present while the refund is
    /// unclaimed; `None` if it was already claimed) and `reason` is the
    /// failure reason.
    Refunded {
        amount: Option<UsdtAmount>,
        reason: String,
    },
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
                DbKeyPrefix::RefundKey => {
                    push_db_pair_items!(
                        dbtx,
                        RefundKeyPrefixAll,
                        RefundKeyKey,
                        Keypair,
                        items,
                        "Usdt Refund Keys"
                    );
                }
                DbKeyPrefix::NextRefundIndex => {
                    push_db_pair_items!(
                        dbtx,
                        NextRefundIndexPrefixAll,
                        NextRefundIndexKey,
                        u64,
                        items,
                        "Usdt Next Refund Index"
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

    use super::{
        Amount, Amounts, EvmAddress, FEE_QUOTE_UNAVAILABLE_MESSAGE, Keypair, SECP256K1, USDT_UNIT,
        UsdtAmount, UsdtClientModule, UsdtInput, check_fee_cap, ensure_fee_quote_available,
    };

    /// Deterministic test keypair (mirrors
    /// [`UsdtClientModule::claim_keypair_static`]'s derivation, but with an
    /// arbitrary fixed seed -- this test needs *a* keypair, not a
    /// particular one).
    fn test_keypair() -> Keypair {
        DerivableSecret::new_root(b"usdt-claim-input-test-seed", b"salt").to_secp_key(SECP256K1)
    }

    /// [`UsdtClientModule::claim_input`] must set the input's own `fee`
    /// field from the quote, and declare the NET `amount - fee` as its
    /// `ClientInput.amounts` -- not the gross `amount` -- so the
    /// USDT-`mintv2` primary module mints exactly `amount - fee` and the
    /// transaction balances against the server's GROSS `process_input`
    /// declaration (`amounts: amount, fees: fee`).
    #[test]
    fn claim_input_sets_fee_and_net_amounts() {
        let keypair = test_keypair();
        let account = EvmAddress([0x11; 20]);
        let amount = UsdtAmount(1_000_000);
        let fee = UsdtAmount(100_000);

        let input = UsdtClientModule::claim_input(&keypair, account, amount, fee)
            .expect("amount comfortably exceeds fee");

        match input.input {
            UsdtInput::V0(v0) => {
                assert_eq!(v0.account, account);
                assert_eq!(v0.amount, amount);
                assert_eq!(v0.fee, fee);
            }
            UsdtInput::RefundV0 { .. } | UsdtInput::Default { .. } => {
                panic!("claim_input must build a V0 input")
            }
        }
        assert_eq!(input.keys, vec![keypair]);
        assert_eq!(
            input.amounts,
            Amounts::new_custom(USDT_UNIT, Amount::from_msats(amount.0 - fee.0)),
            "ClientInput.amounts must be the NET amount, not the gross claimed amount"
        );
    }

    /// (misc #4, finding 06's client-confusion facet.)
    /// `ensure_fee_quote_available` backs both
    /// [`UsdtClientModule::deposit_fee_quote`] and [`UsdtClientModule::withdraw_fee_quote`]: `available: false` must bail
    /// with [`FEE_QUOTE_UNAVAILABLE_MESSAGE`] rather than silently handing
    /// the caller a `UsdtAmount(0)` placeholder quote.
    #[test]
    fn ensure_fee_quote_available_bails_when_unavailable() {
        let err = ensure_fee_quote_available(UsdtAmount(0), false)
            .expect_err("unavailable quote must bail");
        assert_eq!(err.to_string(), FEE_QUOTE_UNAVAILABLE_MESSAGE);
    }

    /// Positive control: a real (`available: true`) quote passes through
    /// unchanged -- the availability guard must not perturb the quote value
    /// itself.
    #[test]
    fn ensure_fee_quote_available_passes_through_when_available() {
        let quote = UsdtAmount(38_880_000);
        let passed = ensure_fee_quote_available(quote, true).expect("available quote must pass");
        assert_eq!(passed, quote);
    }

    /// An uneconomical deposit (the fee would consume all or more of the
    /// claimed amount) must be rejected locally, before ever building or
    /// submitting a transaction -- mirroring the server's
    /// `UsdtInputError::FeeExceedsAmount` rejection and
    /// `fedimint-wallet-client`'s uneconomical-peg-in guard.
    #[test]
    fn claim_input_rejects_uneconomical_deposit() {
        let keypair = test_keypair();
        let account = EvmAddress([0x22; 20]);

        // fee == amount.
        let err =
            UsdtClientModule::claim_input(&keypair, account, UsdtAmount(500), UsdtAmount(500))
                .expect_err("fee equal to amount must be rejected");
        assert!(err.to_string().contains("deposit fee"));

        // fee > amount.
        UsdtClientModule::claim_input(&keypair, account, UsdtAmount(500), UsdtAmount(600))
            .expect_err("fee exceeding amount must be rejected");
    }

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

    /// Security finding 09: the withdrawal-refund key derivation must be
    /// deterministic from the seed (so a refund key is recoverable) AND must
    /// never collide with the deposit claim key at the same index (they live
    /// under distinct child domains).
    #[test]
    fn refund_keypair_is_deterministic_and_disjoint_from_claim_keys() {
        let secret = DerivableSecret::new_root(b"usdt-refund-test-seed", b"salt");

        // Same secret + index => identical refund key; distinct indices differ.
        for index in [0u64, 1, 7, u64::MAX] {
            assert_eq!(
                UsdtClientModule::refund_keypair_static(&secret, index),
                UsdtClientModule::refund_keypair_static(&secret, index),
                "refund key for index {index} must be reproducible from the seed"
            );
        }
        assert_ne!(
            UsdtClientModule::refund_keypair_static(&secret, 0),
            UsdtClientModule::refund_keypair_static(&secret, 1),
        );

        // A refund key must NEVER equal the deposit claim key at the same
        // index (distinct child domains) -- otherwise a refund could be
        // spent/observed via the deposit-claim path.
        for index in [0u64, 1, 2, 7, 100] {
            assert_ne!(
                UsdtClientModule::refund_keypair_static(&secret, index).public_key(),
                UsdtClientModule::claim_keypair_static(&secret, index).public_key(),
                "refund and claim keys must be disjoint at index {index}"
            );
        }
    }

    // --- security finding 07: `check_fee_cap` -----------------------------

    /// An explicit cap is a hard ceiling: a quote above it must bail, citing
    /// the caller's flag name, even though `accept_high_fee` is unset.
    #[test]
    fn withdraw_rejects_quote_over_explicit_cap() {
        let err = check_fee_cap(
            UsdtAmount(200),
            UsdtAmount(1_000),
            Some(UsdtAmount(100)),
            false,
            "--max-fee",
        )
        .expect_err("quote 200 exceeds explicit cap 100");
        assert!(err.to_string().contains("--max-fee"));
        assert!(err.to_string().contains("100"));
        assert!(err.to_string().contains("200"));
    }

    /// Same as [`withdraw_rejects_quote_over_explicit_cap`] but for the
    /// claim path's `--max-deposit-fee` flag -- the error message must name
    /// the flag the caller actually has, not a hardcoded `--max-fee`.
    #[test]
    fn claim_rejects_fee_over_explicit_cap() {
        let err = check_fee_cap(
            UsdtAmount(200),
            UsdtAmount(1_000),
            Some(UsdtAmount(100)),
            false,
            "--max-deposit-fee",
        )
        .expect_err("fee 200 exceeds explicit cap 100");
        assert!(err.to_string().contains("--max-deposit-fee"));
    }

    /// An explicit cap is a hard ceiling regardless of `accept_high_fee`:
    /// the bypass flag only affects the *default* sanity guard, not a
    /// caller-specified cap.
    #[test]
    fn explicit_cap_is_not_overridden_by_accept_high_fee() {
        check_fee_cap(
            UsdtAmount(200),
            UsdtAmount(1_000),
            Some(UsdtAmount(100)),
            true,
            "--max-fee",
        )
        .expect_err("an explicit cap must reject an over-cap quote even with accept_high_fee");
    }

    /// A quote within an explicit cap proceeds.
    #[test]
    fn explicit_cap_within_range_proceeds() {
        check_fee_cap(
            UsdtAmount(50),
            UsdtAmount(1_000),
            Some(UsdtAmount(100)),
            false,
            "--max-fee",
        )
        .expect("quote 50 is within the explicit cap 100");
    }

    /// With no explicit cap and no `accept_high_fee`, a quote above
    /// `FEE_SANITY_PERCENT`% of the amount must bail.
    #[test]
    fn default_sanity_guard_blocks_abnormal_fee_without_accept_flag() {
        // 300 / 1_000 == 30%, above the 25% default threshold.
        let err = check_fee_cap(UsdtAmount(300), UsdtAmount(1_000), None, false, "--max-fee")
            .expect_err("a 30% fee must be blocked by the default sanity guard");
        assert!(err.to_string().contains("30%"));
        assert!(err.to_string().contains("25%"));
        assert!(err.to_string().contains("--accept-high-fee"));
    }

    /// `--accept-high-fee` bypasses the default sanity guard entirely (but
    /// only in the absence of an explicit cap; see
    /// [`explicit_cap_is_not_overridden_by_accept_high_fee`]).
    #[test]
    fn accept_high_fee_bypasses_default_guard() {
        check_fee_cap(UsdtAmount(300), UsdtAmount(1_000), None, true, "--max-fee")
            .expect("accept_high_fee must bypass the default sanity guard");
    }

    /// A quote at or below the default threshold proceeds even without
    /// `accept_high_fee`.
    #[test]
    fn default_sanity_guard_allows_fee_within_threshold() {
        // 100 / 1_000 == 10%, comfortably under 25%.
        check_fee_cap(UsdtAmount(100), UsdtAmount(1_000), None, false, "--max-fee")
            .expect("a 10% fee is within the default sanity threshold");
    }

    /// Boundary: a fee at exactly `FEE_SANITY_PERCENT`% is allowed (the
    /// guard only blocks fees strictly *above* the threshold).
    #[test]
    fn default_sanity_guard_allows_fee_at_exact_threshold() {
        // 250 / 1_000 == exactly 25%.
        check_fee_cap(UsdtAmount(250), UsdtAmount(1_000), None, false, "--max-fee")
            .expect("a fee at exactly the 25% threshold must not be blocked");
    }

    /// A zero-amount transfer has no ratio to compare against; any nonzero
    /// fee must still be treated as abnormal by the default guard (rather
    /// than e.g. dividing by zero or vacuously passing).
    #[test]
    fn default_sanity_guard_blocks_any_fee_on_zero_amount() {
        check_fee_cap(UsdtAmount(1), UsdtAmount(0), None, false, "--max-fee")
            .expect_err("any nonzero fee against a zero amount must be blocked");
    }
}
