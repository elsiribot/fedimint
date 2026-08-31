#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use std::collections::{BTreeMap, BTreeSet};
#[cfg(feature = "cli")]
use std::ffi;
use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use api::UsdtFederationApi;
use db::{
    ClaimKeyKey, ClaimKeyPrefixAll, DbKeyPrefix, EvmRpcUrlKey, EvmRpcUrlPrefixAll,
    NextDepositIndexKey, NextDepositIndexPrefixAll, NextRefundIndexKey, NextRefundIndexPrefixAll,
    RefundKeyKey, RefundKeyPrefixAll,
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
    BootstrapState, DepositFeeQuoteResponse, DepositProof, DepositStatusResponse, EvmAddress, KIND,
    PoolStateResponse, RefundStatusResponse, StatusResponse, USDT_UNIT, UsdtAmount, UsdtCommonInit,
    UsdtInput, UsdtModuleTypes, UsdtOutput, UsdtOutputV0, UserOpStatusResponse,
    WithdrawFeeQuoteResponse, WithdrawalStatus, WithdrawalStatusResponse, usdt_amount,
};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use states::{UsdtStateMachine, WithdrawalRefundCommon, WithdrawalRefundState};
use strum::IntoEnumIterator;

pub mod api;
#[cfg(feature = "cli")]
mod cli;
pub mod db;
pub mod evm;
pub mod states;

/// Cap on the exponential backoff
/// [`UsdtClientModule::await_withdrawal_confirmed`] waits between
/// `withdrawal_status` polls.
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
    /// One entry per rediscovered (already-credited) account.
    pub accounts: Vec<RecoveredAccount>,
    /// Security finding 08: one entry per scanned index that reported
    /// `credited == 0` while `check_uncredited` was set -- its claim key was
    /// (re-)persisted so a funded-but-uncredited deposit is not silently
    /// abandoned. Distinct from `accounts` (which are already credited):
    /// entries here may still become claimable once the deposit is credited
    /// via a `UsdtInput::DepositProofV0` proof submission (see Task 9's
    /// proof-submit flow) -- re-run `recover` or poll `deposit-status` for
    /// each `claim_pk` to follow up. Empty when `check_uncredited` was
    /// `false`.
    pub checked: Vec<CheckedAccount>,
}

/// Outcome of [`UsdtClientModule::submit_crafted_input_for_test`]: whether the
/// federation rejected an adversarial hand-crafted input (defense held) or
/// accepted it and minted value (a security finding). Only available under the
/// non-default `test-util` feature.
#[cfg(feature = "test-util")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CraftedInputOutcome {
    /// The federation ACCEPTED the crafted transaction and issued the paired
    /// USDT-`mintv2` mint output -- i.e. the crafted input credited/minted
    /// `minted` of spendable e-cash. For an adversarial input this is a
    /// SECURITY FINDING.
    Accepted {
        /// The value the accepted crafted input minted into e-cash.
        minted: UsdtAmount,
    },
    /// The federation REJECTED the crafted transaction during consensus input
    /// processing (the expected outcome for a malicious input -- defense held),
    /// carrying the guardians' rejection reason (the rendered
    /// [`fedimint_usdt_common::UsdtInputError`]).
    Rejected {
        /// The guardians' rejection reason.
        reason: String,
    },
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

/// A scanned-but-uncredited (`credited == 0` at scan time) deposit index
/// whose claim key was (re-)persisted during
/// [`UsdtClientModule::recover_deposits`] (security finding 08). This is what
/// makes a funded-but-uncredited deposit recoverable from seed alone: the
/// account may become credited later (via a `UsdtInput::DepositProofV0` proof
/// submission), at which point a follow-up `recover` (or a direct `claim`,
/// since the key is now in the local DB) picks it up.
#[derive(Debug, Clone, Serialize)]
pub struct CheckedAccount {
    /// The seed-derivation index this account's claim key lives at.
    pub index: u64,
    /// The derived deposit account (EVM address).
    pub account: EvmAddress,
    /// The public key of the (re-derived, re-persisted) claim keypair.
    pub claim_pk: secp256k1::PublicKey,
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

    // A deposit input DOES charge a real deposit fee (see
    // `Self::submit_deposit_proof_input`), but it is
    // never reported through this trait method: unlike
    // `output_fee` below, whose `max_fee` must be ADDED on top of the
    // withdrawal output's own `amounts` for the transaction-balancing
    // framework to fund it correctly, a deposit input's fee is baked directly
    // into its own `ClientInput.amounts`, which `claim_input`/
    // `deposit_proof_input` already set to the NET `amount - fee` (mirroring
    // the server's `process_input`, which declares the input GROSS --
    // `amounts: amount, fees: fee` -- so the two sides balance in
    // `USDT_UNIT`: `amount >= (amount - fee) + fee`). Reporting `fee` again
    // here would double-count it and starve the primary module's minted
    // change by `fee`. The transaction-balancing framework calls this for
    // every input in a transaction being built
    // (`Client::finalize_and_submit_transaction` sums `input_fee`/
    // `output_fee` across all modules involved to compute the primary
    // module's balancing output), not only when this module happens to be
    // the primary one, so it must return `Some` for the real input variants
    // rather than `unreachable!()`.
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
    /// address out and later drive [`Self::submit_deposit_proof`] against it.
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
        // new addresses is gated -- proof-submit/withdraw/pool-state stay
        // ungated (a credited deposit is already backed in its own account).
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
    /// client-DB state was lost, re-storing each rediscovered claim key (so a
    /// later [`Self::submit_deposit_proof`] for its index can credit + mint
    /// against it).
    ///
    /// Gap-limit scan: walks seed-derivation indices from `0`, deriving
    /// [`Self::claim_keypair_for_index`] and querying the federation's
    /// `deposit_status` for each. An index whose account has been credited
    /// (`credited > 0`) is treated as used -- its claim key is re-stored
    /// ([`ClaimKeyKey`]) and recorded in [`RecoverySummary::accounts`] -- and
    /// resets the consecutive-miss counter; an uncredited index increments
    /// it. The scan stops after `gap_limit` consecutive misses.
    ///
    /// If `check_uncredited` is set (security finding 08), every scanned
    /// index that reports `credited == 0` ALSO has its claim key persisted,
    /// recorded in [`RecoverySummary::checked`] -- see "Known limitation"
    /// below. The consecutive-miss counter still advances for these indices
    /// (the scan still terminates at `gap_limit`); only
    /// [`Self::recover_deposits`] being run again (or an explicit `claim`)
    /// later picks up a deposit that becomes credited afterward, since
    /// [`NextDepositIndexKey`] is NOT advanced past a merely-persisted (not
    /// yet credited) index -- see below.
    ///
    /// After scanning, [`NextDepositIndexKey`] is advanced to one past the
    /// highest CREDITED index seen (not the highest checked one), so future
    /// [`Self::allocate_deposit`] calls do not collide with recovered
    /// deposits (left untouched if none were found).
    ///
    /// This does NOT auto-credit: recovery is deliberately read-mostly plus
    /// key-restoring, so the caller decides when to submit a deposit proof
    /// per rediscovered index. This explicit rescan (plus its CLI
    /// `recover` subcommand) is the module's recovery path; the module uses
    /// [`NoModuleBackup`], so it is not wired into the client's global
    /// `recover()` flow -- doing so is a possible follow-up.
    ///
    /// # Known limitation
    ///
    /// With `check_uncredited` set, a funded-but-uncredited deposit is no
    /// longer silently abandoned: its claim key is persisted as soon as this
    /// scan reaches its index. Crediting is proof-driven, so the caller must
    /// still fund + submit a `UsdtInput::DepositProofV0` proof (see Task 9's
    /// proof-submit flow) for the deposit to become claimable; this call
    /// itself neither triggers nor waits for crediting, so a caller may need
    /// to re-run `recover` (or poll `deposit-status` using the `claim_pk`
    /// recorded in [`RecoverySummary::checked`]) afterward.
    pub async fn recover_deposits(
        &self,
        gap_limit: u64,
        check_uncredited: bool,
    ) -> anyhow::Result<RecoverySummary> {
        Self::recover_deposits_scan(
            &self.db,
            &*self.module_api,
            &self.module_root_secret,
            gap_limit,
            check_uncredited,
        )
        .await
    }

    /// The scan loop behind [`Self::recover_deposits`], factored out as a
    /// free function generic over [`UsdtFederationApi`] (rather than an
    /// inherent method reading `self.module_api`) so it is unit-testable
    /// against a synthetic implementation without a live federation -- see
    /// the `mod tests` `FakeRecoveryApi`.
    async fn recover_deposits_scan<A>(
        db: &Database,
        api: &A,
        module_root_secret: &DerivableSecret,
        gap_limit: u64,
        check_uncredited: bool,
    ) -> anyhow::Result<RecoverySummary>
    where
        A: UsdtFederationApi + ?Sized,
    {
        let mut accounts = Vec::new();
        let mut checked = Vec::new();
        let mut total_credited = UsdtAmount(0);
        let mut total_claimable = UsdtAmount(0);
        let mut highest_used_index: Option<u64> = None;
        let mut consecutive_misses = 0u64;

        let mut index = 0u64;
        while consecutive_misses < gap_limit {
            let claim_keypair = Self::claim_keypair_static(module_root_secret, index);
            let claim_pk = claim_keypair.public_key();
            let status = api.deposit_status(claim_pk).await?;

            if status.credited.0 > 0 {
                let mut dbtx = db.begin_transaction().await;
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
                // Security finding 08: `deposit_status` alone cannot
                // distinguish a truly unused index from one that was funded
                // on-chain but not yet credited -- both report `credited == 0`
                // here. Rather than silently discarding the index, persist its
                // claim key when `check_uncredited` is set (so a follow-up
                // `UsdtInput::DepositProofV0` proof submission can credit +
                // mint it) -- this does NOT auto-credit (the caller still
                // decides when to submit the proof), it only ensures the
                // funds are not practically stranded. The miss counter still
                // advances so the scan terminates at `gap_limit`.
                if check_uncredited {
                    let mut dbtx = db.begin_transaction().await;
                    dbtx.insert_entry(&ClaimKeyKey(status.account), &claim_keypair)
                        .await;
                    dbtx.commit_tx().await;

                    checked.push(CheckedAccount {
                        index,
                        account: status.account,
                        claim_pk,
                    });
                }

                consecutive_misses += 1;
            }

            index += 1;
        }

        if let Some(highest) = highest_used_index {
            let mut dbtx = db.begin_transaction().await;
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
            checked,
        })
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

    /// Persists a client-configured Ethereum JSON-RPC URL that
    /// [`Self::submit_deposit_proof`] uses (unless a per-call `evm_rpc_url`
    /// argument overrides it) instead of the built-in
    /// [`evm::DEFAULT_EVM_RPC_URLS`] default. Pass `None` to clear it.
    pub async fn set_evm_rpc_url(&self, url: Option<String>) {
        let mut dbtx = self.db.begin_transaction().await;
        match url {
            Some(url) => {
                dbtx.insert_entry(&EvmRpcUrlKey, &url).await;
            }
            None => {
                dbtx.remove_entry(&EvmRpcUrlKey).await;
            }
        }
        dbtx.commit_tx().await;
    }

    /// Resolves the EVM RPC endpoint list [`Self::submit_deposit_proof`] should
    /// use, in precedence order: an explicit per-call `evm_rpc_url`, then a
    /// client-DB [`EvmRpcUrlKey`] override (see [`Self::set_evm_rpc_url`]),
    /// then the built-in [`evm::DEFAULT_EVM_RPC_URLS`].
    async fn resolve_evm_rpc_urls(&self, evm_rpc_url: Option<String>) -> Vec<String> {
        if let Some(url) = evm_rpc_url {
            return vec![url];
        }
        if let Some(url) = self
            .db
            .begin_transaction_nc()
            .await
            .get_value(&EvmRpcUrlKey)
            .await
        {
            return vec![url];
        }
        evm::DEFAULT_EVM_RPC_URLS
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    }

    /// Reports the newest confirmation-depth block height currently anchored
    /// in the federation's consensus block-hash ring, plus the retained window
    /// length (deposit-by-proof, Task 7; thin wrapper around
    /// [`UsdtFederationApi::latest_anchored_block`]).
    pub async fn latest_anchored_block(
        &self,
    ) -> anyhow::Result<fedimint_usdt_common::AnchoredBlockResponse> {
        Ok(self.module_api.latest_anchored_block().await?)
    }

    /// Credits (and, atomically in the same transaction, mints) the deposit at
    /// seed-derivation `index` by fetching an on-chain balance proof and
    /// submitting it as a [`UsdtInput::DepositProofV0`] (deposit-by-proof,
    /// Task 9). Returns the submitted transaction's [`OperationId`].
    ///
    /// Flow:
    /// 1. Derive the `index`'s claim key + deposit `account`
    ///    ([`Self::claim_keypair_for_index`]/[`Self::deposit_address`]) and
    ///    persist the claim key ([`ClaimKeyKey`]) so the deposit is
    ///    recoverable/claimable exactly as [`Self::allocate_deposit`] leaves
    ///    it.
    /// 2. Ask the federation for its newest anchored, confirmation-deep block
    ///    ([`Self::latest_anchored_block`]) and target the proof at it (the
    ///    ring only ever holds already-confirmed heights, so `latest` is a safe
    ///    target).
    /// 3. Fetch `eth_getProof(usdt_contract, [balances_storage_key(account)],
    ///    B)` and `eth_getBlockByNumber(B)` over the client's OWN WASM-safe
    ///    HTTP (see [`evm::EthJsonRpc`]), reconstruct + RLP-encode the header,
    ///    and assert `keccak256(header_rlp) == B.hash` locally before
    ///    submitting.
    /// 4. Submit a transaction pairing the `DepositProofV0` input (funding the
    ///    newly-proven delta GROSS, with the federation's deposit fee quote as
    ///    its `fee`) with the primary (USDT-denominated `mintv2`) module's mint
    ///    output for the NET `delta - fee` -- deposit + claim atomic (see
    ///    [`UsdtInput::DepositProofV0`]).
    ///
    /// `evm_rpc_url` overrides the endpoint for this call only; see
    /// [`Self::resolve_evm_rpc_urls`] for the precedence.
    ///
    /// `max_deposit_fee`/`accept_high_fee` are the security finding 07 fee
    /// cap applied to the freshly fetched deposit fee quote (see
    /// [`check_fee_cap`]).
    ///
    /// # Errors
    ///
    /// Returns an `Err` if the ring has anchored no block yet, the RPC calls
    /// fail, the header reconstruction does not hash to the block's own hash,
    /// the proof proves nothing new over what is already credited, the fee
    /// quote is unavailable or fails the [`check_fee_cap`] guard, or the fee
    /// would consume the whole newly-proven delta.
    pub async fn submit_deposit_proof(
        &self,
        index: u64,
        evm_rpc_url: Option<String>,
        max_deposit_fee: Option<UsdtAmount>,
        accept_high_fee: bool,
    ) -> anyhow::Result<OperationId> {
        let claim_keypair = self.claim_keypair_for_index(index);
        let account = self.deposit_address(&claim_keypair.public_key());

        let anchored = self.module_api.latest_anchored_block().await?;
        if anchored.latest == 0 {
            bail!("federation has not anchored any confirmation-deep block yet; try again shortly");
        }
        let block = anchored.latest;

        let urls = self.resolve_evm_rpc_urls(evm_rpc_url).await;
        let rpc = evm::EthJsonRpc::new(urls)?;
        let (proof, proven) = rpc
            .fetch_deposit_proof(self.cfg.usdt_contract, account, block)
            .await?;

        self.submit_prebuilt_deposit_proof(
            &claim_keypair,
            proof,
            proven,
            max_deposit_fee,
            accept_high_fee,
        )
        .await
    }

    /// Submits an already-built [`DepositProof`] of `claim_keypair`'s derived
    /// deposit account as a [`UsdtInput::DepositProofV0`], crediting AND
    /// minting the newly-proven delta (net of the federation's deposit fee
    /// quote) as USDT e-cash in one transaction.
    ///
    /// This is the transport-agnostic core of [`Self::submit_deposit_proof`]:
    /// the latter obtains `(proof, proven)` via the client's own WASM-safe
    /// `eth_getProof` fetch, but an out-of-band indexer (or a hermetic test)
    /// that already holds a proof can submit it directly here. `proven` is the
    /// balance the proof attests (used only to compute the credit delta over
    /// the federation's current `credited`; the authoritative balance is what
    /// the guardians independently re-derive from the trie).
    ///
    /// Fetches the federation's current deposit fee quote
    /// ([`Self::deposit_fee_quote`]), applies the security finding 07
    /// [`check_fee_cap`] guard against it (`max_deposit_fee`/
    /// `accept_high_fee`) BEFORE submitting
    /// anything, and supplies it as the input's `fee` -- the server validates
    /// it against its own fresh quote (client-supplies-server-validates, see
    /// [`UsdtInput::DepositProofV0`]).
    ///
    /// Persists `claim_keypair` under [`ClaimKeyKey`] (idempotent) so the
    /// deposit is claimable/recoverable exactly as [`Self::allocate_deposit`]
    /// leaves it.
    ///
    /// # Errors
    ///
    /// Returns an `Err` if the proof proves nothing new over what is already
    /// credited, the fee quote is unavailable or fails the fee-cap guard, the
    /// fee would consume the whole delta, or the submission is rejected.
    pub async fn submit_prebuilt_deposit_proof(
        &self,
        claim_keypair: &Keypair,
        proof: DepositProof,
        proven: UsdtAmount,
        max_deposit_fee: Option<UsdtAmount>,
        accept_high_fee: bool,
    ) -> anyhow::Result<OperationId> {
        let claim_pk = claim_keypair.public_key();
        let account = self.deposit_address(&claim_pk);

        {
            let mut dbtx = self.db.begin_transaction().await;
            dbtx.insert_entry(&ClaimKeyKey(account), claim_keypair)
                .await;
            dbtx.commit_tx().await;
        }

        // Only the delta over the account's existing high-water `credited` is
        // new, mintable value -- mirror the server's `process_deposit_proof`
        // high-water logic so the `ClientInput.amounts` we declare matches the
        // `InputMeta.amount` the server will return (or the transaction would
        // not balance).
        let status = self.module_api.deposit_status(claim_pk).await?;
        let delta = proven.0.saturating_sub(status.credited.0);
        if delta == 0 {
            bail!(
                "deposit proof proves {proven} but {} is already credited for {account}; nothing \
                 new to credit",
                status.credited,
            );
        }

        // Security finding 07: the fee-cap guard runs against the freshly
        // fetched quote BEFORE any transaction is built or submitted.
        let fee = self.deposit_fee_quote().await?.fee;
        check_fee_cap(
            fee,
            UsdtAmount(delta),
            max_deposit_fee,
            accept_high_fee,
            "--max-deposit-fee",
        )?;

        self.submit_deposit_proof_input(claim_keypair, account, proof, UsdtAmount(delta), fee)
            .await
    }

    /// Builds the [`UsdtInput::DepositProofV0`] client input funding `delta`
    /// (in [`USDT_UNIT`]) with `claim_keypair`, charging `fee`, submits it
    /// paired with the primary (USDT-denominated `mintv2`) module's mint
    /// output, and awaits the e-cash issuance -- the deposit-by-proof
    /// implicit-funding submission path,
    /// crediting AND minting atomically net of the deposit fee. Factored out
    /// of [`Self::submit_deposit_proof`] so a hermetic test can drive it with
    /// a pre-built [`DepositProof`] + delta without a live EVM RPC.
    async fn submit_deposit_proof_input(
        &self,
        claim_keypair: &Keypair,
        account: EvmAddress,
        proof: DepositProof,
        delta: UsdtAmount,
        fee: UsdtAmount,
    ) -> anyhow::Result<OperationId> {
        let input = Self::deposit_proof_input(claim_keypair, proof, delta, fee)?;

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
                // The REAL deposit fee charged (per `Self::deposit_fee_quote`
                // at submission time); the e-cash minted is `delta - fee`.
                move |_range| UsdtOperationMeta::Claim {
                    account,
                    amount: delta,
                    fee,
                },
                tx,
            )
            .await?;

        // Await the USDT-denominated `mintv2` primary module's e-cash issuance,
        // the deposit's e-cash is minted for the
        // input's NET `delta - fee` funding, and issuance completes strictly
        // after the transaction is submitted.
        self.client_ctx
            .await_primary_module_outputs_for_unit(
                operation_id,
                range.into_iter().collect(),
                USDT_UNIT,
            )
            .await?;

        Ok(operation_id)
    }

    /// Builds the [`UsdtInput::DepositProofV0`] `ClientInput` claiming a
    /// newly-proven `delta` for `claim_keypair`'s derived deposit account,
    /// charging `fee` via NET issuance (mirroring [`Self::claim_input`]
    /// exactly): the input's own `fee` field carries the fee the server
    /// verifies against its own quote, while `amounts` is set to
    /// `delta - fee` so the USDT-`mintv2` primary module mints exactly that
    /// much e-cash. The server's `process_deposit_proof` declares the input
    /// GROSS (`amounts: delta, fees: fee`), so the two sides balance in
    /// [`USDT_UNIT`]. A pure, synchronous helper (no network/DB access) so
    /// the input construction is unit-testable.
    ///
    /// # Errors
    ///
    /// Returns an `Err` if `fee` would consume all or more of `delta`
    /// (mirroring the server's `UsdtInputError::FeeExceedsAmount` rejection,
    /// but caught locally before ever building/submitting the transaction).
    fn deposit_proof_input(
        claim_keypair: &Keypair,
        proof: DepositProof,
        delta: UsdtAmount,
        fee: UsdtAmount,
    ) -> anyhow::Result<ClientInput<UsdtInput>> {
        if delta.0 <= fee.0 {
            bail!("newly-proven deposit delta {delta} does not cover the {fee} deposit fee");
        }

        Ok(ClientInput {
            input: UsdtInput::DepositProofV0 {
                claim_pk: claim_keypair.public_key(),
                proof,
                fee,
            },
            keys: vec![*claim_keypair],
            amounts: Amounts::new_custom(USDT_UNIT, usdt_amount(UsdtAmount(delta.0 - fee.0))),
        })
    }

    /// Adversarial/test-only: submit an ARBITRARY, hand-crafted [`UsdtInput`]
    /// (paired 1:1 with a USDT-`mintv2` mint output funding `declared`)
    /// directly through the client transaction API, bypassing every honest
    /// builder (`submit_deposit_proof`/`submit_prebuilt_deposit_proof`)
    /// and their client-side gates
    /// (delta/`claimable`/fee-cap). This is the raw submission primitive
    /// the `fedimint-usdt-tests` security harness uses to play a malicious
    /// client against the deposit-by-proof flow: it replicates exactly what
    /// [`Self::submit_deposit_proof_input`] does, but with a caller-
    /// supplied `input`, `keys`, and `declared` value rather than a
    /// server-validated one.
    ///
    /// Returns [`CraftedInputOutcome::Rejected`] (the guardians' rejection
    /// reason) when the federation refuses the crafted transaction -- the
    /// expected result for a malicious input, meaning the defense held -- or
    /// [`CraftedInputOutcome::Accepted`] once the paired mint output is
    /// actually issued, meaning the crafted input CREDITED/MINTED value (a
    /// security finding for any adversarial input).
    ///
    /// Gated behind the non-default `test-util` feature so it is never compiled
    /// into the guardian/gateway release image.
    ///
    /// # Errors
    ///
    /// Returns an `Err` only for infrastructure failures (finalizing/submitting
    /// the transaction, or awaiting issuance of an accepted one) -- NOT for a
    /// federation rejection, which is reported as
    /// [`CraftedInputOutcome::Rejected`].
    #[cfg(feature = "test-util")]
    pub async fn submit_crafted_input_for_test(
        &self,
        input: UsdtInput,
        keys: Vec<Keypair>,
        declared: UsdtAmount,
    ) -> anyhow::Result<CraftedInputOutcome> {
        let client_input = ClientInput {
            input,
            keys,
            amounts: Amounts::new_custom(USDT_UNIT, usdt_amount(declared)),
        };

        let operation_id = OperationId::new_random();
        let tx = TransactionBuilder::new().with_inputs(
            self.client_ctx
                .make_client_inputs(ClientInputBundle::new_no_sm(vec![client_input])),
        );

        let range = self
            .client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                KIND.as_str(),
                move |_range| UsdtOperationMeta::Claim {
                    account: EvmAddress([0u8; 20]),
                    amount: declared,
                    fee: UsdtAmount(0),
                },
                tx,
            )
            .await?;
        let txid = range.txid();

        // A malicious input is rejected during consensus input-processing, which
        // surfaces here as a `Rejected` transaction-submission state carrying the
        // guardians' (deterministic, identical-across-guardians) rejection
        // reason. That is the EXPECTED outcome -- the defense held.
        if let Err(reason) = self
            .client_ctx
            .transaction_updates(operation_id)
            .await
            .await_tx_accepted(txid)
            .await
        {
            return Ok(CraftedInputOutcome::Rejected { reason });
        }

        // Accepted: the crafted input funded value the federation credited. Await
        // the paired USDT-`mintv2` issuance to confirm the value was actually
        // minted into spendable e-cash before reporting the (finding) outcome.
        self.client_ctx
            .await_primary_module_outputs_for_unit(
                operation_id,
                range.into_iter().collect(),
                USDT_UNIT,
            )
            .await?;

        Ok(CraftedInputOutcome::Accepted { minted: declared })
    }

    /// Reports the federation's current deposit fee quote: the minimum `fee`
    /// a deposit claim must offer right now
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
    /// [`Self::submit_prebuilt_deposit_proof`], `fedimint-cli`'s
    /// `deposit-fee-quote`/`submit-deposit-proof`)
    /// therefore inherits this bail rather than silently claiming for `0`
    /// fee and hitting `process_input`'s `NoFeeQuoteAvailable` rejection
    /// later.
    pub async fn deposit_fee_quote(&self) -> anyhow::Result<DepositFeeQuoteResponse> {
        let quote = self.module_api.deposit_fee_quote().await?;
        let available = quote.available;
        ensure_fee_quote_available(quote, available)
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
    /// with an exponential-backoff polling
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
    /// primary module's existing notes, mirroring the deposit-proof path's
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
    /// (`submit_deposit_proof_input`), which likewise submits and lets the
    /// caller poll for the effect rather than blocking on the primary
    /// module's output state machines here.
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
                DbKeyPrefix::EvmRpcUrl => {
                    push_db_pair_items!(
                        dbtx,
                        EvmRpcUrlPrefixAll,
                        EvmRpcUrlKey,
                        String,
                        items,
                        "Usdt Evm Rpc Url"
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
    use std::collections::BTreeMap;

    use fedimint_api_client::api::FederationResult;
    use fedimint_core::db::mem_impl::MemDatabase;
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_derive_secret::DerivableSecret;

    use super::{
        Amount, Amounts, Database, DepositFeeQuoteResponse, DepositProof, DepositStatusResponse,
        EvmAddress, FEE_QUOTE_UNAVAILABLE_MESSAGE, IDatabaseTransactionOpsCoreTyped, Keypair,
        OutPoint, PeerId, PoolStateResponse, RefundStatusResponse, SECP256K1, StatusResponse,
        USDT_UNIT, UsdtAmount, UsdtClientModule, UsdtFederationApi, UsdtInput,
        UserOpStatusResponse, WithdrawFeeQuoteResponse, WithdrawalStatusResponse, check_fee_cap,
        ensure_fee_quote_available, secp256k1,
    };
    use crate::db::{ClaimKeyKey, NextDepositIndexKey};

    /// Deterministic test keypair (mirrors
    /// [`UsdtClientModule::claim_keypair_static`]'s derivation, but with an
    /// arbitrary fixed seed -- this test needs *a* keypair, not a
    /// particular one).
    fn test_keypair() -> Keypair {
        DerivableSecret::new_root(b"usdt-claim-input-test-seed", b"salt").to_secp_key(SECP256K1)
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

    /// [`UsdtClientModule::deposit_proof_input`] must build a `DepositProofV0`
    /// input signed by the claim key, carrying the quote-derived `fee` in the
    /// input itself, and funding the NET `delta - fee` as its
    /// `ClientInput.amounts` (mirroring [`UsdtClientModule::claim_input`]'s
    /// net-issuance pattern), so the transaction balances against the
    /// server's `process_deposit_proof` GROSS declaration (`amounts: delta,
    /// fees: fee, pub_key: claim_pk`) and the USDT-`mintv2` primary module
    /// mints exactly `delta - fee`.
    #[test]
    fn deposit_proof_input_binds_claim_key_fee_and_net_delta() {
        let keypair = test_keypair();
        let delta = UsdtAmount(500_000_000);
        let fee = UsdtAmount(2_880_000);
        let proof = DepositProof {
            block_number: 100,
            header_rlp: vec![0x01, 0x02, 0x03],
            account_proof: vec![vec![0xaa]],
            storage_proof: vec![vec![0xbb]],
        };

        let input = UsdtClientModule::deposit_proof_input(&keypair, proof.clone(), delta, fee)
            .expect("delta comfortably exceeds fee");

        match input.input {
            UsdtInput::DepositProofV0 {
                claim_pk,
                proof: input_proof,
                fee: input_fee,
            } => {
                assert_eq!(
                    claim_pk,
                    keypair.public_key(),
                    "the input must carry the claim key the server derives the account from"
                );
                assert_eq!(input_proof, proof, "the proof must be carried verbatim");
                assert_eq!(
                    input_fee, fee,
                    "the input must carry the quote-derived fee for the server to validate"
                );
            }
            UsdtInput::RefundV0 { .. } | UsdtInput::Default { .. } => {
                panic!("deposit_proof_input must build a DepositProofV0 input")
            }
        }
        assert_eq!(
            input.keys,
            vec![keypair],
            "the input must be signed by the claim key"
        );
        assert_eq!(
            input.amounts,
            Amounts::new_custom(USDT_UNIT, Amount::from_msats(delta.0 - fee.0)),
            "ClientInput.amounts must be the NET delta - fee, not the gross delta"
        );
    }

    /// An uneconomical deposit proof (the fee would consume all or more of
    /// the newly-proven delta) must be rejected locally, before ever building
    /// or submitting a transaction -- mirroring the server's
    /// `UsdtInputError::FeeExceedsAmount` rejection and
    /// [`UsdtClientModule::claim_input`]'s identical local guard.
    #[test]
    fn deposit_proof_input_rejects_uneconomical_delta() {
        let keypair = test_keypair();
        let proof = DepositProof {
            block_number: 100,
            header_rlp: vec![0x01],
            account_proof: vec![],
            storage_proof: vec![],
        };

        // fee == delta.
        let err = UsdtClientModule::deposit_proof_input(
            &keypair,
            proof.clone(),
            UsdtAmount(500),
            UsdtAmount(500),
        )
        .expect_err("fee equal to delta must be rejected");
        assert!(err.to_string().contains("deposit fee"));

        // fee > delta.
        UsdtClientModule::deposit_proof_input(&keypair, proof, UsdtAmount(500), UsdtAmount(600))
            .expect_err("fee exceeding delta must be rejected");
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

    // --- security finding 08: `recover_deposits_scan` -----------------------

    fn zero_status(account: EvmAddress) -> DepositStatusResponse {
        DepositStatusResponse {
            account,
            credited: UsdtAmount(0),
            claimed: UsdtAmount(0),
            claimable: UsdtAmount(0),
        }
    }

    fn mem_db() -> Database {
        Database::new(MemDatabase::new(), ModuleDecoderRegistry::default())
    }

    /// A synthetic [`UsdtFederationApi`] for exercising
    /// [`UsdtClientModule::recover_deposits_scan`] without a live federation.
    /// Only `deposit_status` is exercised by the scan loop; every other trait
    /// method panics if called -- a panic there would mean the loop grew a
    /// dependency this fake needs updating for, not a bug in the test itself.
    struct FakeRecoveryApi {
        /// `claim_pk -> deposit_status` response for indices configured by
        /// the test. Any `claim_pk` not present here reports an all-zero
        /// response at a synthetic account, mirroring a genuinely unused
        /// index.
        responses: BTreeMap<secp256k1::PublicKey, DepositStatusResponse>,
    }

    impl FakeRecoveryApi {
        fn new(responses: BTreeMap<secp256k1::PublicKey, DepositStatusResponse>) -> Self {
            Self { responses }
        }

        fn status_for(&self, claim_pk: &secp256k1::PublicKey) -> DepositStatusResponse {
            self.responses
                .get(claim_pk)
                .cloned()
                .unwrap_or_else(|| zero_status(EvmAddress([0u8; 20])))
        }
    }

    #[async_trait::async_trait]
    impl UsdtFederationApi for FakeRecoveryApi {
        async fn group_public_key(&self) -> FederationResult<secp256k1::PublicKey> {
            unimplemented!("recover_deposits_scan never calls group_public_key")
        }

        async fn deposit_status(
            &self,
            claim_pk: secp256k1::PublicKey,
        ) -> FederationResult<DepositStatusResponse> {
            Ok(self.status_for(&claim_pk))
        }

        async fn pool_state(&self, _peer: PeerId) -> FederationResult<PoolStateResponse> {
            unimplemented!("recover_deposits_scan never calls pool_state")
        }

        async fn userop_status(
            &self,
            _peer: PeerId,
            _op_hash: [u8; 32],
        ) -> FederationResult<UserOpStatusResponse> {
            unimplemented!("recover_deposits_scan never calls userop_status")
        }

        async fn withdraw_fee_quote(
            &self,
            _amount: UsdtAmount,
        ) -> FederationResult<WithdrawFeeQuoteResponse> {
            unimplemented!("recover_deposits_scan never calls withdraw_fee_quote")
        }

        async fn deposit_fee_quote(&self) -> FederationResult<DepositFeeQuoteResponse> {
            unimplemented!("recover_deposits_scan never calls deposit_fee_quote")
        }

        async fn withdrawal_status(
            &self,
            _out_point: OutPoint,
        ) -> FederationResult<WithdrawalStatusResponse> {
            unimplemented!("recover_deposits_scan never calls withdrawal_status")
        }

        async fn refund_status(
            &self,
            _out_point: OutPoint,
        ) -> FederationResult<RefundStatusResponse> {
            unimplemented!("recover_deposits_scan never calls refund_status")
        }

        async fn status(&self) -> FederationResult<StatusResponse> {
            unimplemented!("recover_deposits_scan never calls status")
        }

        async fn latest_anchored_block(
            &self,
        ) -> FederationResult<fedimint_usdt_common::AnchoredBlockResponse> {
            unimplemented!("recover_deposits_scan never calls latest_anchored_block")
        }

        async fn withdraw_fees(
            &self,
            _recipient: EvmAddress,
            _amount: UsdtAmount,
            _auth: fedimint_core::module::ApiAuth,
        ) -> FederationResult<()> {
            unimplemented!("recover_deposits_scan never calls withdraw_fees")
        }
    }

    /// The crux of security finding 08's fix: a funded-but-uncredited deposit
    /// (`credited == 0` at scan time, indistinguishable via `deposit_status`
    /// alone from a genuinely unused index) must, with `check_uncredited:
    /// true`, have its claim key persisted -- rather than being silently
    /// discarded as a "miss" -- so a later `UsdtInput::DepositProofV0` credit +
    /// `claim` can recover it from seed alone.
    #[tokio::test]
    async fn recovery_persists_uncredited_indices_when_enabled() {
        let secret = DerivableSecret::new_root(b"usdt-recovery-uncredited-test-seed", b"salt");
        let db = mem_db();

        let claim_keypair0 = UsdtClientModule::claim_keypair_static(&secret, 0);
        let claim_pk0 = claim_keypair0.public_key();
        let account0 = EvmAddress([0x42; 20]);
        let mut responses = BTreeMap::new();
        responses.insert(claim_pk0, zero_status(account0));
        let api = FakeRecoveryApi::new(responses);

        let gap_limit = 3;
        let summary = UsdtClientModule::recover_deposits_scan(&db, &api, &secret, gap_limit, true)
            .await
            .expect("recovery must not fail even though nothing is credited");

        // Nothing was CREDITED, so the "recovered"/`accounts` side stays empty.
        assert_eq!(summary.recovered, 0);
        assert!(summary.accounts.is_empty());

        // Every scanned index (0..gap_limit, all misses) was persisted, index 0
        // among them.
        assert_eq!(
            summary.checked.len(),
            usize::try_from(gap_limit).expect("gap_limit fits in usize in this test")
        );
        let checked0 = summary
            .checked
            .iter()
            .find(|c| c.index == 0)
            .expect("index 0 must be in the checked list");
        assert_eq!(checked0.account, account0);
        assert_eq!(checked0.claim_pk, claim_pk0);

        // The claim key was persisted, so a later deposit-proof submission
        // can use it the moment the deposit becomes credited -- this is the
        // crux of the fix: seed-only recovery no longer discards uncredited
        // indices.
        let mut dbtx = db.begin_transaction_nc().await;
        let stored = dbtx
            .get_value(&ClaimKeyKey(account0))
            .await
            .expect("claim key for the uncredited index must be persisted");
        assert_eq!(stored.public_key(), claim_pk0);
    }

    /// Contrast with [`recovery_persists_uncredited_indices_when_enabled`]:
    /// `check_uncredited: false` must restore the exact pre-fix behavior --
    /// uncredited indices are not persisted.
    #[tokio::test]
    async fn recovery_skips_uncredited_indices_when_check_uncredited_is_false() {
        let secret = DerivableSecret::new_root(b"usdt-recovery-opt-out-test-seed", b"salt");
        let db = mem_db();

        let claim_keypair0 = UsdtClientModule::claim_keypair_static(&secret, 0);
        let claim_pk0 = claim_keypair0.public_key();
        let account0 = EvmAddress([0x43; 20]);
        let mut responses = BTreeMap::new();
        responses.insert(claim_pk0, zero_status(account0));
        let api = FakeRecoveryApi::new(responses);

        let gap_limit = 3;
        let summary = UsdtClientModule::recover_deposits_scan(&db, &api, &secret, gap_limit, false)
            .await
            .expect("recovery must not fail");

        assert!(summary.checked.is_empty());

        let mut dbtx = db.begin_transaction_nc().await;
        assert!(
            dbtx.get_value(&ClaimKeyKey(account0)).await.is_none(),
            "with check_uncredited=false, an uncredited index's claim key must NOT be persisted"
        );
    }

    /// `NextDepositIndexKey` must advance only past the highest CREDITED
    /// index, never past a merely-persisted-but-uncredited one -- otherwise a
    /// later `allocate_deposit` would skip past indices whose deposits might
    /// still be pending credit.
    #[tokio::test]
    async fn recovery_advances_next_deposit_index_only_past_credited_indices() {
        let secret = DerivableSecret::new_root(b"usdt-recovery-index-advance-test-seed", b"salt");
        let db = mem_db();

        let claim_keypair0 = UsdtClientModule::claim_keypair_static(&secret, 0);
        let account0 = EvmAddress([0x45; 20]);
        let mut responses = BTreeMap::new();
        responses.insert(
            claim_keypair0.public_key(),
            DepositStatusResponse {
                account: account0,
                credited: UsdtAmount(1_000_000),
                claimed: UsdtAmount(0),
                claimable: UsdtAmount(1_000_000),
            },
        );
        let api = FakeRecoveryApi::new(responses);

        let gap_limit = 3;
        let summary = UsdtClientModule::recover_deposits_scan(&db, &api, &secret, gap_limit, true)
            .await
            .expect("recovery must not fail");

        assert_eq!(summary.recovered, 1);
        // Indices 1..=3 are misses (checked but uncredited).
        assert_eq!(
            summary.checked.len(),
            usize::try_from(gap_limit).expect("gap_limit fits in usize in this test")
        );

        let mut dbtx = db.begin_transaction_nc().await;
        let next_index = dbtx
            .get_value(&NextDepositIndexKey)
            .await
            .expect("NextDepositIndexKey must be set after a credited recovery");
        assert_eq!(
            next_index, 1,
            "NextDepositIndexKey must advance only past the highest CREDITED index"
        );
    }
}
