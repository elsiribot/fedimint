use std::{ffi, iter};

use clap::Parser;
use fedimint_core::{OutPoint, TransactionId, secp256k1};
use fedimint_usdt_common::{EvmAddress, UsdtAmount};
use serde::Serialize;
use serde_json::Value;

use crate::{UsdtClientModule, check_fee_cap};

#[derive(Debug, Clone, Parser, Serialize)]
enum Opts {
    /// Allocate a fresh claim key, persist it, and print the deposit address
    /// derived from it (`account`) together with the claim public key
    /// (`claim_pk`) needed by `deposit-status`/`claim`.
    DepositAddress,
    /// Report the credited/claimed/claimable state of `claim_pk`'s deposit
    /// account.
    DepositStatus { claim_pk: secp256k1::PublicKey },
    /// Submit a claim transaction for `claim_pk`'s currently claimable
    /// balance (requires a nonzero `claimable` from `deposit-status`, and
    /// that `claim_pk` was previously produced by `deposit-address` on this
    /// client).
    ///
    /// By default, refuses to submit if the federation's deposit fee quote
    /// is more than 25% of the claimable amount (security finding 07) --
    /// pass `--accept-high-fee` to proceed anyway, or `--max-deposit-fee` to
    /// set an explicit hard cap instead of the default sanity guard.
    Claim {
        claim_pk: secp256k1::PublicKey,
        /// Refuse to submit if the federation's deposit fee quote exceeds
        /// this many smallest-on-chain-USDT-units. A hard ceiling: unlike
        /// the default sanity guard, `--accept-high-fee` cannot override it.
        #[arg(long)]
        max_deposit_fee: Option<u64>,
        /// Bypass the default 25%-of-amount sanity guard when no
        /// `--max-deposit-fee` is given. Has no effect if `--max-deposit-fee`
        /// is set.
        #[arg(long)]
        accept_high_fee: bool,
    },
    /// Report the federation's current withdrawal fee quote for `amount`
    /// (the smallest on-chain USDT unit, 1e-6 USDT) -- the minimum `max_fee`
    /// a `withdraw` of `amount` must offer right now.
    FeeQuote { amount: u64 },
    /// Report the federation's current deposit fee quote -- the minimum
    /// `fee` a `claim` must offer right now to cover the federation's
    /// deploy+sweep gas cost of a credited deposit.
    DepositFeeQuote,
    /// Fetch the current withdrawal fee quote, submit a withdrawal of
    /// `amount` (the smallest on-chain USDT unit) to `recipient` (a
    /// 20-byte, optionally `0x`-prefixed hex EVM address), and print the
    /// enqueued withdrawal's `OutPoint` -- pass it to `withdrawal-status`
    /// to track the withdrawal.
    ///
    /// By default, refuses to submit if the federation's withdrawal fee
    /// quote is more than 25% of `amount` (security finding 07) -- pass
    /// `--accept-high-fee` to proceed anyway, or `--max-fee` to set an
    /// explicit hard cap instead of the default sanity guard.
    Withdraw {
        recipient: EvmAddress,
        amount: u64,
        /// Refuse to submit if the federation's withdrawal fee quote
        /// exceeds this many smallest-on-chain-USDT-units. A hard ceiling:
        /// unlike the default sanity guard, `--accept-high-fee` cannot
        /// override it.
        #[arg(long)]
        max_fee: Option<u64>,
        /// Bypass the default 25%-of-amount sanity guard when no
        /// `--max-fee` is given. Has no effect if `--max-fee` is set.
        #[arg(long)]
        accept_high_fee: bool,
    },
    /// Report the consensus-agreed lifecycle stage
    /// (`Unknown`/`Queued`/`Signing`/`Submitted`/`Confirmed`/`Failed`) of a
    /// queued withdrawal, identified by the `OutPoint` (`txid`, `out_idx`)
    /// of the `withdraw` output that enqueued it.
    WithdrawalStatus { txid: TransactionId, out_idx: u64 },
    /// Report a guardian's consensus view of the pool `SimpleAccount`'s
    /// derived address (`account`) and swept-in USDT balance (`balance`, the
    /// smallest on-chain USDT unit). Queried from the lowest-id peer;
    /// `account` is config-derived so every guardian agrees on it even before
    /// the first sweep, and `balance` converges to the swept-in total once a
    /// sweep's `UserOpConfirmed` reaches threshold agreement.
    PoolState,
    /// Report the module's consensus-agreed readiness state
    /// (`AwaitingInfra`/`Ready`/`Degraded`) and the per-condition tally.
    /// `deposit-address` is refused unless this reports `Ready`.
    Status,
    /// Rescan the federation from the seed alone to rediscover deposits whose
    /// client-DB state was lost, re-storing each rediscovered claim key (so
    /// `claim` can then be run per account) and printing a summary. Scans
    /// seed-derivation indices from 0, stopping after `gap_limit` consecutive
    /// unused indices.
    ///
    /// By default (security finding 08), every scanned index reporting
    /// `credited == 0` -- a deposit that was funded on-chain but not yet
    /// credited (via a `deposit-proof` submission) -- ALSO has its claim key
    /// persisted, so it is no longer practically stranded; see the `checked`
    /// field of the printed summary. Pass `--check-uncredited=false` to
    /// restore the old credited-only behavior.
    Recover {
        #[arg(long, default_value = "20")]
        gap_limit: u64,
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        check_uncredited: bool,
    },
    /// Derive `claim_pk`/`account` for seed-derivation `index` WITHOUT
    /// persisting anything or advancing the next-deposit-index counter
    /// (security finding 08). Lets a seed-only user (after client-DB loss)
    /// recompute the `claim_pk` needed for a manual
    /// `deposit-status`/`claim`, e.g. for an index a `recover` scan reported
    /// under `checked`.
    DeriveDeposit {
        #[arg(long)]
        index: u64,
    },
}

/// Handles `Opts::Withdraw`, factored out of [`handle_cli_command`] purely to
/// keep that function under clippy's `too_many_lines` pedantic limit -- no
/// behavior change from when this was inlined.
async fn handle_withdraw(
    usdt: &UsdtClientModule,
    recipient: EvmAddress,
    amount: u64,
    max_fee: Option<u64>,
    accept_high_fee: bool,
) -> anyhow::Result<Value> {
    let amount = UsdtAmount(amount);
    let quote = usdt.withdraw_fee_quote(amount).await?;
    // Security finding 07: the fee-cap guard runs BEFORE `usdt.withdraw`
    // ever burns e-cash -- a rejection here never reaches the library's
    // transaction submission.
    check_fee_cap(
        quote.max_fee,
        amount,
        max_fee.map(UsdtAmount),
        accept_high_fee,
        "--max-fee",
    )?;
    let total_debit = UsdtAmount(amount.0.saturating_add(quote.max_fee.0));
    let range = usdt.withdraw(recipient, amount, quote.max_fee).await?;
    let out_point = UsdtClientModule::withdrawal_out_point(&range);
    Ok(json(serde_json::json!({
        "out_point": out_point.to_string(),
        "recipient": recipient.to_string(),
        "amount": amount.0,
        "max_fee": quote.max_fee.0,
        "total_debit": total_debit.0,
    })))
}

/// Handles `Opts::WithdrawalStatus`, factored out of [`handle_cli_command`]
/// for the same reason as [`handle_withdraw`].
async fn handle_withdrawal_status(
    usdt: &UsdtClientModule,
    out_point: OutPoint,
) -> anyhow::Result<Value> {
    let status = usdt.withdrawal_status(out_point).await?;
    // Security finding 09: on a terminal failure, also surface the
    // reissued-e-cash refund (amount + reason) the withdrawal's refund
    // state machine will claim (or has claimed) back to this client.
    let refund = usdt.refund_status(out_point).await?.refund;
    Ok(json(serde_json::json!({
        "status": status.status,
        "refund": refund.map(|info| serde_json::json!({
            "amount": info.amount.0,
            "reason": info.reason,
        })),
    })))
}

pub(crate) async fn handle_cli_command(
    usdt: &UsdtClientModule,
    args: &[ffi::OsString],
) -> anyhow::Result<Value> {
    let opts = Opts::parse_from(iter::once(&ffi::OsString::from("usdt")).chain(args.iter()));

    let value = match opts {
        Opts::DepositAddress => {
            let (claim_keypair, account) = usdt.allocate_deposit().await?;
            json(serde_json::json!({
                "claim_pk": claim_keypair.public_key(),
                "account": account.to_string(),
            }))
        }
        Opts::DepositStatus { claim_pk } => json(usdt.deposit_status(claim_pk).await?),
        Opts::Claim {
            claim_pk,
            max_deposit_fee,
            accept_high_fee,
        } => {
            // The security finding 07 fee-cap guard runs inside
            // `usdt.claim` (via `submit_claim`), BEFORE any e-cash is
            // minted -- it needs the freshly fetched deposit-fee quote,
            // which is only available once `claim` fetches it internally.
            let result = usdt
                .claim(claim_pk, max_deposit_fee.map(UsdtAmount), accept_high_fee)
                .await?;
            let net = UsdtAmount(result.claimed.0.saturating_sub(result.fee.0));
            json(serde_json::json!({
                "claimed": result.claimed.0,
                "fee": result.fee.0,
                "net": net.0,
            }))
        }
        Opts::FeeQuote { amount } => json(usdt.withdraw_fee_quote(UsdtAmount(amount)).await?),
        Opts::DepositFeeQuote => json(usdt.deposit_fee_quote().await?),
        Opts::Withdraw {
            recipient,
            amount,
            max_fee,
            accept_high_fee,
        } => handle_withdraw(usdt, recipient, amount, max_fee, accept_high_fee).await?,
        Opts::WithdrawalStatus { txid, out_idx } => {
            handle_withdrawal_status(usdt, OutPoint { txid, out_idx }).await?
        }
        Opts::PoolState => {
            // Any guardian answers identically (config-derived account +
            // threshold-agreed balance); query the lowest-id peer. Emit
            // `account` as a hex string (mirroring `DepositAddress`) rather
            // than `PoolStateResponse`'s derived `Serialize`, whose
            // `EvmAddress` newtype serializes as a raw 20-number array.
            let peer = usdt
                .all_peers()
                .into_iter()
                .next()
                .expect("a joined federation always has at least one peer");
            let pool = usdt.pool_state(peer).await?;
            json(serde_json::json!({
                "account": pool.account.to_string(),
                "balance": pool.balance.0,
            }))
        }
        Opts::Status => json(usdt.status().await?),
        Opts::Recover {
            gap_limit,
            check_uncredited,
        } => json(usdt.recover_deposits(gap_limit, check_uncredited).await?),
        Opts::DeriveDeposit { index } => {
            let claim_keypair = usdt.claim_keypair_for_index(index);
            let account = usdt.deposit_address(&claim_keypair.public_key());
            json(serde_json::json!({
                "index": index,
                "claim_pk": claim_keypair.public_key(),
                "account": account.to_string(),
            }))
        }
    };

    Ok(value)
}

fn json<T: Serialize>(value: T) -> Value {
    serde_json::to_value(value).expect("JSON serialization failed")
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::Opts;

    /// A valid compressed secp256k1 public key (the SECP256K1 generator
    /// point), used only to exercise CLI arg parsing -- no real deposit is
    /// involved.
    const TEST_PUBKEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    #[test]
    fn parses_deposit_address() {
        assert!(matches!(
            Opts::try_parse_from(["usdt", "deposit-address"]).expect("parses"),
            Opts::DepositAddress
        ));
    }

    #[test]
    fn parses_deposit_status() {
        assert!(matches!(
            Opts::try_parse_from(["usdt", "deposit-status", TEST_PUBKEY]).expect("parses"),
            Opts::DepositStatus { .. }
        ));
    }

    #[test]
    fn parses_claim() {
        // Bare `claim` (no fee-cap flags) must still parse, defaulting the
        // security finding 07 cap flags to "no explicit cap, sanity guard
        // not bypassed" -- `claim`'s default sanity guard applies.
        assert!(matches!(
            Opts::try_parse_from(["usdt", "claim", TEST_PUBKEY]).expect("parses"),
            Opts::Claim {
                max_deposit_fee: None,
                accept_high_fee: false,
                ..
            }
        ));
    }

    #[test]
    fn parses_claim_with_max_deposit_fee() {
        assert!(matches!(
            Opts::try_parse_from(["usdt", "claim", TEST_PUBKEY, "--max-deposit-fee", "1000"])
                .expect("parses"),
            Opts::Claim {
                max_deposit_fee: Some(1000),
                accept_high_fee: false,
                ..
            }
        ));
    }

    #[test]
    fn parses_claim_with_accept_high_fee() {
        assert!(matches!(
            Opts::try_parse_from(["usdt", "claim", TEST_PUBKEY, "--accept-high-fee"])
                .expect("parses"),
            Opts::Claim {
                max_deposit_fee: None,
                accept_high_fee: true,
                ..
            }
        ));
    }

    #[test]
    fn parses_fee_quote() {
        assert!(matches!(
            Opts::try_parse_from(["usdt", "fee-quote", "1000000"]).expect("parses"),
            Opts::FeeQuote { amount: 1_000_000 }
        ));
    }

    #[test]
    fn parses_deposit_fee_quote() {
        assert!(matches!(
            Opts::try_parse_from(["usdt", "deposit-fee-quote"]).expect("parses"),
            Opts::DepositFeeQuote
        ));
    }

    #[test]
    fn parses_withdraw() {
        // Bare `withdraw` (no fee-cap flags) must still parse, defaulting
        // the security finding 07 cap flags to "no explicit cap, sanity
        // guard not bypassed".
        assert!(matches!(
            Opts::try_parse_from([
                "usdt",
                "withdraw",
                "0x1111111111111111111111111111111111111111",
                "2000000"
            ])
            .expect("parses"),
            Opts::Withdraw {
                amount: 2_000_000,
                max_fee: None,
                accept_high_fee: false,
                ..
            }
        ));
    }

    #[test]
    fn parses_withdraw_with_max_fee() {
        assert!(matches!(
            Opts::try_parse_from([
                "usdt",
                "withdraw",
                "0x1111111111111111111111111111111111111111",
                "2000000",
                "--max-fee",
                "50000"
            ])
            .expect("parses"),
            Opts::Withdraw {
                amount: 2_000_000,
                max_fee: Some(50_000),
                accept_high_fee: false,
                ..
            }
        ));
    }

    #[test]
    fn parses_withdraw_with_accept_high_fee() {
        assert!(matches!(
            Opts::try_parse_from([
                "usdt",
                "withdraw",
                "0x1111111111111111111111111111111111111111",
                "2000000",
                "--accept-high-fee"
            ])
            .expect("parses"),
            Opts::Withdraw {
                amount: 2_000_000,
                max_fee: None,
                accept_high_fee: true,
                ..
            }
        ));
    }

    #[test]
    fn parses_pool_state() {
        assert!(matches!(
            Opts::try_parse_from(["usdt", "pool-state"]).expect("parses"),
            Opts::PoolState
        ));
    }

    #[test]
    fn parses_status() {
        assert!(matches!(
            Opts::try_parse_from(["usdt", "status"]).expect("parses"),
            Opts::Status
        ));
    }

    #[test]
    fn parses_recover_default_gap_limit() {
        // Security finding 08: `check_uncredited` defaults to `true` -- a
        // bare `recover` must check+persist uncredited indices by default,
        // not require an explicit opt-in flag.
        assert!(matches!(
            Opts::try_parse_from(["usdt", "recover"]).expect("parses"),
            Opts::Recover {
                gap_limit: 20,
                check_uncredited: true,
            }
        ));
    }

    #[test]
    fn parses_recover_explicit_gap_limit() {
        assert!(matches!(
            Opts::try_parse_from(["usdt", "recover", "--gap-limit", "5"]).expect("parses"),
            Opts::Recover {
                gap_limit: 5,
                check_uncredited: true,
            }
        ));
    }

    /// `--check-uncredited=false` must restore the pre-finding-08 behavior:
    /// scanned-but-uncredited indices are neither persisted nor checked.
    #[test]
    fn parses_recover_check_uncredited_false() {
        assert!(matches!(
            Opts::try_parse_from(["usdt", "recover", "--check-uncredited", "false"])
                .expect("parses"),
            Opts::Recover {
                gap_limit: 20,
                check_uncredited: false,
            }
        ));
    }

    /// `derive-deposit --index N` must parse without requiring a live
    /// federation -- pure clap parsing, mirroring `help_renders` below.
    #[test]
    fn parses_derive_deposit() {
        assert!(matches!(
            Opts::try_parse_from(["usdt", "derive-deposit", "--index", "7"]).expect("parses"),
            Opts::DeriveDeposit { index: 7 }
        ));
    }

    #[test]
    fn parses_withdrawal_status() {
        let txid = "0".repeat(64);
        assert!(matches!(
            Opts::try_parse_from(["usdt", "withdrawal-status", &txid, "0"]).expect("parses"),
            Opts::WithdrawalStatus { out_idx: 0, .. }
        ));
    }

    /// Proves the `usdt` module subcommand ("`fedimint-cli module usdt
    /// --help`") actually renders a non-empty help page, per the Task 12
    /// acceptance bar -- without needing a live federation, since
    /// `Opts::parse_from` (unlike the outer `ClientCmd::Module` dispatch) is
    /// pure clap parsing.
    #[test]
    fn help_renders() {
        let err = Opts::try_parse_from(["usdt", "--help"]).expect_err("--help short-circuits");
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
        assert!(!err.to_string().is_empty());
    }
}
