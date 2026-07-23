use std::{ffi, iter};

use clap::Parser;
use fedimint_core::{OutPoint, TransactionId, secp256k1};
use fedimint_usdt_common::{EvmAddress, UsdtAmount};
use serde::Serialize;
use serde_json::Value;

use crate::UsdtClientModule;

#[derive(Debug, Clone, Parser, Serialize)]
enum Opts {
    /// Allocate a fresh claim key, persist it, and print the deposit address
    /// derived from it (`account`) together with the claim public key
    /// (`claim_pk`) needed by `check-deposit`/`deposit-status`/`claim`.
    DepositAddress,
    /// Ask the federation to start watching `claim_pk`'s deposit address for
    /// incoming USDT transfers.
    CheckDeposit { claim_pk: secp256k1::PublicKey },
    /// Report the credited/claimed/claimable state of `claim_pk`'s deposit
    /// account.
    DepositStatus { claim_pk: secp256k1::PublicKey },
    /// Submit a claim transaction for `claim_pk`'s currently claimable
    /// balance (requires a nonzero `claimable` from `deposit-status`, and
    /// that `claim_pk` was previously produced by `deposit-address` on this
    /// client).
    Claim { claim_pk: secp256k1::PublicKey },
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
    Withdraw { recipient: EvmAddress, amount: u64 },
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
    Recover {
        #[arg(long, default_value = "20")]
        gap_limit: u64,
    },
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
        Opts::CheckDeposit { claim_pk } => json(usdt.check_deposit(claim_pk).await?),
        Opts::DepositStatus { claim_pk } => json(usdt.deposit_status(claim_pk).await?),
        Opts::Claim { claim_pk } => {
            // Best-effort display value: the fee actually charged is
            // determined by `claim`'s own internal quote fetch
            // (`UsdtClientModule::submit_claim`), moments after this one --
            // the two agree unless the consensus-agreed `FeeVote` median
            // changes in between, which is rare within a single command
            // invocation.
            let quote = usdt.deposit_fee_quote().await?;
            let claimed = usdt.claim(claim_pk).await?;
            json(serde_json::json!({ "claimed": claimed.0, "fee": quote.fee.0 }))
        }
        Opts::FeeQuote { amount } => json(usdt.withdraw_fee_quote(UsdtAmount(amount)).await?),
        Opts::DepositFeeQuote => json(usdt.deposit_fee_quote().await?),
        Opts::Withdraw { recipient, amount } => {
            let amount = UsdtAmount(amount);
            let quote = usdt.withdraw_fee_quote(amount).await?;
            let range = usdt.withdraw(recipient, amount, quote.max_fee).await?;
            let out_point = UsdtClientModule::withdrawal_out_point(&range);
            json(serde_json::json!({
                "out_point": out_point.to_string(),
                "recipient": recipient.to_string(),
                "amount": amount.0,
                "max_fee": quote.max_fee.0,
            }))
        }
        Opts::WithdrawalStatus { txid, out_idx } => {
            let out_point = OutPoint { txid, out_idx };
            json(usdt.withdrawal_status(out_point).await?)
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
        Opts::Recover { gap_limit } => json(usdt.recover_deposits(gap_limit).await?),
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
    fn parses_check_deposit() {
        assert!(matches!(
            Opts::try_parse_from(["usdt", "check-deposit", TEST_PUBKEY]).expect("parses"),
            Opts::CheckDeposit { .. }
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
        assert!(matches!(
            Opts::try_parse_from(["usdt", "claim", TEST_PUBKEY]).expect("parses"),
            Opts::Claim { .. }
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
        assert!(matches!(
            Opts::try_parse_from(["usdt", "recover"]).expect("parses"),
            Opts::Recover { gap_limit: 20 }
        ));
    }

    #[test]
    fn parses_recover_explicit_gap_limit() {
        assert!(matches!(
            Opts::try_parse_from(["usdt", "recover", "--gap-limit", "5"]).expect("parses"),
            Opts::Recover { gap_limit: 5 }
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
