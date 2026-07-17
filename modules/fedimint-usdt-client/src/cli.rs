use std::{ffi, iter};

use clap::Parser;
use fedimint_core::secp256k1;
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
            let claimed = usdt.claim(claim_pk).await?;
            json(serde_json::json!({ "claimed": claimed.0 }))
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
