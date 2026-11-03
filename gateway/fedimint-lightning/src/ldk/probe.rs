//! Background probing, which keeps LDK's scorer current for the nodes the
//! gateway pays most.
//!
//! LDK only learns that a channel cannot carry an amount when an HTLC fails
//! over it, and it penalizes that one channel, not the node pair. A payee
//! reached through a hub with many drained parallel channels therefore costs
//! a payment one retry per channel, and the retry window runs out before LDK
//! tries a different hub. A probe is an HTLC with a random payment hash that
//! no one can claim, so it moves no funds, and its outcome trains the scorer
//! the same way a failed payment would, but before a user is waiting.

use std::sync::Arc;
use std::time::Duration;

use bitcoin::secp256k1::PublicKey;
use fedimint_core::Amount;
use fedimint_core::task::{TaskGroup, block_in_place};
use fedimint_core::util::FmtCompact;
use fedimint_logging::LOG_LIGHTNING;
use tracing::{debug, info};

/// How long after start-up the first probe goes out. Until gossip has synced,
/// LDK finds no route to most targets.
const PROBE_START_DELAY: Duration = Duration::from_mins(5);

/// Time between two probes. Probes settle in seconds, so this keeps about one
/// in flight, which ties up little of the liquidity real payments need.
const PROBE_INTERVAL: Duration = Duration::from_secs(20);

/// Amounts each target is probed with, covering small, typical and large user
/// sends. A path's liquidity is learned per amount, so one size is not enough.
const PROBE_AMOUNTS: [Amount; 3] = [
    Amount::from_sats(20_000),
    Amount::from_sats(100_000),
    Amount::from_sats(500_000),
];

/// What the background prober probes, and within which fee budget.
#[derive(Debug, Clone, Default)]
pub struct ProbeConfig {
    /// Nodes to probe. With none, the prober does not run.
    pub targets: Vec<PublicKey>,
    /// Base of the routing fee budget a probe route may cost. Probes should
    /// look for the routes a payment with the gateway's fee budget would take,
    /// since that is what the scorer needs to know about.
    pub max_fee_base_msat: u64,
    /// Proportional part of the routing fee budget, in parts per million.
    pub max_fee_ppm: u64,
}

impl ProbeConfig {
    fn max_fee_msat(&self, amount: Amount) -> u64 {
        amount
            .msats
            .saturating_mul(self.max_fee_ppm)
            .saturating_div(1_000_000)
            .saturating_add(self.max_fee_base_msat)
    }
}

/// Every target with every amount, in turn and forever. Consecutive probes go
/// to different targets, so no single path towards one carries them back to
/// back. Empty if there are no targets.
fn probe_schedule(targets: &[PublicKey]) -> impl Iterator<Item = (PublicKey, Amount)> + '_ {
    PROBE_AMOUNTS
        .iter()
        .flat_map(move |amount| targets.iter().map(move |target| (*target, *amount)))
        .cycle()
}

/// Starts the prober on `task_group` unless `config` has no targets.
pub(super) fn spawn_prober(task_group: &TaskGroup, node: Arc<ldk_node::Node>, config: ProbeConfig) {
    if config.targets.is_empty() {
        return;
    }

    info!(target: LOG_LIGHTNING, targets = config.targets.len(), "Starting LDK prober");
    task_group.spawn_cancellable("ldk prober", async move {
        fedimint_core::runtime::sleep(PROBE_START_DELAY).await;

        for (target, amount) in probe_schedule(&config.targets) {
            let max_fee_msat = config.max_fee_msat(amount);
            // Route finding walks the whole network graph, which is CPU work
            // that must not stall the async workers.
            let result = block_in_place(|| {
                node.spontaneous_payment().send_probes_with_max_fee(
                    amount.msats,
                    target,
                    max_fee_msat,
                )
            });

            match result {
                Ok(0) => debug!(
                    target: LOG_LIGHTNING,
                    %target, %amount,
                    "Sent no probe: every path was too short or would drain our first hop"
                ),
                Ok(probes) => {
                    debug!(target: LOG_LIGHTNING, %target, %amount, probes, "Sent probes")
                }
                // Includes finding no route within the fee budget, which is
                // worth knowing for a target users pay.
                Err(err) => info!(
                    target: LOG_LIGHTNING,
                    %target, %amount, max_fee_msat, err = %err.fmt_compact(),
                    "Could not probe target"
                ),
            }

            fedimint_core::runtime::sleep(PROBE_INTERVAL).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::str::FromStr;

    use bitcoin::secp256k1::PublicKey;
    use fedimint_core::Amount;

    use super::{PROBE_AMOUNTS, ProbeConfig, probe_schedule};

    fn key(hex: &str) -> PublicKey {
        PublicKey::from_str(hex).expect("test keys are valid compressed points")
    }

    #[test]
    fn schedule_covers_every_target_and_amount_before_repeating() {
        let targets = [
            key("029fc6217803748cc8fb6b041acbe81e6e295a914487dcea7e5d7e141b64883826"),
            key("039174f846626c6053ba80f5443d0db33da384f1dde135bf7080ba1eec465019c3"),
        ];
        let pairs = targets.len() * PROBE_AMOUNTS.len();

        let first_round = probe_schedule(&targets).take(pairs).collect::<Vec<_>>();
        let distinct = first_round.iter().collect::<BTreeSet<_>>();
        assert_eq!(
            distinct.len(),
            pairs,
            "one round probes each pair exactly once"
        );

        let second_round = probe_schedule(&targets)
            .skip(pairs)
            .take(pairs)
            .collect::<Vec<_>>();
        assert_eq!(
            first_round, second_round,
            "the schedule repeats round by round"
        );

        assert!(
            first_round.windows(2).all(|w| w[0].0 != w[1].0),
            "consecutive probes go to different targets"
        );
    }

    #[test]
    fn schedule_without_targets_is_empty() {
        assert_eq!(probe_schedule(&[]).next(), None);
    }

    #[test]
    fn fee_budget_matches_the_routing_fee_formula() {
        let config = ProbeConfig {
            targets: Vec::new(),
            max_fee_base_msat: 3_000,
            max_fee_ppm: 5_000,
        };
        assert_eq!(config.max_fee_msat(Amount::from_sats(20_000)), 103_000);

        let huge = ProbeConfig {
            targets: Vec::new(),
            max_fee_base_msat: u64::MAX,
            max_fee_ppm: u64::MAX,
        };
        assert_eq!(huge.max_fee_msat(Amount::from_msats(u64::MAX)), u64::MAX);
    }
}
