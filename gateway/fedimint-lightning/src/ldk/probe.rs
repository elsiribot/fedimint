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
//!
//! An attempt retries like a payment does: when a route fails, LDK has
//! already marked the channel it failed at, so routing again finds a way
//! around it. The attempt stops at the first route that reaches the target,
//! so each one leaves the scorer knowing a path that works right now, not
//! only one that does not.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{self, Write as _};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bitcoin::secp256k1::PublicKey;
use fedimint_core::Amount;
use fedimint_core::task::{TaskGroup, block_in_place};
use fedimint_core::util::FmtCompact;
use fedimint_logging::LOG_LIGHTNING;
use ldk_node::lightning::ln::channelmanager::PaymentId;
use ldk_node::lightning::routing::gossip::NodeId;
use ldk_node::payment::ProbeOutcome;
use lightning_invoice::Bolt11Invoice;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc};
use tracing::{info, warn};

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

/// How far back payments count towards a destination's rank, and how long a
/// destination stays a probe target after its last payment.
const RECENT_DESTINATION_WINDOW: Duration = Duration::from_hours(30 * 24);

/// File in the LDK data directory that keeps the recent destinations across
/// restarts. Without it every deploy would start the 30-day window over.
const RECENT_DESTINATIONS_FILE: &str = "probe_destinations.json";

/// Paid invoices waiting for the prober. The prober reads them once per round,
/// and a round takes minutes, so this only needs to absorb a burst of sends.
const PAID_INVOICE_QUEUE_LEN: usize = 1024;

/// Routes an attempt tries when [`ProbeConfig::max_routes`] is unset.
const DEFAULT_MAX_ROUTES: usize = 3;

/// How long the paths of one route get to settle. A probe settles in seconds;
/// one held longer ties up liquidity on its path, so the attempt ends there
/// rather than sending more.
const ROUTE_TIMEOUT: Duration = Duration::from_secs(60);

/// What the background prober probes, and within which fee budget.
#[derive(Debug, Clone, Default)]
pub struct ProbeConfig {
    /// Nodes to probe in every round.
    pub targets: Vec<PublicKey>,
    /// Also probe up to this many destinations of recent sends, those paid
    /// most often in the last [`RECENT_DESTINATION_WINDOW`]. `None` probes only
    /// [`Self::targets`]; with neither, the prober does not run.
    pub recent_destinations: Option<NonZeroUsize>,
    /// Base of the routing fee budget a probe route may cost. Probes should
    /// look for the routes a payment with the gateway's fee budget would take,
    /// since that is what the scorer needs to know about.
    pub max_fee_base_msat: u64,
    /// Proportional part of the routing fee budget, in parts per million.
    pub max_fee_ppm: u64,
    /// Routes one attempt tries before giving up on a target and amount;
    /// `None` tries [`DEFAULT_MAX_ROUTES`].
    pub max_routes: Option<NonZeroUsize>,
}

impl ProbeConfig {
    fn max_routes(&self) -> usize {
        self.max_routes
            .map_or(DEFAULT_MAX_ROUTES, NonZeroUsize::get)
    }

    fn max_fee_msat(&self, amount: Amount) -> u64 {
        amount
            .msats
            .saturating_mul(self.max_fee_ppm)
            .saturating_div(1_000_000)
            .saturating_add(self.max_fee_base_msat)
    }
}

/// Where a paid invoice goes, as far as a probe can follow it.
#[derive(Debug, Clone)]
pub(super) struct PaidInvoice {
    payee: PublicKey,
    /// First node of each route hint: the LSP in front of a private payee.
    hint_entries: Vec<PublicKey>,
}

impl PaidInvoice {
    pub(super) fn new(invoice: &Bolt11Invoice) -> Self {
        Self {
            payee: invoice.get_payee_pub_key(),
            hint_entries: invoice
                .route_hints()
                .iter()
                .filter_map(|hint| hint.0.first().map(|hop| hop.src_node_id))
                .collect(),
        }
    }

    /// The nodes to probe for this invoice: the payee if the network graph
    /// knows it, since a probe can only follow public channels; otherwise the
    /// hint entries it knows. Wallets add made-up hints, e.g. with absurd
    /// fees, so a hint entry missing from the graph is not probed either.
    fn probe_targets(&self, is_public: impl Fn(&PublicKey) -> bool) -> Vec<PublicKey> {
        if is_public(&self.payee) {
            return vec![self.payee];
        }
        self.hint_entries
            .iter()
            .filter(|entry| is_public(entry))
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

/// When each destination was paid within [`RECENT_DESTINATION_WINDOW`].
#[derive(Debug, Default)]
struct RecentDestinations {
    paid_at: HashMap<PublicKey, VecDeque<SystemTime>>,
}

/// [`RecentDestinations`] on disk: node id (hex) to payment times in unix
/// seconds, oldest first.
#[derive(Debug, Default, Serialize, Deserialize)]
struct StoredDestinations {
    paid_at_secs: BTreeMap<String, Vec<u64>>,
}

impl RecentDestinations {
    fn record(&mut self, destination: PublicKey, at: SystemTime) {
        self.paid_at.entry(destination).or_default().push_back(at);
    }

    /// Forgets payments older than the window, then returns up to `max`
    /// destinations, most payments first and the most recently paid first
    /// among equals.
    fn top(&mut self, max: NonZeroUsize, now: SystemTime) -> Vec<PublicKey> {
        let cutoff = now
            .checked_sub(RECENT_DESTINATION_WINDOW)
            .unwrap_or(SystemTime::UNIX_EPOCH);
        self.paid_at.retain(|_, times| {
            while times.front().is_some_and(|at| *at < cutoff) {
                times.pop_front();
            }
            !times.is_empty()
        });

        let mut ranked = self
            .paid_at
            .iter()
            .map(|(destination, times)| {
                let last = times.back().copied().unwrap_or(SystemTime::UNIX_EPOCH);
                (times.len(), last, *destination)
            })
            .collect::<Vec<_>>();
        ranked.sort_by(|a, b| b.cmp(a));
        ranked
            .into_iter()
            .take(max.get())
            .map(|(_, _, destination)| destination)
            .collect()
    }

    /// Payments recorded for `destination` in the window, as of the last
    /// [`Self::top`].
    fn payments(&self, destination: &PublicKey) -> usize {
        self.paid_at.get(destination).map_or(0, VecDeque::len)
    }

    fn to_stored(&self) -> StoredDestinations {
        StoredDestinations {
            paid_at_secs: self
                .paid_at
                .iter()
                .map(|(destination, times)| {
                    let secs = times
                        .iter()
                        .map(|at| {
                            at.duration_since(SystemTime::UNIX_EPOCH)
                                .map_or(0, |since| since.as_secs())
                        })
                        .collect();
                    (destination.to_string(), secs)
                })
                .collect(),
        }
    }

    /// Entries that do not parse are dropped: the file only decides which
    /// nodes get probed, so a damaged one costs some probe coverage until
    /// the destinations are paid again, nothing more.
    fn from_stored(stored: StoredDestinations) -> Self {
        let paid_at = stored
            .paid_at_secs
            .into_iter()
            .filter_map(|(destination, secs)| {
                let destination = PublicKey::from_str(&destination).ok()?;
                let mut times = secs
                    .into_iter()
                    .map(|secs| SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
                    .collect::<Vec<_>>();
                times.sort();
                Some((destination, times.into()))
            })
            .collect();
        Self { paid_at }
    }

    /// An absent file is a first start. A file that cannot be read or parsed
    /// is logged and replaced on the next save, see [`Self::from_stored`].
    fn load(path: &Path) -> Self {
        let stored = match fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|err| err.to_string()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(StoredDestinations::default()),
            Err(err) => Err(err.to_string()),
        };
        match stored {
            Ok(stored) => Self::from_stored(stored),
            Err(err) => {
                warn!(
                    target: LOG_LIGHTNING,
                    path = %path.display(), err = %err,
                    "Could not load the recent probe destinations, starting without them"
                );
                Self::default()
            }
        }
    }

    /// Writes a temporary file and renames it over `path`, so a crash leaves
    /// either the old list or the new one.
    fn save(&self, path: &Path) -> io::Result<()> {
        let bytes = serde_json::to_vec(&self.to_stored()).map_err(io::Error::other)?;
        let tmp = path.with_extension("json.tmp");
        let mut file = fs::File::create(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&tmp, path)?;
        if let Some(dir) = path.parent() {
            fs::File::open(dir)?.sync_all()?;
        }
        Ok(())
    }
}

/// One round's targets: the configured ones, then the recent destinations
/// not already among them, without our direct peers, since LDK never probes a
/// path of a single hop.
fn round_targets(
    configured: &[PublicKey],
    recent: &[PublicKey],
    peers: &BTreeSet<PublicKey>,
) -> Vec<PublicKey> {
    let mut seen = BTreeSet::new();
    configured
        .iter()
        .chain(recent)
        .filter(|target| !peers.contains(target) && seen.insert(**target))
        .copied()
        .collect()
}

/// Every target with every amount, in turn. Consecutive probes go to
/// different targets, so no single path towards one carries them back to
/// back.
fn round_schedule(targets: &[PublicKey]) -> impl Iterator<Item = (PublicKey, Amount)> + '_ {
    PROBE_AMOUNTS
        .iter()
        .flat_map(move |amount| targets.iter().map(move |target| (*target, *amount)))
}

/// Where [`super::GatewayLdkClient::pay`] reports the invoices it pays to.
pub(super) type PaidInvoiceSender = mpsc::Sender<PaidInvoice>;

/// Starts the prober on `task_group` unless `config` gives it nothing to
/// probe. Returns the sender for paid invoices if the prober follows recent
/// destinations, which it keeps in `data_dir`.
pub(super) fn spawn_prober(
    task_group: &TaskGroup,
    node: Arc<ldk_node::Node>,
    config: ProbeConfig,
    data_dir: &Path,
) -> Option<PaidInvoiceSender> {
    if config.targets.is_empty() && config.recent_destinations.is_none() {
        return None;
    }

    let (paid_sender, recent) = match config.recent_destinations {
        Some(max) => {
            let (sender, receiver) = mpsc::channel(PAID_INVOICE_QUEUE_LEN);
            let path = data_dir.join(RECENT_DESTINATIONS_FILE);
            let destinations = block_in_place(|| RecentDestinations::load(&path));
            (
                Some(sender),
                Some(RecentTracking {
                    max,
                    receiver,
                    path,
                    destinations,
                }),
            )
        }
        None => (None, None),
    };

    info!(
        target: LOG_LIGHTNING,
        targets = config.targets.len(),
        recent_destinations = ?config.recent_destinations,
        "Starting LDK prober"
    );
    task_group.spawn_cancellable("ldk prober", run_prober(node, config, recent));

    paid_sender
}

/// The prober's view of recent sends, when it follows them.
struct RecentTracking {
    max: NonZeroUsize,
    receiver: mpsc::Receiver<PaidInvoice>,
    path: PathBuf,
    destinations: RecentDestinations,
}

impl RecentTracking {
    /// Takes in the invoices paid since the last round and returns this
    /// round's recent targets. The payment time recorded is when the prober
    /// read the invoice, at most one round late, which the 30-day window
    /// does not notice.
    fn update(&mut self, node: &ldk_node::Node) -> Vec<PublicKey> {
        let graph = node.network_graph();
        let is_public = |key: &PublicKey| graph.node(&NodeId::from_pubkey(key)).is_some();
        let now = fedimint_core::time::now();
        let mut paid = 0;
        while let Ok(invoice) = self.receiver.try_recv() {
            for destination in invoice.probe_targets(is_public) {
                self.destinations.record(destination, now);
                paid += 1;
            }
        }
        let top = self.destinations.top(self.max, now);
        if paid > 0
            && let Err(err) = block_in_place(|| self.destinations.save(&self.path))
        {
            warn!(
                target: LOG_LIGHTNING,
                path = %self.path.display(), err = %err.fmt_compact(),
                "Could not save the recent probe destinations"
            );
        }
        top
    }
}

async fn run_prober(
    node: Arc<ldk_node::Node>,
    config: ProbeConfig,
    mut recent: Option<RecentTracking>,
) {
    fedimint_core::runtime::sleep(PROBE_START_DELAY).await;

    loop {
        let recent_targets = recent
            .as_mut()
            .map(|recent| recent.update(&node))
            .unwrap_or_default();

        let peers = node
            .list_channels()
            .into_iter()
            .map(|channel| channel.counterparty_node_id)
            .collect::<BTreeSet<_>>();
        let targets = round_targets(&config.targets, &recent_targets, &peers);
        // One line per round so that whoever reads the log knows which nodes
        // are being probed and why, including those added from recent sends.
        info!(
            target: LOG_LIGHTNING,
            configured = %join_keys(&config.targets),
            recent = %recent_targets
                .iter()
                .map(|target| {
                    let payments = recent.as_ref().map_or(0, |r| r.destinations.payments(target));
                    format!("{target}:{payments}")
                })
                .collect::<Vec<_>>()
                .join(","),
            skipped_peers = %join_keys(
                &config.targets.iter().chain(&recent_targets)
                    .filter(|target| peers.contains(target))
                    .copied()
                    .collect::<Vec<_>>()
            ),
            "Starting probe round"
        );

        if targets.is_empty() {
            // Nothing paid recently and nothing configured beyond our peers.
            fedimint_core::runtime::sleep(PROBE_INTERVAL).await;
            continue;
        }

        for (target, amount) in round_schedule(&targets) {
            probe(&node, &config, target, amount).await;
            fedimint_core::runtime::sleep(PROBE_INTERVAL).await;
        }
    }
}

fn join_keys(keys: &[PublicKey]) -> String {
    keys.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// How one route of an attempt ended.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RouteOutcome {
    /// Every path of the route reached the target.
    Reached,
    /// At least one path failed; the channels they failed at, where LDK
    /// knows them.
    Failed(Vec<u64>),
    /// LDK sent nothing: every path was a single hop or would put our first
    /// hop under the liquidity limit.
    Skipped,
    /// No route within the fee budget, or another error sending.
    NoRoute,
    /// Not every path settled within [`ROUTE_TIMEOUT`].
    TimedOut,
}

impl RouteOutcome {
    fn name(&self) -> &'static str {
        match self {
            Self::Reached => "reached",
            Self::Failed(_) => "failed",
            Self::Skipped => "skipped",
            Self::NoRoute => "no_route",
            Self::TimedOut => "timeout",
        }
    }

    fn sent(&self) -> bool {
        matches!(self, Self::Reached | Self::Failed(_) | Self::TimedOut)
    }
}

/// The routes one attempt has tried so far, and whether to try another.
#[derive(Debug, Default)]
struct Attempt {
    routes: Vec<RouteOutcome>,
}

impl Attempt {
    fn record(&mut self, outcome: RouteOutcome) {
        self.routes.push(outcome);
    }

    /// Only a failed route earns another try: after a success there is
    /// nothing left to learn, after a timeout an HTLC may still hold
    /// liquidity, and when LDK found no route or skipped it, routing again
    /// finds the same.
    fn wants_another_route(&self, max_routes: usize) -> bool {
        matches!(self.routes.last(), Some(RouteOutcome::Failed(_)))
            && self.routes_sent() < max_routes
    }

    fn routes_sent(&self) -> usize {
        self.routes.iter().filter(|route| route.sent()).count()
    }

    fn first(&self) -> &'static str {
        self.routes.first().map_or("none", RouteOutcome::name)
    }

    /// The last route's outcome; a retry that found no route or was skipped
    /// leaves the attempt failed, since an earlier route did.
    fn final_outcome(&self) -> &'static str {
        match self.routes.last() {
            Some(RouteOutcome::Skipped | RouteOutcome::NoRoute) if self.routes_sent() > 0 => {
                "failed"
            }
            Some(last) => last.name(),
            None => "none",
        }
    }

    fn failed_channels(&self) -> Vec<u64> {
        let mut seen = BTreeSet::new();
        self.routes
            .iter()
            .filter_map(|route| match route {
                RouteOutcome::Failed(channels) => Some(channels),
                _ => None,
            })
            .flatten()
            .filter(|channel| seen.insert(**channel))
            .copied()
            .collect()
    }
}

/// Probes `target` with `amount`, re-routing after a failure up to
/// [`ProbeConfig::max_routes`] routes. Logs `Sent probes` for every route (a
/// log reader pairs it with ldk-node's per-path `Probe of ... to <target>`
/// lines that follow; `probes` says how many), `Sent no probe` and
/// `Could not probe target` for the first route as before, and one
/// `Probe attempt done` line per attempt.
async fn probe(node: &ldk_node::Node, config: &ProbeConfig, target: PublicKey, amount: Amount) {
    let max_fee_msat = config.max_fee_msat(amount);
    let payments = node.spontaneous_payment();
    // Subscribed before sending, so no outcome can come too early.
    let mut outcomes = payments.subscribe_probe_outcomes();
    let mut attempt = Attempt::default();

    loop {
        let first = attempt.routes.is_empty();
        // Route finding walks the whole network graph, which is CPU work
        // that must not stall the async workers.
        let sent = block_in_place(|| {
            payments.send_probe_paths_with_max_fee(amount.msats, target, max_fee_msat)
        });
        let outcome = match sent {
            Ok(ids) if ids.is_empty() => {
                // LDK logs why it skipped each path right before this.
                if first {
                    info!(
                        target: LOG_LIGHTNING,
                        %target, amount_msat = amount.msats,
                        "Sent no probe: every path was too short or would drain our first hop"
                    );
                }
                RouteOutcome::Skipped
            }
            Ok(ids) => {
                info!(
                    target: LOG_LIGHTNING,
                    %target, amount_msat = amount.msats, probes = ids.len(),
                    "Sent probes"
                );
                wait_for_paths(&mut outcomes, ids).await
            }
            // Includes finding no route within the fee budget, which is
            // worth knowing for a target users pay.
            Err(err) => {
                if first {
                    info!(
                        target: LOG_LIGHTNING,
                        %target, amount_msat = amount.msats, max_fee_msat, err = %err.fmt_compact(),
                        "Could not probe target"
                    );
                }
                RouteOutcome::NoRoute
            }
        };
        attempt.record(outcome);
        if !attempt.wants_another_route(config.max_routes()) {
            break;
        }
    }

    info!(
        target: LOG_LIGHTNING,
        %target,
        amount_msat = amount.msats,
        routes = attempt.routes_sent(),
        first = attempt.first(),
        outcome = attempt.final_outcome(),
        failed_channels = %attempt
            .failed_channels()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(","),
        "Probe attempt done"
    );
}

/// Waits until every path in `ids` has reached its target or failed.
async fn wait_for_paths(
    outcomes: &mut broadcast::Receiver<ProbeOutcome>,
    ids: Vec<PaymentId>,
) -> RouteOutcome {
    let mut pending = ids.into_iter().collect::<HashSet<_>>();
    let mut failed = Vec::new();
    let settled = fedimint_core::runtime::timeout(ROUTE_TIMEOUT, async {
        while !pending.is_empty() {
            match outcomes.recv().await {
                Ok(outcome) => {
                    if pending.remove(&outcome.payment_id) && !outcome.reached {
                        failed.push(outcome.failed_channel);
                    }
                }
                // Missed outcomes leave their paths pending until the
                // timeout, which only ends this attempt early.
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => return false,
            }
        }
        true
    })
    .await;

    match settled {
        Ok(true) if failed.is_empty() => RouteOutcome::Reached,
        Ok(true) => RouteOutcome::Failed(failed.into_iter().flatten().collect()),
        Ok(false) | Err(_) => RouteOutcome::TimedOut,
    }
}

#[cfg(test)]
mod tests;
