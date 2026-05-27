//! Throughput / latency benchmark driver for a Fedimint federation.
//!
//! Drives mint payment transactions (arbitrary amount, decomposed into
//! tier-denominated notes by the standard `represent_amount` logic real
//! clients use) at a configurable target TPS across a pool of parallel worker
//! clients, recording per-tx accepted + finalized latency and the per-tx
//! input/output shape. See `README.md` for usage.

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use devimint::cmd;
use devimint::util::FedimintCli;
use fedimint_client::secret::{PlainRootSecretStrategy, RootSecretStrategy};
use fedimint_client::transaction::TransactionBuilder;
use fedimint_client::{Client, ClientHandleArc, RootSecret};
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::core::{IntoDynInstance, OperationId};
use fedimint_core::db::Database;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::{Amount, OutPoint};
use fedimint_mint_client::{MintClientInit, MintClientModule, OOBNotes};
use fedimint_wallet_client::WalletClientInit;
use rand::Rng as _;
use serde::Serialize;
use fedimint_core::runtime::{JoinHandle, sleep};
use fedimint_core::runtime::spawn as spawn_task;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

#[derive(Parser, Debug, Clone)]
#[command(version, about)]
struct Args {
    /// Federation invite code. Falls back to FM_INVITE_CODE env or
    /// `fedimint-cli`.
    #[arg(long)]
    invite_code: Option<String>,

    /// Persistent data dir root (otherwise in-memory DBs are used). When set,
    /// worker DBs go under <data_dir>/worker-<i>.
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// Target transactions per second across the whole worker pool.
    #[arg(long)]
    target_tps: f64,

    /// How long to run the steady-state benchmark, in seconds.
    #[arg(long, default_value = "60")]
    duration_secs: u64,

    /// Payment amount in msats per bench transaction. The mint module
    /// decomposes this into tier-denominated notes via `represent_amount`
    /// (the same coin-selection logic real clients use), so each tx ends up
    /// with a realistic mix of inputs, user outputs, and balancer change
    /// outputs — not a hand-tuned single-tier reissue.
    ///
    /// If `--payment-amount-max-msats` is also set, this is the *minimum* of a
    /// uniform random range sampled per tx; otherwise it's a fixed amount.
    #[arg(long, default_value = "10000")]
    payment_amount_msats: u64,

    /// Upper bound of the per-tx random payment-amount range, in msats. If set,
    /// each tx samples uniformly in [`payment_amount_msats`,
    /// `payment_amount_max_msats`].
    #[arg(long)]
    payment_amount_max_msats: Option<u64>,

    /// Target inventory level for the mint module's `represent_amount`
    /// algorithm: how many notes per tier the wallet aims to hold. Matches the
    /// fedimint balancer's default of 2.
    #[arg(long, default_value = "2")]
    target_denomination_sets: u16,

    /// Number of parallel worker clients. Each worker holds its own client +
    /// DB and submits transactions strictly sequentially — needed because a
    /// single client's state machines panic on RocksDB WriteConflict when many
    /// in-flight ops race for the wallet ledger. To drive higher TPS than one
    /// client can sustain (≈ 1 / federation_round_trip), increase this.
    #[arg(long, default_value = "4")]
    workers: usize,

    /// Optional pre-funded OOB notes (skip the `fedimint-cli spend` bootstrap).
    #[arg(long)]
    initial_notes: Option<String>,

    /// Amount in msats to source for EACH worker from the devimint default
    /// client when `--initial-notes` is not provided. Each worker is a closed
    /// loop (every tx is net-neutral on balance), so just a few notes' worth
    /// is plenty — keep it small to spare the devimint CLI's bitcoin allowance
    /// across multi-step ramp sweeps. 4 MiB-ish msat = 1 note from the 4 Msat
    /// tier.
    #[arg(long, default_value = "4194304")]
    bootstrap_amount_msats: u64,

    /// Write a JSON report here on completion.
    #[arg(long)]
    report_json: Option<PathBuf>,

    /// Skip the pre-bench warmup transaction (used for initial gateway/cache
    /// priming).
    #[arg(long)]
    no_warmup: bool,
}

#[derive(Debug, Clone, Serialize)]
struct LatencySamples {
    accepted_ms: Vec<u64>,
    finalized_ms: Vec<u64>,
    // Per-tx note counts.
    user_outputs: Vec<u64>,
    change_outputs: Vec<u64>,
    total_outputs: Vec<u64>,
    payment_msats: Vec<u64>,
}

impl LatencySamples {
    fn new() -> Self {
        Self {
            accepted_ms: Vec::new(),
            finalized_ms: Vec::new(),
            user_outputs: Vec::new(),
            change_outputs: Vec::new(),
            total_outputs: Vec::new(),
            payment_msats: Vec::new(),
        }
    }

    fn record(
        &mut self,
        accepted: Duration,
        finalized: Duration,
        user_outputs: u64,
        change_outputs: u64,
        payment_msats: u64,
    ) {
        self.accepted_ms.push(accepted.as_millis() as u64);
        self.finalized_ms.push(finalized.as_millis() as u64);
        self.user_outputs.push(user_outputs);
        self.change_outputs.push(change_outputs);
        self.total_outputs.push(user_outputs + change_outputs);
        self.payment_msats.push(payment_msats);
    }
}

/// Inclusive `[min, max]` payment-amount range. `min == max` means a fixed
/// payment per tx; otherwise each tx samples uniformly in the range.
#[derive(Debug, Clone, Copy)]
struct PaymentRange {
    min_msats: u64,
    max_msats: u64,
}

impl PaymentRange {
    fn sample(&self) -> Amount {
        let v = if self.min_msats == self.max_msats {
            self.min_msats
        } else {
            rand::thread_rng().gen_range(self.min_msats..=self.max_msats)
        };
        Amount::from_msats(v)
    }
}

fn percentile(sorted: &[u64], p: f64) -> Option<u64> {
    if sorted.is_empty() {
        return None;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    Some(sorted[idx.min(sorted.len() - 1)])
}

#[derive(Debug, Serialize)]
struct PercentileSummary {
    n: usize,
    min: u64,
    p50: u64,
    p90: u64,
    p95: u64,
    p99: u64,
    max: u64,
    avg: u64,
}

impl PercentileSummary {
    fn from_samples(samples: &[u64]) -> Option<Self> {
        if samples.is_empty() {
            return None;
        }
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        let avg = (sorted.iter().sum::<u64>() as f64 / sorted.len() as f64) as u64;
        Some(Self {
            n: sorted.len(),
            min: *sorted.first().unwrap(),
            p50: percentile(&sorted, 0.50).unwrap(),
            p90: percentile(&sorted, 0.90).unwrap(),
            p95: percentile(&sorted, 0.95).unwrap(),
            p99: percentile(&sorted, 0.99).unwrap(),
            max: *sorted.last().unwrap(),
            avg,
        })
    }
}

#[derive(Debug, Serialize)]
struct BenchReport {
    target_tps: f64,
    duration_secs: u64,
    achieved_tps: f64,
    submitted: u64,
    completed: u64,
    errors: u64,
    accepted_latency_ms: Option<PercentileSummary>,
    finalized_latency_ms: Option<PercentileSummary>,
    user_outputs_per_tx: Option<PercentileSummary>,
    change_outputs_per_tx: Option<PercentileSummary>,
    total_outputs_per_tx: Option<PercentileSummary>,
    payment_msats_per_tx: Option<PercentileSummary>,
    per_second: Vec<PerSecond>,
    backed_up: bool,
}

#[derive(Debug, Clone, Serialize)]
struct PerSecond {
    t: u64,
    submitted: u64,
    completed: u64,
    in_flight: u64,
    errors: u64,
    p50_finalized_ms: Option<u64>,
    p95_finalized_ms: Option<u64>,
}

struct Counters {
    submitted: u64,
    completed: u64,
    errors: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    fedimint_logging::TracingSetup::default().init()?;
    let args = Args::parse();

    let invite_code = match args.invite_code.clone() {
        Some(c) => InviteCode::from_str(&c)?,
        None => match std::env::var("FM_INVITE_CODE").ok() {
            Some(c) => InviteCode::from_str(&c)?,
            None => fallback_invite_code_from_cli().await?,
        },
    };

    let payment_range = PaymentRange {
        min_msats: args.payment_amount_msats,
        max_msats: args
            .payment_amount_max_msats
            .unwrap_or(args.payment_amount_msats),
    };
    if payment_range.min_msats > payment_range.max_msats {
        bail!(
            "--payment-amount-msats ({}) > --payment-amount-max-msats ({})",
            payment_range.min_msats,
            payment_range.max_msats
        );
    }
    let sets = args.target_denomination_sets;
    let warmup_payment = Amount::from_msats(payment_range.max_msats);
    let workers = build_worker_pool(&args, &invite_code, warmup_payment).await?;
    if !args.no_warmup {
        info!("Warmup transaction…");
        submit_single_payment(&workers[0], warmup_payment, sets)
            .await
            .context("warmup tx failed")?;
    }

    let report = run_benchmark(workers, &args, payment_range, sets).await?;

    let json = serde_json::to_string_pretty(&report)?;
    println!("\n=== Benchmark report ===\n{json}");

    if let Some(path) = args.report_json.as_ref() {
        tokio::fs::write(path, json.as_bytes()).await?;
        info!("Wrote JSON report to {}", path.display());
    }

    Ok(())
}

async fn fallback_invite_code_from_cli() -> Result<InviteCode> {
    info!("No --invite-code or FM_INVITE_CODE set, asking fedimint-cli…");
    let value = cmd!(FedimintCli, "invite-code", "0").out_json().await?;
    let s = value["invite_code"]
        .as_str()
        .context("missing invite_code in fedimint-cli output")?;
    InviteCode::from_str(s)
}

async fn build_client(
    invite_code: InviteCode,
    rocksdb: Option<&PathBuf>,
) -> Result<ClientHandleArc> {
    let db = if let Some(rocksdb) = rocksdb {
        if !rocksdb.exists() {
            tokio::fs::create_dir_all(rocksdb).await?;
        }
        Database::new(
            fedimint_rocksdb::RocksDb::build(rocksdb).open().await?,
            ModuleRegistry::default(),
        )
    } else {
        fedimint_core::db::mem_impl::MemDatabase::new().into()
    };

    // Local devimint federation: no DHT lookup needed (overrides come from
    // FM_IROH_CONNECT_OVERRIDES), and we don't want the experimental "next"
    // iroh stack adding noise either.
    let mut builder = Client::builder()
        .await?
        .with_iroh_enable_dht(false)
        .with_iroh_enable_next(false);
    builder.with_module(MintClientInit);
    builder.with_module(WalletClientInit::default());

    let client_secret = Client::load_or_generate_client_secret(&db).await?;
    let root_secret =
        RootSecret::StandardDoubleDerive(PlainRootSecretStrategy::to_root_secret(&client_secret));
    let connectors = ConnectorRegistry::build_from_client_env()?.bind().await?;

    let client = if Client::is_initialized(&db).await {
        builder.open(connectors, db, root_secret).await
    } else {
        builder
            .preview(connectors, &invite_code)
            .await?
            .join(db, root_secret)
            .await
    }?;
    Ok(Arc::new(client))
}

/// Build a pool of `workers` independent client instances, each prefunded
/// with `bootstrap_amount_msats`. The wallet's natural coin-selection logic
/// diversifies the note inventory across tiers as the bench loop runs, so we
/// don't need to pre-split into a single fixed denomination.
async fn build_worker_pool(
    args: &Args,
    invite_code: &InviteCode,
    payment: Amount,
) -> Result<Vec<ClientHandleArc>> {
    let workers = args.workers.max(1);
    let per_worker_amount = Amount::from_msats(args.bootstrap_amount_msats);
    info!(
        "Building {workers} worker clients (target_tps={}, per_worker_amount={per_worker_amount}, payment_per_tx={payment})",
        args.target_tps
    );

    // Build every client first (cheap; just connects + loads DB).
    let mut clients = Vec::with_capacity(workers);
    for i in 0..workers {
        let db_path = args
            .data_dir
            .as_ref()
            .map(|d| d.join(format!("worker-{i}")));
        clients.push(build_client(invite_code.clone(), db_path.as_ref()).await?);
    }

    // Figure out which workers are underfunded and how much they need.
    let mut deficits: Vec<Amount> = Vec::with_capacity(workers);
    let mut total_deficit = Amount::ZERO;
    for (i, c) in clients.iter().enumerate() {
        let balance = c.get_balance_for_btc().await?;
        let need = per_worker_amount.saturating_sub(balance);
        deficits.push(need);
        if need != Amount::ZERO {
            info!("worker {i} balance {balance} (deficit {need})");
            total_deficit = total_deficit
                .checked_add(need)
                .context("total deficit overflow")?;
        }
    }

    if total_deficit != Amount::ZERO {
        // Worker 0 is the "bank": it pulls one combined chunk from
        // `fedimint-cli spend` and then redistributes to the other underfunded
        // workers via OOB notes. This keeps cumulative CLI draw to roughly
        // `total_deficit` regardless of worker count, instead of
        // `worker_count × overspent_note_tier`.
        //
        // We pull a generous safety buffer because each `do_spend_notes` call
        // selects notes using SelectNotesWithAtleastAmount, which can leave
        // the bank's residual notes fragmented across denominations that no
        // longer compose to the next request even though the total still
        // would. Two extra `per_worker_amount`s per recipient absorbs that
        // drift; the unused remainder simply stays in the bank wallet.
        let bank_self_deficit = deficits[0];
        let bank_outgoing: Amount = Amount::from_msats(deficits[1..].iter().map(|a| a.msats).sum());
        let outgoing_recipients = deficits
            .iter()
            .skip(1)
            .filter(|a| **a != Amount::ZERO)
            .count() as u64;
        let buffer =
            Amount::from_msats(per_worker_amount.msats.saturating_mul(outgoing_recipients));
        let cli_pull = bank_self_deficit
            .checked_add(bank_outgoing)
            .and_then(|a| a.checked_add(buffer))
            .context("bank deficit overflow")?;
        if cli_pull != Amount::ZERO {
            info!(
                "bank (worker 0) pulling {cli_pull} from fedimint-cli (self: {bank_self_deficit}, outgoing OOB: {bank_outgoing})"
            );
            bootstrap_funds(
                &clients[0],
                args.initial_notes.as_deref(),
                clients[0]
                    .get_balance_for_btc()
                    .await?
                    .checked_add(cli_pull)
                    .context("bank target overflow")?,
            )
            .await
            .context("bank bootstrap")?;
        }
        // Distribute to underfunded peers (skip bank itself; its deficit is
        // already covered by the pull above).
        for (i, need) in deficits.iter().enumerate().skip(1) {
            if *need == Amount::ZERO {
                continue;
            }
            info!("transferring {need} from bank to worker {i} via OOB");
            let oob = do_spend_notes(&clients[0], *need)
                .await
                .with_context(|| format!("bank spend for worker {i}"))?;
            reissue(&clients[i], oob)
                .await
                .with_context(|| format!("worker {i} reissue of bank notes"))?;
        }
    }

    for (i, c) in clients.iter().enumerate() {
        let balance = c.get_balance_for_btc().await?;
        info!("worker {i} balance {balance}");
    }

    Ok(clients)
}

/// Spend `amount` from `client` as OOB notes. Adapted from the load-test tool's
/// `do_spend_notes` — selects notes summing to at least `amount` and returns
/// them as transferable e-cash.
async fn do_spend_notes(client: &ClientHandleArc, amount: Amount) -> Result<OOBNotes> {
    use fedimint_mint_client::SelectNotesWithAtleastAmount;
    use futures::StreamExt;

    let mint = client.get_first_module::<MintClientModule>()?;
    let (operation_id, oob) = mint
        .spend_notes_with_selector(
            &SelectNotesWithAtleastAmount,
            amount,
            Duration::from_secs(600),
            false,
            (),
        )
        .await?;
    // Drain the first state machine update so the spend is durably reserved
    // before we hand the notes out to the recipient.
    let mut updates = mint
        .subscribe_spend_notes(operation_id)
        .await?
        .into_stream();
    if let Some(update) = updates.next().await {
        match update {
            fedimint_mint_client::SpendOOBState::Created
            | fedimint_mint_client::SpendOOBState::Success => {}
            other => bail!("bank OOB spend failed: {other:?}"),
        }
    }
    Ok(oob)
}

/// Make sure the client has at least roughly `target` msats by:
/// 1. Reissuing `initial_notes` if provided, OR
/// 2. Falling back to `fedimint-cli spend <amount>` and reissuing the output.
async fn bootstrap_funds(
    client: &ClientHandleArc,
    initial_notes: Option<&str>,
    target: Amount,
) -> Result<()> {
    let balance = client.get_balance_for_btc().await?;
    if balance >= target {
        info!("Wallet already has {balance}, skipping bootstrap");
        return Ok(());
    }

    let notes = match initial_notes {
        Some(s) => OOBNotes::from_str(s)?,
        None => {
            let needed = target.saturating_sub(balance);
            info!("Pulling {needed} from fedimint-cli spend (allow-overpay)");
            let value = cmd!(
                FedimintCli,
                "spend",
                "--allow-overpay",
                needed.msats.to_string()
            )
            .out_json()
            .await?;
            let s = value["notes"]
                .as_str()
                .context("fedimint-cli spend output missing notes field")?;
            OOBNotes::from_str(s)?
        }
    };
    reissue(client, notes).await
}

async fn reissue(client: &ClientHandleArc, notes: OOBNotes) -> Result<()> {
    use fedimint_mint_client::ReissueExternalNotesState;
    use futures::StreamExt;

    let mint = client.get_first_module::<MintClientModule>()?;
    let op = mint.reissue_external_notes(notes, ()).await?;
    let mut updates = mint
        .subscribe_reissue_external_notes(op)
        .await?
        .into_stream();
    while let Some(update) = updates.next().await {
        if let ReissueExternalNotesState::Failed(e) = update {
            bail!("Reissue of bootstrap notes failed: {e}");
        }
    }
    Ok(())
}

#[derive(Debug)]
struct TxOutcome {
    accepted: Duration,
    finalized: Duration,
    user_outputs: u64,
    change_outputs: u64,
}

/// Build and submit a single payment transaction — `payment` msats split into
/// tier-denominated notes by the mint module's standard `represent_amount`
/// algorithm (the same one real clients use). The wallet's balancer then
/// picks inputs and adds tier-decomposed change.
///
/// Everything must happen inside a single autocommit-driven `dbtx`. An outer
/// dbtx wrapping `finalize_and_submit_transaction` (which has its own
/// autocommit) caused `WriteConflict` panics even with a single worker because
/// the two dbtx's overlapped on the wallet namespace.
async fn submit_single_payment_locked(
    client: &ClientHandleArc,
    payment: Amount,
    sets: u16,
) -> Result<(
    OperationId,
    fedimint_core::TransactionId,
    SystemTime,
    u64,
    fedimint_core::OutPointRange,
)> {
    use fedimint_core::db::AutocommitError;

    let operation_id = OperationId::new_random();
    let submit_start = fedimint_core::time::now();
    let mint_id = client.get_first_module::<MintClientModule>()?.id;
    let mint_kind: &'static str = "mint";

    let res = client
        .db()
        .autocommit(
            |dbtx, _attempt| {
                let client = client.clone();
                Box::pin(async move {
                    let mint = client.get_first_module::<MintClientModule>()?;
                    let bundle = {
                        let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(mint_id).0;
                        mint.create_output(
                            &mut module_dbtx.to_ref_nc(),
                            operation_id,
                            sets,
                            payment,
                        )
                        .await
                    };
                    let user_outputs = bundle.outputs().len() as u64;
                    let tx_builder =
                        TransactionBuilder::new().with_outputs(bundle.into_dyn(mint_id));
                    let outpoint_range = client
                        .finalize_and_submit_transaction_dbtx(
                            dbtx,
                            operation_id,
                            mint_kind,
                            |_| (),
                            tx_builder,
                        )
                        .await?;
                    anyhow::Ok((outpoint_range.txid(), user_outputs, outpoint_range))
                })
            },
            Some(100),
        )
        .await;

    let (txid, user_outputs, outpoint_range) = match res {
        Ok(v) => v,
        Err(AutocommitError::ClosureError { error, .. }) => return Err(error),
        Err(AutocommitError::CommitFailed {
            attempts,
            last_error,
        }) => bail!("autocommit gave up after {attempts}: {last_error}"),
    };
    Ok((
        operation_id,
        txid,
        submit_start,
        user_outputs,
        outpoint_range,
    ))
}

/// Wait for `await_tx_accepted` and `await_output_finalized` for every output
/// (user-added and balancer change). Safe to run concurrently — these only
/// touch the API and state machines, not the wallet's write lock.
///
/// We await *all* outputs, not just the user-added ones, so the wallet's note
/// inventory is fully consistent before the next loop iteration; otherwise
/// pending change can starve subsequent input selection.
async fn await_settlement(
    client: &ClientHandleArc,
    operation_id: OperationId,
    txid: fedimint_core::TransactionId,
    submit_start: SystemTime,
    user_outputs: u64,
    change_range: fedimint_core::OutPointRange,
) -> Result<TxOutcome> {
    let mint = client.get_first_module::<MintClientModule>()?;

    client
        .transaction_updates(operation_id)
        .await
        .await_tx_accepted(txid)
        .await
        .map_err(|e| anyhow!("tx not accepted: {e}"))?;
    let accepted = fedimint_core::time::now()
        .duration_since(submit_start)
        .unwrap_or_default();

    let change_outputs = change_range.count() as u64;
    for idx in 0..user_outputs {
        mint.await_output_finalized(operation_id, OutPoint { txid, out_idx: idx })
            .await?;
    }
    for out_point in change_range {
        mint.await_output_finalized(operation_id, out_point).await?;
    }
    let finalized = fedimint_core::time::now()
        .duration_since(submit_start)
        .unwrap_or_default();

    debug!(
        ?accepted,
        ?finalized,
        user_outputs,
        change_outputs,
        "tx complete"
    );
    Ok(TxOutcome {
        accepted,
        finalized,
        user_outputs,
        change_outputs,
    })
}

/// Combined submit+await used for the warmup transaction where concurrency
/// isn't a concern.
async fn submit_single_payment(
    client: &ClientHandleArc,
    payment: Amount,
    sets: u16,
) -> Result<TxOutcome> {
    let (op, txid, start, user_outputs, change_range) =
        submit_single_payment_locked(client, payment, sets).await?;
    await_settlement(client, op, txid, start, user_outputs, change_range).await
}

async fn run_benchmark(
    workers: Vec<ClientHandleArc>,
    args: &Args,
    payment_range: PaymentRange,
    sets: u16,
) -> Result<BenchReport> {
    let duration = Duration::from_secs(args.duration_secs);
    let n_workers = workers.len() as f64;
    let per_worker_tps = args.target_tps / n_workers;
    let per_tx = Duration::from_secs_f64(1.0 / per_worker_tps);

    let counters = Arc::new(Mutex::new(Counters {
        submitted: 0,
        completed: 0,
        errors: 0,
    }));
    let latencies = Arc::new(Mutex::new(LatencySamples::new()));
    let per_second_log = Arc::new(Mutex::new(Vec::<PerSecond>::new()));

    let test_start = fedimint_core::time::now();

    // Per-second reporter: every second, snapshot counters and recent latencies
    // and emit a PerSecond row both to the logs and to the in-memory history.
    let ticker_counters = counters.clone();
    let ticker_latencies = latencies.clone();
    let ticker_history = per_second_log.clone();
    let ticker: JoinHandle<()> = spawn_task("bench-ticker", async move {
        let mut last_finalized_count = 0usize;
        let mut t: u64 = 0;
        loop {
            sleep(Duration::from_secs(1)).await;
            t += 1;
            let (sub, comp, err) = {
                let c = ticker_counters.lock().await;
                (c.submitted, c.completed, c.errors)
            };
            let in_flight = sub.saturating_sub(comp + err);
            let (p50, p95) = {
                let l = ticker_latencies.lock().await;
                if l.finalized_ms.len() > last_finalized_count {
                    let mut recent: Vec<u64> = l.finalized_ms[last_finalized_count..].to_vec();
                    last_finalized_count = l.finalized_ms.len();
                    recent.sort_unstable();
                    (percentile(&recent, 0.50), percentile(&recent, 0.95))
                } else {
                    (None, None)
                }
            };
            let row = PerSecond {
                t,
                submitted: sub,
                completed: comp,
                in_flight,
                errors: err,
                p50_finalized_ms: p50,
                p95_finalized_ms: p95,
            };
            info!(
                "t={}s  submitted={}  completed={}  in_flight={}  errors={}  p50_final={:?}ms  p95_final={:?}ms",
                row.t,
                row.submitted,
                row.completed,
                row.in_flight,
                row.errors,
                row.p50_finalized_ms,
                row.p95_finalized_ms,
            );
            ticker_history.lock().await.push(row);
        }
    });

    let payment_desc = if payment_range.min_msats == payment_range.max_msats {
        format!("{} msat", payment_range.min_msats)
    } else {
        format!(
            "uniform [{}, {}] msat",
            payment_range.min_msats, payment_range.max_msats
        )
    };
    info!(
        "Starting benchmark: target_tps={} ({} workers × {:.2} tps), duration={}s, payment={payment_desc}, sets={sets}",
        args.target_tps,
        workers.len(),
        per_worker_tps,
        args.duration_secs
    );

    // One driver task per worker: each runs a strict submit→await loop, paced
    // by its own token bucket. With sequential ops on its own DB the worker
    // avoids the WriteConflict storms a single shared client suffers under
    // concurrency.
    let mut worker_handles: Vec<JoinHandle<()>> = Vec::new();
    for (i, client) in workers.into_iter().enumerate() {
        let counters = counters.clone();
        let latencies = latencies.clone();
        worker_handles.push(spawn_task("bench-worker", async move {
            let mut next_due = test_start;
            loop {
                let now = fedimint_core::time::now();
                if now.duration_since(test_start).unwrap_or_default() >= duration {
                    break;
                }
                if let Ok(wait) = next_due.duration_since(now)
                    && !wait.is_zero()
                {
                    sleep(wait).await;
                }
                next_due += per_tx;
                {
                    let mut c = counters.lock().await;
                    c.submitted += 1;
                }
                let payment = payment_range.sample();
                match submit_single_payment(&client, payment, sets).await {
                    Ok(outcome) => {
                        {
                            let mut l = latencies.lock().await;
                            l.record(
                                outcome.accepted,
                                outcome.finalized,
                                outcome.user_outputs,
                                outcome.change_outputs,
                                payment.msats,
                            );
                        }
                        let mut c = counters.lock().await;
                        c.completed += 1;
                    }
                    Err(e) => {
                        warn!("worker {i} tx failed: {e:#}");
                        let mut c = counters.lock().await;
                        c.errors += 1;
                    }
                }
            }
        }));
    }

    for h in worker_handles {
        let _ = h.await;
    }

    let submit_phase = fedimint_core::time::now()
        .duration_since(test_start)
        .unwrap_or_default();
    info!("All workers finished at {:?}", submit_phase);

    ticker.abort();

    let per_second = per_second_log.lock().await.clone();
    let counters = counters.lock().await;
    let latencies = latencies.lock().await;

    let accepted_summary = PercentileSummary::from_samples(&latencies.accepted_ms);
    let finalized_summary = PercentileSummary::from_samples(&latencies.finalized_ms);

    let achieved_tps = if duration.as_secs_f64() > 0.0 {
        counters.completed as f64 / duration.as_secs_f64()
    } else {
        0.0
    };
    // Federation is "backed up" if either:
    //  - the achieved TPS lags target TPS by more than 15% (we couldn't keep up),
    //    or
    //  - the finalized p95 latency is much larger than p50 (queueing tail).
    let backed_up = {
        let lagging = achieved_tps < args.target_tps * 0.85;
        let big_tail = finalized_summary
            .as_ref()
            .map(|s| s.p50 > 0 && s.p95 > s.p50 * 3)
            .unwrap_or(false);
        lagging || big_tail
    };

    let user_outputs_summary = PercentileSummary::from_samples(&latencies.user_outputs);
    let change_outputs_summary = PercentileSummary::from_samples(&latencies.change_outputs);
    let total_outputs_summary = PercentileSummary::from_samples(&latencies.total_outputs);
    let payment_summary = PercentileSummary::from_samples(&latencies.payment_msats);

    Ok(BenchReport {
        target_tps: args.target_tps,
        duration_secs: args.duration_secs,
        achieved_tps,
        submitted: counters.submitted,
        completed: counters.completed,
        errors: counters.errors,
        accepted_latency_ms: accepted_summary,
        finalized_latency_ms: finalized_summary,
        user_outputs_per_tx: user_outputs_summary,
        change_outputs_per_tx: change_outputs_summary,
        total_outputs_per_tx: total_outputs_summary,
        payment_msats_per_tx: payment_summary,
        per_second,
        backed_up,
    })
}
