use std::collections::BTreeSet;
use std::num::NonZeroUsize;
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use bitcoin::secp256k1::PublicKey;
use fedimint_core::Amount;

use super::{
    Attempt, DEFAULT_MAX_ROUTES, PROBE_AMOUNTS, PaidInvoice, ProbeConfig,
    RECENT_DESTINATION_WINDOW, RecentDestinations, RouteOutcome, StoredDestinations,
    round_schedule, round_targets,
};

const BLINK: &str = "029fc6217803748cc8fb6b041acbe81e6e295a914487dcea7e5d7e141b64883826";
const LIGHTSPARK: &str = "039174f846626c6053ba80f5443d0db33da384f1dde135bf7080ba1eec465019c3";
const SPARK_PAYEE: &str = "030936e7a016fb3f5ce53c8db29da2b6dfbf8e068ea058c363e0fd77f444270d8a";
const ACINQ: &str = "03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f";

fn key(hex: &str) -> PublicKey {
    PublicKey::from_str(hex).expect("test keys are valid compressed points")
}

fn max(n: usize) -> NonZeroUsize {
    NonZeroUsize::new(n).expect("tests pass a positive maximum")
}

#[test]
fn schedule_covers_every_target_and_amount_once() {
    let targets = [key(BLINK), key(LIGHTSPARK)];
    let round = round_schedule(&targets).collect::<Vec<_>>();

    assert_eq!(round.len(), targets.len() * PROBE_AMOUNTS.len());
    assert_eq!(
        round.iter().collect::<BTreeSet<_>>().len(),
        round.len(),
        "a round probes each pair exactly once"
    );
    assert!(
        round.windows(2).all(|w| w[0].0 != w[1].0),
        "consecutive probes go to different targets"
    );
}

#[test]
fn round_targets_drop_peers_and_duplicates_keeping_configured_first() {
    let peers = BTreeSet::from([key(ACINQ)]);
    let targets = round_targets(
        &[key(BLINK), key(ACINQ)],
        &[key(LIGHTSPARK), key(BLINK)],
        &peers,
    );
    assert_eq!(targets, vec![key(BLINK), key(LIGHTSPARK)]);
}

#[test]
fn a_public_payee_is_probed_directly() {
    let paid = PaidInvoice {
        payee: key(BLINK),
        hint_entries: vec![key(LIGHTSPARK)],
    };
    assert_eq!(paid.probe_targets(|_| true), vec![key(BLINK)]);
}

#[test]
fn a_private_payee_is_probed_through_the_hint_entries_the_graph_knows() {
    let known = [key(LIGHTSPARK)];
    let paid = PaidInvoice {
        payee: key(SPARK_PAYEE),
        // A made-up hint (here ACINQ, unknown to this graph) is not probed,
        // and a repeated hint is probed once.
        hint_entries: vec![key(LIGHTSPARK), key(ACINQ), key(LIGHTSPARK)],
    };
    assert_eq!(
        paid.probe_targets(|node| known.contains(node)),
        vec![key(LIGHTSPARK)]
    );
}

#[test]
fn recent_destinations_rank_by_payments_then_recency() {
    let start = SystemTime::UNIX_EPOCH + Duration::from_hours(1_000_000);
    let mut recent = RecentDestinations::default();
    recent.record(key(BLINK), start);
    recent.record(key(LIGHTSPARK), start);
    recent.record(key(LIGHTSPARK), start + Duration::from_secs(1));
    recent.record(key(ACINQ), start + Duration::from_secs(2));

    let now = start + Duration::from_secs(3);
    assert_eq!(
        recent.top(max(3), now),
        vec![key(LIGHTSPARK), key(ACINQ), key(BLINK)],
        "most payments first, then the most recently paid"
    );
    assert_eq!(recent.top(max(1), now), vec![key(LIGHTSPARK)]);
}

#[test]
fn recent_destinations_forget_payments_older_than_the_window() {
    let start = SystemTime::UNIX_EPOCH + Duration::from_hours(1_000_000);
    let mut recent = RecentDestinations::default();
    recent.record(key(BLINK), start);
    recent.record(key(LIGHTSPARK), start);
    recent.record(key(LIGHTSPARK), start + RECENT_DESTINATION_WINDOW);

    let now = start + RECENT_DESTINATION_WINDOW + Duration::from_secs(1);
    assert_eq!(recent.top(max(5), now), vec![key(LIGHTSPARK)]);
    assert_eq!(
        recent.paid_at[&key(LIGHTSPARK)].len(),
        1,
        "the expired payment no longer counts"
    );
}

#[test]
fn fee_budget_matches_the_routing_fee_formula() {
    let config = ProbeConfig {
        max_fee_base_msat: 3_000,
        max_fee_ppm: 5_000,
        ..ProbeConfig::default()
    };
    assert_eq!(config.max_fee_msat(Amount::from_sats(20_000)), 103_000);

    let huge = ProbeConfig {
        max_fee_base_msat: u64::MAX,
        max_fee_ppm: u64::MAX,
        ..ProbeConfig::default()
    };
    assert_eq!(huge.max_fee_msat(Amount::from_msats(u64::MAX)), u64::MAX);
}

#[test]
fn recent_destinations_survive_a_save_and_load() {
    let dir = tempfile::tempdir().expect("a temporary directory can be created");
    let path = dir.path().join("probe_destinations.json");
    let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1_793_600_000);

    let mut recent = RecentDestinations::default();
    recent.record(key(LIGHTSPARK), start);
    recent.record(key(LIGHTSPARK), start + Duration::from_secs(60));
    recent.record(key(BLINK), start + Duration::from_secs(30));
    recent
        .save(&path)
        .expect("saving to a fresh directory works");

    let mut loaded = RecentDestinations::load(&path);
    let now = start + Duration::from_secs(120);
    assert_eq!(
        loaded.top(max(5), now),
        recent.top(max(5), now),
        "the same ranking after a restart"
    );
    assert_eq!(loaded.payments(&key(LIGHTSPARK)), 2);
}

#[test]
fn a_missing_or_damaged_file_starts_empty() {
    let dir = tempfile::tempdir().expect("a temporary directory can be created");
    let path = dir.path().join("probe_destinations.json");
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_793_600_000);

    assert!(RecentDestinations::load(&path).top(max(5), now).is_empty());

    std::fs::write(&path, b"{not json").expect("the file can be written");
    assert!(RecentDestinations::load(&path).top(max(5), now).is_empty());
}

#[test]
fn unparseable_stored_entries_are_dropped_and_times_sorted() {
    let stored = StoredDestinations {
        paid_at_secs: [
            ("not a key".to_string(), vec![1]),
            (BLINK.to_string(), vec![1_793_600_060, 1_793_600_000]),
        ]
        .into(),
    };
    let recent = RecentDestinations::from_stored(stored);
    assert_eq!(recent.paid_at.len(), 1);
    let times = &recent.paid_at[&key(BLINK)];
    assert!(
        times.front() < times.back(),
        "oldest first, as `top` prunes from the front"
    );
}

fn attempt(routes: &[RouteOutcome]) -> Attempt {
    let mut attempt = Attempt::default();
    for route in routes {
        attempt.record(route.clone());
    }
    attempt
}

#[test]
fn only_a_failed_route_earns_another_try() {
    assert!(attempt(&[RouteOutcome::Failed(vec![7])]).wants_another_route(3));
    for done in [
        RouteOutcome::Reached,
        RouteOutcome::TimedOut,
        RouteOutcome::Skipped,
        RouteOutcome::NoRoute,
    ] {
        assert!(
            !attempt(std::slice::from_ref(&done)).wants_another_route(3),
            "{done:?} ends the attempt"
        );
        assert!(
            !attempt(&[RouteOutcome::Failed(vec![7]), done.clone()]).wants_another_route(3),
            "{done:?} after a failure ends the attempt"
        );
    }
}

#[test]
fn an_attempt_stops_after_max_routes_failed() {
    let failed = || RouteOutcome::Failed(vec![1]);
    assert!(attempt(&[failed(), failed()]).wants_another_route(3));
    assert!(!attempt(&[failed(), failed(), failed()]).wants_another_route(3));
    assert!(!attempt(&[failed()]).wants_another_route(1));
}

#[test]
fn attempt_summary_reports_first_and_final_outcome() {
    let retried = attempt(&[
        RouteOutcome::Failed(vec![5, 9]),
        RouteOutcome::Failed(vec![9]),
        RouteOutcome::Reached,
    ]);
    assert_eq!(retried.routes_sent(), 3);
    assert_eq!(retried.first(), "failed");
    assert_eq!(retried.final_outcome(), "reached");
    assert_eq!(retried.failed_channels(), vec![5, 9]);

    // A retry that finds no other route leaves the attempt failed, not
    // "no route": a route was tried and failed.
    let exhausted = attempt(&[RouteOutcome::Failed(vec![5]), RouteOutcome::NoRoute]);
    assert_eq!(exhausted.routes_sent(), 1);
    assert_eq!(exhausted.final_outcome(), "failed");

    let unroutable = attempt(&[RouteOutcome::NoRoute]);
    assert_eq!(
        (
            unroutable.routes_sent(),
            unroutable.first(),
            unroutable.final_outcome()
        ),
        (0, "no_route", "no_route")
    );
}

#[test]
fn max_routes_defaults_when_unset() {
    assert_eq!(ProbeConfig::default().max_routes(), DEFAULT_MAX_ROUTES);
    let one = ProbeConfig {
        max_routes: Some(max(1)),
        ..ProbeConfig::default()
    };
    assert_eq!(one.max_routes(), 1);
}
