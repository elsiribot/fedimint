//! End-to-end integration tests for the `swap` module: a real cross-unit
//! atomic swap driven over consensus by a two-unit test federation.
//!
//! Unit-level correctness (offer lifecycle, fill/reclaim races, expiry,
//! determinism, solvency) is already covered by the `-server` and `-client`
//! unit tests against a seeded clock and in-memory state. THIS crate proves the
//! pieces compose: a real federation carrying TWO `mintv2` instances (a Bitcoin
//! primary plus a second instance denominated in a custom [`AmountUnit`]) plus
//! the swap module, with independent maker/taker clients whose funds actually
//! move between units when a swap settles.
//!
//! # Two-unit fixture
//!
//! [`fixtures`] boots `Fixtures::new_primary(Mintv2ClientInit, Mintv2Init)`
//! (the Bitcoin-denominated primary, i.e. [`UNIT_A`]) plus a second `mintv2`
//! instance via `with_extra_module_instance(MINTV2_KIND, MintGenParams {
//! amount_unit: UNIT_B })`, the swap module, and the dummy module used purely
//! as a per-unit test faucet.
//!
//! # Funding a client in a given unit
//!
//! There is no on-chain leg here, so e-cash is bootstrapped with the dummy
//! module, which prints funds from thin air. [`DummyClientModule::
//! create_input_in_unit`] mints a dummy input in an arbitrary unit; submitting
//! it with no matching output leaves the whole amount as a surplus that the
//! primary module registered for that unit (the corresponding `mintv2`
//! instance) issues back as e-cash change. Mint fees are disabled on the
//! federation so the credited balance is exactly the funded amount, keeping the
//! final-balance assertions exact.
//!
//! # Awaiting ASYNC settlement
//!
//! `make_offer`/`fill_offer` return as soon as their transaction is accepted,
//! but the actual cross-unit transfer happens LATER: the maker's state machine
//! polls `get_offer` until the offer is `Filled`, then auto-claims the taker
//! leg; the taker's state machine claims the maker leg once its fill is
//! accepted; and each claim's reissued e-cash is credited by a mint output
//! state machine after that. Balances are therefore never asserted the instant
//! a call returns -- [`await_balance`] polls `get_balance_for_unit` until it
//! reaches the expected value (or a bounded timeout elapses).

use std::time::Duration;

use anyhow::bail;
use fedimint_client::transaction::TransactionBuilder;
use fedimint_client::ClientHandleArc;
use fedimint_core::core::OperationId;
use fedimint_core::module::AmountUnit;
use fedimint_core::runtime::{sleep, Instant};
use fedimint_core::{Amount, OutPoint};
use fedimint_dummy_client::{DummyClientInit, DummyClientModule};
use fedimint_dummy_server::DummyInit;
use fedimint_mintv2_client::MintClientInit as Mintv2ClientInit;
use fedimint_mintv2_common::config::MintGenParams;
use fedimint_mintv2_common::KIND as MINTV2_KIND;
use fedimint_mintv2_server::MintInit as Mintv2Init;
use fedimint_swap_client::{SwapClientInit, SwapClientModule};
use fedimint_swap_common::OfferState;
use fedimint_swap_server::SwapInit;
use fedimint_testing::fixtures::Fixtures;

/// The maker leg's unit: the federation's Bitcoin-denominated primary `mintv2`.
const UNIT_A: AmountUnit = AmountUnit::BITCOIN;
/// The taker leg's unit: a second `mintv2` instance denominated in this custom
/// unit (any id other than [`AmountUnit::BITCOIN`]).
const UNIT_B: AmountUnit = AmountUnit::new_custom(2);

/// Every amount is a multiple of `mintv2`'s smallest client denomination (512
/// msats, `2^9`) so it is representable exactly with no denomination-rounding
/// dust -- otherwise the exact-equality balance assertions below could not
/// hold.
const FUND_A: Amount = Amount::from_msats(8_192_000);
const FUND_B: Amount = Amount::from_msats(8_192_000);
/// The maker's offered leg (given up in [`UNIT_A`]).
const AMT_A: Amount = Amount::from_msats(4_096_000);
/// The taker's leg the maker asks for (received in [`UNIT_B`]).
const AMT_B: Amount = Amount::from_msats(2_048_000);

/// A generous, offer-lifetime TTL. The non-expiry tests never wait anywhere
/// near this long, so the consensus-clock skew is irrelevant to them.
const TTL_SECS: u64 = 3600;

/// Bounded budget for awaiting an async settlement to reflect in a balance. The
/// maker SM's fill poll backs off to at most 5s, so this comfortably covers a
/// claim landing plus the reissued change being credited.
const SETTLE_TIMEOUT: Duration = Duration::from_secs(60);

/// A two-`mintv2`-unit federation (Bitcoin primary + a [`UNIT_B`] instance)
/// plus the swap module and the dummy faucet.
fn fixtures() -> Fixtures {
    Fixtures::new_primary(Mintv2ClientInit, Mintv2Init)
        .with_extra_module_instance(
            MINTV2_KIND,
            MintGenParams {
                amount_unit: UNIT_B,
            },
        )
        .with_module(DummyClientInit, DummyInit)
        .with_module(SwapClientInit, SwapInit)
}

/// Prints `amount` of `unit` e-cash into `client` via the dummy faucet and
/// waits for the reissued notes to be credited, so the balance is spendable
/// once this returns.
async fn fund_unit(
    client: &ClientHandleArc,
    unit: AmountUnit,
    amount: Amount,
) -> anyhow::Result<()> {
    let dummy = client.get_first_module::<DummyClientModule>()?;
    let input = dummy.create_input_in_unit(unit, amount);
    let operation_id = OperationId::new_random();

    let range = client
        .finalize_and_submit_transaction(
            operation_id,
            "fund unit via dummy faucet",
            |_| (),
            TransactionBuilder::new().with_inputs(input),
        )
        .await?;

    client
        .await_primary_module_outputs_for_unit(operation_id, range.into_iter().collect(), unit)
        .await?;

    Ok(())
}

/// Polls `client`'s balance in `unit` until it equals `expected`, failing after
/// [`SETTLE_TIMEOUT`]. This is how the tests wait for the ASYNC swap settlement
/// (see the module doc comment) without a flaky fixed sleep.
async fn await_balance(
    client: &ClientHandleArc,
    unit: AmountUnit,
    expected: Amount,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + SETTLE_TIMEOUT;
    loop {
        let balance = client.get_balance_for_unit(unit).await?;
        if balance == expected {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "balance for unit {unit:?} never reached {expected} (last read {balance}) within \
                 {SETTLE_TIMEOUT:?}"
            );
        }
        sleep(Duration::from_millis(200)).await;
    }
}

/// Fails unless exactly one open offer with `offer_id` (and the expected terms)
/// is visible to `client`.
async fn assert_offer_listed(client: &ClientHandleArc, offer_id: OutPoint) -> anyhow::Result<()> {
    let swap = client.get_first_module::<SwapClientModule>()?;
    let offers = swap.list_open_offers().await?;
    let (_, offer) = offers
        .iter()
        .find(|(id, _)| *id == offer_id)
        .unwrap_or_else(|| panic!("open offer {offer_id} must be listed, got {offers:?}"));
    assert_eq!(offer.maker_unit, UNIT_A);
    assert_eq!(offer.maker_amount, AMT_A);
    assert_eq!(offer.taker_unit, UNIT_B);
    assert_eq!(offer.taker_amount, AMT_B);
    assert_eq!(offer.state, OfferState::Open);
    Ok(())
}

async fn offer_is_listed(client: &ClientHandleArc, offer_id: OutPoint) -> anyhow::Result<bool> {
    let swap = client.get_first_module::<SwapClientModule>()?;
    Ok(swap
        .list_open_offers()
        .await?
        .iter()
        .any(|(id, _)| *id == offer_id))
}

/// The core proof: a maker offers [`AMT_A`] of [`UNIT_A`] for [`AMT_B`] of
/// [`UNIT_B`], a taker fills it, and both clients' balances move across units
/// once the swap settles asynchronously over consensus.
#[tokio::test(flavor = "multi_thread")]
async fn happy_round_trip_swaps_funds_across_units() -> anyhow::Result<()> {
    let fed = fixtures()
        .new_fed_builder(0)
        .disable_mint_fees()
        .build()
        .await;

    let maker = fed.new_client().await;
    let taker = fed.new_client().await;

    fund_unit(&maker, UNIT_A, FUND_A).await?;
    fund_unit(&taker, UNIT_B, FUND_B).await?;
    assert_eq!(maker.get_balance_for_unit(UNIT_A).await?, FUND_A);
    assert_eq!(taker.get_balance_for_unit(UNIT_B).await?, FUND_B);

    let offer_id = maker
        .get_first_module::<SwapClientModule>()?
        .make_offer(UNIT_A, AMT_A, UNIT_B, AMT_B, TTL_SECS)
        .await?;

    // The offer is visible to the (independent) taker with the right terms.
    assert_offer_listed(&taker, offer_id).await?;

    taker
        .get_first_module::<SwapClientModule>()?
        .fill_offer(offer_id)
        .await?;

    // Settlement is async: poll every leg until it reflects the swap.
    // Maker: gave AMT_A of UNIT_A, received AMT_B of UNIT_B.
    await_balance(&maker, UNIT_A, FUND_A - AMT_A).await?;
    await_balance(&maker, UNIT_B, AMT_B).await?;
    // Taker: gave AMT_B of UNIT_B, received AMT_A of UNIT_A.
    await_balance(&taker, UNIT_A, AMT_A).await?;
    await_balance(&taker, UNIT_B, FUND_B - AMT_B).await?;

    Ok(())
}

/// A maker who opens an offer that nobody fills can reclaim the escrowed leg:
/// its [`UNIT_A`] balance is restored and the offer disappears from the open
/// list.
#[tokio::test(flavor = "multi_thread")]
async fn reclaim_restores_maker_leg_when_unfilled() -> anyhow::Result<()> {
    let fed = fixtures()
        .new_fed_builder(0)
        .disable_mint_fees()
        .build()
        .await;

    let maker = fed.new_client().await;
    fund_unit(&maker, UNIT_A, FUND_A).await?;
    assert_eq!(maker.get_balance_for_unit(UNIT_A).await?, FUND_A);

    let swap = maker.get_first_module::<SwapClientModule>()?;
    let offer_id = swap
        .make_offer(UNIT_A, AMT_A, UNIT_B, AMT_B, TTL_SECS)
        .await?;

    // Offer opened; the maker leg is escrowed off the balance.
    assert!(offer_is_listed(&maker, offer_id).await?);
    await_balance(&maker, UNIT_A, FUND_A - AMT_A).await?;

    // No taker fills; the maker cancels and gets the leg back.
    swap.reclaim(offer_id).await?;
    await_balance(&maker, UNIT_A, FUND_A).await?;
    assert!(
        !offer_is_listed(&maker, offer_id).await?,
        "a reclaimed offer must no longer be open"
    );

    Ok(())
}

/// Two funded takers race to fill the same offer. Exactly one wins; the other's
/// fill is rejected and its escrowed [`UNIT_B`] funds are left untouched. The
/// assertions are order-independent -- either taker may win.
#[tokio::test(flavor = "multi_thread")]
async fn two_taker_race_settles_exactly_one() -> anyhow::Result<()> {
    let fed = fixtures()
        .new_fed_builder(0)
        .disable_mint_fees()
        .build()
        .await;

    let maker = fed.new_client().await;
    let taker_a = fed.new_client().await;
    let taker_b = fed.new_client().await;

    fund_unit(&maker, UNIT_A, FUND_A).await?;
    fund_unit(&taker_a, UNIT_B, FUND_B).await?;
    fund_unit(&taker_b, UNIT_B, FUND_B).await?;

    let offer_id = maker
        .get_first_module::<SwapClientModule>()?
        .make_offer(UNIT_A, AMT_A, UNIT_B, AMT_B, TTL_SECS)
        .await?;
    assert_offer_listed(&taker_a, offer_id).await?;

    // Both takers attempt the fill concurrently.
    let (res_a, res_b) = tokio::join!(
        async {
            taker_a
                .get_first_module::<SwapClientModule>()?
                .fill_offer(offer_id)
                .await
        },
        async {
            taker_b
                .get_first_module::<SwapClientModule>()?
                .fill_offer(offer_id)
                .await
        },
    );

    // Exactly one fill is accepted; the other is rejected.
    assert!(
        res_a.is_ok() ^ res_b.is_ok(),
        "exactly one fill must win the race (a: {res_a:?}, b: {res_b:?})"
    );

    let (winner, loser) = if res_a.is_ok() {
        (&taker_a, &taker_b)
    } else {
        (&taker_b, &taker_a)
    };

    // The winner receives the maker leg; the maker receives the winner's leg.
    await_balance(winner, UNIT_A, AMT_A).await?;
    await_balance(winner, UNIT_B, FUND_B - AMT_B).await?;
    await_balance(&maker, UNIT_B, AMT_B).await?;
    await_balance(&maker, UNIT_A, FUND_A - AMT_A).await?;

    // The loser's escrowed funds are restored in full (the rejected fill is
    // refunded), and it never received any of the maker leg.
    await_balance(loser, UNIT_B, FUND_B).await?;
    assert_eq!(loser.get_balance_for_unit(UNIT_A).await?, Amount::ZERO);

    Ok(())
}
