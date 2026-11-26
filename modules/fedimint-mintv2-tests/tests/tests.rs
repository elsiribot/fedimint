use std::collections::BTreeMap;
use std::pin::pin;

use anyhow::ensure;
use assert_matches::assert_matches;
use async_stream::stream;
use fedimint_client::error::OperationLookupError;
use fedimint_client::secret::{PlainRootSecretStrategy, RootSecretStrategy};
use fedimint_client::transaction::TransactionBuilder;
use fedimint_client::{ClientHandleArc, ModuleRecoveryCompleted, RootSecret};
use fedimint_core::Amount;
use fedimint_core::base32::{self, FEDIMINT_PREFIX};
use fedimint_core::config::FederationId;
use fedimint_core::core::OperationId;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::module::{AmountUnit, Amounts};
use fedimint_core::secp256k1::{Keypair, SECP256K1};
use fedimint_dummy_client::{DummyClientInit, DummyClientModule};
use fedimint_dummy_server::DummyInit;
use fedimint_eventlog::{Event, EventLogEntry, EventLogId};
use fedimint_mintv2_client::{
    ECash, FinalReceiveOperationState, MintClientInit, MintClientModule, MintOperationMeta,
    ReceiveECashError, ReceivePaymentEvent, ReceivePaymentStatus, ReceivePaymentUpdateEvent,
    ReissueError, SendECashError, SendPaymentEvent, SpendableNote,
};
use fedimint_mintv2_common::{Denomination, KIND};
use fedimint_mintv2_server::MintInit;
use fedimint_testing::federation::FederationTest;
use fedimint_testing::fixtures::Fixtures;
use futures::StreamExt;
use serde_json::Value;

#[derive(Debug, PartialEq, Eq)]
enum MintEvent {
    Send(SendPaymentEvent),
    Receive(ReceivePaymentEvent),
    ReceiveUpdate(ReceivePaymentUpdateEvent),
}

fn mint_event_stream(client: &ClientHandleArc) -> impl futures::Stream<Item = MintEvent> {
    let client = client.clone();
    let mut log_rx = client.log_event_added_rx();
    let mut next_id = EventLogId::LOG_START;

    stream! {
        loop {
            let events = client.get_event_log(Some(next_id), 100).await;

            for entry in events {
                next_id = entry.id().saturating_add(1);

                if let Some(event) = try_parse_mint_event(entry.as_raw()) {
                    yield event;
                }
            }

            let _ = log_rx.changed().await;
        }
    }
}

fn try_parse_mint_event(entry: &EventLogEntry) -> Option<MintEvent> {
    if entry.module_kind() != Some(&KIND) {
        return None;
    }

    if entry.kind == SendPaymentEvent::KIND {
        return entry.to_event().map(MintEvent::Send);
    }

    if entry.kind == ReceivePaymentUpdateEvent::KIND {
        return entry.to_event().map(MintEvent::ReceiveUpdate);
    }

    if entry.kind == ReceivePaymentEvent::KIND {
        return entry.to_event().map(MintEvent::Receive);
    }

    None
}

const SEND_SK: [u8; 64] = [0x42; 64];
const RECEIVE_SK: [u8; 64] = [0x69; 64];

fn root_secret(bytes: &[u8; 64]) -> RootSecret {
    RootSecret::StandardDoubleDerive(PlainRootSecretStrategy::to_root_secret(bytes))
}

async fn issue_ecash(client: &ClientHandleArc, amount: Amount) -> anyhow::Result<()> {
    let dummy_module = client.get_first_module::<DummyClientModule>()?;
    let dummy_input = dummy_module.create_input(amount);
    let operation_id = OperationId::new_random();

    let outpoint_range = client
        .finalize_and_submit_transaction(
            operation_id,
            "Issue e-cash via dummy module",
            |_| (),
            TransactionBuilder::new().with_inputs(dummy_input),
        )
        .await?;

    client
        .await_primary_bitcoin_module_outputs(operation_id, outpoint_range.into_iter().collect())
        .await?;

    Ok(())
}

fn fixtures() -> Fixtures {
    let fixtures = Fixtures::new_primary(MintClientInit, MintInit);

    fixtures.with_module(DummyClientInit, DummyInit)
}

#[tokio::test(flavor = "multi_thread")]
async fn send_and_receive() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;

    let client_send = fed
        .join_client_with_db(MemDatabase::new().into(), root_secret(&SEND_SK))
        .await;

    let client_receive = fed
        .join_client_with_db(MemDatabase::new().into(), root_secret(&RECEIVE_SK))
        .await;

    issue_ecash(&client_send, Amount::from_sats(11_000)).await?;

    let mut send_events = pin!(mint_event_stream(&client_send));
    let mut receive_events = pin!(mint_event_stream(&client_receive));

    for i in 0..10 {
        tracing::info!("Sending ecash payment {i} of 10");

        // Exercise both with and without the optional invite code.
        let include_invite = i % 2 == 0;

        let (operation_id, ecash) = client_send
            .get_first_module::<MintClientModule>()?
            .send(Amount::from_sats(1_000), Value::Null, include_invite)
            .await?;

        let Some(MintEvent::Send(send)) = send_events.next().await else {
            panic!("Expected Send event");
        };
        assert_eq!(send.operation_id, operation_id);

        let ecash = base32::encode_prefixed(FEDIMINT_PREFIX, &ecash);

        let ecash: ECash = base32::decode_prefixed(FEDIMINT_PREFIX, &ecash).unwrap();

        // When requested, the sender embeds the federation invite code so a
        // recipient can join the issuing federation directly from the received
        // ecash. Otherwise no invite is present.
        assert_eq!(
            ecash
                .federation_invite()
                .map(|invite| invite.federation_id()),
            include_invite.then(|| client_send.federation_id()),
        );

        // The sender attaches the unit its mint is configured with; the test
        // federation's mint is denominated in Bitcoin.
        assert_eq!(ecash.unit(), AmountUnit::BITCOIN);

        let operation_id = client_receive
            .get_first_module::<MintClientModule>()?
            .receive(ecash, Value::Null)
            .await?;

        let state = client_receive
            .get_first_module::<MintClientModule>()?
            .await_final_receive_operation_state(operation_id)
            .await?;

        assert_eq!(state, FinalReceiveOperationState::Success);

        let Some(MintEvent::Receive(receive)) = receive_events.next().await else {
            panic!("Expected Receive event");
        };
        assert_eq!(receive.operation_id, operation_id);

        let Some(MintEvent::ReceiveUpdate(update)) = receive_events.next().await else {
            panic!("Expected ReceiveUpdate event");
        };
        assert_eq!(update.operation_id, receive.operation_id);
        assert_eq!(update.status, ReceivePaymentStatus::Success);

        test_client_recovery(&fed, &client_send, root_secret(&SEND_SK)).await?;
        test_client_recovery(&fed, &client_receive, root_secret(&RECEIVE_SK)).await?;
    }

    ensure!(client_receive.get_balance_for_btc().await? >= Amount::from_sats(9900));

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn awaiting_an_unknown_receive_operation_reports_not_found() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;
    let client = fed.new_client().await;
    let operation_id = OperationId::new_random();

    assert_matches!(
        client
            .get_first_module::<MintClientModule>()?
            .await_final_receive_operation_state(operation_id)
            .await,
        Err(OperationLookupError::NotFound(_))
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn receive_fee_quote_matches_actual_fee() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;

    let client_send = fed
        .join_client_with_db(MemDatabase::new().into(), root_secret(&SEND_SK))
        .await;
    let client_receive = fed
        .join_client_with_db(MemDatabase::new().into(), root_secret(&RECEIVE_SK))
        .await;

    issue_ecash(&client_send, Amount::from_sats(11_000)).await?;

    // Receive several times so the receiver's note inventory — and therefore the
    // rebalance-driven fee — differs between iterations (first into an empty
    // wallet, then into a progressively more populated one).
    for i in 0..5 {
        let (_operation_id, ecash) = client_send
            .get_first_module::<MintClientModule>()?
            .send(Amount::from_sats(1_000), Value::Null, false)
            .await?;
        let ecash: ECash = base32::decode_prefixed(
            FEDIMINT_PREFIX,
            &base32::encode_prefixed(FEDIMINT_PREFIX, &ecash),
        )
        .unwrap();

        let mint = client_receive.get_first_module::<MintClientModule>()?;
        let ecash_value = ecash.amount();

        let quote = mint.receive_fee_quote(&ecash).await?;
        let before = client_receive.get_balance_for_btc().await?;

        let operation_id = mint.receive(ecash, Value::Null).await?;
        let state = mint
            .await_final_receive_operation_state(operation_id)
            .await?;
        ensure!(state == FinalReceiveOperationState::Success);

        // The receive state machine reports `Success` once the tx is accepted,
        // but the reissued (change) notes are credited by the output state
        // machines. Wait for those before reading the settled balance.
        let MintOperationMeta::Receive {
            change_outpoint_range,
            ..
        } = client_receive
            .operation_log()
            .get_operation(operation_id)
            .await
            .expect("operation exists")
            .meta::<MintOperationMeta>()
        else {
            panic!("expected a receive operation");
        };
        client_receive
            .await_primary_bitcoin_module_outputs(
                operation_id,
                change_outpoint_range.into_iter().collect(),
            )
            .await?;

        let after = client_receive.get_balance_for_btc().await?;
        let actual_fee = ecash_value - (after - before);

        ensure!(
            quote.total() == Amounts::new_bitcoin(actual_fee),
            "iteration {i}: quoted fee {quote:?} != actual fee {actual_fee:?}"
        );
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn send_fee_quote_matches_actual_fee() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;

    let client = fed
        .join_client_with_db(MemDatabase::new().into(), root_secret(&SEND_SK))
        .await;

    issue_ecash(&client, Amount::from_sats(11_000)).await?;

    // Send several times so the wallet's note inventory — and therefore whether a
    // self-reissue (and its fee) is needed to reach the requested denomination —
    // differs between iterations.
    for i in 0..5 {
        let mint = client.get_first_module::<MintClientModule>()?;

        // Settle any pending change from the previous iteration so the quote and
        // the send observe the same inventory.
        client.wait_for_all_active_state_machines().await;

        let quote = mint.send_fee_quote(Amount::from_sats(1_000)).await?;
        let before = client.get_balance_for_btc().await?;

        let (_operation_id, ecash) = mint
            .send(Amount::from_sats(1_000), Value::Null, false)
            .await?;
        let sent_value = ecash.amount();

        // A send may trigger an internal reissue whose change notes are credited
        // by output state machines; wait for them before reading the balance.
        client.wait_for_all_active_state_machines().await;
        let after = client.get_balance_for_btc().await?;

        // Value conservation: the wallet loses exactly the sent value plus the fee.
        let actual_fee = before - after - sent_value;

        ensure!(
            quote.total() == Amounts::new_bitcoin(actual_fee),
            "iteration {i}: quoted fee {quote:?} != actual fee {actual_fee:?}"
        );
    }

    Ok(())
}

/// Wait for and return the `amount` from the mintv2 module's
/// `ModuleRecoveryCompleted` event in `client`'s event log.
///
/// `ModuleRecoveryCompleted` is a core event (its module tag is unset), so
/// unlike `mint_event_stream` it's matched by event kind and by the mintv2
/// `kind` carried in the payload (recovery runs for the dummy module too).
///
/// Blocks until the event has been ordered into the log; it is emitted as
/// recovery finishes, so this returns shortly after `wait_for_all_recoveries`.
async fn mintv2_recovery_completed_amount(client: &ClientHandleArc) -> Option<Amount> {
    let mut log_rx = client.log_event_added_rx();
    let mut next_id = EventLogId::LOG_START;

    loop {
        for entry in client.get_event_log(Some(next_id), 100).await {
            next_id = entry.id().saturating_add(1);

            if entry.as_raw().kind != ModuleRecoveryCompleted::KIND {
                continue;
            }

            let event: ModuleRecoveryCompleted = entry
                .as_raw()
                .to_event()
                .expect("recovery-completed payload must decode");

            if event.kind.as_ref() == Some(&KIND) {
                return event.amount;
            }
        }

        log_rx
            .changed()
            .await
            .expect("event log notifier stays alive while the client is running");
    }
}

async fn test_client_recovery(
    fed: &FederationTest,
    client: &ClientHandleArc,
    root_secret: RootSecret,
) -> anyhow::Result<()> {
    // Wait for state machines to complete
    client.wait_for_all_active_state_machines().await;

    let expected_balance = client.get_balance_for_btc().await?;

    assert_ne!(expected_balance, Amount::ZERO);

    let recovering_client = fed
        .recover_client_with_db(MemDatabase::new().into(), root_secret.clone())
        .await;

    // Neither module is held back by the recovery: the dummy module implements
    // none, and the mint fixed the extent of its own before it was initialized.
    // So both are usable while the recovery is still running, rather than only
    // once it has finished and the client has been reopened.
    ensure!(
        recovering_client.all_modules_usable(),
        "A module was held back by the recovery"
    );
    recovering_client.get_first_module::<DummyClientModule>()?;
    recovering_client.get_first_module::<MintClientModule>()?;

    recovering_client.wait_for_all_recoveries().await?;

    // The mintv2 module's recovery-completed event reports the total value of
    // the notes it reconstructed, which equals the pre-recovery balance.
    let event_amount = mintv2_recovery_completed_amount(&recovering_client).await;
    ensure!(
        event_amount == Some(expected_balance),
        "recovery-completed event amount mismatch: expected {expected_balance}, got {event_amount:?}"
    );

    // The recovered notes are signed and land in the very client that ran the
    // recovery, without it having to be reopened first.
    recovering_client.wait_for_all_active_state_machines().await;

    let recovered_balance = recovering_client.get_balance_for_btc().await?;

    ensure!(
        recovered_balance == expected_balance,
        "Recovery balance mismatch: expected {expected_balance}, got {recovered_balance}"
    );

    // Reopening must neither restart the recovery nor duplicate what it
    // recovered.
    let reopened_client = fed
        .open_client_with_db(recovering_client.db().clone(), root_secret)
        .await;

    reopened_client.wait_for_all_active_state_machines().await;

    let reopened_balance = reopened_client.get_balance_for_btc().await?;

    ensure!(
        reopened_balance == expected_balance,
        "Balance changed on reopen: expected {expected_balance}, got {reopened_balance}"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn double_spend_is_rejected() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;

    let (client_send, client_receive) = fed.two_clients().await;

    issue_ecash(&client_send, Amount::from_sats(10_000)).await?;

    let mut send_events = pin!(mint_event_stream(&client_send));
    let mut receive_events = pin!(mint_event_stream(&client_receive));

    let (send_operation_id, ecash) = client_send
        .get_first_module::<MintClientModule>()?
        .send(Amount::from_sats(1_000), Value::Null, false)
        .await?;

    let Some(MintEvent::Send(send)) = send_events.next().await else {
        panic!("Expected Send event");
    };
    assert_eq!(send.operation_id, send_operation_id);

    let operation_id = client_send
        .get_first_module::<MintClientModule>()?
        .receive(ecash.clone(), Value::Null)
        .await?;

    let state = client_send
        .get_first_module::<MintClientModule>()?
        .await_final_receive_operation_state(operation_id)
        .await?;

    assert_eq!(state, FinalReceiveOperationState::Success);

    let Some(MintEvent::Receive(receive)) = send_events.next().await else {
        panic!("Expected Receive event");
    };
    assert_eq!(receive.operation_id, operation_id);

    let Some(MintEvent::ReceiveUpdate(update)) = send_events.next().await else {
        panic!("Expected ReceiveUpdate event");
    };
    assert_eq!(update.operation_id, receive.operation_id);
    assert_eq!(update.status, ReceivePaymentStatus::Success);

    let operation_id = client_receive
        .get_first_module::<MintClientModule>()?
        .receive(ecash, Value::Null)
        .await?;

    let state = client_receive
        .get_first_module::<MintClientModule>()?
        .await_final_receive_operation_state(operation_id)
        .await?;

    assert_eq!(state, FinalReceiveOperationState::Rejected);

    let Some(MintEvent::Receive(receive)) = receive_events.next().await else {
        panic!("Expected Receive event");
    };
    assert_eq!(receive.operation_id, operation_id);

    let Some(MintEvent::ReceiveUpdate(update)) = receive_events.next().await else {
        panic!("Expected ReceiveUpdate event");
    };
    assert_eq!(update.operation_id, receive.operation_id);
    assert_eq!(update.status, ReceivePaymentStatus::Rejected);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn transaction_with_invalid_signature_is_rejected() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;

    let client = fed.new_client().await;

    issue_ecash(&client, Amount::from_sats(10_000)).await?;

    let mut events = pin!(mint_event_stream(&client));

    let (operation_id, ecash) = client
        .get_first_module::<MintClientModule>()?
        .send(Amount::from_sats(1_000), Value::Null, false)
        .await?;

    let Some(MintEvent::Send(send)) = events.next().await else {
        panic!("Expected Send event");
    };
    assert_eq!(send.operation_id, operation_id);

    let mut invalid_notes = ecash.notes();

    for note in &mut invalid_notes {
        note.signature = tbs::Signature(bls12_381::G1Affine::generator());
    }

    let invalid_ecash = ECash::new(ecash.mint().unwrap(), invalid_notes);

    let operation_id = client
        .get_first_module::<MintClientModule>()?
        .receive(invalid_ecash, Value::Null)
        .await?;

    let state = client
        .get_first_module::<MintClientModule>()?
        .await_final_receive_operation_state(operation_id)
        .await?;

    assert_eq!(state, FinalReceiveOperationState::Rejected);

    let Some(MintEvent::Receive(receive)) = events.next().await else {
        panic!("Expected Receive event");
    };
    assert_eq!(receive.operation_id, operation_id);

    let Some(MintEvent::ReceiveUpdate(update)) = events.next().await else {
        panic!("Expected ReceiveUpdate event");
    };
    assert_eq!(update.operation_id, receive.operation_id);
    assert_eq!(update.status, ReceivePaymentStatus::Rejected);

    let valid_ecash = ECash::new(ecash.mint().unwrap(), ecash.notes());

    let operation_id = client
        .get_first_module::<MintClientModule>()?
        .receive(valid_ecash, Value::Null)
        .await?;

    let state = client
        .get_first_module::<MintClientModule>()?
        .await_final_receive_operation_state(operation_id)
        .await?;

    assert_eq!(state, FinalReceiveOperationState::Success);

    let Some(MintEvent::Receive(receive)) = events.next().await else {
        panic!("Expected Receive event");
    };
    assert_eq!(receive.operation_id, operation_id);

    let Some(MintEvent::ReceiveUpdate(update)) = events.next().await else {
        panic!("Expected ReceiveUpdate event");
    };
    assert_eq!(update.operation_id, receive.operation_id);
    assert_eq!(update.status, ReceivePaymentStatus::Success);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn receive_rejects_ecash_from_another_federation() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;
    let client = fed.new_client().await;

    issue_ecash(&client, Amount::from_sats(10_000)).await?;

    let (_operation_id, ecash) = client
        .get_first_module::<MintClientModule>()?
        .send(Amount::from_sats(1_000), Value::Null, false)
        .await?;

    // Re-wrap the same notes under a federation id that is not ours. `receive`
    // checks the mint id before submitting anything to consensus.
    let foreign_ecash = ECash::new(FederationId::dummy(), ecash.notes());

    assert_matches!(
        client
            .get_first_module::<MintClientModule>()?
            .receive(foreign_ecash, Value::Null)
            .await,
        Err(ReceiveECashError::WrongFederation)
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn receiving_the_same_ecash_twice_is_rejected() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;
    let client = fed.new_client().await;

    issue_ecash(&client, Amount::from_sats(10_000)).await?;

    let (_operation_id, ecash) = client
        .get_first_module::<MintClientModule>()?
        .send(Amount::from_sats(1_000), Value::Null, false)
        .await?;

    let operation_id = client
        .get_first_module::<MintClientModule>()?
        .receive(ecash.clone(), Value::Null)
        .await?;

    assert_eq!(
        client
            .get_first_module::<MintClientModule>()?
            .await_final_receive_operation_state(operation_id)
            .await?,
        FinalReceiveOperationState::Success,
    );

    // The operation id is derived from the ecash itself, so a second receive of
    // the identical notes finds the existing operation and refuses rather than
    // submitting a duplicate transaction.
    assert_matches!(
        client
            .get_first_module::<MintClientModule>()?
            .receive(ecash, Value::Null)
            .await,
        Err(ReceiveECashError::AlreadyReceived)
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn receive_rejects_notes_below_the_base_fee() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;
    let client = fed.new_client().await;

    // `Denomination(0)` is one msat, far below the hundred-msat base fee, so
    // reissuing it could never pay for itself. The signature is never checked
    // because the denomination guard runs first.
    let dust_note = SpendableNote {
        denomination: Denomination(0),
        keypair: Keypair::from_seckey_slice(SECP256K1, &[1u8; 32])?,
        signature: tbs::Signature(bls12_381::G1Affine::generator()),
    };

    let dust_ecash = ECash::new(client.federation_id(), vec![dust_note]);

    assert_matches!(
        client
            .get_first_module::<MintClientModule>()?
            .receive(dust_ecash, Value::Null)
            .await,
        Err(ReceiveECashError::UneconomicalDenomination)
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn send_without_funds_reports_insufficient_balance() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;

    // Deliberately no `issue_ecash` call: the wallet is empty.
    let client = fed.new_client().await;

    assert_matches!(
        client
            .get_first_module::<MintClientModule>()?
            .send(Amount::from_sats(1_000), Value::Null, false)
            .await
            .map(|(_operation_id, ecash)| ecash.amount()),
        Err(SendECashError::InsufficientBalance)
    );

    Ok(())
}

mod db;

/// Sum of the face values of `denominations`.
fn face_value(denominations: &[Denomination]) -> Amount {
    denominations.iter().map(|d| d.amount()).sum()
}

/// Sum of the mint fees on `denominations`, one fee per note.
fn fees(mint: &MintClientModule, denominations: &[Denomination]) -> Amount {
    denominations
        .iter()
        .map(|d| mint.fee_consensus().fee(d.amount()))
        .sum()
}

/// What is left of the `inputs` once the `outputs` and every fee are paid.
fn remainder(mint: &MintClientModule, inputs: &[Denomination], outputs: &[Denomination]) -> Amount {
    face_value(inputs) - fees(mint, inputs) - face_value(outputs) - fees(mint, outputs)
}

/// Greedily spend `amount` on notes of at most `max`, each paying its own fee,
/// largest first.
fn split_with_fees(mint: &MintClientModule, mut amount: Amount, max: u8) -> Vec<Denomination> {
    let mut denominations = Vec::new();

    for denomination in (9..=max).rev().map(Denomination) {
        let cost = denomination.amount() + mint.fee_consensus().fee(denomination.amount());

        while amount >= cost {
            amount -= cost;
            denominations.push(denomination);
        }
    }

    denominations
}

/// A client holding the 11,000 sats the dummy module issued it, settled.
async fn funded_client(fed: &FederationTest) -> anyhow::Result<ClientHandleArc> {
    let client = fed.new_client().await;

    issue_ecash(&client, Amount::from_sats(11_000)).await?;

    client.wait_for_all_active_state_machines().await;

    Ok(client)
}

/// Reissue `inputs` into `outputs`, wait for it, and check that exactly the
/// named notes went and came and that the balance fell by Σin − Σout. Returns
/// the note counts afterwards.
async fn reissue_and_check(
    client: &ClientHandleArc,
    inputs: Vec<Denomination>,
    outputs: Vec<Denomination>,
) -> anyhow::Result<BTreeMap<Denomination, u64>> {
    let mint = client.get_first_module::<MintClientModule>()?;

    let counts_before = mint.get_count_by_denomination().await;
    let balance_before = client.get_balance_for_btc().await?;

    let operation_id = mint
        .reissue(inputs.clone(), outputs.clone(), Value::Null)
        .await?;

    mint.await_reissue(operation_id).await?;

    client.wait_for_all_active_state_machines().await;

    let MintOperationMeta::Reissue {
        change_outpoint_range,
        amount,
        ..
    } = client
        .operation_log()
        .get_operation(operation_id)
        .await
        .expect("operation exists")
        .meta::<MintOperationMeta>()
    else {
        panic!("expected a reissue operation");
    };

    assert_eq!(change_outpoint_range.into_iter().count(), outputs.len());
    assert_eq!(amount, face_value(&outputs));

    let counts_after = mint.get_count_by_denomination().await;
    let balance_after = client.get_balance_for_btc().await?;

    assert_eq!(
        balance_before - balance_after,
        face_value(&inputs) - face_value(&outputs)
    );

    let tiers = counts_before
        .keys()
        .chain(counts_after.keys())
        .chain(&inputs)
        .chain(&outputs)
        .copied()
        .collect::<std::collections::BTreeSet<Denomination>>();

    for tier in tiers {
        let spent = inputs.iter().filter(|d| **d == tier).count() as u64;
        let issued = outputs.iter().filter(|d| **d == tier).count() as u64;
        let before = counts_before.get(&tier).copied().unwrap_or(0);
        let after = counts_after.get(&tier).copied().unwrap_or(0);

        assert_eq!(after, before - spent + issued, "tier {tier}");
    }

    Ok(counts_after)
}

#[tokio::test(flavor = "multi_thread")]
async fn reissue_merges_chosen_notes() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;
    let client = funded_client(&fed).await?;
    let mint = client.get_first_module::<MintClientModule>()?;

    let counts = mint.get_count_by_denomination().await;
    assert!(counts[&Denomination(12)] >= 2);
    assert!(counts[&Denomination(11)] >= 1);

    // Two notes of 12 alone are worth exactly one of 13, which leaves nothing
    // for the fees, so a note of 11 pays them.
    let inputs = vec![Denomination(12), Denomination(11), Denomination(12)];
    let rest = split_with_fees(&mint, remainder(&mint, &inputs, &[Denomination(13)]), 41);
    let outputs = std::iter::once(Denomination(13)).chain(rest).collect();

    let counts_before = counts;
    let counts_after = reissue_and_check(&client, inputs, outputs).await?;

    assert_eq!(
        counts_after[&Denomination(13)],
        counts_before[&Denomination(13)] + 1
    );
    assert_eq!(
        counts_after.get(&Denomination(12)).copied().unwrap_or(0),
        counts_before[&Denomination(12)] - 2
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reissue_splits_a_chosen_note() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;
    let client = funded_client(&fed).await?;
    let mint = client.get_first_module::<MintClientModule>()?;

    assert!(mint.get_count_by_denomination().await[&Denomination(15)] >= 1);

    let inputs = vec![Denomination(15)];
    let outputs = split_with_fees(&mint, remainder(&mint, &inputs, &[]), 14);

    assert!(outputs.len() > 1);
    assert!(
        outputs
            .iter()
            .all(|d| (Denomination(9)..=Denomination(14)).contains(d))
    );

    reissue_and_check(&client, inputs, outputs).await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reissue_with_a_remainder_touches_no_other_note() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;
    let client = funded_client(&fed).await?;
    let mint = client.get_first_module::<MintClientModule>()?;

    let ceiling = Denomination(9).amount() + mint.fee_consensus().fee(Denomination(9).amount());

    // Pile up notes of 9, so that the primary module, were it asked to
    // balance anything, would pick from that tier first.
    let inputs = vec![Denomination(15)];
    let nines = vec![Denomination(9); 9];
    let rest = split_with_fees(&mint, remainder(&mint, &inputs, &nines), 14);
    let outputs = nines.into_iter().chain(rest).collect();

    let counts = reissue_and_check(&client, inputs, outputs).await?;

    assert!(counts[&Denomination(9)] > 6);

    let inputs = vec![Denomination(14)];
    let outputs = vec![
        Denomination(10),
        Denomination(11),
        Denomination(12),
        Denomination(13),
    ];
    let r = remainder(&mint, &inputs, &outputs);

    assert!(Amount::ZERO < r && r < ceiling, "remainder {r}");

    let counts_after = reissue_and_check(&client, inputs, outputs).await?;

    assert_eq!(counts_after[&Denomination(9)], counts[&Denomination(9)]);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn unbalanced_reissue_is_refused_before_submission() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;
    let client = funded_client(&fed).await?;
    let mint = client.get_first_module::<MintClientModule>()?;

    let counts = mint.get_count_by_denomination().await;
    let balance = client.get_balance_for_btc().await?;
    let operations = client
        .operation_log()
        .paginate_operations_rev(100, None)
        .await
        .len();

    // The fees push the outputs above the inputs.
    assert_matches!(
        mint.reissue(vec![Denomination(12)], vec![Denomination(12)], Value::Null)
            .await,
        Err(ReissueError::Unbalanced { .. })
    );

    // A note of 9 and its fee would still fit into what is left over.
    assert_matches!(
        mint.reissue(vec![Denomination(14)], vec![Denomination(13)], Value::Null)
            .await,
        Err(ReissueError::Unbalanced { .. })
    );

    assert_eq!(mint.get_count_by_denomination().await, counts);
    assert_eq!(client.get_balance_for_btc().await?, balance);
    assert_eq!(
        client
            .operation_log()
            .paginate_operations_rev(100, None)
            .await
            .len(),
        operations
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reissue_of_a_note_not_held_is_refused() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;
    let client = funded_client(&fed).await?;
    let mint = client.get_first_module::<MintClientModule>()?;

    let counts = mint.get_count_by_denomination().await;
    let balance = client.get_balance_for_btc().await?;
    let operations = client
        .operation_log()
        .paginate_operations_rev(100, None)
        .await
        .len();

    assert!(!counts.contains_key(&Denomination(30)));

    // Balanced, so the only thing wrong is the missing note.
    let inputs = vec![Denomination(30)];
    let outputs = split_with_fees(&mint, remainder(&mint, &inputs, &[]), 29);

    assert_matches!(
        mint.reissue(inputs, outputs, Value::Null).await,
        Err(ReissueError::MissingNote(Denomination(30)))
    );

    assert_eq!(mint.get_count_by_denomination().await, counts);
    assert_eq!(client.get_balance_for_btc().await?, balance);
    assert_eq!(
        client
            .operation_log()
            .paginate_operations_rev(100, None)
            .await
            .len(),
        operations
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reissue_into_a_denomination_outside_the_client_range_is_refused() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;
    let client = funded_client(&fed).await?;
    let mint = client.get_first_module::<MintClientModule>()?;

    let counts = mint.get_count_by_denomination().await;
    let balance = client.get_balance_for_btc().await?;
    let operations = client
        .operation_log()
        .paginate_operations_rev(100, None)
        .await
        .len();

    // A consensus denomination the federation would sign, but below the
    // client denominations.
    assert_matches!(
        mint.reissue(
            vec![Denomination(12)],
            vec![Denomination(11), Denomination(8)],
            Value::Null
        )
        .await,
        Err(ReissueError::InvalidDenomination(Denomination(8)))
    );

    // Not a denomination at all: `1 << 64` would overflow.
    assert_matches!(
        mint.reissue(vec![Denomination(12)], vec![Denomination(64)], Value::Null)
            .await,
        Err(ReissueError::InvalidDenomination(Denomination(64)))
    );

    assert_eq!(mint.get_count_by_denomination().await, counts);
    assert_eq!(client.get_balance_for_btc().await?, balance);
    assert_eq!(
        client
            .operation_log()
            .paginate_operations_rev(100, None)
            .await
            .len(),
        operations
    );

    Ok(())
}
