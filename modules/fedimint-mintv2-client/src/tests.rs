use bls12_381::G1Affine;
use fedimint_core::Amount;
use fedimint_core::module::{AmountUnit, Amounts};
use fedimint_core::secp256k1::{SECP256K1, SecretKey};
use fedimint_mintv2_common::config::FeeConsensus;
use fedimint_mintv2_common::{Denomination, MintInput, MintOutput, Note};

use super::{AwaitOutputError, ReissueError, mint_input_fee, mint_output_fee, reissue_overpayment};

fn d(exponents: &[u8]) -> Vec<Denomination> {
    exponents.iter().copied().map(Denomination).collect()
}

#[test]
fn an_exact_or_small_remainder_is_allowed() {
    let fee = FeeConsensus::new(0).unwrap();

    // 4096 - 100 - (2048 + 1024 + 512) - 300
    assert_eq!(
        reissue_overpayment(&fee, &d(&[12]), &d(&[11, 10, 9])).unwrap(),
        Amount::from_msats(112)
    );

    assert_eq!(
        reissue_overpayment(&FeeConsensus::zero(), &d(&[10]), &d(&[9, 9])).unwrap(),
        Amount::ZERO
    );
}

#[test]
fn a_shortfall_or_a_remainder_that_fits_a_note_is_refused() {
    let fee = FeeConsensus::new(0).unwrap();

    assert!(matches!(
        reissue_overpayment(&fee, &d(&[12]), &d(&[12])),
        Err(ReissueError::Unbalanced { .. })
    ));

    // A remainder of exactly the smallest note plus its fee is refused.
    assert!(matches!(
        reissue_overpayment(&FeeConsensus::zero(), &d(&[10]), &d(&[9])),
        Err(ReissueError::Unbalanced { .. })
    ));
}

#[test]
fn an_empty_side_is_refused() {
    let fee = FeeConsensus::new(0).unwrap();

    assert!(matches!(
        reissue_overpayment(&fee, &[], &d(&[9])),
        Err(ReissueError::Empty)
    ));
    assert!(matches!(
        reissue_overpayment(&fee, &d(&[12]), &[]),
        Err(ReissueError::Empty)
    ));
}

#[test]
fn an_overpayment_is_allowed_with_a_relative_fee() {
    // At 1000 ppm every tier pays a different fee: 100 msat plus 1 msat per
    // full 1000 msat of its own amount.
    let fee = FeeConsensus::new(1_000).unwrap();

    // 32768 - 132 - 31744 - (116 + 108 + 104 + 102 + 101)
    assert_eq!(
        reissue_overpayment(&fee, &d(&[15]), &d(&[14, 13, 12, 11, 10])).unwrap(),
        Amount::from_msats(361)
    );

    // The ceiling is 512 + fee(512) = 612: 773 is refused.
    assert!(matches!(
        reissue_overpayment(&fee, &d(&[15, 9]), &d(&[14, 13, 12, 11, 10])),
        Err(ReissueError::Unbalanced { .. })
    ));
}

#[test]
fn a_denomination_outside_the_client_denominations_is_refused() {
    let fee = FeeConsensus::new(0).unwrap();

    assert!(matches!(
        reissue_overpayment(&fee, &d(&[12]), &d(&[11, 8])),
        Err(ReissueError::InvalidDenomination(Denomination(8)))
    ));
    assert!(matches!(
        reissue_overpayment(&fee, &d(&[42]), &d(&[12])),
        Err(ReissueError::InvalidDenomination(Denomination(42)))
    ));
    // Would overflow `1 << d` if an amount were computed from it.
    assert!(matches!(
        reissue_overpayment(&fee, &d(&[12]), &d(&[200])),
        Err(ReissueError::InvalidDenomination(Denomination(200)))
    ));
}

fn input(denomination: u8) -> MintInput {
    MintInput::new_v0(Note {
        denomination: Denomination(denomination),
        nonce: SecretKey::from_slice(&[1; 32])
            .unwrap()
            .public_key(SECP256K1),
        signature: tbs::Signature(G1Affine::generator()),
    })
}

fn output(denomination: u8) -> MintOutput {
    MintOutput::new_v0(
        Denomination(denomination),
        tbs::BlindedMessage(G1Affine::generator()),
        [0; 16],
    )
}

/// The client's view of an overpaid reissue balances only because fees follow
/// the denominations: the same check as `finalize_transaction`, at 1000 ppm.
#[test]
fn an_overpaid_reissue_balances_with_fees_from_denominations() {
    let fee = FeeConsensus::new(1_000).unwrap();
    let unit = AmountUnit::BITCOIN;
    let declared = |amount: Amount| Amounts::new_custom(unit, amount);

    let inputs = [16, 9];
    let outputs = [10, 11, 12, 13, 14, 15];

    let overpayment = reissue_overpayment(&fee, &d(&inputs), &d(&outputs)).unwrap();
    let largest = Denomination(15).amount();

    // The overpayment raises the fee on the declared amount of the largest
    // output, so a fee taken from the declared amount would unbalance this.
    assert_ne!(fee.fee(largest + overpayment), fee.fee(largest));

    let mut inputs_total = Amount::ZERO;
    let mut fees = Amount::ZERO;

    for denomination in inputs {
        let amount = Denomination(denomination).amount();
        inputs_total += amount;
        fees += mint_input_fee(&fee, unit, &declared(amount), &input(denomination))
            .unwrap()
            .get(&unit)
            .copied()
            .unwrap();
    }

    let mut outputs_total = Amount::ZERO;

    for denomination in outputs {
        let mut amount = Denomination(denomination).amount();
        if denomination == 15 {
            amount += overpayment;
        }

        // The fee on the declared amount is never charged.
        let charged = mint_output_fee(&fee, unit, &declared(amount), &output(denomination))
            .unwrap()
            .get(&unit)
            .copied()
            .unwrap();
        assert_eq!(charged, fee.fee(Denomination(denomination).amount()));

        outputs_total += amount;
        fees += charged;
    }

    assert_eq!(inputs_total, outputs_total + fees);
}

#[test]
fn an_output_failure_is_not_a_rejection() {
    assert!(matches!(
        ReissueError::from(AwaitOutputError::Rejected),
        ReissueError::Rejected
    ));
    assert!(matches!(
        ReissueError::from(AwaitOutputError::Failed),
        ReissueError::OutputsFailed
    ));
}
