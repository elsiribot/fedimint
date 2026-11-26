use fedimint_core::Amount;
use fedimint_mintv2_common::Denomination;
use fedimint_mintv2_common::config::FeeConsensus;

use super::{ReissueError, reissue_overpayment};

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
