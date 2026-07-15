// Tests are added task by task.

use cggmp21::ExecutionId;
use rand::rngs::OsRng;

const N: u16 = 4;
const T: u16 = 3;

#[tokio::test(flavor = "multi_thread")]
async fn dkg_produces_consistent_group_key() {
    let eid = ExecutionId::new(b"fedimint-threshold-ecdsa-test-dkg");

    let shares =
        round_based::sim::run_with_setup((0..N).map(|_| OsRng), |i, party, mut rng| async move {
            crate::run_keygen(eid, i, T, N, &mut rng, party).await
        })
        .expect("simulation failed")
        .into_iter()
        .collect::<anyhow::Result<Vec<_>>>()
        .expect("keygen failed");

    assert_eq!(shares.len(), usize::from(N));
    // All parties must agree on the group public key.
    let pk0 = shares[0].shared_public_key();
    for share in &shares[1..] {
        assert_eq!(share.shared_public_key(), pk0);
    }
}
