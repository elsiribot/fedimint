// Tests are added task by task.

use cggmp21::ExecutionId;
use cggmp21::key_share::AnyKeyShare as _;
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

#[tokio::test(flavor = "multi_thread")]
async fn aux_gen_and_assembly_yield_full_key_share() {
    let eid_keygen = ExecutionId::new(b"test-aux-keygen");
    let eid_aux = ExecutionId::new(b"test-aux-auxgen");

    let cores =
        round_based::sim::run_with_setup((0..N).map(|_| OsRng), |i, party, mut rng| async move {
            crate::run_keygen(eid_keygen, i, T, N, &mut rng, party).await
        })
        .expect("sim failed")
        .into_iter()
        .collect::<anyhow::Result<Vec<_>>>()
        .expect("keygen failed");

    let aux_infos =
        round_based::sim::run_with_setup((0..N).map(|_| OsRng), |i, party, mut rng| async move {
            let primes = cggmp21::PregeneratedPrimes::generate(&mut rng);
            crate::run_aux_gen(eid_aux, i, N, primes, &mut rng, party).await
        })
        .expect("sim failed")
        .into_iter()
        .collect::<anyhow::Result<Vec<_>>>()
        .expect("aux gen failed");

    for (core, aux) in cores.into_iter().zip(aux_infos) {
        let share = crate::assemble_key_share(core, aux).expect("assembly failed");
        // serde round-trip: shares must be storable in the guardian DB.
        let json = serde_json::to_string(&share).expect("serialize");
        let restored: crate::KeyShare = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.shared_public_key(), share.shared_public_key());
    }
}
