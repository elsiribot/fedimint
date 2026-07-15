// Tests are added task by task.

use cggmp21::ExecutionId;
use cggmp21::key_share::AnyKeyShare as _;
use rand::rngs::OsRng;
use sha3::{Digest as _, Keccak256};

use crate::Curve;

const N: u16 = 4;
const T: u16 = 3;

fn dealer_shares() -> Vec<crate::KeyShare> {
    cggmp21::trusted_dealer::builder::<Curve, _>(N)
        .set_threshold(Some(T))
        .hd_wallet(true)
        .generate_shares(&mut OsRng)
        .expect("trusted dealer share generation failed")
}

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

#[tokio::test(flavor = "multi_thread")]
async fn threshold_signing_verifies_against_group_key() {
    let shares = dealer_shares();
    let eid = ExecutionId::new(b"test-signing");

    // Any t-subset may sign; pick keygen indexes [0, 1, 3].
    let signers: [u16; T as usize] = [0, 1, 3];
    let digest: [u8; 32] = Keccak256::digest(b"fedimint usdt withdrawal test").into();

    let signatures = round_based::sim::run_with_setup(
        signers
            .iter()
            .map(|&keygen_i| (shares[usize::from(keygen_i)].clone(), OsRng)),
        |i, party, (share, mut rng)| async move {
            crate::run_signing(eid, i, &signers, &share, None, digest, &mut rng, party).await
        },
    )
    .expect("sim failed")
    .into_iter()
    .collect::<anyhow::Result<Vec<_>>>()
    .expect("signing failed");

    let group_pk = crate::group_public_key(&shares[0]).expect("group key");
    let msg = secp256k1::Message::from_digest(digest);
    let secp = secp256k1::Secp256k1::verification_only();
    for sig in &signatures {
        secp.verify_ecdsa(&msg, sig, &group_pk)
            .expect("signature must verify");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn signing_with_fewer_than_threshold_fails() {
    let shares = dealer_shares();
    let eid = ExecutionId::new(b"test-signing-subthreshold");
    let signers: [u16; 2] = [0, 1]; // t is 3
    let digest: [u8; 32] = Keccak256::digest(b"must not sign").into();

    let results = round_based::sim::run_with_setup(
        signers
            .iter()
            .map(|&keygen_i| (shares[usize::from(keygen_i)].clone(), OsRng)),
        |i, party, (share, mut rng)| async move {
            crate::run_signing(eid, i, &signers, &share, None, digest, &mut rng, party).await
        },
    );

    // Either the sim errors or every party's protocol run errors —
    // under no circumstances may a valid signature come back.
    if let Ok(outputs) = results {
        assert!(outputs.into_iter().all(|r| r.is_err()));
    }
}
