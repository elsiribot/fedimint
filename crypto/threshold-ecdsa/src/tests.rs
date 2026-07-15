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
async fn aux_gen_assembly_and_signing_yield_working_key_share() {
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

    let mut shares = Vec::with_capacity(usize::from(N));
    for (core, aux) in cores.into_iter().zip(aux_infos) {
        let share = crate::assemble_key_share(core, aux).expect("assembly failed");
        // serde round-trip: shares must be storable in the guardian DB.
        let json = serde_json::to_string(&share).expect("serialize");
        let restored: crate::KeyShare = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.shared_public_key(), share.shared_public_key());
        shares.push(share);
    }

    // Compose the full pipeline: sign with a t-subset of the DKG-produced,
    // aux-assembled shares (not trusted-dealer shares) and verify the
    // resulting signature against the group key.
    let eid_signing = ExecutionId::new(b"test-aux-signing");
    let signers: [u16; T as usize] = [0, 1, 3];
    let digest: [u8; 32] = Keccak256::digest(b"fedimint usdt aux pipeline test").into();

    let signatures = round_based::sim::run_with_setup(
        signers
            .iter()
            .map(|&keygen_i| (shares[usize::from(keygen_i)].clone(), OsRng)),
        |i, party, (share, mut rng)| async move {
            crate::run_signing(
                eid_signing,
                i,
                &signers,
                &share,
                None,
                digest,
                &mut rng,
                party,
            )
            .await
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

#[test]
fn evm_address_matches_known_vector() {
    // Private key 0x...01 -> the well-known address
    // 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf
    let secp = secp256k1::Secp256k1::new();
    let mut sk_bytes = [0u8; 32];
    sk_bytes[31] = 1;
    let sk = secp256k1::SecretKey::from_slice(&sk_bytes).expect("valid key");
    let pk = sk.public_key(&secp);
    assert_eq!(
        crate::evm_address(&pk),
        <[u8; 20]>::try_from(
            hex::decode("7e5f4552091a69125d5dfcb7b8c2659029395bdf")
                .expect("valid hex")
                .as_slice()
        )
        .expect("20 bytes"),
    );
}

/// The phase's acceptance test: real 4-party CGGMP21 keygen, aux-info
/// generation, and 3-of-4 threshold signing, all driven entirely over
/// `drive_over_exchange` + `InMemoryMesh` + `EncryptedRoundCodec` (no
/// `round_based::sim`), with the resulting signature verified against the
/// group key by the independent `secp256k1` crate.
///
/// Each protocol invocation (keygen, aux, signing) gets its own fresh mesh:
/// a mesh endpoint is consumed in lockstep by one synchronous sequence of
/// rounds, so it cannot be reused across protocol runs. Each spawned task
/// owns exactly one mesh endpoint (built via `into_iter().enumerate()`,
/// never `remove(0)` with a shifting index).
// cggmp21's `into_state_machine`/`sign_sync` wrap the protocol via
// `round_based::state_machine::wrap_protocol`, whose `SharedStateRef` holds
// an `Rc<RefCell<..>>` — not `Send`. So the per-party state machines below
// cannot cross `tokio::spawn`'s `Send` bound. They still need to run
// concurrently (each party's `exchange()` call blocks until every other
// party has sent its round payload), so we schedule them cooperatively on
// one thread with `LocalSet`/`spawn_local` instead of across the
// multi-thread pool. This is purely a scheduling-primitive choice — the
// protocol messages still cross the real `RoundExchange`/`EncryptedRoundCodec`
// transport exactly as they would under `tokio::spawn`.
#[tokio::test(flavor = "multi_thread")]
async fn keygen_and_signing_over_exchange_transport() {
    use crate::transport::{EncryptedRoundCodec, drive_over_exchange, in_memory_mesh};

    let local = tokio::task::LocalSet::new();
    local
        .run_until(tokio::time::timeout(
            std::time::Duration::from_secs(600),
            async {
                let secp = secp256k1::Secp256k1::new();

                // Per-party static encryption keypairs for the codec, reused across
                // all three protocol invocations below.
                let enc_sks: Vec<secp256k1::SecretKey> = (0..N)
                    .map(|i| {
                        let mut b = [2u8; 32];
                        b[31] = (i + 1) as u8;
                        secp256k1::SecretKey::from_slice(&b).expect("valid scalar")
                    })
                    .collect();
                let enc_pks: Vec<secp256k1::PublicKey> =
                    enc_sks.iter().map(|sk| sk.public_key(&secp)).collect();

                // --- DKG over the transport ---
                let eid_keygen = ExecutionId::new(b"exchange-transport-keygen");
                let meshes = in_memory_mesh(N);
                let mut handles = Vec::with_capacity(usize::from(N));
                for (i, mut mesh) in meshes.into_iter().enumerate() {
                    let i = i as u16;
                    let codec = EncryptedRoundCodec::new(i, enc_sks[i as usize], enc_pks.clone());
                    handles.push(tokio::task::spawn_local(async move {
                        let mut rng = OsRng;
                        let sm = cggmp21::keygen::<Curve>(eid_keygen, i, N)
                            .set_threshold(T)
                            .hd_wallet(true)
                            .into_state_machine(&mut rng);
                        drive_over_exchange(sm, &codec, &mut mesh).await
                    }));
                }
                let mut cores = Vec::with_capacity(usize::from(N));
                for h in handles {
                    cores.push(h.await.expect("join").expect("driver").expect("keygen"));
                }

                let group_pk_curve = cores[0].shared_public_key();
                for c in &cores[1..] {
                    assert_eq!(
                        c.shared_public_key(),
                        group_pk_curve,
                        "all parties must agree on the DKG group key"
                    );
                }

                // --- aux-info (Paillier + ring-Pedersen setup) over the transport ---
                let eid_aux = ExecutionId::new(b"exchange-transport-aux");
                let meshes = in_memory_mesh(N);
                let mut handles = Vec::with_capacity(usize::from(N));
                for (i, mut mesh) in meshes.into_iter().enumerate() {
                    let i = i as u16;
                    let codec = EncryptedRoundCodec::new(i, enc_sks[i as usize], enc_pks.clone());
                    handles.push(tokio::task::spawn_local(async move {
                        let mut rng = OsRng;
                        let primes = cggmp21::PregeneratedPrimes::generate(&mut rng);
                        let sm = cggmp21::aux_info_gen(eid_aux, i, N, primes)
                            .into_state_machine(&mut rng);
                        drive_over_exchange(sm, &codec, &mut mesh).await
                    }));
                }
                let mut auxs = Vec::with_capacity(usize::from(N));
                for h in handles {
                    auxs.push(h.await.expect("join").expect("driver").expect("aux gen"));
                }

                // Full key shares (core + aux), assembled from transport-driven DKG.
                let shares: Vec<crate::KeyShare> = cores
                    .into_iter()
                    .zip(auxs)
                    .map(|(core, aux)| {
                        crate::assemble_key_share(core, aux).expect("assembly failed")
                    })
                    .collect();

                // --- 3-of-4 threshold signing over the transport ---
                let eid_signing = ExecutionId::new(b"exchange-transport-signing");
                let signers: [u16; T as usize] = [0, 1, 3];
                let signer_pks: Vec<secp256k1::PublicKey> =
                    signers.iter().map(|&k| enc_pks[usize::from(k)]).collect();
                let digest: [u8; 32] =
                    Keccak256::digest(b"fedimint usdt exchange transport signing").into();
                let data = cggmp21::DataToSign::from_scalar(
                    cggmp21::generic_ec::Scalar::from_be_bytes_mod_order(digest),
                );

                let meshes = in_memory_mesh(T);
                let mut handles = Vec::with_capacity(usize::from(T));
                for (pos, mut mesh) in meshes.into_iter().enumerate() {
                    let pos = pos as u16;
                    let keygen_index = signers[usize::from(pos)];
                    let codec = EncryptedRoundCodec::new(
                        pos,
                        enc_sks[usize::from(keygen_index)],
                        signer_pks.clone(),
                    );
                    let share = shares[usize::from(keygen_index)].clone();
                    handles.push(tokio::task::spawn_local(async move {
                        let mut rng = OsRng;
                        let sm = cggmp21::signing(eid_signing, pos, &signers, &share)
                            .sign_sync(&mut rng, data);
                        drive_over_exchange(sm, &codec, &mut mesh).await
                    }));
                }
                let mut signatures = Vec::with_capacity(usize::from(T));
                for h in handles {
                    signatures.push(h.await.expect("join").expect("driver").expect("signing"));
                }

                // Independent verification: convert to the workspace's canonical
                // secp256k1 signature type and check against the group public key.
                let group_pk = crate::group_public_key(&shares[0]).expect("group key");
                let msg = secp256k1::Message::from_digest(digest);
                let verifier = secp256k1::Secp256k1::verification_only();
                for sig in &signatures {
                    let mut compact = [0u8; 64];
                    compact[..32].copy_from_slice(&sig.r.to_be_bytes());
                    compact[32..].copy_from_slice(&sig.s.to_be_bytes());
                    let mut ecdsa_sig = secp256k1::ecdsa::Signature::from_compact(&compact)
                        .expect("valid compact sig");
                    ecdsa_sig.normalize_s();
                    verifier
                        .verify_ecdsa(&msg, &ecdsa_sig, &group_pk)
                        .expect("signature must verify against the group key");
                }
            },
        ))
        .await
        .expect("acceptance test timed out");
}

/// A [`crate::transport::RoundExchange`] wrapper that flips a byte in one
/// specific sender's payload on the first round, to prove that
/// `drive_over_exchange` aborts cleanly (returns `Err`, no panic, no hang)
/// on a corrupted round payload instead of silently accepting garbage.
struct CorruptingExchange {
    inner: crate::transport::InMemoryMesh,
    corrupt_sender: crate::transport::PartyIndex,
    triggered: bool,
}

#[async_trait::async_trait]
impl crate::transport::RoundExchange for CorruptingExchange {
    fn party_index(&self) -> crate::transport::PartyIndex {
        self.inner.party_index()
    }

    fn n(&self) -> u16 {
        self.inner.n()
    }

    async fn exchange(&mut self, ours: Vec<u8>) -> anyhow::Result<Vec<Vec<u8>>> {
        let mut all = self.inner.exchange(ours).await?;
        if !self.triggered {
            self.triggered = true;
            if let Some(bytes) = all.get_mut(usize::from(self.corrupt_sender))
                && let Some(last) = bytes.last_mut()
            {
                *last ^= 0xff;
            }
        }
        Ok(all)
    }
}

/// A minimal single-round state machine: send a point-to-point message to
/// every other party, then wait for one message from each of them. Enough
/// to drive one real exchange round (with actual ECIES-boxed p2p payloads,
/// so a corrupted byte lands inside an AEAD ciphertext deterministically —
/// same shape as `codec.rs`'s `tampered_ciphertext_is_rejected` test)
/// without pulling in the cost of a full cggmp21 protocol.
struct P2PRoundOnce {
    me: crate::transport::PartyIndex,
    n: u16,
    next_recipient: u16,
    received: usize,
}

impl round_based::state_machine::StateMachine for P2PRoundOnce {
    type Output = ();
    type Msg = u8;

    fn proceed(&mut self) -> round_based::state_machine::ProceedResult<Self::Output, Self::Msg> {
        while self.next_recipient < self.n {
            let recipient = self.next_recipient;
            self.next_recipient += 1;
            if recipient == self.me {
                continue;
            }
            return round_based::state_machine::ProceedResult::SendMsg(round_based::Outgoing {
                recipient: round_based::MessageDestination::OneParty(recipient),
                msg: self.me as u8,
            });
        }
        if self.received < usize::from(self.n - 1) {
            return round_based::state_machine::ProceedResult::NeedsOneMoreMessage;
        }
        round_based::state_machine::ProceedResult::Output(())
    }

    fn received_msg(
        &mut self,
        _msg: round_based::Incoming<Self::Msg>,
    ) -> Result<(), round_based::Incoming<Self::Msg>> {
        self.received += 1;
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn corrupted_round_payload_aborts_driver_cleanly() {
    use crate::transport::{EncryptedRoundCodec, in_memory_mesh};

    let secp = secp256k1::Secp256k1::new();
    let sks: Vec<secp256k1::SecretKey> = (0..N)
        .map(|i| {
            let mut b = [3u8; 32];
            b[31] = (i + 1) as u8;
            secp256k1::SecretKey::from_slice(&b).expect("valid scalar")
        })
        .collect();
    let pks: Vec<secp256k1::PublicKey> = sks.iter().map(|sk| sk.public_key(&secp)).collect();

    // Corrupt party 1's payload on the first (and only) round, as observed
    // by every other party.
    let corrupt_sender: crate::transport::PartyIndex = 1;
    let meshes = in_memory_mesh(N);
    let mut handles = Vec::with_capacity(usize::from(N));
    for (i, mesh) in meshes.into_iter().enumerate() {
        let i = i as u16;
        let mut exchange = CorruptingExchange {
            inner: mesh,
            corrupt_sender,
            triggered: false,
        };
        let codec = EncryptedRoundCodec::new(i, sks[i as usize], pks.clone());
        handles.push(tokio::spawn(async move {
            let sm = P2PRoundOnce {
                me: i,
                n: N,
                next_recipient: 0,
                received: 0,
            };
            crate::transport::drive_over_exchange(sm, &codec, &mut exchange).await
        }));
    }

    let mut saw_err = false;
    for (i, h) in handles.into_iter().enumerate() {
        let result = h.await.expect("task must not panic");
        if i as u16 == corrupt_sender {
            // Nothing is corrupted from party `corrupt_sender`'s own point
            // of view (the driver never opens its own payload), so it
            // completes normally.
            result.expect("uncorrupted party completes");
        } else if result.is_err() {
            saw_err = true;
        }
    }
    assert!(
        saw_err,
        "at least one party must see the corrupted payload and abort with Err"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn derived_key_signing_verifies_against_derived_pubkey() {
    let shares = dealer_shares();
    let eid = ExecutionId::new(b"test-derived-signing");
    let signers: [u16; T as usize] = [0, 1, 2];
    let path: &[u32] = &[7, 42]; // e.g. (account, deposit-index)
    let digest: [u8; 32] = Keccak256::digest(b"deposit sweep").into();

    let signatures = round_based::sim::run_with_setup(
        signers
            .iter()
            .map(|&keygen_i| (shares[usize::from(keygen_i)].clone(), OsRng)),
        |i, party, (share, mut rng)| async move {
            crate::run_signing(
                eid,
                i,
                &signers,
                &share,
                Some(path),
                digest,
                &mut rng,
                party,
            )
            .await
        },
    )
    .expect("sim failed")
    .into_iter()
    .collect::<anyhow::Result<Vec<_>>>()
    .expect("signing failed");

    let child_pk = crate::derived_public_key(&shares[0], path).expect("derive");
    let group_pk = crate::group_public_key(&shares[0]).expect("group key");
    assert_ne!(child_pk, group_pk, "derived key must differ from group key");

    let msg = secp256k1::Message::from_digest(digest);
    let secp = secp256k1::Secp256k1::verification_only();
    for sig in &signatures {
        secp.verify_ecdsa(&msg, sig, &child_pk)
            .expect("must verify against the DERIVED key");
        assert!(
            secp.verify_ecdsa(&msg, sig, &group_pk).is_err(),
            "must NOT verify against the group key"
        );
    }
}
