use core::fmt;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

use bitcoin::key::{Keypair, Secp256k1};
use fedimint_core::core::{Input, IntoDynInstance, ModuleKind, Output};
use fedimint_core::secp256k1::rand::rngs::OsRng;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::Amounts;
use fedimint_core::transaction::TransactionSignature;

use super::{
    ClientInputBundle, ClientOutput, ClientOutputBundle, ClientOutputSM, TransactionBuilder,
};
use crate::module::OutPointRange;
use crate::transaction::{ClientInput, ClientInputAuth, ClientInputSM};

#[derive(Encodable, Decodable, Clone, Debug, Hash, PartialEq, Eq)]
pub struct NoopInput;

impl fmt::Display for NoopInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NoopInput")
    }
}

impl Input for NoopInput {
    const KIND: ModuleKind = ModuleKind::from_static_str("test");
}

impl IntoDynInstance for NoopInput {
    type DynType = fedimint_core::core::DynInput;

    fn into_dyn(self, instance_id: fedimint_core::core::ModuleInstanceId) -> Self::DynType {
        fedimint_core::core::DynInput::from_typed(instance_id, self)
    }
}

#[derive(Encodable, Decodable, Clone, Debug, Hash, PartialEq, Eq)]
pub struct NoopOutput;

impl fmt::Display for NoopOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NoopOutput")
    }
}

impl Output for NoopOutput {
    const KIND: ModuleKind = ModuleKind::from_static_str("test");
}

impl IntoDynInstance for NoopOutput {
    type DynType = fedimint_core::core::DynOutput;

    fn into_dyn(self, instance_id: fedimint_core::core::ModuleInstanceId) -> Self::DynType {
        fedimint_core::core::DynOutput::from_typed(instance_id, self)
    }
}

#[test]
/// Exercise empty bundles
///
/// Actually exercise empty bundles (since it's rare in real code)
/// and ensure that their SM-gens are *not* called, while the SM-gens
/// of non-empty bundles work as expected.
fn tx_builder_empty_bundles() {
    // We'll collect ranges sms were called into this thing to compare at the end
    let sm_called = Arc::new(Mutex::new(String::new()));

    let no_call_input_sm = ClientInputSM {
        state_machines: Arc::new(move |_out_point_range: OutPointRange| {
            panic!("Don't call me maybe");
        }),
    };

    let no_call_output_sm = ClientOutputSM {
        state_machines: Arc::new(move |_out_point_range: OutPointRange| {
            panic!("Don't call me maybe");
        }),
    };
    let yes_call_input_sm = ClientInputSM {
        state_machines: Arc::new({
            let sm_called = sm_called.clone();
            move |out_point_range: OutPointRange| {
                sm_called
                    .lock()
                    .unwrap()
                    .write_fmt(format_args!("i-{:?},", out_point_range.start_idx()))
                    .expect("Can't fail");
                vec![]
            }
        }),
    };

    let yes_call_output_sm = ClientOutputSM {
        state_machines: Arc::new({
            let sm_called = sm_called.clone();
            move |out_point_range: OutPointRange| {
                sm_called
                    .clone()
                    .lock()
                    .unwrap()
                    .write_fmt(format_args!("o-{:?},", out_point_range.start_idx()))
                    .expect("Can't fail");
                vec![]
            }
        }),
    };

    // This is ugly due to repetition, but the more manual, the better, and in real
    // code some of these conversions are hidden in the generics. Oh well.
    TransactionBuilder::new()
        .with_inputs(
            ClientInputBundle::<NoopInput>::new(vec![], vec![no_call_input_sm.clone()])
                .into_instanceless()
                .into_dyn(0),
        )
        .with_inputs(
            ClientInputBundle::<NoopInput>::new(
                vec![ClientInput {
                    input: NoopInput,
                    auth: ClientInputAuth::Witness(vec![]),
                    amounts: Amounts::new_bitcoin_msats(1),
                }],
                vec![yes_call_input_sm.clone()],
            )
            .into_instanceless()
            .into_dyn(3),
        )
        .with_inputs(
            ClientInputBundle::<NoopInput>::new(vec![], vec![no_call_input_sm.clone()])
                .into_instanceless()
                .into_dyn(0),
        )
        .with_inputs(
            ClientInputBundle::<NoopInput>::new(
                vec![ClientInput {
                    input: NoopInput,
                    auth: ClientInputAuth::Witness(vec![]),
                    amounts: Amounts::new_bitcoin_msats(1),
                }],
                vec![yes_call_input_sm],
            )
            .into_instanceless()
            .into_dyn(3),
        )
        .with_outputs(
            ClientOutputBundle::<NoopOutput>::new(vec![], vec![no_call_output_sm.clone()])
                .into_instanceless()
                .into_dyn(0),
        )
        .with_outputs(
            ClientOutputBundle::<NoopOutput>::new(
                vec![ClientOutput {
                    output: NoopOutput,
                    amounts: Amounts::new_bitcoin_msats(1),
                }],
                vec![yes_call_output_sm.clone()],
            )
            .into_instanceless()
            .into_dyn(3),
        )
        .with_outputs(
            ClientOutputBundle::<NoopOutput>::new(vec![], vec![no_call_output_sm.clone()])
                .into_instanceless()
                .into_dyn(0),
        )
        .with_outputs(
            ClientOutputBundle::<NoopOutput>::new(
                vec![ClientOutput {
                    output: NoopOutput,
                    amounts: Amounts::new_bitcoin_msats(1),
                }],
                vec![yes_call_output_sm],
            )
            .into_instanceless()
            .into_dyn(3),
        )
        .build(&Secp256k1::new(), rand::thread_rng());

    // This actually depends on how builder processes inputs and outputs,
    // but if it ever changes, just adjust the string.
    assert_eq!(*sm_called.lock().unwrap(), String::from("i-0,i-1,o-0,o-1,"));
}

#[test]
/// Witness bytes attached via [`ClientInputAuth::Witness`] must end up in
/// [`TransactionSignature::Witnessed`] at the same index as the input that
/// carried them: this positional alignment is the contract every server-side
/// witness-verification consumer relies on.
fn tx_builder_witness_positional_alignment() {
    let witness_a = vec![0xaa, 0xaa, 0xaa];
    let witness_b = vec![0xbb, 0xbb];

    let (transaction, _states) = TransactionBuilder::new()
        .with_inputs(
            ClientInputBundle::<NoopInput, super::NeverClientStateMachine>::new_no_sm(vec![
                ClientInput {
                    input: NoopInput,
                    auth: ClientInputAuth::Witness(witness_a.clone()),
                    amounts: Amounts::new_bitcoin_msats(1),
                },
                ClientInput {
                    input: NoopInput,
                    auth: ClientInputAuth::Witness(witness_b.clone()),
                    amounts: Amounts::new_bitcoin_msats(1),
                },
            ])
            .into_instanceless()
            .into_dyn(0),
        )
        .build(&Secp256k1::new(), rand::thread_rng());

    let TransactionSignature::Witnessed(witnesses) = transaction.signatures else {
        panic!("expected TransactionSignature::Witnessed");
    };

    assert_eq!(witnesses.len(), 2);
    assert_eq!(
        witnesses[0], witness_a,
        "witness at index 0 must match the first input"
    );
    assert_eq!(
        witnesses[1], witness_b,
        "witness at index 1 must match the second input"
    );
}

#[test]
/// A transaction whose inputs are all `ClientInputAuth::Key` must encode as
/// `TransactionSignature::NaiveMultisig`, byte-identical to what an unpatched
/// client would have produced. Emitting `Witnessed` here instead would make a
/// patched client wire-incompatible with any unpatched guardian, since an
/// unpatched decoder does not know that variant and rejects it outright.
fn tx_builder_all_keys_uses_naive_multisig_encoding() {
    let secp = Secp256k1::new();
    let kp = Keypair::new(&secp, &mut OsRng);

    let (transaction, _states) = TransactionBuilder::new()
        .with_inputs(
            ClientInputBundle::<NoopInput, super::NeverClientStateMachine>::new_no_sm(vec![
                ClientInput {
                    input: NoopInput,
                    auth: ClientInputAuth::Key(kp),
                    amounts: Amounts::new_bitcoin_msats(1),
                },
            ])
            .into_instanceless()
            .into_dyn(0),
        )
        .build(&secp, rand::thread_rng());

    match transaction.signatures {
        TransactionSignature::NaiveMultisig(sigs) => assert_eq!(sigs.len(), 1),
        TransactionSignature::Witnessed(_) => {
            panic!("an all-Key transaction must not use the Witnessed encoding")
        }
        TransactionSignature::Default { .. } => panic!("unexpected default encoding"),
    }
}

#[test]
/// A transaction with a mix of `Key` and `Witness` inputs must still use
/// `Witnessed`, since it cannot be represented in `NaiveMultisig`.
fn tx_builder_mixed_auth_uses_witnessed_encoding() {
    let secp = Secp256k1::new();
    let kp = Keypair::new(&secp, &mut OsRng);

    let (transaction, _states) = TransactionBuilder::new()
        .with_inputs(
            ClientInputBundle::<NoopInput, super::NeverClientStateMachine>::new_no_sm(vec![
                ClientInput {
                    input: NoopInput,
                    auth: ClientInputAuth::Key(kp),
                    amounts: Amounts::new_bitcoin_msats(1),
                },
                ClientInput {
                    input: NoopInput,
                    auth: ClientInputAuth::Witness(vec![0x42]),
                    amounts: Amounts::new_bitcoin_msats(1),
                },
            ])
            .into_instanceless()
            .into_dyn(0),
        )
        .build(&secp, rand::thread_rng());

    assert!(matches!(
        transaction.signatures,
        TransactionSignature::Witnessed(_)
    ));
}
