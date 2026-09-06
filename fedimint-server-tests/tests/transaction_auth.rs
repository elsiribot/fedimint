use fedimint_core::Amount;
use fedimint_core::core::{DynInput, DynOutput, ModuleInstanceId};
use fedimint_core::db::Database;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::module::{AmountUnit, CORE_CONSENSUS_VERSION, CommonModuleInit};
use fedimint_core::secp256k1::rand::rngs::OsRng;
use fedimint_core::secp256k1::{Keypair, Message, Secp256k1};
use fedimint_core::transaction::{Transaction, TransactionError, TransactionSignature};
use fedimint_dummy_common::config::{DummyConfig, DummyConfigConsensus, DummyConfigPrivate};
use fedimint_dummy_common::{DummyCommonInit, DummyInput, DummyOutput};
use fedimint_dummy_server::Dummy;
use fedimint_server::consensus::transaction::{TxProcessingMode, process_transaction_with_dbtx};
use fedimint_server::core::{DynServerModule, ServerModuleRegistry};

const INSTANCE: ModuleInstanceId = 0;

fn registry() -> ServerModuleRegistry {
    let dummy = Dummy::new(DummyConfig {
        private: DummyConfigPrivate,
        consensus: DummyConfigConsensus,
    });

    ModuleRegistry::from_iter([(
        INSTANCE,
        DummyCommonInit::KIND,
        DynServerModule::from(dummy),
    )])
}

/// A balanced one-in one-out dummy transaction, unsigned.
fn unsigned_tx(
    pub_key: fedimint_core::secp256k1::PublicKey,
) -> (Vec<DynInput>, Vec<DynOutput>, [u8; 8]) {
    let inputs = vec![DynInput::from_typed(
        INSTANCE,
        DummyInput {
            amount: Amount::from_msats(1000),
            unit: AmountUnit::BITCOIN,
            pub_key,
        },
    )];
    let outputs = vec![DynOutput::from_typed(
        INSTANCE,
        DummyOutput {
            amount: Amount::from_msats(1000),
            unit: AmountUnit::BITCOIN,
        },
    )];
    (inputs, outputs, [0x11; 8])
}

async fn process(tx: &Transaction) -> Result<(), TransactionError> {
    let db: Database = Database::new(MemDatabase::new(), Default::default());
    let mut dbtx = db.begin_transaction_nc().await;
    process_transaction_with_dbtx(
        registry(),
        &mut dbtx,
        tx,
        CORE_CONSENSUS_VERSION,
        TxProcessingMode::Consensus,
    )
    .await
}

fn sign(
    inputs: &[DynInput],
    outputs: &[DynOutput],
    nonce: [u8; 8],
    kp: &Keypair,
) -> fedimint_core::secp256k1::schnorr::Signature {
    let txid = Transaction::tx_hash_from_parts(inputs, outputs, nonce);
    let msg = Message::from_digest(*txid.as_ref());
    Secp256k1::new().sign_schnorr(&msg, kp)
}

#[tokio::test]
async fn naive_multisig_encoding_still_accepted() {
    let kp = Keypair::new(&Secp256k1::new(), &mut OsRng);
    let (inputs, outputs, nonce) = unsigned_tx(kp.public_key());
    let sig = sign(&inputs, &outputs, nonce, &kp);

    let tx = Transaction {
        inputs,
        outputs,
        nonce,
        signatures: TransactionSignature::NaiveMultisig(vec![sig]),
    };

    process(&tx)
        .await
        .expect("the legacy encoding must still work");
}

#[tokio::test]
async fn witnessed_encoding_accepted() {
    let kp = Keypair::new(&Secp256k1::new(), &mut OsRng);
    let (inputs, outputs, nonce) = unsigned_tx(kp.public_key());
    let sig = sign(&inputs, &outputs, nonce, &kp);

    let tx = Transaction {
        inputs,
        outputs,
        nonce,
        signatures: TransactionSignature::Witnessed(vec![sig.as_ref().to_vec()]),
    };

    process(&tx)
        .await
        .expect("a Key input's witness is its signature");
}

#[tokio::test]
async fn witness_over_a_different_txid_rejected() {
    let kp = Keypair::new(&Secp256k1::new(), &mut OsRng);
    let (inputs, outputs, nonce) = unsigned_tx(kp.public_key());

    // Sign a transaction with a different nonce, hence a different txid.
    let sig = sign(&inputs, &outputs, [0x22; 8], &kp);

    let tx = Transaction {
        inputs,
        outputs,
        nonce,
        signatures: TransactionSignature::Witnessed(vec![sig.as_ref().to_vec()]),
    };

    assert!(matches!(
        process(&tx).await,
        Err(TransactionError::InvalidSignature { .. })
    ));
}

#[tokio::test]
async fn wrong_witness_count_rejected() {
    let kp = Keypair::new(&Secp256k1::new(), &mut OsRng);
    let (inputs, outputs, nonce) = unsigned_tx(kp.public_key());

    let tx = Transaction {
        inputs,
        outputs,
        nonce,
        signatures: TransactionSignature::Witnessed(vec![]),
    };

    assert!(matches!(
        process(&tx).await,
        Err(TransactionError::InvalidWitnessLength)
    ));
}
