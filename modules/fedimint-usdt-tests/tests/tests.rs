use fedimint_client::ClientHandleArc;
use fedimint_mint_client::{MintClientInit, MintClientModule};
use fedimint_mint_server::MintInit;
use fedimint_testing::fixtures::Fixtures;
use fedimint_usdt_client::api::UsdtFederationApi;
use fedimint_usdt_client::{UsdtClientInit, UsdtClientModule};
use fedimint_usdt_server::UsdtInit;

fn fixtures() -> Fixtures {
    Fixtures::new_primary(MintClientInit, MintInit).with_module(UsdtClientInit, UsdtInit)
}

/// Boots a federation with the usdt module attached alongside mint (the
/// fee-paying primary module). `fedimint-testing` performs trusted-dealer
/// config generation (not `distributed_gen`), so this exercises
/// `UsdtInit::trusted_dealer_gen`, client-side module initialization, and the
/// `group_public_key` diagnostic API endpoint added in this phase.
#[tokio::test(flavor = "multi_thread")]
async fn federation_boots_with_usdt_module_and_serves_group_public_key() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_not_degraded().await;
    let (client1, client2): (ClientHandleArc, ClientHandleArc) = fed.two_clients().await;

    // The client module must have initialized successfully for both clients,
    // proving their `UsdtClientConfig` (with a `group_public_key`) was loaded
    // from the trusted-dealer-generated consensus config.
    let usdt1 = client1.get_first_module::<UsdtClientModule>()?;
    let usdt2 = client2.get_first_module::<UsdtClientModule>()?;

    // The mint module must also be usable, confirming the federation is a
    // healthy, fully functioning fedimint federation with usdt attached.
    let _mint_module = client1.get_first_module::<MintClientModule>()?;

    // Exercise the `group_public_key` diagnostic endpoint end-to-end: it
    // proves the DKG(trusted-dealer)-produced config is loaded on the server
    // side and queryable over the wire, and that every guardian agrees on the
    // same group public key.
    let key1 = client1
        .api()
        .with_module(usdt1.id)
        .group_public_key()
        .await?;
    let key2 = client2
        .api()
        .with_module(usdt2.id)
        .group_public_key()
        .await?;

    assert_eq!(
        key1, key2,
        "all guardians must agree on the same DKG group public key"
    );
    assert_eq!(
        key1.serialize().len(),
        33,
        "group_public_key must be a valid compressed secp256k1 public key"
    );

    Ok(())
}
