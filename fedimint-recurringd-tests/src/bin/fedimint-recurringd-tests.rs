use std::ops::ControlFlow;

use devimint::tests::log_binary_versions;
use devimint::util::{almost_equal, poll};
use devimint::{DevFed, cmd};
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    devimint::run_devfed_test()
        .call(|dev_fed, process_mgr| async move {
            log_binary_versions().await?;

            let DevFed {
                fed,
                gw_lnd,
                gw_ldk_second,
                recurringd,
                ..
            } = dev_fed.to_dev_fed(&process_mgr).await?;

            // Test admin auth is checked
            {
                let dummy_invite = "fed114znk7uk7ppugdjuytr8venqf2tkywd65cqvg3u93um64tu5cw4yr0n3fvn7qmwvm4g48cpndgnm4gqq4waen5te0xyerwt3s9cczuvf6xyurzde597s7crdvsk2vmyarjw9gwyqjdzj";
                let url = format!("{}lnv1/federations", recurringd.api_url);
                let client = reqwest::Client::new();
                let response_no_auth = client
                    .put(&url)
                    .header("Content-Type", "application/json")
                    .json(&serde_json::json!({ "invite": dummy_invite }))
                    .send()
                    .await?;
                assert!(response_no_auth.status().is_client_error());

                let response_with_wrong_auth = client
                    .put(&url)
                    .header("Authorization", "Bearer wrong-token")
                    .header("Content-Type", "application/json")
                    .json(&serde_json::json!({ "invite": dummy_invite }))
                    .send()
                    .await?;
                assert!(response_with_wrong_auth.status().is_client_error());
            }

            // Give the LND Gateway a balance, it's the only GW serving LNv1 and recurringd
            // is currently LNv1-only
            fed.pegin_gateways(10_000_000, vec![&gw_lnd]).await?;

            let client = fed.new_joined_client("recurringd-test-client").await?;

            let lnurl = cmd!(
                client,
                "module",
                "ln",
                "lnurl",
                "register",
                recurringd.api_url()
            )
            .out_json()
            .await?["lnurl"]
                .as_str()
                .unwrap()
                .to_owned();

            let lnurl_list = cmd!(client, "module", "ln", "lnurl", "list")
                .out_json()
                .await?["codes"]
                .as_object()
                .unwrap()
                .clone();

            assert_eq!(lnurl_list.len(), 1);

            let listed_lnurl = lnurl_list["0"].clone();
            assert_eq!(listed_lnurl["lnurl"].as_str().unwrap(), &lnurl);
            assert_eq!(listed_lnurl["last_derivation_index"].as_i64().unwrap(), 0);

            let url = fedimint_lnurl::parse_lnurl(&lnurl).expect("valid lnurl");
            let pay_response = fedimint_lnurl::request(&url).await.expect("pay request");
            let invoice_response = fedimint_lnurl::get_invoice(&pay_response, 1_000_000)
                .await
                .expect("invoice request");
            gw_ldk_second.client().pay_invoice(invoice_response.pr.clone()).await?;

            let invoice_op_id = poll("lnurl_receive", || async {
                cmd!(client, "dev", "wait", "2")
                    .run()
                    .await
                    .map_err(ControlFlow::Break)?;

                let invoice_list = cmd!(client, "module", "ln", "lnurl", "invoices", "0")
                    .out_json()
                    .await
                    .map_err(ControlFlow::Break)?["invoices"]
                    .as_object()
                    .unwrap()
                    .clone();

                if invoice_list.is_empty() {
                    return Err(ControlFlow::Continue(anyhow::anyhow!(
                        "No invoice recognized yet"
                    )));
                }

                Ok(invoice_list["1"]["operation_id"]
                    .as_str()
                    .unwrap()
                    .to_owned())
            })
            .await?;

            let await_invoice_result = cmd!(
                client,
                "module",
                "ln",
                "lnurl",
                "await-invoice-paid",
                invoice_op_id
            )
            .out_json()
            .await?;

            assert_eq!(
                await_invoice_result["amount_msat"].as_i64().unwrap(),
                1_000_000
            );
            assert_eq!(
                await_invoice_result["invoice"].as_str().unwrap(),
                &invoice_response.pr.to_string()
            );

            let client_balance = client.balance().await?;
            almost_equal(client_balance, 1_000_000, 5_000).unwrap();
            info!("Client balance: {client_balance}");

            // === Test LNURL receives after recovery from backup (issue #8465) ===
            //
            // After recovering from seed the client gets a fresh DB with no operation
            // log and no recurring payment codes. Re-registering the same LNURL with
            // recurringd is idempotent (same root key from the same seed). The scanner
            // then replays old invoices from index 1, but the incoming LN contracts
            // backing them were already claimed pre-recovery, so the claim transaction
            // is rejected by the federation as a double-spend.
            //
            // Expected behavior:
            //   - Old receives: show up in the operation log as
            //     RecurringPaymentReceive, but settle as Canceled (ClaimRejected)
            //   - New receives after recovery: work normally and settle as Claimed

            info!("--- LNURL recovery test ---");

            // Spend all funds before recovery so that any balance after recovery
            // can only come from new LNURL payments, not from e-cash recovery.
            let drain_invoice = gw_ldk_second.client().create_invoice(900_000).await?;
            cmd!(
                client,
                "ln-pay",
                drain_invoice.to_string()
            )
            .run()
            .await?;
            let pre_recovery_balance = client.balance().await?;
            info!(pre_recovery_balance, "Client balance after draining");
            assert!(
                pre_recovery_balance < 200_000,
                "Client balance should be near zero before recovery, got {pre_recovery_balance}"
            );

            // Restore a new client from the seed. `new_restored` internally
            // reads the mnemonic from `client` and restores into a fresh DB.
            let restored_client = client
                .new_restored("recurringd-recovered", fed.invite_code()?)
                .await?;
            info!("Client restored from seed");

            // The restored client should have recovered whatever e-cash was left
            let post_recovery_balance = restored_client.balance().await?;
            info!(post_recovery_balance, "Restored client balance (e-cash recovery only)");

            // Verify the restored client has no LNURL codes (fresh DB)
            let restored_lnurl_list =
                cmd!(restored_client, "module", "ln", "lnurl", "list")
                    .out_json()
                    .await?["codes"]
                    .as_object()
                    .unwrap()
                    .clone();
            assert_eq!(
                restored_lnurl_list.len(),
                0,
                "Restored client should have no LNURL codes before re-registration"
            );

            // Re-register the LNURL on the restored client. Since the root key is
            // derived deterministically from the seed, recurringd recognizes it as the
            // same payment code and returns the same LNURL string.
            let restored_lnurl = cmd!(
                restored_client,
                "module",
                "ln",
                "lnurl",
                "register",
                recurringd.api_url()
            )
            .out_json()
            .await?["lnurl"]
                .as_str()
                .unwrap()
                .to_owned();
            assert_eq!(
                restored_lnurl, lnurl,
                "Recovered client should get the same LNURL"
            );
            info!("Re-registered LNURL on restored client");

            // Wait for the scanner to pick up the old invoice (index 1).
            // The restored client starts scanning from last_derivation_index+1 = 1.
            // Recurringd has that invoice cached, so it returns immediately.
            let old_invoice_op_id = poll("recovered_lnurl_old_invoice", || async {
                cmd!(restored_client, "dev", "wait", "2")
                    .run()
                    .await
                    .map_err(ControlFlow::Break)?;

                let invoice_list = cmd!(
                    restored_client,
                    "module",
                    "ln",
                    "lnurl",
                    "invoices",
                    "0"
                )
                .out_json()
                .await
                .map_err(ControlFlow::Break)?["invoices"]
                    .as_object()
                    .unwrap()
                    .clone();

                if invoice_list.is_empty() {
                    return Err(ControlFlow::Continue(anyhow::anyhow!(
                        "No invoice recognized yet on restored client"
                    )));
                }

                Ok(invoice_list["1"]["operation_id"]
                    .as_str()
                    .unwrap()
                    .to_owned())
            })
            .await?;
            info!(
                old_invoice_op_id,
                "Restored client picked up old invoice"
            );

            // Verify the old invoice appeared in the operation log
            let restored_ops = cmd!(
                restored_client,
                "list-operations",
                "--limit",
                "100"
            )
            .out_json()
            .await?;
            let ops_list = restored_ops["operations"].as_array().unwrap();
            let has_old_op = ops_list.iter().any(|op| {
                op["id"].as_str() == Some(&old_invoice_op_id)
            });
            assert!(
                has_old_op,
                "Old invoice operation must appear in the operation log"
            );

            // Await the old invoice operation: it must fail because the incoming
            // contract was already claimed before recovery (double-spend).
            let old_invoice_await_result = cmd!(
                restored_client,
                "module",
                "ln",
                "lnurl",
                "await-invoice-paid",
                &old_invoice_op_id
            )
            .out_json()
            .await;
            assert!(
                old_invoice_await_result.is_err(),
                "Old invoice must fail after recovery (contract already claimed)"
            );
            info!(
                error = %old_invoice_await_result.unwrap_err(),
                "Old invoice correctly failed after recovery"
            );

            // Balance must not have increased from the old invoice replay
            let balance_after_old_replay = restored_client.balance().await?;
            info!(balance_after_old_replay, "Balance after old invoice replay");
            assert!(
                balance_after_old_replay <= post_recovery_balance + 5_000,
                "Old invoice replay must not credit funds (got {balance_after_old_replay}, \
                 expected at most {})",
                post_recovery_balance + 5_000
            );

            // Now test that NEW receives after recovery work normally.
            // Request a new invoice via the same LNURL and pay it.
            let pay_response_2 = fedimint_lnurl::request(&url).await.expect("pay request");
            let invoice_response_2 = fedimint_lnurl::get_invoice(&pay_response_2, 500_000)
                .await
                .expect("invoice request");
            gw_ldk_second
                .client()
                .pay_invoice(invoice_response_2.pr.clone())
                .await?;
            info!("Paid new invoice via LNURL after recovery");

            // Wait for the restored client to pick up the new invoice
            let new_invoice_op_id = poll("recovered_lnurl_new_invoice", || async {
                cmd!(restored_client, "dev", "wait", "2")
                    .run()
                    .await
                    .map_err(ControlFlow::Break)?;

                let invoice_list = cmd!(
                    restored_client,
                    "module",
                    "ln",
                    "lnurl",
                    "invoices",
                    "0"
                )
                .out_json()
                .await
                .map_err(ControlFlow::Break)?["invoices"]
                    .as_object()
                    .unwrap()
                    .clone();

                // The new invoice should be at a higher index than the old one.
                // Old invoice was at index 1, new one should be at index 2 or higher.
                let max_idx = invoice_list
                    .keys()
                    .filter_map(|k| k.parse::<u64>().ok())
                    .max()
                    .unwrap_or(0);

                if max_idx <= 1 {
                    return Err(ControlFlow::Continue(anyhow::anyhow!(
                        "New invoice not yet recognized (max_idx={max_idx})"
                    )));
                }

                let new_op_id = invoice_list[&max_idx.to_string()]["operation_id"]
                    .as_str()
                    .unwrap()
                    .to_owned();

                // Make sure it's a different operation than the old one
                if new_op_id == old_invoice_op_id {
                    return Err(ControlFlow::Continue(anyhow::anyhow!(
                        "Only old invoice found, waiting for new one"
                    )));
                }

                Ok(new_op_id)
            })
            .await?;
            info!(
                new_invoice_op_id,
                "Restored client picked up new invoice"
            );

            // The new invoice must complete successfully
            let new_invoice_result = cmd!(
                restored_client,
                "module",
                "ln",
                "lnurl",
                "await-invoice-paid",
                &new_invoice_op_id
            )
            .out_json()
            .await?;
            assert_eq!(
                new_invoice_result["amount_msat"].as_i64().unwrap(),
                500_000,
                "New invoice amount should match"
            );
            info!("New invoice after recovery claimed successfully");

            // The new payment must have increased the balance
            let final_balance = restored_client.balance().await?;
            info!(final_balance, "Restored client final balance");
            almost_equal(
                final_balance,
                post_recovery_balance + 500_000,
                10_000,
            )
            .unwrap();

            // Verify the final operation log has both the old (failed) and new
            // (succeeded) LNURL receive operations
            let final_ops = cmd!(
                restored_client,
                "list-operations",
                "--limit",
                "100"
            )
            .out_json()
            .await?;
            let final_ops_list = final_ops["operations"].as_array().unwrap();
            let ln_ops: Vec<_> = final_ops_list
                .iter()
                .filter(|op| op["operation_kind"].as_str() == Some("ln"))
                .collect();
            info!(
                total = final_ops_list.len(),
                ln_ops = ln_ops.len(),
                "Restored client final operation counts"
            );
            assert!(
                ln_ops.len() >= 2,
                "Expected at least 2 ln operations (old replay + new receive), got {}",
                ln_ops.len()
            );

            Ok(())
        })
        .await
}
