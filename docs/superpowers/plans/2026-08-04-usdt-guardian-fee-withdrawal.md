# USDT Guardian Fee Withdrawal — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give guardians a 2f+1-threshold-authorized way to withdraw accrued USDT fee revenue from the pool `SimpleAccount` to a chosen EVM address, so they can recoup ETH gas fronted by their broadcaster EOAs.

**Architecture:** Track realized fee revenue in a new `PoolState.accrued_fees` counter, credited only at consensus apply points where the fee's USDT is physically in the pool. Guardians cast per-request `(recipient, amount)` votes via an `ApiAuth`-guarded endpoint; a threshold agreeing on the identical pair triggers a `WithdrawFees` pool `UserOp` (a batch-of-one transfer), gated by `amount ≤ accrued_fees` and `amount ≤ pool.balance`. The whole flow clones the existing `RecoverResidual` vote→threshold→UserOp machinery.

**Tech Stack:** Rust, fedimint module framework (`ServerModule`/`ClientModule`), alloy (ERC-4337 UserOps, ERC-20 `transfer`), threshold-ECDSA signing sessions, RocksDB via fedimint's `Database` abstraction.

## Global Constraints

- **Consensus determinism:** every `process_input`/`process_output`/`process_consensus_item`/`apply_*` path reads ONLY the ordered input, prior consensus DB state, and `cfg.consensus`. No RPC, wall-clock, `our_peer_id`, floats, or `Math.random`-equivalent. Every honest guardian must compute byte-identical results.
- **Append-only wire enums:** new variants of `UserOpPurpose`, `UsdtConsensusItem` are appended LAST (encoding is derive-ordinal-based). Never reorder existing variants.
- **DB encoding changes require a migration:** adding a field to a `Decodable` struct (`DepositRecord`, `PoolState`) needs a `migrate_db_v5` registered under `DatabaseVersion(5)`.
- **Version bump:** `MODULE_CONSENSUS_VERSION` `0.11 → 0.12` (`modules/fedimint-usdt-common/src/lib.rs:149`), with a new changelog paragraph.
- **`UsdtAmount` has no arithmetic operators.** It is `Copy`. Operate on `.0` with `u64` `saturating_add`/`saturating_sub`, then re-wrap: `UsdtAmount(a.0.saturating_add(b.0))`.
- **No `unwrap()` in non-test code** — use `expect("reason")` (project rule). Structured logging: `field = value`, `target: "usdt"`.
- **New DB prefix byte:** `WithdrawFeesVote = 0x16` (0x15 is `RecoverResidualVote`, the highest live; 0x05 is a permanent gap — do not reuse).
- After any code change run `just format`; before finishing run `just clippy` and `just final-lint`.

## File map

- `modules/fedimint-usdt-common/src/lib.rs` — `MODULE_CONSENSUS_VERSION`, `UsdtConsensusItem` (+`WithdrawFeesVote`), `WithdrawFeesVote`/`WithdrawFeesRequest` types, `PoolStateResponse` (+`accrued_fees`), reuse existing `is_dev_chain`/`EvmAddress`.
- `modules/fedimint-usdt-common/src/endpoint_constants.rs` — `WITHDRAW_FEES_ENDPOINT`.
- `modules/fedimint-usdt-server/src/db.rs` — `DepositRecord.fees_accrued`, `PoolState.accrued_fees`, `UserOpPurpose::WithdrawFees`, `WithdrawFeesVoteKey`/prefix, `DbKeyPrefix::WithdrawFeesVote = 0x16`.
- `modules/fedimint-usdt-server/src/lib.rs` — `migrate_db_v5`, `process_input` accrual, `apply_user_op_confirmed` (DeployAndSweep credit + new `WithdrawFees` arm + `expected` decode arm), `apply_withdraw_confirmed`/`create_withdrawal_refund` accrual, `withdraw_batch_in_flight` widening, `maybe_trigger_fee_withdrawal`, `consensus_proposal` intent, `process_consensus_item` vote arm, `pool_state` endpoint, `withdraw_fees` endpoint, `fee_withdrawal_intent` field, `audit` test.
- `modules/fedimint-usdt-client/src/api.rs` — `withdraw_fees(recipient, amount, auth)`.
- `modules/fedimint-usdt-client/src/cli.rs` — extend `PoolState` output with `accrued_fees`.
- `docs/usdt-module.md` — document the guardian flow.

---

### Task 1: Schema + migration + version bump

Add the two trailing `UsdtAmount` fields and their migration, bump the consensus version. This must land as one unit: the encoding change and its migration are inseparable, and every struct literal must be updated or the crate won't compile.

**Files:**
- Modify: `modules/fedimint-usdt-server/src/db.rs` (`DepositRecord`, `PoolState`)
- Modify: `modules/fedimint-usdt-server/src/lib.rs` (`migrate_db_v5` + registration + every `PoolState`/`DepositRecord` literal)
- Modify: `modules/fedimint-usdt-common/src/lib.rs` (`MODULE_CONSENSUS_VERSION` + changelog)
- Test: `modules/fedimint-usdt-server/src/db.rs` (`deposit_record_round_trips`), `modules/fedimint-usdt-server/src/lib.rs` (new migration test)

**Interfaces:**
- Produces: `DepositRecord { …, pub fees_accrued: UsdtAmount }`; `PoolState { …, pub accrued_fees: UsdtAmount }`; `migrate_db_v5`; module DB version now 6 (migrations keyed 0..=5).

- [ ] **Step 1: Add the fields.** In `db.rs`, add as the LAST field of each struct:

```rust
// in DepositRecord (after `nonce: u64,`)
    /// Cumulative deposit-fee USDT charged against this account in
    /// `process_input` but not yet moved into the pool. Credited into
    /// `PoolState.accrued_fees` (and reset to 0) when a `DeployAndSweep`
    /// confirms and sweeps this account's balance into the pool, so a deposit
    /// fee counts as withdrawable revenue only once its USDT is physically in
    /// the pool. Appended in MODULE_CONSENSUS_VERSION 0.12 (migrate_db_v5).
    pub fees_accrued: UsdtAmount,
```

```rust
// in PoolState (after `nonce: u64,`)
    /// Realized, withdrawable federation fee revenue physically held in the
    /// pool `SimpleAccount`, in USDT units. Credited by confirmed deposit
    /// sweeps and confirmed/failed withdrawals; debited by confirmed
    /// `WithdrawFees` payouts. Invariant: `accrued_fees <= balance`. Appended
    /// in MODULE_CONSENSUS_VERSION 0.12 (migrate_db_v5).
    pub accrued_fees: UsdtAmount,
```

- [ ] **Step 2: Write `migrate_db_v5` and register it.** In `lib.rs`, next to `migrate_db_v4`, add:

```rust
/// MODULE_CONSENSUS_VERSION 0.12: append `DepositRecord.fees_accrued` and
/// `PoolState.accrued_fees` (each a trailing `UsdtAmount`, encoded as 8 bytes).
/// A pre-0.12 row lacks the field, so append `UsdtAmount(0)`'s encoding to every
/// existing row of both keyspaces. `PoolState` is a singleton (0 or 1 row);
/// `DepositRecord` is prefix-scanned. Pre-upgrade fees are therefore not
/// retroactively withdrawable (counter starts at 0) -- intentional.
async fn migrate_db_v5(mut ctx: ServerModuleDbMigrationFnContext<'_, Usdt>) -> anyhow::Result<()> {
    let zero = UsdtAmount(0).consensus_encode_to_vec();
    for prefix in [DbKeyPrefix::DepositRecord as u8, DbKeyPrefix::PoolState as u8] {
        let entries: Vec<(Vec<u8>, Vec<u8>)> = ctx
            .dbtx()
            .raw_find_by_prefix(&[prefix])
            .await
            .expect("DB error")
            .collect()
            .await;
        for (key, mut value) in entries {
            value.extend_from_slice(&zero);
            ctx.dbtx()
                .raw_insert_bytes(&key, &value)
                .await
                .expect("DB error");
        }
    }
    Ok(())
}
```

Register in `get_database_migrations` after the `DatabaseVersion(4)` entry:

```rust
        migrations.insert(
            DatabaseVersion(5),
            Box::new(|ctx| migrate_db_v5(ctx).boxed()),
        );
```

Ensure `use fedimint_core::encoding::Encodable as _;` (for `consensus_encode_to_vec`) is in scope in `lib.rs` (it already is via the module's imports; add `as _` import only if the method isn't resolvable).

- [ ] **Step 3: Fix every struct literal.** Run `cargo check -p fedimint-usdt-server -q`; the compiler lists every `PoolState { … }` and `DepositRecord { … }` literal missing the new field. Add `accrued_fees: UsdtAmount(0)` / `fees_accrued: UsdtAmount(0)` to each (production `unwrap_or(PoolState { … })` defaults at the pool-balance gate and the confirm paths; `pool_state` endpoint default; all `#[cfg(test)]` constructors incl. `deposit_record_round_trips` in `db.rs`). These defaults are correct: a freshly-defaulted pool/record has zero realized fees.

- [ ] **Step 4: Bump the version + changelog.** In `common/src/lib.rs`, change line 149 to:

```rust
pub const MODULE_CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion::new(0, 12);
```

Add immediately above it a `///` paragraph:

```rust
/// Bumped to `0.12`: guardian fee withdrawal. Appends two trailing
/// `UsdtAmount` fields (`DepositRecord.fees_accrued`, `PoolState.accrued_fees`,
/// migrated by `migrate_db_v5`), appends `UserOpPurpose::WithdrawFees` and
/// `UsdtConsensusItem::WithdrawFeesVote` (both append-only wire variants), and
/// adds the `WithdrawFeesVote` keyspace (`0x16`). Read-side: `PoolStateResponse`
/// gains an `accrued_fees` field.
```

- [ ] **Step 5: Write the migration test.** In `lib.rs` `#[cfg(test)] mod tests`, add:

```rust
    #[tokio::test]
    async fn migrate_db_v5_appends_zero_fee_fields() {
        // A pre-0.12 PoolState/DepositRecord row is the current struct minus its
        // trailing UsdtAmount. Encode the *current* struct with a NON-zero
        // trailing field, strip the last 8 bytes to simulate the old shape,
        // insert raw, run migrate_db_v5, and confirm it decodes with a ZERO
        // trailing field (the migration must append 0, not preserve garbage).
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();

        let account = EvmAddress([0x11; 20]);
        let old_pool = PoolState {
            account,
            balance: UsdtAmount(1234),
            nonce: 7,
            accrued_fees: UsdtAmount(0),
        };
        let mut pool_bytes = old_pool.consensus_encode_to_vec();
        pool_bytes.truncate(pool_bytes.len() - 8); // drop accrued_fees

        let old_rec = DepositRecord {
            claim_pk: test_pubkey(0x22),
            credited: UsdtAmount(500),
            claimed: UsdtAmount(100),
            last_observed_block: 3,
            swept: UsdtAmount(50),
            nonce: 1,
            fees_accrued: UsdtAmount(0),
        };
        let mut rec_bytes = old_rec.consensus_encode_to_vec();
        rec_bytes.truncate(rec_bytes.len() - 8);

        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.raw_insert_bytes(&[DbKeyPrefix::PoolState as u8], &pool_bytes)
                .await
                .unwrap();
            let mut rec_key = vec![DbKeyPrefix::DepositRecord as u8];
            rec_key.extend_from_slice(&DepositRecordKey(account).consensus_encode_to_vec());
            dbtx.raw_insert_bytes(&rec_key, &rec_bytes).await.unwrap();
            dbtx.commit_tx().await;
        }

        let mut dbtx = db.begin_transaction().await;
        migrate_db_v5(ServerModuleDbMigrationFnContext::new(dbtx.to_ref_nc(), module.clone()))
            .await
            .unwrap();
        // (Adapt the ctx construction to the crate's test convention if a
        // helper exists; the assertion below is the point.)
        dbtx.commit_tx().await;

        let mut dbtx = db.begin_transaction().await;
        let pool = dbtx.get_value(&PoolStateKey).await.unwrap();
        assert_eq!(pool.accrued_fees, UsdtAmount(0));
        assert_eq!(pool.balance, UsdtAmount(1234)); // pre-existing bytes intact
        let rec = dbtx.get_value(&DepositRecordKey(account)).await.unwrap();
        assert_eq!(rec.fees_accrued, UsdtAmount(0));
        assert_eq!(rec.swept, UsdtAmount(50));
    }
```

If constructing `ServerModuleDbMigrationFnContext` directly in a test is awkward, instead assert via the framework's migration-test harness if the crate has one (search `apply_migrations`/`ServerModuleDbMigrationFnContext` in tests); otherwise keep the raw-bytes round-trip assertion by calling `migrate_db_v5` through whatever ctor the other `migrate_db_v*` tests use.

- [ ] **Step 6: Run tests.** `just format` then:
```
cargo test -p fedimint-usdt-server -q migrate_db_v5_appends_zero_fee_fields
cargo test -p fedimint-usdt-server -q deposit_record_round_trips
cargo check -p fedimint-usdt-server -p fedimint-usdt-common -q
```
Expected: PASS / clean check.

- [ ] **Step 7: Commit.**
```bash
git add modules/fedimint-usdt-server/src/db.rs modules/fedimint-usdt-server/src/lib.rs modules/fedimint-usdt-common/src/lib.rs
git commit -m "feat(usdt): add accrued-fee schema fields + migrate_db_v5 (consensus 0.12)"
```

---

### Task 2: Accrue deposit fees

Charge deposit fees onto the record at claim time; move them into `PoolState.accrued_fees` when the sweep confirms.

**Files:**
- Modify: `modules/fedimint-usdt-server/src/lib.rs` (`process_input` ~2364; `apply_user_op_confirmed` DeployAndSweep success arm ~5127–5145)
- Test: `modules/fedimint-usdt-server/src/lib.rs` tests

**Interfaces:**
- Consumes: `DepositRecord.fees_accrued`, `PoolState.accrued_fees` (Task 1).
- Produces: deposit fees realized into `PoolState.accrued_fees` on sweep confirm.

- [ ] **Step 1: Write the failing test for `process_input` accrual.** Model on `process_input_rejects_deposit_fee_below_quote` (it already seeds fee votes + a `DepositRecord`). Add:

```rust
    #[tokio::test]
    async fn process_input_accrues_deposit_fee_onto_record() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();
        let account = EvmAddress([0x57; 20]);
        seed_fee_votes(db, 4, sample_fee_vote()).await;
        let quote = deposit_fee_quote(&sample_fee_vote()).expect("realistic vote must quote");

        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(
                &DepositRecordKey(account),
                &DepositRecord {
                    claim_pk: test_pubkey(0xef),
                    credited: UsdtAmount(500_000_000),
                    claimed: UsdtAmount(0),
                    last_observed_block: 0,
                    swept: UsdtAmount(0),
                    nonce: 0,
                    fees_accrued: UsdtAmount(0),
                },
            )
            .await;
            dbtx.commit_tx().await;
        }

        let mut dbtx = db.begin_transaction().await;
        module
            .process_input(
                &mut dbtx.to_ref_nc(),
                &UsdtInput::V0(UsdtInputV0 {
                    account,
                    amount: UsdtAmount(200_000_000),
                    fee: quote,
                }),
                test_in_point(),
            )
            .await
            .expect("valid claim");
        let rec = dbtx
            .to_ref_nc()
            .get_value(&DepositRecordKey(account))
            .await
            .unwrap();
        assert_eq!(rec.fees_accrued, quote);
        assert_eq!(rec.claimed, UsdtAmount(200_000_000));
    }
```

- [ ] **Step 2: Run it — FAIL** (`fees_accrued` stays 0). `cargo test -p fedimint-usdt-server -q process_input_accrues_deposit_fee_onto_record` → assert failure.

- [ ] **Step 3: Implement.** In `process_input`, between `record.claimed = …` (lib.rs:2364) and the `insert_entry` (2365), add:

```rust
        // Accrue the deposit fee onto this account's record. It is credited
        // into PoolState.accrued_fees (and reset) only when the sweep confirms
        // (see apply_user_op_confirmed's DeployAndSweep arm), so a deposit fee
        // becomes withdrawable revenue only once its USDT is physically pooled.
        record.fees_accrued =
            UsdtAmount(record.fees_accrued.0.saturating_add(input.fee.0));
```

- [ ] **Step 4: Run — PASS.**

- [ ] **Step 5: Write the failing test for sweep-confirm credit.** Search the tests module for an existing DeployAndSweep-confirm test (grep `apply_user_op_confirmed` / `DeployAndSweep` in tests) and clone its setup. The test seeds a `SubmittedUserOp` with `purpose: UserOpPurpose::DeployAndSweep { source }` and a matching `DepositRecord { fees_accrued: UsdtAmount(777), credited, swept: 0, … }`, drives the confirm with a successful observation, then asserts:

```rust
        let pool = dbtx.to_ref_nc().get_value(&PoolStateKey).await.unwrap();
        assert_eq!(pool.accrued_fees, UsdtAmount(777));
        let rec = dbtx.to_ref_nc().get_value(&DepositRecordKey(source)).await.unwrap();
        assert_eq!(rec.fees_accrued, UsdtAmount(0)); // reset after crediting
```

(Use the existing confirm-test harness verbatim for the setup; only the two asserts and the seeded `fees_accrued: UsdtAmount(777)` are new.)

- [ ] **Step 6: Run — FAIL.**

- [ ] **Step 7: Implement.** In `apply_user_op_confirmed`, DeployAndSweep success arm, inside `if obs.success { … }` where `pool.balance` is credited (lib.rs:5142), add the accrued-fee credit; and in the `if let Some(mut record) = …` block that runs on success, zero `fees_accrued`:

```rust
                if obs.success {
                    // … existing pool.balance saturating_add(effective_swept) …
                    // Realize this account's accrued deposit fees now that its
                    // USDT (fee portion included) is physically in the pool.
                    if let Some(record) = dbtx.get_value(&DepositRecordKey(source)).await {
                        pool.balance =
                            UsdtAmount(pool.balance.0.saturating_add(effective_swept.0));
                        pool.accrued_fees =
                            UsdtAmount(pool.accrued_fees.0.saturating_add(record.fees_accrued.0));
                    } else {
                        pool.balance =
                            UsdtAmount(pool.balance.0.saturating_add(effective_swept.0));
                    }
                    dbtx.insert_entry(&PoolStateKey, &pool).await;
                    retrigger_source = Some(source);
                }
```

Then in the existing `if let Some(mut record) = dbtx.get_value(&DepositRecordKey(source)).await { record.nonce += 1; if obs.success { record.swept = … } … }` block, add inside the `if obs.success` arm:

```rust
                        record.fees_accrued = UsdtAmount(0);
```

(Keep the existing `pool.balance` add exactly once — merge the snippet above with the existing lines rather than double-adding. The net effect: on success, `pool.balance += effective_swept`, `pool.accrued_fees += record.fees_accrued`, and `record.fees_accrued = 0`.)

- [ ] **Step 8: Run — PASS.** Then `cargo test -p fedimint-usdt-server -q` (full module tests) to catch regressions.

- [ ] **Step 9: Commit.**
```bash
git add modules/fedimint-usdt-server/src/lib.rs
git commit -m "feat(usdt): accrue deposit fees into PoolState.accrued_fees on sweep"
```

---

### Task 3: Accrue withdrawal fees

Realize withdrawal fees at confirm: full `max_fee` on success, `incurred` on terminal-failure refund, nothing on re-queue.

**Files:**
- Modify: `modules/fedimint-usdt-server/src/lib.rs` (`apply_withdraw_confirmed` success branch ~5347–5376; `create_withdrawal_refund` ~5531–5537)
- Test: `modules/fedimint-usdt-server/src/lib.rs` tests

**Interfaces:**
- Consumes: `PoolState.accrued_fees`; `UnclaimedWithdrawalKey → UsdtWithdrawalV0 { max_fee }`; `WithdrawalIncurredFeeKey`.
- Produces: withdrawal fees realized into `PoolState.accrued_fees` at confirm.

- [ ] **Step 1: Failing test — success credits `max_fee`.** Clone the existing successful-withdrawal-confirm test (grep `apply_withdraw_confirmed`/`WithdrawalState::Confirmed` in tests). Seed a `PoolState { balance: 1_000, accrued_fees: 0, … }`, an `UnclaimedWithdrawal` with `amount: 100, max_fee: 9`, drive a **successful** confirm with `swept = 100`, assert:

```rust
        let pool = dbtx.to_ref_nc().get_value(&PoolStateKey).await.unwrap();
        assert_eq!(pool.balance, UsdtAmount(900));       // -= amount
        assert_eq!(pool.accrued_fees, UsdtAmount(9));    // += max_fee
```

- [ ] **Step 2: Run — FAIL.**

- [ ] **Step 3: Implement success credit.** In `apply_withdraw_confirmed`, before the `dbtx.insert_entry(&PoolStateKey, &pool)` at lib.rs:5346, extend the `if obs.success { … }` that debits `pool.balance`:

```rust
        if obs.success {
            pool.balance = UsdtAmount(pool.balance.0.saturating_sub(swept.0));
            // Realize retained withdrawal fees: on success the federation keeps
            // the FULL max_fee of each settled withdrawal (the recipient was
            // only ever paid `amount`; max_fee never left the pool -- see
            // `audit`, lib.rs:2525). Read max_fee before the loop below removes
            // the UnclaimedWithdrawal records.
            let mut fee_total: u64 = 0;
            for &out_point in outpoints {
                if let Some(w) = dbtx.get_value(&UnclaimedWithdrawalKey(out_point)).await {
                    fee_total = fee_total.saturating_add(w.max_fee.0);
                }
            }
            pool.accrued_fees = UsdtAmount(pool.accrued_fees.0.saturating_add(fee_total));
        }
        dbtx.insert_entry(&PoolStateKey, &pool).await;
```

- [ ] **Step 4: Run — PASS.**

- [ ] **Step 5: Failing test — terminal failure credits `incurred`.** Clone the existing singleton-failure/refund test (grep `create_withdrawal_refund`/`WithdrawalState::Failed`). Seed `PoolState { accrued_fees: 0, … }`, an `UnclaimedWithdrawal { amount: 100, max_fee: 20 }`, a `WithdrawalIncurredFeeKey(out_point) = UsdtAmount(7)`, drive a singleton (`n == 1`) **failed** confirm, assert:

```rust
        let refund = dbtx.to_ref_nc().get_value(&RefundKey(out_point)).await.unwrap();
        assert_eq!(refund.amount, UsdtAmount(113)); // (100+20) - 7
        let pool = dbtx.to_ref_nc().get_value(&PoolStateKey).await.unwrap();
        assert_eq!(pool.accrued_fees, UsdtAmount(7)); // += incurred
```

(If the existing failure test drives `obs.actual_gas_cost_wei` to compute `incurred` rather than seeding `WithdrawalIncurredFeeKey` directly, mirror that; the assertion is `accrued_fees == incurred` where `incurred` is whatever the refund subtracts.)

- [ ] **Step 6: Run — FAIL.**

- [ ] **Step 7: Implement failure credit.** In `create_withdrawal_refund`, right after `let refund_amount = UsdtAmount(gross.saturating_sub(incurred));` (lib.rs:5537) and past the `Some(withdrawal)` guard (so the already-refunded early-return never reaches it), add:

```rust
        // Realize the retained withdrawal fee on terminal failure: the refund
        // returns `gross - incurred`, so the federation keeps exactly the
        // `incurred` gas it actually burned. (Non-terminal, re-queued failures
        // reach `apply_withdraw_confirmed`'s `n > 1` branch, not here, and
        // realize nothing yet.)
        let mut pool = dbtx.get_value(&PoolStateKey).await.unwrap_or(PoolState {
            account: self.pool_account(),
            balance: UsdtAmount(0),
            nonce: 0,
            accrued_fees: UsdtAmount(0),
        });
        pool.accrued_fees = UsdtAmount(pool.accrued_fees.0.saturating_add(incurred));
        dbtx.insert_entry(&PoolStateKey, &pool).await;
```

- [ ] **Step 8: Run — PASS**, then full `cargo test -p fedimint-usdt-server -q`.

- [ ] **Step 9: Commit.**
```bash
git add modules/fedimint-usdt-server/src/lib.rs
git commit -m "feat(usdt): accrue withdrawal fees (max_fee on success, incurred on refund)"
```

---

### Task 4: Expose `accrued_fees` on the pool-state read surface

**Files:**
- Modify: `modules/fedimint-usdt-common/src/lib.rs` (`PoolStateResponse` ~1123)
- Modify: `modules/fedimint-usdt-server/src/lib.rs` (`POOL_STATE_ENDPOINT` handler ~2596–2618)
- Modify: `modules/fedimint-usdt-client/src/cli.rs` (`Opts::PoolState` arm ~256–272)
- Test: `modules/fedimint-usdt-client/src/cli.rs` tests

**Interfaces:**
- Produces: `PoolStateResponse { account, balance, accrued_fees }`.

- [ ] **Step 1: Extend the response type.** In `common/src/lib.rs`:

```rust
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct PoolStateResponse {
    pub account: EvmAddress,
    pub balance: UsdtAmount,
    pub accrued_fees: UsdtAmount,
}
```

- [ ] **Step 2: Populate it.** In the `POOL_STATE_ENDPOINT` handler, change the `Ok(PoolStateResponse { … })` to include `accrued_fees: pool.accrued_fees,`. The `unwrap_or(PoolState { … })` default there already gets `accrued_fees: UsdtAmount(0)` from Task 1.

- [ ] **Step 3: Print it in the CLI.** In `cli.rs` `Opts::PoolState` arm, extend the json:

```rust
            json(serde_json::json!({
                "account": pool.account.to_string(),
                "balance": pool.balance.0,
                "accrued_fees": pool.accrued_fees.0,
            }))
```

- [ ] **Step 4: Update the CLI parse test** if `parses_pool_state` asserts exact output; otherwise no test change. Run:
```
cargo check -p fedimint-usdt-common -p fedimint-usdt-server -p fedimint-usdt-client -q
cargo test -p fedimint-usdt-client -q parses_pool_state
```
Expected: clean.

- [ ] **Step 5: Commit.**
```bash
git add modules/fedimint-usdt-common/src/lib.rs modules/fedimint-usdt-server/src/lib.rs modules/fedimint-usdt-client/src/cli.rs
git commit -m "feat(usdt): report accrued_fees in pool_state endpoint + CLI"
```

---

### Task 5: `WithdrawFees` UserOp — purpose, build, confirm, in-flight guard

Add the on-chain execution primitive: a batch-of-one pool transfer to the fee recipient, its confirm handling (debit balance + accrued_fees, GC votes), and serialization against user withdrawals.

**Files:**
- Modify: `modules/fedimint-usdt-server/src/db.rs` (`UserOpPurpose`)
- Modify: `modules/fedimint-usdt-server/src/lib.rs` (`apply_user_op_confirmed` `expected` match + main match + new `apply_fee_withdrawal_confirmed`; `withdraw_batch_in_flight`)
- Test: `modules/fedimint-usdt-server/src/lib.rs` tests

**Interfaces:**
- Consumes: `build_withdrawal_batch_userop`, `decode_batch_transfer_total`, `PoolState.{balance,accrued_fees,nonce}`.
- Produces: `fedimint_usdt_common::WithdrawFeesVote`; `UserOpPurpose::WithdrawFees { recipient: EvmAddress, amount: UsdtAmount }`; `WithdrawFeesVoteKey`/`WithdrawFeesVotePrefix`; `apply_fee_withdrawal_confirmed`; widened in-flight guard.

This task defines the `WithdrawFeesVote` type and its keyspace (needed here for vote GC on confirm); Task 6 only adds the consensus-item variant and the trigger that populates it.

- [ ] **Step 0: Define the vote type in common.** In `modules/fedimint-usdt-common/src/lib.rs`:

```rust
/// A guardian's vote to withdraw `amount` of accrued fee revenue from the pool
/// to `recipient`. A 2f+1 threshold agreeing on the IDENTICAL `(recipient,
/// amount)` pair triggers a `WithdrawFees` payout UserOp.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct WithdrawFeesVote {
    pub recipient: EvmAddress,
    pub amount: UsdtAmount,
}
```

- [ ] **Step 1: Append the purpose variant + the vote keyspace.** In `db.rs`, append to `UserOpPurpose` (LAST variant):

```rust
    /// A fee-revenue payout UserOp FROM the pool SimpleAccount: a single
    /// ERC-20 `transfer(recipient, amount)` moving accrued fee USDT out of the
    /// pool. Shares `PoolState.nonce` with `Withdraw`, so the two are mutually
    /// serialized by `withdraw_batch_in_flight`. Appended in consensus 0.12.
    WithdrawFees { recipient: EvmAddress, amount: UsdtAmount },
```

Add the vote keyspace (used for GC here, populated in Task 6). Prefix byte `0x16`:

```rust
// in DbKeyPrefix enum:
    WithdrawFeesVote = 0x16,
```

```rust
#[derive(Clone, Debug, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct WithdrawFeesVoteKey(pub PeerId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct WithdrawFeesVotePrefix;

impl_db_record!(
    key = WithdrawFeesVoteKey,
    value = fedimint_usdt_common::WithdrawFeesVote,
    db_prefix = DbKeyPrefix::WithdrawFeesVote,
);
impl_db_lookup!(key = WithdrawFeesVoteKey, query_prefix = WithdrawFeesVotePrefix);
```

(`WithdrawFeesVote` was defined in Step 0.)

- [ ] **Step 2: Failing test — confirm debits balance + accrued_fees, GCs votes, bumps nonce.**

```rust
    #[tokio::test]
    async fn withdraw_fees_confirm_debits_and_gcs_votes() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();
        let recipient = EvmAddress([0xab; 20]);

        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_entry(
                &PoolStateKey,
                &PoolState {
                    account: module.pool_account(),
                    balance: UsdtAmount(1_000),
                    nonce: 5,
                    accrued_fees: UsdtAmount(300),
                },
            )
            .await;
            // seed a threshold of matching votes so GC is observable
            for p in [0u16, 1, 2] {
                dbtx.insert_entry(
                    &WithdrawFeesVoteKey(PeerId::from(p)),
                    &fedimint_usdt_common::WithdrawFeesVote { recipient, amount: UsdtAmount(120) },
                )
                .await;
            }
            dbtx.commit_tx().await;
        }

        let mut dbtx = db.begin_transaction().await;
        module
            .apply_fee_withdrawal_confirmed(&mut dbtx.to_ref_nc(), &successful_obs(), UsdtAmount(120))
            .await;
        let pool = dbtx.to_ref_nc().get_value(&PoolStateKey).await.unwrap();
        assert_eq!(pool.balance, UsdtAmount(880));
        assert_eq!(pool.accrued_fees, UsdtAmount(180));
        assert_eq!(pool.nonce, 6);
        let remaining: Vec<_> = dbtx
            .to_ref_nc()
            .find_by_prefix(&WithdrawFeesVotePrefix)
            .await
            .collect()
            .await;
        assert!(remaining.is_empty(), "votes GC'd on confirm");
    }
```

Use the tests module's existing successful-observation constructor for `successful_obs()` (grep `UserOpConfirmedObservation {` in tests for the helper/literal; reuse it). If none exists, build the literal inline matching `apply_withdraw_confirmed` tests.

- [ ] **Step 3: Run — FAIL** (`apply_fee_withdrawal_confirmed` undefined).

- [ ] **Step 4: Implement `apply_fee_withdrawal_confirmed`.** Add the method near `apply_withdraw_confirmed`:

```rust
    /// Confirm handling for a `WithdrawFees` payout. On success, debit both
    /// `PoolState.balance` and `PoolState.accrued_fees` by the transferred
    /// amount (`swept`, re-derived from calldata and cross-checked upstream).
    /// The pool nonce advances unconditionally (the EntryPoint consumed it
    /// whether the transfer succeeded or reverted). Votes are GC'd
    /// unconditionally so any subsequent fee withdrawal needs a FRESH 2f+1
    /// threshold (mirrors RecoverResidual's vote GC) -- preventing a
    /// stuck-vote retrigger loop after a revert.
    async fn apply_fee_withdrawal_confirmed(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        obs: &UserOpConfirmedObservation,
        swept: UsdtAmount,
    ) {
        let mut pool = dbtx.get_value(&PoolStateKey).await.unwrap_or(PoolState {
            account: self.pool_account(),
            balance: UsdtAmount(0),
            nonce: 0,
            accrued_fees: UsdtAmount(0),
        });
        pool.nonce += 1;
        if obs.success {
            pool.balance = UsdtAmount(pool.balance.0.saturating_sub(swept.0));
            pool.accrued_fees = UsdtAmount(pool.accrued_fees.0.saturating_sub(swept.0));
        }
        dbtx.insert_entry(&PoolStateKey, &pool).await;

        dbtx.remove_by_prefix(&WithdrawFeesVotePrefix).await;
    }
```

Wire it into `apply_user_op_confirmed`. In the `expected` match (lib.rs:5049), add:

```rust
                UserOpPurpose::WithdrawFees { .. } => {
                    crate::user_op::decode_batch_transfer_total(&submitted.signed.unsigned)
                }
```

In the main `match &submitted.purpose` (lib.rs:5122), add:

```rust
            UserOpPurpose::WithdrawFees { .. } => {
                self.apply_fee_withdrawal_confirmed(dbtx, obs, effective_swept)
                    .await;
            }
```

- [ ] **Step 5: Run — PASS.**

- [ ] **Step 6: Failing test — in-flight guard blocks fee withdrawal behind a user Withdraw and vice-versa.**

```rust
    #[tokio::test]
    async fn in_flight_guard_serializes_withdraw_and_fee_withdraw() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();
        let mut dbtx = db.begin_transaction().await;
        // A pending user Withdraw must block a fee-withdrawal trigger.
        dbtx.insert_entry(
            &PendingUserOpKey([0x01; 32]),
            &PendingUserOp {
                op: dummy_unsigned_userop(),        // reuse a test helper / minimal literal
                purpose: UserOpPurpose::Withdraw { outpoints: vec![] },
                created_block: 0,
            },
        )
        .await;
        assert!(module.withdraw_batch_in_flight(&mut dbtx.to_ref_nc()).await);
        dbtx.remove_entry(&PendingUserOpKey([0x01; 32])).await;
        // A pending WithdrawFees must ALSO block (both share the pool nonce).
        dbtx.insert_entry(
            &PendingUserOpKey([0x02; 32]),
            &PendingUserOp {
                op: dummy_unsigned_userop(),
                purpose: UserOpPurpose::WithdrawFees {
                    recipient: EvmAddress([0x03; 20]),
                    amount: UsdtAmount(1),
                },
                created_block: 0,
            },
        )
        .await;
        assert!(module.withdraw_batch_in_flight(&mut dbtx.to_ref_nc()).await);
    }
```

(For `dummy_unsigned_userop()`, reuse whatever minimal `UnsignedUserOp` the existing pending-op tests construct; grep `PendingUserOp {` in tests.)

- [ ] **Step 7: Run — FAIL** (second assert: guard ignores `WithdrawFees`).

- [ ] **Step 8: Widen the guard.** In `withdraw_batch_in_flight`, change both `matches!` predicates (lib.rs:4398 and 4416):

```rust
            .find(|(_, p)| matches!(
                p.purpose,
                UserOpPurpose::Withdraw { .. } | UserOpPurpose::WithdrawFees { .. }
            ))
```
```rust
            .find(|(_, s)| matches!(
                s.purpose,
                UserOpPurpose::Withdraw { .. } | UserOpPurpose::WithdrawFees { .. }
            ))
```

- [ ] **Step 9: Run — PASS**, then full `cargo test -p fedimint-usdt-server -q`.

- [ ] **Step 10: Commit.**
```bash
git add modules/fedimint-usdt-server/src/db.rs modules/fedimint-usdt-server/src/lib.rs
git commit -m "feat(usdt): WithdrawFees UserOp purpose, confirm handling, in-flight serialization"
```

---

### Task 6: `WithdrawFeesVote` consensus item + trigger

Add the vote type, the consensus-item plumbing, and the threshold trigger that builds the `WithdrawFees` op.

**Files:**
- Modify: `modules/fedimint-usdt-common/src/lib.rs` (`WithdrawFeesVote`, `UsdtConsensusItem::WithdrawFeesVote`)
- Modify: `modules/fedimint-usdt-server/src/lib.rs` (`process_consensus_item` new arm; new `maybe_trigger_fee_withdrawal`)
- Test: `modules/fedimint-usdt-server/src/lib.rs` tests

**Interfaces:**
- Consumes: `WithdrawFeesVoteKey`/`WithdrawFeesVotePrefix` (Task 5), `build_withdrawal_batch_userop`, `withdraw_batch_in_flight`, `start_session`, `is_dev_chain`.
- Produces: `UsdtConsensusItem::WithdrawFeesVote(WithdrawFeesVote)`; `maybe_trigger_fee_withdrawal`.

- [ ] **Step 1: Add the consensus item.** The `WithdrawFeesVote` type was defined in Task 5 Step 0. Append to `UsdtConsensusItem` (LAST variant) in `common/src/lib.rs`:

```rust
    /// A guardian's fee-withdrawal vote (consensus 0.12). See `WithdrawFeesVote`.
    WithdrawFeesVote(WithdrawFeesVote),
```

- [ ] **Step 2: Failing test — threshold of matching votes enqueues a `WithdrawFees` op; mismatches and over-limit do not.**

```rust
    #[tokio::test]
    async fn fee_withdrawal_triggers_only_on_threshold_and_within_limits() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();
        seed_block_count_votes(db, 4, 10).await;
        seed_fee_votes(db, 4, sample_fee_vote()).await;
        let recipient = EvmAddress([0xcd; 20]);

        // Pool has 500 balance and 200 accrued fees.
        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_entry(
                &PoolStateKey,
                &PoolState {
                    account: module.pool_account(),
                    balance: UsdtAmount(500),
                    nonce: 1,
                    accrued_fees: UsdtAmount(200),
                },
            )
            .await;
            dbtx.commit_tx().await;
        }

        // Two votes for (recipient, 150): below threshold (3) -> no op.
        let mut dbtx = db.begin_transaction().await;
        for p in [0u16, 1] {
            module
                .process_consensus_item(
                    &mut dbtx.to_ref_nc(),
                    UsdtConsensusItem::WithdrawFeesVote(WithdrawFeesVote {
                        recipient,
                        amount: UsdtAmount(150),
                    }),
                    PeerId::from(p),
                )
                .await
                .unwrap();
        }
        assert!(pending_withdraw_fees(&mut dbtx.to_ref_nc()).await.is_none());

        // Third matching vote reaches threshold -> op enqueued.
        module
            .process_consensus_item(
                &mut dbtx.to_ref_nc(),
                UsdtConsensusItem::WithdrawFeesVote(WithdrawFeesVote {
                    recipient,
                    amount: UsdtAmount(150),
                }),
                PeerId::from(2),
            )
            .await
            .unwrap();
        let op = pending_withdraw_fees(&mut dbtx.to_ref_nc()).await.expect("enqueued");
        assert!(matches!(
            op.purpose,
            UserOpPurpose::WithdrawFees { recipient: r, amount: a }
                if r == recipient && a == UsdtAmount(150)
        ));
    }
```

Add a small tests-module helper:

```rust
    async fn pending_withdraw_fees(dbtx: &mut DatabaseTransaction<'_>) -> Option<PendingUserOp> {
        dbtx.find_by_prefix(&PendingUserOpPrefix)
            .await
            .map(|(_, p)| p)
            .filter(|p| matches!(p.purpose, UserOpPurpose::WithdrawFees { .. }))
            .next()
            .await
    }
```

Also add two asserting cases (can be separate `#[tokio::test]`s reusing the setup): (a) three votes for `amount: 300` (> accrued 200) → no op; (b) three votes for `amount: 600` (> balance 500) → no op.

- [ ] **Step 3: Run — FAIL** (`WithdrawFeesVote` consensus arm unhandled → the item is rejected/ignored, no op).

- [ ] **Step 4: Implement the consensus arm.** In `process_consensus_item`, add:

```rust
            UsdtConsensusItem::WithdrawFeesVote(vote) => {
                ensure!(vote.amount.0 > 0, "fee-withdrawal vote amount must be positive");
                if !is_dev_chain(self.cfg.consensus.chain_id) {
                    ensure!(
                        vote.recipient != EvmAddress([0u8; 20]),
                        "fee-withdrawal recipient must not be the zero address on non-dev \
                         chain_id {}",
                        self.cfg.consensus.chain_id
                    );
                }
                let key = WithdrawFeesVoteKey(peer_id);
                if dbtx.insert_entry(&key, &vote).await == Some(vote.clone()) {
                    bail!("fee-withdrawal vote is redundant");
                }
                self.maybe_trigger_fee_withdrawal(dbtx).await;
                Ok(())
            }
```

Ensure `is_dev_chain` is imported from common in `lib.rs`.

- [ ] **Step 5: Implement `maybe_trigger_fee_withdrawal`.** Model on `maybe_trigger_residual_recovery` + `build_and_enqueue_withdrawal_batch`:

```rust
    /// If a 2f+1 threshold of guardians has voted for the IDENTICAL
    /// `(recipient, amount)` fee withdrawal, and `amount` is within both the
    /// accrued fee revenue and the physical pool balance, and no pool op is in
    /// flight, build and enqueue a `WithdrawFees` payout UserOp (a batch-of-one
    /// transfer) and start its MPC signing session. Deterministic: reads only
    /// consensus DB + cfg.
    async fn maybe_trigger_fee_withdrawal(&self, dbtx: &mut DatabaseTransaction<'_>) {
        // Serialize against user withdrawals on the shared pool nonce.
        if self.withdraw_batch_in_flight(dbtx).await {
            return;
        }

        let votes: Vec<fedimint_usdt_common::WithdrawFeesVote> = dbtx
            .find_by_prefix(&WithdrawFeesVotePrefix)
            .await
            .map(|(_, v)| v)
            .collect()
            .await;
        if votes.is_empty() {
            return;
        }

        // Tally by exact (recipient, amount). BTreeMap keeps the scan
        // deterministic; with a 2f+1 threshold at most one pair can qualify.
        let mut counts: std::collections::BTreeMap<([u8; 20], u64), usize> =
            std::collections::BTreeMap::new();
        for v in &votes {
            *counts.entry((v.recipient.0, v.amount.0)).or_default() += 1;
        }
        let threshold = self.num_peers.threshold();
        let Some((&(recipient_bytes, amount_u64), _)) =
            counts.iter().find(|(_, &c)| c >= threshold)
        else {
            return;
        };
        let recipient = EvmAddress(recipient_bytes);
        let amount = UsdtAmount(amount_u64);

        let pool = dbtx.get_value(&PoolStateKey).await.unwrap_or(PoolState {
            account: self.pool_account(),
            balance: UsdtAmount(0),
            nonce: 0,
            accrued_fees: UsdtAmount(0),
        });
        // Economic guard: never pay out more than realized fee revenue.
        if amount.0 > pool.accrued_fees.0 {
            return;
        }
        // Physical guard: never build a transfer the pool can't fund (would
        // revert on-chain); wait until in-transit backing settles.
        if amount.0 > pool.balance.0 {
            return;
        }

        let median = self.fee_vote_median(dbtx).await;
        let owner = evm_address(&self.cfg.consensus.group_public_key);
        let needs_deploy = pool.nonce == 0;
        let params = WithdrawalBatchParams {
            account_factory: self.cfg.consensus.account_factory,
            usdt_contract: self.cfg.consensus.usdt_contract,
            pool: pool.account,
            owner,
            withdrawals: vec![(recipient, amount)],
            nonce: alloy::primitives::U256::from(pool.nonce),
            needs_deploy,
            paymaster_and_data: Vec::new(),
            gas_bounds: GasBounds::withdrawal_batch(1, needs_deploy)
                .with_median_fees(median.map(|m| m.max_fee_per_gas_wei)),
        };
        let op = crate::user_op::build_withdrawal_batch_userop(params);
        let op_hash = user_op_hash(
            &op,
            self.cfg.consensus.entry_point,
            self.cfg.consensus.chain_id,
        );
        if dbtx.get_value(&PendingUserOpKey(op_hash)).await.is_some()
            || dbtx.get_value(&SubmittedUserOpKey(op_hash)).await.is_some()
        {
            return;
        }

        let created_block = self.consensus_block_count(dbtx).await;
        dbtx.insert_entry(
            &PendingUserOpKey(op_hash),
            &PendingUserOp {
                op: op.clone(),
                purpose: UserOpPurpose::WithdrawFees { recipient, amount },
                created_block,
            },
        )
        .await;
        info!(
            target: "usdt",
            ?op_hash,
            recipient = %recipient,
            amount = amount.0,
            nonce = pool.nonce,
            "fee withdrawal reached threshold; enqueued WithdrawFees op, starting MPC signing"
        );

        let digest = eth_signed_message_hash(op_hash);
        self.start_session(dbtx, SigningPurpose::UserOp(op_hash), digest, 0)
            .await;
    }
```

- [ ] **Step 6: Run — PASS** (all three trigger tests), then full `cargo test -p fedimint-usdt-server -q`.

- [ ] **Step 7: Commit.**
```bash
git add modules/fedimint-usdt-common/src/lib.rs modules/fedimint-usdt-server/src/lib.rs
git commit -m "feat(usdt): WithdrawFeesVote consensus item + threshold trigger"
```

---

### Task 7: Authenticated endpoint + proposal + client method

Let a guardian cast a vote via an `ApiAuth`-guarded endpoint; propose it in consensus.

**Files:**
- Modify: `modules/fedimint-usdt-common/src/endpoint_constants.rs` (`WITHDRAW_FEES_ENDPOINT`)
- Modify: `modules/fedimint-usdt-common/src/lib.rs` (`WithdrawFeesRequest`)
- Modify: `modules/fedimint-usdt-server/src/lib.rs` (`fee_withdrawal_intent` field + ctor wiring; `consensus_proposal`; `api_endpoints`)
- Modify: `modules/fedimint-usdt-client/src/api.rs` (`withdraw_fees`)
- Test: `modules/fedimint-usdt-server/src/lib.rs` tests

**Interfaces:**
- Consumes: `check_auth` (`fedimint_core::net::auth`), `WithdrawFeesVote` (Task 6), `WithdrawFeesVoteKey` (Task 5).
- Produces: `WITHDRAW_FEES_ENDPOINT`; `WithdrawFeesRequest { recipient, amount }`; `Usdt.fee_withdrawal_intent: Arc<Mutex<Option<WithdrawFeesVote>>>`; client `withdraw_fees`.

- [ ] **Step 1: Constants + request type.** In `endpoint_constants.rs`:

```rust
/// Guardian-authenticated: cast this guardian's fee-withdrawal vote.
pub const WITHDRAW_FEES_ENDPOINT: &str = "withdraw_fees";
```

In `common/src/lib.rs`:

```rust
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct WithdrawFeesRequest {
    pub recipient: EvmAddress,
    pub amount: UsdtAmount,
}
```

- [ ] **Step 2: Add the intent field.** On the `Usdt` struct, add:

```rust
    /// Guardian-local, in-memory pending fee-withdrawal vote set by the
    /// authenticated `withdraw_fees` endpoint and drained (one-shot) by
    /// `consensus_proposal`. In-memory so a restart before proposal just means
    /// the guardian re-casts; no value is at risk. Mirrors `fee_estimate`.
    fee_withdrawal_intent: Arc<Mutex<Option<fedimint_usdt_common::WithdrawFeesVote>>>,
```

Initialize `fee_withdrawal_intent: Arc::new(Mutex::new(None))` in every `Usdt` constructor (`new`, `new_for_test`, and any others — the compiler will flag each).

- [ ] **Step 3: Propose the intent.** In `consensus_proposal`, alongside the residual block, add:

```rust
        // One-shot drain of this guardian's pending fee-withdrawal vote.
        if let Some(vote) =
            std::mem::take(&mut *self.fee_withdrawal_intent.lock().expect("not poisoned"))
        {
            items.push(UsdtConsensusItem::WithdrawFeesVote(vote));
        }
```

- [ ] **Step 4: Failing test — endpoint requires auth and sets the intent.** Since endpoint handlers are awkward to call directly, test the two observable halves: (a) `check_auth` rejects an unauthenticated context (covered by the framework); (b) setting `fee_withdrawal_intent` then calling `consensus_proposal` yields the vote item, and a second `consensus_proposal` does not (one-shot). Write:

```rust
    #[tokio::test]
    async fn consensus_proposal_drains_fee_withdrawal_intent_once() {
        let module = test_module_with_block_count(4, 0).await;
        let recipient = EvmAddress([0x0f; 20]);
        *module.fee_withdrawal_intent.lock().unwrap() =
            Some(fedimint_usdt_common::WithdrawFeesVote { recipient, amount: UsdtAmount(42) });

        let mut dbtx = module.db_for_test().begin_transaction().await;
        let first = module.consensus_proposal(&mut dbtx.to_ref_nc()).await;
        assert!(first.iter().any(|it| matches!(
            it,
            UsdtConsensusItem::WithdrawFeesVote(v)
                if v.recipient == recipient && v.amount == UsdtAmount(42)
        )));
        let second = module.consensus_proposal(&mut dbtx.to_ref_nc()).await;
        assert!(!second
            .iter()
            .any(|it| matches!(it, UsdtConsensusItem::WithdrawFeesVote(_))));
    }
```

(Adjust `consensus_proposal`'s call signature to match the trait — it may return `Vec<UsdtConsensusItem>` directly or via a wrapper; mirror an existing `consensus_proposal` test if present.)

- [ ] **Step 5: Run — FAIL** (field/import), then implement Steps 2–3 fully and re-run — PASS.

- [ ] **Step 6: Add the endpoint.** In `api_endpoints`, before the closing `]`:

```rust
            api_endpoint! {
                WITHDRAW_FEES_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Usdt, context, req: WithdrawFeesRequest| -> () {
                    // Guardian-only: casting a fee-withdrawal vote is a
                    // deliberate, authenticated action.
                    check_auth(context)?;
                    if req.amount.0 == 0 {
                        return Err(ApiError::bad_request(
                            "fee-withdrawal amount must be positive".to_string(),
                        ));
                    }
                    *module.fee_withdrawal_intent.lock().expect("not poisoned") =
                        Some(fedimint_usdt_common::WithdrawFeesVote {
                            recipient: req.recipient,
                            amount: req.amount,
                        });
                    Ok(())
                }
            },
```

Add `use fedimint_core::net::auth::check_auth;` and ensure `ApiError` is imported in `lib.rs`.

- [ ] **Step 7: Client method.** In `client/src/api.rs`, add to the `UsdtFederationApi` trait + rely on the blanket impl:

```rust
    async fn withdraw_fees(
        &self,
        recipient: EvmAddress,
        amount: UsdtAmount,
        auth: ApiAuth,
    ) -> FederationResult<()> {
        self.request_admin(
            WITHDRAW_FEES_ENDPOINT,
            ApiRequestErased::new(WithdrawFeesRequest { recipient, amount }),
            auth,
        )
        .await
    }
```

Add imports: `fedimint_core::module::ApiAuth`, `fedimint_api_client::api::FederationApiExt` (for `request_admin`; confirm the exact path), `WITHDRAW_FEES_ENDPOINT`, `WithdrawFeesRequest`, `EvmAddress`, `UsdtAmount`.

- [ ] **Step 8: Build + test.**
```
cargo check -p fedimint-usdt-common -p fedimint-usdt-server -p fedimint-usdt-client -q
cargo test -p fedimint-usdt-server -q consensus_proposal_drains_fee_withdrawal_intent_once
```
Expected: clean / PASS.

- [ ] **Step 9: Commit.**
```bash
git add modules/fedimint-usdt-common modules/fedimint-usdt-server modules/fedimint-usdt-client
git commit -m "feat(usdt): authenticated withdraw_fees endpoint + consensus proposal + client method"
```

---

### Task 8: Solvency audit test, docs, final lint

**Files:**
- Test: `modules/fedimint-usdt-server/src/lib.rs` (audit/solvency test)
- Modify: `docs/usdt-module.md`

**Interfaces:** none new.

- [ ] **Step 1: Solvency invariant test.** Add an end-to-end-ish test asserting `accrued_fees ≤ balance` holds and the audit stays solvent after a mixed sequence: seed fee votes; run a deposit `process_input` (fee accrues on record); confirm a `DeployAndSweep` (credits balance + accrued_fees); run a withdrawal `process_output` + successful confirm (debits balance by amount, credits accrued_fees by max_fee); then a `WithdrawFees` confirm draining part of accrued_fees. After each stage assert:

```rust
        let pool = dbtx.to_ref_nc().get_value(&PoolStateKey).await.unwrap();
        assert!(pool.accrued_fees.0 <= pool.balance.0, "fee revenue never exceeds pool balance");
```

And after the full sequence, call `module.audit(...)` the way existing audit tests do (grep `fn audit`/`Audit::` in tests) and assert the net position is non-negative / unchanged in the expected direction. If wiring a full `audit` call is heavy, at minimum keep the `accrued_fees ≤ balance` assertions at each stage.

- [ ] **Step 2: Run — PASS.**

- [ ] **Step 3: Document the flow.** In `docs/usdt-module.md`, add a "Guardian fee withdrawal" section: what accrues (deposit fees + retained withdrawal fees), the `pool_state` `accrued_fees` field, and how a guardian casts a vote — via the admin API against their OWN node with their guardian password, e.g.:

```
# each guardian, against their own node:
fedimint-cli admin api --peer-id <N> --password <guardian-pw> \
  module_<usdt-module-id>_withdraw_fees \
  '{"recipient":"0x…","amount":<usdt_e6>}'
```

Note the 2f+1 threshold on the identical `(recipient, amount)` pair, that the payout waits behind any in-flight user withdrawal, and that `amount` is capped at `accrued_fees`. Explicitly note the module *client* CLI has no guardian auth, so casting is done through the admin API surface, not `fedimint-cli module usdt`.

- [ ] **Step 4: Full lint + test.**
```
just format
just clippy
just final-lint
cargo test -p fedimint-usdt-server -p fedimint-usdt-common -p fedimint-usdt-client -q
```
Expected: clean.

- [ ] **Step 5: Commit.**
```bash
git add modules/fedimint-usdt-server/src/lib.rs docs/usdt-module.md
git commit -m "test(usdt): fee-withdrawal solvency invariant; docs for guardian flow"
```

---

## Self-review notes (author)

- **Spec coverage:** accounting (Tasks 1–3), vote→threshold→UserOp (Tasks 5–6), auth endpoint + proposal (Task 7), serialization (Task 5 Steps 6–8), read surface (Task 4), version/migration (Task 1), validation (Task 6 Step 4), testing (each task + Task 8). All spec sections map to a task.
- **Deferred-to-implementer, not placeholders:** exact struct-literal fix sites (Task 1 Step 3) and a few test helper reuses (`successful_obs`, `dummy_unsigned_userop`, the audit-call form) are resolved by grepping named existing helpers — the surrounding code is fully specified.
- **Type consistency:** `WithdrawFeesVote { recipient: EvmAddress, amount: UsdtAmount }` used identically in common, db value, consensus item, endpoint intent, and trigger; `UserOpPurpose::WithdrawFees { recipient, amount }` identical in db, in-flight guard, confirm arm, trigger; `apply_fee_withdrawal_confirmed(dbtx, obs, swept)` matches its call site.
