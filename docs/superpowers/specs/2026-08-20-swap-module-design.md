# Atomic Swap Module — Design

**Date:** 2026-08-20
**Module:** `fedimint-swap-*` (new)
**Status:** Approved design; implementation plan to follow.

## Problem

A single federation can custody value in more than one `AmountUnit` — Bitcoin
e-cash and USDT-denominated e-cash already coexist on the demo feds, and the
mint issues notes tagged per unit. But there is **no way to exchange one unit
for another inside the federation.** A holder of USDT e-cash who wants Bitcoin
e-cash (or vice versa) has to exit to an external venue and re-enter — losing
the privacy, speed, and custody model the federation otherwise provides.

## Goal

A module that lets one party (the **maker**) lock a fixed amount of unit A and
publish the exact amount of unit B they want for it, and lets another party (the
**taker**) fill that offer — after which each party withdraws the other's locked
leg as fresh e-cash. The exchange must be **atomic**: either both legs settle or
neither does, with no window in which one party can walk away with both.

The module is **unit-agnostic**: it swaps any `AmountUnit` for any other. It does
not hardcode BTC or USDT.

## Non-goals

- **Partial fills.** An offer is all-or-nothing: one taker fills the whole thing
  or nobody does. No pro-rata fills, no price-as-ratio, no rounding.
- **Order-book matching.** No consensus-side matching engine, no price-time
  priority, no automatic bid/ask crossing. Offers are discovered and filled
  explicitly. A matching engine is a possible separate future project.
- **Cross-federation / trustless swaps.** This swaps two units *within one
  federation*. It is not an on-chain HTLC or submarine swap across trust
  domains (see Trust model).
- **Fees.** v1 charges no swap fee (see Fees).
- **Privacy of offers.** Offer terms are visible in consensus state by
  construction (see Privacy).

## Trust model — escrow, not a trustless swap

Fedimint's transaction balance equation is enforced **per unit**:
`TransactionItemAmounts` carries an `Amounts` map
(`BTreeMap<AmountUnit, Amount>`), and inputs must equal outputs *within each
unit*. A single transaction therefore **cannot** express "100 USDT → 0.002 BTC":
the two legs live in different unit-spaces and there is no exchange rate in the
balance equation — only par, per unit.

So a swap cannot be one balanced transaction. The module instead **holds custody
of both legs** and settles them across separate transactions. This is *not* a
cryptographic cross-chain atomic swap; it is an **on-consensus escrow**. The
atomicity guarantee comes from **consensus serialization**, not from an on-chain
timelock:

- A `Fill` and a `Reclaim` on the same offer cannot both succeed — consensus
  orders them, the first flips the offer's state, and the second fails its state
  check with its funds untouched.
- Once an offer is `Filled`, both legs are locked in module state and each
  party's withdrawal is independently guaranteed.

The trust assumption is **exactly the one holders already accept**: the
guardians custody the e-cash. The swap adds no new trust — it makes the
federation's own ledger swap two units atomically by ordering, the same way the
mint already trusts guardians to honor a note.

## Architecture

Standard three-crate module pattern, modeled on the mint module:

- `fedimint-swap-common` — `SwapInput`, `SwapOutput`, errors, config, the
  `Offer` type, endpoint constants.
- `fedimint-swap-server` — consensus logic: `process_input`, `process_output`,
  the consensus-timestamp clock, offer state, endpoints.
- `fedimint-swap-client` — maker and taker state machines, `list_open_offers`,
  offer construction helpers.
- `fedimint-swap-tests` — integration tests.

## State — one `Offer` record per offer

Keyed by the `OutPoint` of the `MakeOffer` output that created it: unique and
deterministic, so there are no maker-chosen IDs to collide or squat.

```rust
struct Offer {
    maker_pk: PublicKey,        // authorizes claiming the taker's leg AND reclaiming the maker's leg
    maker_unit: AmountUnit,     // the leg the maker locks
    maker_amount: Amount,
    taker_unit: AmountUnit,     // what the maker wants — the leg the taker locks
    taker_amount: Amount,
    expiry: u64,                // consensus-timestamp seconds; backstop deadline
    state: OfferState,          // Open | Filled { taker_pk }
    maker_claimed: bool,        // the maker has withdrawn the TAKER's leg
    taker_claimed: bool,        // the taker has withdrawn the MAKER's leg
}

enum OfferState {
    Open,
    Filled { taker_pk: PublicKey },
}
```

**Naming convention (load-bearing):** each leg is named by *who deposits it*
(`maker_*` / `taker_*`), and the `*_claimed` flags are named by *who claims* —
because each party withdraws the **other's** leg, so `maker_claimed` = "the maker
has taken what they came for," which is the `taker` leg. Keeping the crossover in
one place (the naming) avoids it leaking into every call site.

An offer whose both `*_claimed` flags are set (or that was `Reclaim`ed) is fully
settled and can be garbage-collected.

## Transaction operations

Four operations, each a module `Input` or `Output`. An **Input** provides
funding *into* a transaction (value the module releases from escrow); an
**Output** consumes funding *out of* a transaction (value the module takes into
escrow). Each pairs with a mint input/output for the corresponding unit, so
every transaction balances at par **within a single unit** — the cross-unit
relationship lives entirely in `Offer` state, never in the balance equation.

### `SwapOutput`

```rust
enum SwapOutput {
    MakeOffer {
        maker_unit: AmountUnit,
        maker_amount: Amount,
        taker_unit: AmountUnit,
        taker_amount: Amount,
        expiry: u64,
        maker_pk: PublicKey,
    },
    Fill {
        offer_id: OutPoint,
        taker_pk: PublicKey,
    },
}
```

- **Make.** Paired with a mint input spending `maker_amount` of `maker_unit`.
  `process_output` returns `amounts = {maker_unit: maker_amount}` (so the tx
  balances in `maker_unit`), validates the offer parameters (both amounts
  non-zero, `maker_unit != taker_unit`, `expiry` strictly in the future per the
  consensus clock), and writes a new `Open` offer keyed by this output's
  `OutPoint`.
- **Fill.** Paired with a mint input spending `taker_amount` of `taker_unit`.
  `process_output` returns `amounts = {taker_unit: taker_amount}`, requires the
  referenced offer to be `Open` **and not past `expiry`**; on success flips it to
  `Filled { taker_pk }`. If the offer is missing, already filled, or expired, the
  output errors and the **whole transaction is rejected** — the taker's e-cash is
  never spent (it was only ever an input to a rejected tx).

### `SwapInput`

The `Claim` input must carry an explicit `party` discriminant. `process_input`
does not see the transaction signature — it **produces** the `pub_key` that core
then verifies the signature against (the USDT `Claim` model: "there is no extra
signature inside the input"). So the server must decide *which* key to demand
before any signature check, and cannot infer maker-vs-taker from who signed.

```rust
enum SwapInput {
    Claim { offer_id: OutPoint, party: Party },
    Reclaim { offer_id: OutPoint },
}

enum Party { Maker, Taker }
```

- **Claim** (`party = Maker`). Paired with a mint output re-issuing e-cash.
  Requires the offer `Filled` and `!maker_claimed`. Returns
  `InputMeta { amounts: {taker_unit: taker_amount}, fees: 0, pub_key: maker_pk }`
  and sets `maker_claimed`. The maker withdraws the **taker's** leg.
- **Claim** (`party = Taker`). Requires `Filled` and `!taker_claimed`. Returns
  `amounts = {maker_unit: maker_amount}`, `pub_key = taker_pk`, sets
  `taker_claimed`. The taker withdraws the **maker's** leg.
- **Reclaim.** Requires the offer `Open` (covers both a voluntary cancel and a
  post-`expiry` reclaim — both are only meaningful while unfilled). Returns
  `amounts = {maker_unit: maker_amount}`, `pub_key = maker_pk`, and deletes the
  offer. Always `maker_pk`, so it needs no `party`.

**Misuse resistance.** A taker submitting `Claim { party: Maker }` merely causes
`maker_pk` to be demanded; their signature fails and nothing moves — they cannot
steal the other leg. Each leg is claimable **exactly once** via the `*_claimed`
flags, mirroring USDT's single-claim refund records.

**Open representation choice (for the implementation plan):** `Claim { offer_id,
party }` versus two variants `ClaimMakerLeg` / `ClaimTakerLeg`. Both carry the
same information; the two-variant form makes the match exhaustive at every call
site (the "enums over discriminant fields" reflex) at the cost of a little
duplication. Decide during implementation; the wire content is identical.

## Expiry — the consensus-timestamp clock

Consensus has no inherent wall clock, and the module must not depend on any
specific chain module (it is unit-agnostic). It reuses the **peer-proposed
median** pattern already proven in this codebase (the USDT block-count consensus
and the LN block-height consensus):

- Each guardian periodically proposes its local `now()` as a `SwapConsensusItem`.
- The module stores the **median** of the latest per-peer proposals as a
  monotonic consensus timestamp (never allowed to move backward).
- `expiry` on an offer is wall-clock seconds compared against that timestamp.

This is Byzantine-tolerant (median of `3f+1`), generic (no chain dependency), and
operator-legible ("offers expire after 1 hour"). `MakeOffer` requires `expiry`
strictly in the future; `Fill` requires the current consensus timestamp `<
expiry`.

**Rejected alternative — session count.** Denominating `expiry` in the existing
consensus session counter needs no new consensus item, but it is not wall-clock,
drifts with consensus activity, and reads oddly to users. The median-timestamp
clock is preferred despite the extra consensus item, and matches a pattern the
team already operates.

## Consensus, atomicity, and edge cases

- **Fill vs. Reclaim race.** Both target an `Open` offer. Consensus serializes
  them: whichever is ordered first transitions the offer; the second fails its
  state precondition and is rejected with funds untouched. No double-spend, no
  fund loss — a taker only ever risks their fill being rejected, exactly like a
  maker pulling a limit order before it is hit.
- **Two takers race for one offer.** First `Fill` wins (offer → `Filled`); the
  second sees `Filled` and is rejected before its `taker_amount` is spent.
- **Double claim.** Guarded by `maker_claimed` / `taker_claimed`; a second claim
  of the same leg finds the flag set and errors.
- **Settlement is unconditional once `Filled`.** Both legs are in escrow; neither
  party's claim depends on the other acting. There is no state in which one party
  holds both legs.
- **Cancellation only applies to `Open`.** A `Filled` offer can never be
  cancelled or reclaimed by either party — the legs belong to the counterparties.

## Fees

v1 charges **no swap fee**. Every leg moves value 1:1 within a single unit, so
there is no fee arithmetic to get wrong and no solvency invariant to maintain. A
flat maker/taker fee accruing to a fee pool (as in the USDT module) can be added
later behind config, as a new `SwapOutput`/`SwapInput` version, without a
wire-breaking change to `V0`.

## Privacy

Unlike an e-cash spend, an offer and its fill are **visible in consensus state**:
guardians observe the units, amounts, expiry, and timing of every offer. Parties
are pseudonymous (keys are fresh per offer), but the swap itself is not private
the way a blind-signed reissuance is. Withdrawal re-blinds the proceeds back into
ordinary e-cash. This is inherent to on-consensus escrow and is documented as a
known property, not a defect.

## Client

- **Maker state machine.** Submit `MakeOffer` → watch the offer; on `Filled`,
  submit `Claim { party: Maker }` to withdraw the taker's leg; on cancel or after
  `expiry` while still `Open`, submit `Reclaim` to recover the locked leg. Both
  paths derive `maker_pk` deterministically from the client seed.
- **Taker state machine.** Submit `Fill`; on acceptance, submit `Claim { party:
  Taker }` to withdraw the maker's leg; on rejection, no funds were ever spent, so
  the SM terminates cleanly.
- **Discovery.** A `list_open_offers` endpoint returns the `Open` offers from
  consensus state — a rudimentary public order board takers browse before
  filling. (No matching; the taker chooses.)
- **Terminal states.** Every SM has an explicit terminal state (`Settled`,
  `Reclaimed`, `FillRejected`) so a crash/restart is resumable and no SM sits in
  a transient state indefinitely.

## Testing

- Unit tests for `process_input` / `process_output`: make, fill, both claims,
  reclaim, and every rejection (fill-not-open, fill-expired, wrong-`party` claim,
  double claim, reclaim-after-fill).
- The Fill-vs-Reclaim and two-taker races, asserted order-independent under the
  test harness's parallelism.
- A solvency invariant test: escrow released never exceeds escrow locked, per
  unit, across an arbitrary interleaving of operations.
- Consensus-timestamp monotonicity: median never moves backward across proposals.
- DB migration snapshot test scaffolding from the first release (the module ships
  at DB v0; future versions add migrations).

## Rollout

This is a **new module**, not an additive upgrade to an existing one. Unlike the
USDT v6/v7 deploys (which only bumped a running module's consensus version and
ran an additive DB migration), introducing `fedimint-swap` means a **config /
consensus change registering a new module instance across all guardians**. On the
demo feds this is a heavier lift — every guardian must run the new binary and
agree the module into the federation's configuration. Sequencing and DKG/config
implications are deferred to the implementation plan.
