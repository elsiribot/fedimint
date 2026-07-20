/// Returns the federation's aggregate (group) threshold-ECDSA public key,
/// proving that DKG-produced config has been loaded and is queryable.
pub const GROUP_PUBLIC_KEY_ENDPOINT: &str = "group_public_key";

/// Enqueues this guardian's local deposit-checker task to start watching the
/// deposit address derived for a given claim key, returning that address.
pub const CHECK_DEPOSIT_ENDPOINT: &str = "check_deposit";

/// Reports the credited/claimed/claimable state of a claim key's deposit
/// account.
pub const DEPOSIT_STATUS_ENDPOINT: &str = "deposit_status";

/// Test-only (Phase 6a acceptance): pushes a digest into this guardian's
/// in-memory `pending_signing_starts` queue, to be proposed as a
/// `UsdtConsensusItem::StartSigning` consensus item on the guardian's next
/// `consensus_proposal`. Starting a signing session must go through
/// consensus (rather than being triggered on each guardian independently) so
/// every guardian starts it atomically in the same consensus order; calling
/// this on a single guardian is enough to reach every guardian via the
/// resulting consensus item. Phase-6a scaffolding: intentionally not
/// access-gated (the usdt module is experimental and opt-in via
/// `FM_ENABLE_MODULE_USDT`); Phase 7 replaces it with deterministic session
/// creation from pending sign-request records and removes this endpoint.
pub const DEBUG_START_SIGNING_ENDPOINT: &str = "debug_start_signing";

/// Reports the federation-agreed outcome of a threshold-ECDSA signing
/// session: `Some(compact 64-byte signature)` once a guardian's
/// `UsdtConsensusItem::MpcSignature` proposal has been verified and written
/// to the consensus `SigningSession.state` as `Completed` (Phase 6b), `None`
/// while the session is still in progress. Read from the consensus DB, so
/// ANY guardian — not just a signer — can answer, and every honest
/// guardian's answer is identical once the session has completed.
pub const SIGNING_SESSION_STATUS_ENDPOINT: &str = "signing_session_status";
