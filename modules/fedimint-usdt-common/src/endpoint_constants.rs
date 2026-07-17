/// Returns the federation's aggregate (group) threshold-ECDSA public key,
/// proving that DKG-produced config has been loaded and is queryable.
pub const GROUP_PUBLIC_KEY_ENDPOINT: &str = "group_public_key";

/// Enqueues this guardian's local deposit-checker task to start watching the
/// deposit address derived for a given claim key, returning that address.
pub const CHECK_DEPOSIT_ENDPOINT: &str = "check_deposit";

/// Reports the credited/claimed/claimable state of a claim key's deposit
/// account.
pub const DEPOSIT_STATUS_ENDPOINT: &str = "deposit_status";
