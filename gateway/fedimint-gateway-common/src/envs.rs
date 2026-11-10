/// Environment variable that specifies the URL to connect to LND. Necessary for
/// LND configuration.
pub const FM_LND_RPC_ADDR_ENV: &str = "FM_LND_RPC_ADDR";

/// Environment variable that specifies the location of LND's TLS certificate.
/// Necessary for LND configuration.
pub const FM_LND_TLS_CERT_ENV: &str = "FM_LND_TLS_CERT";

/// Environment variable that specifies the location of LND's macaroon.
/// Necessary for LND configuration.
pub const FM_LND_MACAROON_ENV: &str = "FM_LND_MACAROON";

/// Environment variable the specifies the port that the LDK Node should use.
/// Necessary for LDK configuration.
pub const FM_PORT_LDK: &str = "FM_PORT_LDK";

/// The alias for the LDK Node
pub const FM_LDK_ALIAS_ENV: &str = "FM_LDK_ALIAS";

/// Comma-separated node public keys of peers the LDK Node adds route hints for
/// to every invoice, through the two usable channels to them with the most
/// inbound capacity.
pub const FM_LDK_ROUTE_HINT_PEERS_ENV: &str = "FM_LDK_ROUTE_HINT_PEERS";

/// Comma-separated addresses (`<ip>:<port>` or `<host>:<port>`) the LDK Node
/// announces to the network, so peers can reach it. Without them it announces
/// its listening address, `0.0.0.0`.
pub const FM_LDK_ANNOUNCE_ADDRESSES_ENV: &str = "FM_LDK_ANNOUNCE_ADDRESSES";

/// Comma-separated node public keys the LDK Node probes in the background, so
/// its scorer knows which paths towards them have liquidity before a payment
/// needs one.
pub const FM_LDK_PROBE_TARGETS_ENV: &str = "FM_LDK_PROBE_TARGETS";

/// How many of the destinations the LDK Node paid most often in the last 30
/// days it probes in addition to `FM_LDK_PROBE_TARGETS`. Unset follows none.
pub const FM_LDK_PROBE_RECENT_DESTINATIONS_ENV: &str = "FM_LDK_PROBE_RECENT_DESTINATIONS";

/// How many routes one probe attempt of the LDK Node tries before it gives up
/// on a target and amount: after a failed route it re-routes around what
/// failed, like a payment's retry would. Unset tries 3.
pub const FM_LDK_PROBE_MAX_ROUTES_ENV: &str = "FM_LDK_PROBE_MAX_ROUTES";

// The LDK Node's scorer: how fast it forgets what probes and payments taught
// it, and how much an uncertain channel costs next to its fees. Each unset
// variable keeps LDK's default; see LDK's `ProbabilisticScoringDecayParameters`
// and `ProbabilisticScoringFeeParameters` for what each one does.

/// Half-life of the liquidity bounds learned from one probe or payment, in
/// seconds (LDK default: 1800).
pub const FM_LDK_SCORER_LIQUIDITY_OFFSET_HALF_LIFE_SECS_ENV: &str =
    "FM_LDK_SCORER_LIQUIDITY_OFFSET_HALF_LIFE_SECS";
/// Half-life of a channel's liquidity history once nothing updates it, in
/// seconds (LDK default: 14 days).
pub const FM_LDK_SCORER_HISTORICAL_NO_UPDATES_HALF_LIFE_SECS_ENV: &str =
    "FM_LDK_SCORER_HISTORICAL_NO_UPDATES_HALF_LIFE_SECS";
/// Fixed penalty per hop, msat (LDK default: 1024).
pub const FM_LDK_SCORER_BASE_PENALTY_MSAT_ENV: &str = "FM_LDK_SCORER_BASE_PENALTY_MSAT";
/// Per-hop penalty per 2^30 msat sent (LDK default: 131072).
pub const FM_LDK_SCORER_BASE_PENALTY_AMOUNT_MULTIPLIER_MSAT_ENV: &str =
    "FM_LDK_SCORER_BASE_PENALTY_AMOUNT_MULTIPLIER_MSAT";
/// Penalty per -log10 of the success probability from the latest liquidity
/// bounds, msat (LDK default: 0, i.e. off).
pub const FM_LDK_SCORER_LIQUIDITY_PENALTY_MULTIPLIER_MSAT_ENV: &str =
    "FM_LDK_SCORER_LIQUIDITY_PENALTY_MULTIPLIER_MSAT";
/// Same, per 2^20 msat sent (LDK default: 0, i.e. off).
pub const FM_LDK_SCORER_LIQUIDITY_PENALTY_AMOUNT_MULTIPLIER_MSAT_ENV: &str =
    "FM_LDK_SCORER_LIQUIDITY_PENALTY_AMOUNT_MULTIPLIER_MSAT";
/// Penalty per -log10 of the success probability from the liquidity history,
/// msat (LDK default: 10000).
pub const FM_LDK_SCORER_HISTORICAL_LIQUIDITY_PENALTY_MULTIPLIER_MSAT_ENV: &str =
    "FM_LDK_SCORER_HISTORICAL_LIQUIDITY_PENALTY_MULTIPLIER_MSAT";
/// Same, per 2^20 msat sent (LDK default: 1250).
pub const FM_LDK_SCORER_HISTORICAL_LIQUIDITY_PENALTY_AMOUNT_MULTIPLIER_MSAT_ENV: &str =
    "FM_LDK_SCORER_HISTORICAL_LIQUIDITY_PENALTY_AMOUNT_MULTIPLIER_MSAT";

/// Environment variable for overriding the iroh secret key
pub const FM_GATEWAY_IROH_SECRET_KEY_OVERRIDE_ENV: &str = "FM_GATEWAY_IROH_SECRET_KEY_OVERRIDE";

/// Environment variable that specifies the `time_pref` used in LND
/// `SendPaymentRequest`. Must parse as an f64 in the range [-1.0, 1.0], where
/// -1 optimizes for fees and 1 optimizes for reliability.
pub const FM_LND_TIME_PREF_ENV: &str = "FM_LND_TIME_PREF";

/// Environment variable that specifies how long (in seconds) LND will keep
/// trying to route an outgoing payment before giving up. Passed as
/// `timeout_seconds` in LND `SendPaymentRequest`. Must parse as an i32 in the
/// range [1, 600].
pub const FM_LND_PAYMENT_TIMEOUT_SECS_ENV: &str = "FM_LND_PAYMENT_TIMEOUT_SECS";
