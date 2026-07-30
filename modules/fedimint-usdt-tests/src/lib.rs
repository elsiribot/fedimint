//! Library surface of the `fedimint-usdt-tests` crate.
//!
//! Historically this crate was `bin`s + integration `tests` only; the library
//! exists solely to share the ADVERSARIAL attack-construction functions
//! ([`attacks`]) between the hermetic security integration tests
//! (`tests/adversary.rs`) and the live-federation security binary
//! (`bin/usdt_adversary.rs`). A `tests/common/` module cannot be imported by a
//! `bin/` target, so anything both must use lives here instead.
//!
//! This crate is `publish = false` and never WASM-shipped; the attack builders
//! are a security-testing tool, deliberately NOT part of any guardian/gateway
//! image.

pub mod attacks;
