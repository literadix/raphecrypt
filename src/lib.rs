//! Library API for `raphecrypt`.
//!
//! The binary uses these modules directly, and integration tests can exercise
//! the same parsing and processing code without going through private `main.rs`
//! modules.

pub mod processing;
pub mod scan;

#[cfg(not(target_arch = "wasm32"))]
pub mod cli;

#[cfg(target_arch = "wasm32")]
pub mod wasm;
