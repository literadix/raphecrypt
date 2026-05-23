//! Library API for `raphecrypt`.
//!
//! The binary uses these modules directly, and integration tests can exercise
//! the same parsing and processing code without going through private `main.rs`
//! modules.

pub mod cli;
pub mod processing;
