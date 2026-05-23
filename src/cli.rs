//! Command-line argument definition.
//!
//! The `Cli` type is intentionally a thin clap wrapper. It owns parsed values,
//! while accessor methods expose borrowed views so the rest of the application
//! does not need to clone user input such as passwords or hidden messages.

use std::path::{Path, PathBuf};

use clap::Parser;

/// Parsed command-line options for one invocation of `raphecrypt`.
#[derive(Debug, Parser)]
#[command(
    name = "raphecrypt",
    version,
    about = "Reads Unicode text, processes it, and writes Unicode text."
)]
pub struct Cli {
    /// Input file. Reads from standard input when omitted.
    #[arg(short, long, value_name = "FILE")]
    input: Option<PathBuf>,

    /// Output file. Writes to standard output when omitted.
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Unicode text to hide invisibly in the output.
    ///
    /// Encryption/hiding and decryption/extraction are separate operating
    /// modes, so clap rejects invocations that provide both.
    #[arg(short, long, value_name = "TEXT", conflicts_with = "decrypt")]
    encrypt: Option<String>,

    /// Extract hidden text. Provide a value to use it as the decryption password.
    ///
    /// `num_args = 0..=1` makes the password value optional:
    ///
    /// - `--decrypt` means "extract without a password".
    /// - `--decrypt mysecret` means "decrypt with this password".
    ///
    /// `default_missing_value = ""` lets the application distinguish between
    /// the flag being absent (`None`) and present without a password (`Some("")`).
    #[arg(short, long, value_name = "PASSWORD", num_args = 0..=1, default_missing_value = "")]
    decrypt: Option<String>,

    /// Password used to encrypt the hidden text before hiding it.
    ///
    /// This option only makes sense when text is being hidden, so clap requires
    /// `--encrypt` whenever `--password` is supplied.
    #[arg(short, long, value_name = "TEXT", requires = "encrypt")]
    password: Option<String>,
}

impl Cli {
    /// Parses arguments from the current process environment.
    pub fn parse_args() -> Self {
        Self::parse()
    }

    /// Returns the input path, or `None` when standard input should be used.
    pub fn input(&self) -> Option<&Path> {
        self.input.as_deref()
    }

    /// Returns the output path, or `None` when standard output should be used.
    pub fn output(&self) -> Option<&Path> {
        self.output.as_deref()
    }

    /// Returns the message requested by `--encrypt`, if the user supplied one.
    pub fn encrypt(&self) -> Option<&str> {
        self.encrypt.as_deref()
    }

    /// Returns the optional value carried by `--decrypt`.
    ///
    /// The cases are:
    ///
    /// - `None`: decrypt mode was not requested.
    /// - `Some("")`: decrypt mode was requested without a password.
    /// - `Some(value)`: decrypt mode was requested with `value` as password.
    pub fn decrypt(&self) -> Option<&str> {
        self.decrypt.as_deref()
    }

    /// Returns the password used to encrypt newly hidden text, if any.
    pub fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }
}
