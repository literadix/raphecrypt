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

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::Cli;

    #[test]
    fn parses_input_and_output_paths() {
        let cli = Cli::try_parse_from([
            "raphecrypt",
            "--input",
            "input.txt",
            "--output",
            "output.txt",
        ])
        .unwrap();

        assert_eq!(cli.input().unwrap().to_str(), Some("input.txt"));
        assert_eq!(cli.output().unwrap().to_str(), Some("output.txt"));
    }

    #[test]
    fn parses_encrypt_without_password() {
        let cli = Cli::try_parse_from(["raphecrypt", "--encrypt", "hidden"]).unwrap();

        assert_eq!(cli.encrypt(), Some("hidden"));
        assert_eq!(cli.password(), None);
        assert_eq!(cli.decrypt(), None);
    }

    #[test]
    fn parses_encrypt_with_password() {
        let cli = Cli::try_parse_from([
            "raphecrypt",
            "--encrypt",
            "hidden",
            "--password",
            "mysecret",
        ])
        .unwrap();

        assert_eq!(cli.encrypt(), Some("hidden"));
        assert_eq!(cli.password(), Some("mysecret"));
    }

    #[test]
    fn parses_decrypt_without_password_as_empty_value() {
        let cli = Cli::try_parse_from(["raphecrypt", "--decrypt"]).unwrap();

        assert_eq!(cli.decrypt(), Some(""));
        assert_eq!(cli.encrypt(), None);
        assert_eq!(cli.password(), None);
    }

    #[test]
    fn parses_decrypt_with_password() {
        let cli = Cli::try_parse_from(["raphecrypt", "--decrypt", "mysecret"]).unwrap();

        assert_eq!(cli.decrypt(), Some("mysecret"));
    }

    #[test]
    fn rejects_password_without_encrypt() {
        assert!(Cli::try_parse_from(["raphecrypt", "--password", "mysecret"]).is_err());
    }

    #[test]
    fn rejects_encrypt_and_decrypt_together() {
        assert!(Cli::try_parse_from(["raphecrypt", "--encrypt", "hidden", "--decrypt"]).is_err());
    }
}
