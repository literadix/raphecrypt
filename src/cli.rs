//! Command-line argument definition.

use std::path::{Path, PathBuf};

use clap::Parser;
use zeroize::Zeroize;

/// Parsed command-line options for one invocation of `raphecrypt`.
#[derive(Debug, Parser)]
#[command(
    name = "raphecrypt",
    version,
    about = "Hide or extract Unicode messages inside visible text."
)]
pub struct Cli {
    #[arg(
        short,
        long,
        value_name = "FILE",
        help = "Read visible text from this file"
    )]
    input: Option<PathBuf>,

    #[arg(
        short,
        long,
        value_name = "FILE",
        help = "Write output text to this file"
    )]
    output: Option<PathBuf>,

    // Keep `--encrypt` as a hidden compatibility alias for earlier README/API
    // versions, but present the clearer `--hide` name to new users.
    #[arg(
        short = 'e',
        long = "hide",
        alias = "encrypt",
        value_name = "TEXT",
        conflicts_with_all = ["extract", "scan"],
        help = "Hide this Unicode text inside the visible input"
    )]
    hide: Option<String>,

    // Clap represents `--extract` without a value as `Some("")`, which the
    // application maps to "extract without a password".
    #[arg(
        short = 'd',
        long = "extract",
        alias = "decrypt",
        value_name = "PASSWORD",
        num_args = 0..=1,
        default_missing_value = "",
        conflicts_with = "scan",
        help = "Extract hidden text; optional value is the decryption password"
    )]
    extract: Option<String>,

    #[arg(
        long,
        conflicts_with_all = ["hide", "extract"],
        help = "Scan input for non-visible Unicode characters"
    )]
    scan: bool,

    #[arg(
        short,
        long,
        value_name = "TEXT",
        conflicts_with_all = ["password_file", "password_stdin"],
        help = "Password used to protect or decrypt hidden text"
    )]
    password: Option<String>,

    #[arg(
        long,
        value_name = "FILE",
        conflicts_with_all = ["password", "password_stdin"],
        help = "Read the password from a file"
    )]
    password_file: Option<PathBuf>,

    #[arg(
        long,
        conflicts_with_all = ["password", "password_file"],
        help = "Read the password from standard input"
    )]
    password_stdin: bool,
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

    /// Returns the message requested by `--hide`, if the user supplied one.
    pub fn hide(&self) -> Option<&str> {
        self.hide.as_deref()
    }

    /// Returns the optional value carried by `--extract`.
    ///
    /// The cases are:
    ///
    /// - `None`: extract mode was not requested.
    /// - `Some("")`: extract mode was requested without an inline password.
    /// - `Some(value)`: extract mode was requested with `value` as password.
    pub fn extract(&self) -> Option<&str> {
        self.extract.as_deref()
    }

    /// Returns whether scan mode was requested.
    pub fn scan(&self) -> bool {
        self.scan
    }

    /// Returns the direct password argument, if any.
    pub fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    /// Returns the file to read the password from, if requested.
    pub fn password_file(&self) -> Option<&Path> {
        self.password_file.as_deref()
    }

    /// Returns whether the password should be read from standard input.
    pub fn password_stdin(&self) -> bool {
        self.password_stdin
    }

    /// Returns whether any non-inline password source was provided.
    pub fn password_source_requested(&self) -> bool {
        self.password.is_some() || self.password_file.is_some() || self.password_stdin
    }
}

impl Drop for Cli {
    fn drop(&mut self) {
        if let Some(value) = &mut self.hide {
            value.zeroize();
        }
        if let Some(value) = &mut self.extract {
            value.zeroize();
        }
        if let Some(value) = &mut self.password {
            value.zeroize();
        }
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
    fn parses_hide_without_password() {
        let cli = Cli::try_parse_from(["raphecrypt", "--hide", "hidden"]).unwrap();

        assert_eq!(cli.hide(), Some("hidden"));
        assert_eq!(cli.password(), None);
        assert_eq!(cli.extract(), None);
    }

    #[test]
    fn parses_legacy_encrypt_alias() {
        let cli = Cli::try_parse_from(["raphecrypt", "--encrypt", "hidden"]).unwrap();

        assert_eq!(cli.hide(), Some("hidden"));
    }

    #[test]
    fn parses_hide_with_password() {
        let cli = Cli::try_parse_from(["raphecrypt", "--hide", "hidden", "--password", "mysecret"])
            .unwrap();

        assert_eq!(cli.hide(), Some("hidden"));
        assert_eq!(cli.password(), Some("mysecret"));
    }

    #[test]
    fn parses_extract_without_password_as_empty_value() {
        let cli = Cli::try_parse_from(["raphecrypt", "--extract"]).unwrap();

        assert_eq!(cli.extract(), Some(""));
        assert_eq!(cli.hide(), None);
        assert_eq!(cli.password(), None);
    }

    #[test]
    fn parses_legacy_decrypt_alias() {
        let cli = Cli::try_parse_from(["raphecrypt", "--decrypt"]).unwrap();

        assert_eq!(cli.extract(), Some(""));
    }

    #[test]
    fn parses_extract_with_password() {
        let cli = Cli::try_parse_from(["raphecrypt", "--extract", "mysecret"]).unwrap();

        assert_eq!(cli.extract(), Some("mysecret"));
    }

    #[test]
    fn parses_scan_mode() {
        let cli = Cli::try_parse_from(["raphecrypt", "--scan"]).unwrap();

        assert!(cli.scan());
        assert_eq!(cli.hide(), None);
        assert_eq!(cli.extract(), None);
    }

    #[test]
    fn parses_password_file() {
        let cli = Cli::try_parse_from([
            "raphecrypt",
            "--hide",
            "hidden",
            "--password-file",
            "pass.txt",
        ])
        .unwrap();

        assert_eq!(cli.password_file().unwrap().to_str(), Some("pass.txt"));
        assert!(cli.password_source_requested());
    }

    #[test]
    fn parses_password_stdin() {
        let cli = Cli::try_parse_from([
            "raphecrypt",
            "--input",
            "input.txt",
            "--hide",
            "hidden",
            "--password-stdin",
        ])
        .unwrap();

        assert!(cli.password_stdin());
        assert!(cli.password_source_requested());
    }

    #[test]
    fn rejects_multiple_password_sources() {
        assert!(
            Cli::try_parse_from([
                "raphecrypt",
                "--hide",
                "hidden",
                "--password",
                "mysecret",
                "--password-file",
                "pass.txt"
            ])
            .is_err()
        );
    }

    #[test]
    fn rejects_hide_and_extract_together() {
        assert!(Cli::try_parse_from(["raphecrypt", "--hide", "hidden", "--extract"]).is_err());
    }

    #[test]
    fn rejects_scan_with_hide_or_extract() {
        assert!(Cli::try_parse_from(["raphecrypt", "--scan", "--hide", "hidden"]).is_err());
        assert!(Cli::try_parse_from(["raphecrypt", "--scan", "--extract"]).is_err());
    }
}
