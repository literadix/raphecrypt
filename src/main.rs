//! Application entry point.
//!
//! This module keeps process-level concerns separate from the text processing
//! logic:
//!
//! - Parse command-line arguments in `cli`.
//! - Read all input text from a file or standard input.
//! - Choose either hide/encrypt mode or extract/decrypt mode.
//! - Write the resulting text to a file or standard output.
//!
//! All payload encoding, encryption, decryption, and validation lives in
//! `processing`.

mod cli;
mod processing;

use std::{error::Error, fs, io};

use cli::Cli;

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse_args();

    let input = read_input(cli.input())?;

    // `--decrypt` is represented as `Some("")` when the flag is present
    // without a password. Convert that empty marker to `None` before passing
    // it into the processing layer so the processing API can model optional
    // passwords in the usual Rust shape.
    let output = match cli.decrypt() {
        Some(password) => processing::extract_hidden_text(&input, non_empty(password))?,
        None => processing::process_text(&input, cli.encrypt(), cli.password())?,
    };
    write_output(cli.output(), &output)?;

    Ok(())
}

/// Converts clap's empty-string marker for optional values into `None`.
fn non_empty(value: &str) -> Option<&str> {
    if value.is_empty() { None } else { Some(value) }
}

/// Reads the complete visible/carrier text from the selected input source.
///
/// The program operates on full Unicode strings instead of streaming chunks
/// because payload markers can appear anywhere in the text and extraction needs
/// to find the complete marker-delimited payload.
fn read_input(path: Option<&std::path::Path>) -> io::Result<String> {
    match path {
        Some(path) => fs::read_to_string(path),
        None => {
            let mut input = String::new();
            io::Read::read_to_string(&mut io::stdin(), &mut input)?;
            Ok(input)
        }
    }
}

/// Writes the complete processed text to the selected output sink.
fn write_output(path: Option<&std::path::Path>, output: &str) -> io::Result<()> {
    match path {
        Some(path) => fs::write(path, output),
        None => {
            io::Write::write_all(&mut io::stdout(), output.as_bytes())?;
            Ok(())
        }
    }
}
