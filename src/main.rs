//! Application entry point.

use std::{
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
};

use raphecrypt::{cli::Cli, processing};
use zeroize::Zeroizing;

fn main() {
    if let Err(error) = run() {
        eprintln!("raphecrypt: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), AppError> {
    let cli = Cli::parse_args();

    validate_password_usage(&cli)?;

    let input = read_input(cli.input())?;
    let password = resolve_password(&cli)?;

    // `--extract` is represented as `Some("")` when the flag is present
    // without a password. Convert that empty marker to `None` before passing
    // it into the processing layer so the processing API can model optional
    // passwords in the usual Rust shape.
    let output = match cli.extract() {
        Some(inline_password) => {
            let password =
                non_empty(inline_password).or_else(|| password.as_ref().map(|p| p.as_str()));
            processing::extract_hidden_text(&input, password)?
        }
        None => {
            processing::process_text(&input, cli.hide(), password.as_ref().map(|p| p.as_str()))?
        }
    };
    write_output(cli.output(), &output)?;

    Ok(())
}

#[derive(Debug)]
enum AppError {
    InlineAndExternalPassword,
    PasswordStdinNeedsInput,
    PasswordWithoutMode,
    ReadInput {
        path: Option<PathBuf>,
        source: io::Error,
    },
    ReadPasswordFile {
        path: PathBuf,
        source: io::Error,
    },
    ReadPasswordStdin {
        source: io::Error,
    },
    WriteOutput {
        path: Option<PathBuf>,
        source: io::Error,
    },
    Processing(processing::ProcessingError),
}

impl fmt::Display for AppError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InlineAndExternalPassword => formatter.write_str(
                "provide the extraction password either as --extract <PASSWORD> or with one password source, not both",
            ),
            Self::PasswordStdinNeedsInput => formatter.write_str(
                "--password-stdin requires --input so standard input is not used for both text and password",
            ),
            Self::PasswordWithoutMode => formatter.write_str(
                "a password source requires --hide or --extract",
            ),
            Self::ReadInput { path: Some(path), .. } => {
                write!(formatter, "failed to read input file {}", path.display())
            }
            Self::ReadInput { path: None, .. } => {
                formatter.write_str("failed to read text from standard input")
            }
            Self::ReadPasswordFile { path, .. } => {
                write!(formatter, "failed to read password file {}", path.display())
            }
            Self::ReadPasswordStdin { .. } => {
                formatter.write_str("failed to read password from standard input")
            }
            Self::WriteOutput { path: Some(path), .. } => {
                write!(formatter, "failed to write output file {}", path.display())
            }
            Self::WriteOutput { path: None, .. } => {
                formatter.write_str("failed to write text to standard output")
            }
            Self::Processing(error) => write!(formatter, "{error}"),
        }
    }
}

impl Error for AppError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ReadInput { source, .. }
            | Self::ReadPasswordFile { source, .. }
            | Self::ReadPasswordStdin { source }
            | Self::WriteOutput { source, .. } => Some(source),
            Self::Processing(error) => Some(error),
            Self::InlineAndExternalPassword
            | Self::PasswordStdinNeedsInput
            | Self::PasswordWithoutMode => None,
        }
    }
}

impl From<processing::ProcessingError> for AppError {
    fn from(error: processing::ProcessingError) -> Self {
        Self::Processing(error)
    }
}

fn validate_password_usage(cli: &Cli) -> Result<(), AppError> {
    let mode_selected = cli.hide().is_some() || cli.extract().is_some();

    if cli.password_source_requested() && !mode_selected {
        return Err(AppError::PasswordWithoutMode);
    }

    if cli.password_stdin() && cli.input().is_none() {
        return Err(AppError::PasswordStdinNeedsInput);
    }

    if cli.extract().and_then(non_empty).is_some() && cli.password_source_requested() {
        return Err(AppError::InlineAndExternalPassword);
    }

    Ok(())
}

fn resolve_password(cli: &Cli) -> Result<Option<Zeroizing<String>>, AppError> {
    if let Some(password) = cli.password() {
        return Ok(Some(Zeroizing::new(password.to_owned())));
    }

    if let Some(path) = cli.password_file() {
        let mut password =
            fs::read_to_string(path).map_err(|source| AppError::ReadPasswordFile {
                path: path.to_path_buf(),
                source,
            })?;
        strip_one_trailing_newline(&mut password);
        return Ok(Some(Zeroizing::new(password)));
    }

    if cli.password_stdin() {
        let mut password = String::new();
        io::Read::read_to_string(&mut io::stdin(), &mut password)
            .map_err(|source| AppError::ReadPasswordStdin { source })?;
        strip_one_trailing_newline(&mut password);
        return Ok(Some(Zeroizing::new(password)));
    }

    Ok(None)
}

/// Converts clap's empty-string marker for optional values into `None`.
fn non_empty(value: &str) -> Option<&str> {
    if value.is_empty() { None } else { Some(value) }
}

fn strip_one_trailing_newline(value: &mut String) {
    if value.ends_with("\r\n") {
        value.truncate(value.len() - 2);
    } else if value.ends_with('\n') {
        value.truncate(value.len() - 1);
    }
}

/// Reads the complete visible/carrier text from the selected input source.
///
/// The program operates on full Unicode strings instead of streaming chunks
/// because payload markers can appear anywhere in the text and extraction needs
/// to find the complete marker-delimited payload.
fn read_input(path: Option<&Path>) -> Result<String, AppError> {
    match path {
        Some(path) => fs::read_to_string(path).map_err(|source| AppError::ReadInput {
            path: Some(path.to_path_buf()),
            source,
        }),
        None => {
            let mut input = String::new();
            io::Read::read_to_string(&mut io::stdin(), &mut input)
                .map_err(|source| AppError::ReadInput { path: None, source })?;
            Ok(input)
        }
    }
}

/// Writes the complete processed text to the selected output sink.
fn write_output(path: Option<&Path>, output: &str) -> Result<(), AppError> {
    match path {
        Some(path) => fs::write(path, output).map_err(|source| AppError::WriteOutput {
            path: Some(path.to_path_buf()),
            source,
        }),
        None => {
            io::Write::write_all(&mut io::stdout(), output.as_bytes())
                .map_err(|source| AppError::WriteOutput { path: None, source })?;
            Ok(())
        }
    }
}
