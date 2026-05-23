//! Text payload creation and extraction.
//!
//! This module owns the stable payload format used by `raphecrypt`.
//!
//! A hidden payload is stored inside visible Unicode text as:
//!
//! ```text
//! visible text + PAYLOAD_START + bit characters + PAYLOAD_END + trailing newline
//! ```
//!
//! The bytes represented by the bit characters start with a four-byte version
//! marker:
//!
//! - `RPH0`: plaintext hidden text bytes follow directly.
//! - `RPH1`: encrypted payload bytes follow as `salt || nonce || ciphertext`.
//!
//! The public API intentionally deals in `String`/`&str` so callers do not need
//! to know about the marker characters, byte layout, or crypto details.

use std::{error::Error, fmt};

use argon2::Argon2;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
};

/// Marker inserted before the hidden bit stream.
const PAYLOAD_START: char = '\u{e0001}';
/// Marker inserted after the hidden bit stream.
const PAYLOAD_END: char = '\u{e007f}';
/// Unicode tag character used to encode a zero bit.
const BIT_ZERO: char = '\u{e0030}';
/// Unicode tag character used to encode a one bit.
const BIT_ONE: char = '\u{e0031}';

/// Payload version for hidden text that is not password-protected.
const PLAINTEXT_PAYLOAD_VERSION: &[u8] = b"RPH0";
/// Payload version for hidden text encrypted before it is embedded.
const ENCRYPTED_PAYLOAD_VERSION: &[u8] = b"RPH1";
/// Argon2 salt length in bytes.
const SALT_LEN: usize = 16;
/// XChaCha20-Poly1305 nonce length in bytes.
const NONCE_LEN: usize = 24;
/// XChaCha20-Poly1305 key length in bytes.
const KEY_LEN: usize = 32;

/// Errors returned while creating, hiding, extracting, or decrypting payloads.
#[derive(Debug)]
pub enum ProcessingError {
    /// The encrypted payload could not be authenticated and decrypted.
    Decryption,
    /// The payload is encrypted, but the caller did not provide a password.
    EncryptedPayloadNeedsPassword,
    /// The marker-delimited payload exists but does not match the expected format.
    InvalidPayload,
    /// The decoded payload bytes are not valid UTF-8 text.
    InvalidUtf8,
    /// Argon2 could not derive an encryption/decryption key.
    KeyDerivation,
    /// No payload start marker was found in the input text.
    MissingPayload,
    /// XChaCha20-Poly1305 could not encrypt the hidden text.
    Encryption,
}

impl fmt::Display for ProcessingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decryption => formatter.write_str("failed to decrypt hidden text"),
            Self::EncryptedPayloadNeedsPassword => {
                formatter.write_str("hidden text is encrypted; provide a decryption password")
            }
            Self::InvalidPayload => formatter.write_str("hidden payload is invalid"),
            Self::InvalidUtf8 => formatter.write_str("hidden payload is not valid UTF-8"),
            Self::KeyDerivation => formatter.write_str("failed to derive encryption key"),
            Self::MissingPayload => formatter.write_str("no hidden payload found"),
            Self::Encryption => formatter.write_str("failed to encrypt hidden text"),
        }
    }
}

impl Error for ProcessingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

/// Hides `hidden_text` inside `input`.
///
/// If `hidden_text` is `None`, the input is returned unchanged. This keeps the
/// default CLI behavior simple: reading and writing text without `--encrypt` is
/// a pass-through operation.
///
/// If `password` is `Some`, the hidden text is encrypted before it is embedded.
/// If `password` is `None`, the hidden text is embedded as plaintext payload
/// bytes. In both cases, the visible part of `input` is preserved.
pub fn process_text(
    input: &str,
    hidden_text: Option<&str>,
    password: Option<&str>,
) -> Result<String, ProcessingError> {
    let Some(hidden_text) = hidden_text else {
        return Ok(input.to_owned());
    };

    let hidden_payload = create_hidden_payload(hidden_text, password)?;

    Ok(hide_payload(input, &hidden_payload))
}

/// Extracts the hidden text from `input`.
///
/// `password` should be:
///
/// - `None` for plaintext payloads created without `--password`.
/// - `Some(value)` for encrypted payloads created with `--password value`.
///
/// The function returns only the recovered hidden message, not the visible
/// carrier text.
pub fn extract_hidden_text(input: &str, password: Option<&str>) -> Result<String, ProcessingError> {
    let payload = extract_payload(input)?;

    if let Some(plaintext) = payload.strip_prefix(PLAINTEXT_PAYLOAD_VERSION) {
        return String::from_utf8(plaintext.to_vec()).map_err(|_| ProcessingError::InvalidUtf8);
    }

    if let Some(encrypted_payload) = payload.strip_prefix(ENCRYPTED_PAYLOAD_VERSION) {
        let password = password.ok_or(ProcessingError::EncryptedPayloadNeedsPassword)?;
        let plaintext = decrypt_hidden_text(encrypted_payload, password)?;

        return String::from_utf8(plaintext).map_err(|_| ProcessingError::InvalidUtf8);
    }

    Err(ProcessingError::InvalidPayload)
}

/// Builds the binary payload that will later be encoded as invisible bits.
///
/// The returned bytes always start with a version marker so extraction can
/// choose the correct decoding path without needing any external metadata.
fn create_hidden_payload(
    hidden_text: &str,
    password: Option<&str>,
) -> Result<Vec<u8>, ProcessingError> {
    match password {
        Some(password) => encrypt_hidden_text(hidden_text, password),
        None => {
            let mut payload =
                Vec::with_capacity(PLAINTEXT_PAYLOAD_VERSION.len() + hidden_text.len());
            payload.extend_from_slice(PLAINTEXT_PAYLOAD_VERSION);
            payload.extend_from_slice(hidden_text.as_bytes());
            Ok(payload)
        }
    }
}

/// Encrypts hidden text and returns the versioned encrypted payload bytes.
///
/// Layout:
///
/// ```text
/// RPH1 || salt || nonce || ciphertext
/// ```
///
/// The salt is stored with the payload because it is required to derive the
/// same key during decryption. The nonce is also stored with the payload; it is
/// not secret, but must be unique for each encryption under a given key.
fn encrypt_hidden_text(hidden_text: &str, password: &str) -> Result<Vec<u8>, ProcessingError> {
    let mut salt = [0_u8; SALT_LEN];
    let mut nonce = [0_u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let mut key = [0_u8; KEY_LEN];
    Argon2::default()
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|_| ProcessingError::KeyDerivation)?;

    let cipher = XChaCha20Poly1305::new(&key.into());
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), hidden_text.as_bytes())
        .map_err(|_| ProcessingError::Encryption)?;

    let mut payload = Vec::with_capacity(
        ENCRYPTED_PAYLOAD_VERSION.len() + salt.len() + nonce.len() + ciphertext.len(),
    );
    payload.extend_from_slice(ENCRYPTED_PAYLOAD_VERSION);
    payload.extend_from_slice(&salt);
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&ciphertext);

    Ok(payload)
}

/// Decrypts the encrypted part of an `RPH1` payload.
///
/// The caller has already stripped the `RPH1` version marker, so `payload`
/// starts at the salt. The function validates that enough bytes exist for salt
/// and nonce before splitting the buffer; the remaining bytes are treated as the
/// authenticated ciphertext.
fn decrypt_hidden_text(payload: &[u8], password: &str) -> Result<Vec<u8>, ProcessingError> {
    let min_payload_len = SALT_LEN + NONCE_LEN;

    if payload.len() < min_payload_len {
        return Err(ProcessingError::InvalidPayload);
    }

    let (salt, rest) = payload.split_at(SALT_LEN);
    let (nonce, ciphertext) = rest.split_at(NONCE_LEN);

    let mut key = [0_u8; KEY_LEN];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|_| ProcessingError::KeyDerivation)?;

    let cipher = XChaCha20Poly1305::new(&key.into());
    cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| ProcessingError::Decryption)
}

/// Finds, validates, and decodes the marker-delimited hidden payload.
///
/// The invisible payload is encoded as one character per bit. Bits are read
/// most-significant first because `hide_payload` writes them in that order.
/// Every eight validated bit characters become one byte in the returned vector.
fn extract_payload(input: &str) -> Result<Vec<u8>, ProcessingError> {
    let start = input
        .find(PAYLOAD_START)
        .ok_or(ProcessingError::MissingPayload)?;
    let payload_start = start + PAYLOAD_START.len_utf8();
    let end = input[payload_start..]
        .find(PAYLOAD_END)
        .map(|end| payload_start + end)
        .ok_or(ProcessingError::InvalidPayload)?;
    let encoded_payload = &input[payload_start..end];
    let bit_count = encoded_payload.chars().count();

    if bit_count % 8 != 0 {
        return Err(ProcessingError::InvalidPayload);
    }

    let mut payload = Vec::with_capacity(bit_count / 8);
    let mut byte = 0_u8;

    for (index, character) in encoded_payload.chars().enumerate() {
        // Shift first so the first character encountered becomes the high bit
        // of the output byte, matching the writer's `(0..8).rev()` order.
        byte <<= 1;
        match character {
            BIT_ZERO => {}
            BIT_ONE => byte |= 1,
            _ => return Err(ProcessingError::InvalidPayload),
        }

        if index % 8 == 7 {
            payload.push(byte);
            byte = 0;
        }
    }

    Ok(payload)
}

/// Embeds payload bytes inside visible text as invisible Unicode characters.
///
/// The visible text is copied unchanged except for one deliberate placement
/// rule: if the input ends with `\n` or `\r\n`, the payload is inserted before
/// that final newline sequence. That keeps command-line output pleasant because
/// a trailing newline remains the final visible output.
fn hide_payload(visible_text: &str, hidden_payload: &[u8]) -> String {
    let mut output = String::with_capacity(visible_text.len() + 2 + hidden_payload.len() * 8);
    let (visible_body, trailing_newline) = split_trailing_newline(visible_text);

    output.push_str(visible_body);
    output.push(PAYLOAD_START);

    for byte in hidden_payload {
        for bit_index in (0..8).rev() {
            let bit = (byte >> bit_index) & 1;
            output.push(if bit == 0 { BIT_ZERO } else { BIT_ONE });
        }
    }

    output.push(PAYLOAD_END);
    output.push_str(trailing_newline);
    output
}

/// Splits off exactly one trailing line ending, if present.
///
/// `\r\n` is checked before `\n` so Windows-style line endings are preserved as
/// a unit instead of being split into a visible trailing `\r` plus `\n`.
fn split_trailing_newline(input: &str) -> (&str, &str) {
    if let Some(body) = input.strip_suffix("\r\n") {
        (body, "\r\n")
    } else if let Some(body) = input.strip_suffix('\n') {
        (body, "\n")
    } else {
        (input, "")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BIT_ONE, BIT_ZERO, ENCRYPTED_PAYLOAD_VERSION, PAYLOAD_END, PAYLOAD_START,
        PLAINTEXT_PAYLOAD_VERSION, ProcessingError, create_hidden_payload, extract_hidden_text,
        process_text,
    };

    #[test]
    fn preserves_unicode_text() {
        let input = "Hello, cryptographer.\nUnicode: café, 東京, 🔐\n";

        assert_eq!(process_text(input, None, None).unwrap(), input);
    }

    #[test]
    fn hides_unicode_text_without_changing_visible_text() {
        let input = "Visible café 東京 🔐\n";
        let output = process_text(input, Some("secret café"), None).unwrap();
        let visible: String = output
            .chars()
            .filter(|character| {
                !matches!(*character, PAYLOAD_START | PAYLOAD_END | BIT_ZERO | BIT_ONE)
            })
            .collect();

        assert_eq!(visible, input);
        assert_ne!(output, input);
    }

    #[test]
    fn encodes_hidden_text_between_invisible_markers() {
        let output = process_text("carrier", Some("A"), None).unwrap();

        assert!(output.starts_with("carrier"));
        assert!(output.contains(PAYLOAD_START));
        assert!(output.ends_with(PAYLOAD_END));
    }

    #[test]
    fn keeps_trailing_newline_at_end_of_output() {
        let output = process_text("Hello\n", Some("hello"), None).unwrap();

        assert!(output.starts_with("Hello"));
        assert!(output.ends_with('\n'));
    }

    #[test]
    fn keeps_trailing_crlf_at_end_of_output() {
        let output = process_text("Hello\r\n", Some("hello"), None).unwrap();

        assert!(output.starts_with("Hello"));
        assert!(output.ends_with("\r\n"));
    }

    #[test]
    fn plaintext_payload_contains_hidden_text_when_password_is_absent() {
        let payload = create_hidden_payload("secret café", None).unwrap();

        assert!(payload.starts_with(PLAINTEXT_PAYLOAD_VERSION));
        assert!(payload.ends_with("secret café".as_bytes()));
    }

    #[test]
    fn encrypted_payload_does_not_contain_hidden_text_when_password_is_present() {
        let payload = create_hidden_payload("secret café", Some("correct horse battery staple"))
            .expect("payload should encrypt");

        assert!(payload.starts_with(ENCRYPTED_PAYLOAD_VERSION));
        assert!(
            !payload
                .windows("secret café".len())
                .any(|window| window == "secret café".as_bytes())
        );
    }

    #[test]
    fn extracts_plaintext_hidden_text_without_password() {
        let output = process_text("Visible text", Some("secret café 東京 🔐"), None).unwrap();

        assert_eq!(
            extract_hidden_text(&output, None).unwrap(),
            "secret café 東京 🔐"
        );
    }

    #[test]
    fn decrypts_hidden_text_with_password() {
        let output = process_text(
            "Visible text",
            Some("secret café 東京 🔐"),
            Some("correct horse battery staple"),
        )
        .unwrap();

        assert_eq!(
            extract_hidden_text(&output, Some("correct horse battery staple")).unwrap(),
            "secret café 東京 🔐"
        );
    }

    #[test]
    fn encrypted_hidden_text_requires_password() {
        let output = process_text(
            "Visible text",
            Some("secret café"),
            Some("correct horse battery staple"),
        )
        .unwrap();

        assert!(matches!(
            extract_hidden_text(&output, None),
            Err(ProcessingError::EncryptedPayloadNeedsPassword)
        ));
    }
}
