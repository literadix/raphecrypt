# raphecrypt

`raphecrypt` is a command-line utility for carrying hidden Unicode messages inside ordinary visible text.

It can hide a message in visible text, optionally protect that hidden message with a password, and extract the hidden message again later. Without a password, the message is hidden but not password-protected.

## Quick Start

Hide a message:

```sh
printf 'Visible text\n' | raphecrypt --hide 'hidden café 東京 🔐' > output.txt
```

Extract a message that was hidden without a password:

```sh
raphecrypt --input output.txt --extract
```

Hide a message with password protection:

```sh
printf 'Visible text\n' | raphecrypt --hide 'hidden café 東京 🔐' --password 'mysecret' > output.txt
```

Extract and decrypt a password-protected message:

```sh
raphecrypt --input output.txt --extract 'mysecret'
```

## Usage

```sh
raphecrypt [OPTIONS]
```

Options:

```text
-i, --input <FILE>              Read visible text from this file
-o, --output <FILE>             Write output text to this file
-e, --hide <TEXT>               Hide this Unicode text inside the visible input
-d, --extract [PASSWORD]        Extract hidden text; optional value is the decryption password
-p, --password <TEXT>           Password used to protect or decrypt hidden text
    --password-file <FILE>      Read the password from a file
    --password-stdin            Read the password from standard input
-h, --help                      Print help
-V, --version                   Print version
```

`--encrypt` remains available as an alias for `--hide`, and `--decrypt` remains available as an alias for `--extract`.

## Examples

Read from a file and write to a file:

```sh
raphecrypt --input input.txt --output output.txt
```

Read from standard input and write to standard output:

```sh
printf 'café 東京 🔐\n' | raphecrypt
```

Hide Unicode text while leaving the visible text readable:

```sh
printf 'Visible text\n' | raphecrypt --hide 'hidden café 東京 🔐'
```

Read visible text from a file, hide Unicode text, and write the result to a file:

```sh
raphecrypt --input input.txt --output output.txt --hide 'hidden café 東京 🔐'
```

Protect the hidden text with a password before hiding it:

```sh
printf 'Visible text\n' | raphecrypt --hide 'hidden café 東京 🔐' --password 'mysecret'
```

Extract hidden text that was hidden without a password:

```sh
raphecrypt --input output.txt --extract
```

Decrypt hidden text that was protected with a password:

```sh
raphecrypt --input output.txt --extract 'mysecret'
```

Read the password from a file:

```sh
raphecrypt --input output.txt --extract --password-file password.txt
```

Read the password from standard input:

```sh
printf 'mysecret\n' | raphecrypt --input output.txt --extract --password-stdin
```

When running through Cargo during development, put `--` before the program options:

```sh
cargo run -- --input input.txt --output output.txt
```

## Passwords

Passwords are optional. If you hide text without a password, the message is only hidden in the visible text. Anyone who knows how to extract the payload can read it.

If the hidden message is sensitive, use a long, unique passphrase. Avoid passing sensitive passwords directly on the command line when possible, because command arguments can be saved in shell history or visible to other local tools. Prefer `--password-file` or `--password-stdin` for sensitive use.

There is no password recovery. If the password is lost or typed differently later, the hidden message cannot be decrypted.

## Security Notes

When you use a password, `raphecrypt` protects the hidden message with XChaCha20-Poly1305, a modern authenticated encryption algorithm. For end users, this means the hidden message is designed to remain private unless the correct password is known, and accidental or intentional changes to the protected message should be detected during extraction.

The encryption is strong, but password strength still matters. A short, reused, or easy-to-guess password can make the protected message much easier to attack.

Hidden Unicode text can be fragile. Some websites, chat systems, editors, formatters, or copy/paste paths may remove or normalize invisible Unicode characters. If that happens, the hidden message may no longer be extractable.

Related reference: [ChaCha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305)

## Technical Notes

When `--hide` is provided, the program inserts an invisible Unicode payload into the output. The visible part of the output remains the original input text.

The hidden payload uses Unicode format characters from the `\p{Cf}` category. This hides the text in the output stream, but hiding without a password is steganographic hiding, not cryptographic encryption.

When `--password`, `--password-file`, or `--password-stdin` is provided, the hidden text is encrypted before it is embedded. When `--extract` is used without a password, the program extracts a plaintext hidden payload. When a password is provided during extraction, the password is used to decrypt an encrypted hidden payload and the recovered hidden text is written as the output.

## Build

```sh
cargo build
```

For an optimized release build:

```sh
cargo build --release
```

The release binary will be written to:

```sh
target/release/raphecrypt
```
