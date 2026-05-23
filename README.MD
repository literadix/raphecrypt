# raphecrypt

`raphecrypt` is a command-line utility for carrying hidden Unicode messages inside ordinary visible text.

It can pass text through unchanged, hide a message inside visible text, protect the hidden message with an optional password, extract a hidden message again, or decrypt an extracted message when the correct password is provided. When no password is given, the message is hidden but not password-protected. The visible text can come from a file or standard input, and the result can be written to a file or standard output.

When `--encrypt` is provided, the program inserts an invisible Unicode payload into the output. The visible part of the output remains the original input text.

The hidden payload is encoded from the UTF-8 bytes of the `--encrypt` text using invisible Unicode format characters from the `\p{Cf}` category. The current alphabet uses Unicode tag characters so terminals do not render placeholder glyphs for the hidden payload. This hides the text in the output stream, but it is steganographic hiding, not cryptographic encryption by itself.

When `--password` is provided, the hidden text is encrypted first using XChaCha20-Poly1305 with a key derived from the password using Argon2id. Without `--password`, the hidden text is only encoded invisibly and is not encrypted.

When `--decrypt` is provided without a value, the program extracts a plaintext hidden payload. When `--decrypt <PASSWORD>` is provided, the password is used to decrypt an encrypted hidden payload and the recovered hidden text is written as the output.

## XChaCha20-Poly1305

When you use a password, `raphecrypt` protects the hidden message with XChaCha20-Poly1305, a modern authenticated encryption algorithm. For end users, this means the hidden message is designed to remain private unless the correct password is known, and accidental or intentional changes to the protected message should be detected during decryption.

The encryption is strong, but the password still matters. A short, reused, or easy-to-guess password can make the protected message much easier to attack. Use a long, unique passphrase when the hidden message is sensitive.

There is no password recovery. If the password is lost or typed differently later, the hidden message cannot be decrypted.

Reference: [ChaCha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305)

## Usage

```sh
raphecrypt [OPTIONS]
```

Options:

```text
-i, --input <FILE>    Input file. Reads from standard input when omitted
-o, --output <FILE>   Output file. Writes to standard output when omitted
-e, --encrypt <TEXT>  Unicode text to hide invisibly in the output
-d, --decrypt [PASSWORD]
                      Extract hidden text. Provide a value to use it as the decryption password
-p, --password <TEXT> Password used to encrypt the hidden text before hiding it
-h, --help            Print help
-V, --version         Print version
```

## Examples

Read from a file and write to a file:

```sh
raphecrypt --input input.txt --output output.txt
```

Read from a file and write to standard output:

```sh
raphecrypt --input input.txt
```

Read from standard input and write to a file:

```sh
printf 'café 東京 🔐\n' | raphecrypt --output output.txt
```

Read from standard input and write to standard output:

```sh
printf 'café 東京 🔐\n' | raphecrypt
```

Hide Unicode text in the output while only showing the input text:

```sh
printf 'Visible text\n' | raphecrypt --encrypt 'hidden café 東京 🔐'
```

Read visible text from a file, hide Unicode text, and write the result to a file:

```sh
raphecrypt --input input.txt --output output.txt --encrypt 'hidden café 東京 🔐'
```

Encrypt the hidden text with a password before hiding it:

```sh
printf 'Visible text\n' | raphecrypt --encrypt 'hidden café 東京 🔐' --password 'mysecret'
```

Extract hidden text that was hidden without a password:

```sh
raphecrypt --input output.txt --decrypt
```

Decrypt hidden text that was encrypted with a password:

```sh
raphecrypt --input output.txt --decrypt 'mysecret'
```

When running through Cargo during development, put `--` before the program options:

```sh
cargo run -- --input input.txt --output output.txt
```

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
