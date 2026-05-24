# raphecrypt

`raphecrypt` is a command-line utility for carrying hidden Unicode messages inside ordinary visible text.

It can hide a message in visible text, optionally protect that hidden message with a password, and extract the hidden message again later. Without a password, the message is hidden but not password-protected.

## Use Cases

`raphecrypt` is useful when you want text to carry a second layer of information while still looking like ordinary text.

- Add private notes to visible messages, documents, or snippets without changing what readers see.
- Send a password-protected note through a plain-text channel while keeping the visible text harmless and readable.
- Attach metadata, tracking IDs, or workflow hints to text that still needs to look clean in editors, terminals, or logs.
- Create puzzle, game, or ARG-style messages where hidden text can be discovered later.
- Mark generated text or drafts with invisible context so you can identify, extract, or verify it later.
- Store a short recovery hint or operator note inside a copied text block without needing a separate sidecar file.

This is not a replacement for secure messaging. Some apps and websites may remove invisible Unicode characters, so test the full copy/paste or delivery path before relying on it.

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

## HEX View Examples

The visible input bytes stay readable in the output. The hidden payload is added as extra invisible Unicode bytes before the final newline.

Create a small input file:

```sh
printf 'Visible text\n' > input.txt
xxd -g 1 -c 16 input.txt
```

HEX output:

```text
00000000: 56 69 73 69 62 6c 65 20 74 65 78 74 0a     Visible text.
```

Interpretation:

```text
56 69 73 69 62 6c 65 20 74 65 78 74  = "Visible text"
0a                                      = newline
```

Hide `hi` without a password:

```sh
raphecrypt --input input.txt --hide 'hi' --output output.txt
xxd -g 1 -c 16 output.txt
```

Abbreviated HEX output:

```text
00000000: 56 69 73 69 62 6c 65 20 74 65 78 74 f3 a0 80 81  Visible text....
00000010: f3 a0 80 b0 f3 a0 80 b1 f3 a0 80 b0 f3 a0 80 b1  ................
...
000000d0: f3 a0 81 bf 0a                                      .....
```

Interpretation:

```text
56 69 73 69 62 6c 65 20 74 65 78 74  = unchanged visible text
f3 a0 80 81                            = hidden payload start marker
f3 a0 80 b0 / f3 a0 80 b1              = hidden payload bit characters
f3 a0 81 bf                            = hidden payload end marker
0a                                      = final newline
```

Extracting this file returns the hidden text:

```sh
raphecrypt --input output.txt --extract
```

```text
hi
```

Hide `hi` with password protection:

```sh
raphecrypt --input input.txt --hide 'hi' --password 'mysecret' --output output.txt
xxd -g 1 -c 16 output.txt
```

Abbreviated HEX output:

```text
00000000: 56 69 73 69 62 6c 65 20 74 65 78 74 f3 a0 80 81  Visible text....
00000010: f3 a0 80 b1 f3 a0 80 b0 f3 a0 80 b1 f3 a0 80 b0  ................
...
```

The visible prefix is still `Visible text`, but the hidden section is different from the no-password example. It is also different on each run because password-protected output uses fresh random values for encryption.

Decrypting this file with the same password returns the hidden text:

```sh
raphecrypt --input output.txt --extract 'mysecret'
```

```text
hi
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

## Web App

Build the static single-page app:

```sh
sh scripts/build-web.sh
```

This creates:

```text
dist/index.html
dist/styles.css
dist/app.js
dist/raphecrypt.wasm
```

Serve the `dist` directory with the native Rust web server:

```sh
cargo run --bin webserver
```

Then open:

```text
http://127.0.0.1:8000
```

The web app provides:

- Encode: visible text + hidden text + optional password -> encoded text
- Decode: encoded text + optional password -> hidden text
