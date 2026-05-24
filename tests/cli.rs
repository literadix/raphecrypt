use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

fn run_raphecrypt(args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_raphecrypt"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn raphecrypt");

    child
        .stdin
        .as_mut()
        .expect("stdin should be piped")
        .write_all(stdin.as_bytes())
        .expect("failed to write test stdin");

    child
        .wait_with_output()
        .expect("failed to wait for raphecrypt")
}

fn stdout_text(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout should be valid UTF-8")
}

fn stderr_text(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr should be valid UTF-8")
}

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(test_name: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "raphecrypt-{test_name}-{}-{nanos}",
            std::process::id()
        ));

        fs::create_dir(&path).expect("failed to create test directory");

        Self { path }
    }

    fn path(&self, file_name: &str) -> PathBuf {
        self.path.join(file_name)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn path_arg(path: &Path) -> String {
    path.to_str()
        .expect("test path should be valid UTF-8")
        .to_owned()
}

#[test]
fn help_text_is_user_facing() {
    let output = run_raphecrypt(&["--help"], "");
    let stdout = stdout_text(&output);

    assert!(output.status.success());
    assert!(stdout.contains("--hide <TEXT>"));
    assert!(stdout.contains("--extract [<PASSWORD>]"));
    assert!(stdout.contains("--scan"));
    assert!(stdout.contains("--password-file <FILE>"));
    assert!(stdout.contains("--password-stdin"));
    assert!(!stdout.contains("num_args"));
    assert!(!stdout.contains("default_missing_value"));
    assert!(!stdout.contains("clap"));
}

#[test]
fn passes_stdin_to_stdout_when_no_mode_is_selected() {
    let output = run_raphecrypt(&[], "Visible café 東京\n");

    assert!(output.status.success());
    assert_eq!(stdout_text(&output), "Visible café 東京\n");
}

#[test]
fn hides_and_extracts_plaintext_message_through_stdout() {
    let encoded = run_raphecrypt(&["--hide", "secret café"], "Visible text\n");
    assert!(encoded.status.success());

    let decoded = run_raphecrypt(&["--extract"], &stdout_text(&encoded));

    assert!(decoded.status.success());
    assert_eq!(stdout_text(&decoded), "secret café");
}

#[test]
fn legacy_encrypt_and_decrypt_aliases_still_work() {
    let encoded = run_raphecrypt(&["--encrypt", "secret"], "Visible text\n");
    assert!(encoded.status.success());

    let decoded = run_raphecrypt(&["--decrypt"], &stdout_text(&encoded));

    assert!(decoded.status.success());
    assert_eq!(stdout_text(&decoded), "secret");
}

#[test]
fn hides_and_extracts_encrypted_message_with_password_file() {
    let dir = TestDir::new("password-file");
    let input = dir.path("input.txt");
    let encoded = dir.path("encoded.txt");
    let password = dir.path("password.txt");

    fs::write(&input, "Visible text\n").unwrap();
    fs::write(&password, "mysecret\n").unwrap();

    let hide = run_raphecrypt(
        &[
            "--input",
            &path_arg(&input),
            "--output",
            &path_arg(&encoded),
            "--hide",
            "secret café",
            "--password-file",
            &path_arg(&password),
        ],
        "",
    );
    assert!(hide.status.success(), "{}", stderr_text(&hide));

    let extract = run_raphecrypt(
        &[
            "--input",
            &path_arg(&encoded),
            "--extract",
            "--password-file",
            &path_arg(&password),
        ],
        "",
    );

    assert!(extract.status.success(), "{}", stderr_text(&extract));
    assert_eq!(stdout_text(&extract), "secret café");
}

#[test]
fn extracts_encrypted_message_with_password_from_stdin() {
    let dir = TestDir::new("password-stdin");
    let input = dir.path("input.txt");
    let encoded = dir.path("encoded.txt");

    fs::write(&input, "Visible text\n").unwrap();

    let hide = run_raphecrypt(
        &[
            "--input",
            &path_arg(&input),
            "--output",
            &path_arg(&encoded),
            "--hide",
            "secret",
            "--password",
            "mysecret",
        ],
        "",
    );
    assert!(hide.status.success(), "{}", stderr_text(&hide));

    let extract = run_raphecrypt(
        &[
            "--input",
            &path_arg(&encoded),
            "--extract",
            "--password-stdin",
        ],
        "mysecret\n",
    );

    assert!(extract.status.success(), "{}", stderr_text(&extract));
    assert_eq!(stdout_text(&extract), "secret");
}

#[test]
fn wrong_password_exits_with_error() {
    let encoded = run_raphecrypt(
        &["--hide", "secret", "--password", "mysecret"],
        "Visible text\n",
    );
    assert!(encoded.status.success());

    let decoded = run_raphecrypt(&["--extract", "wrong"], &stdout_text(&encoded));

    assert!(!decoded.status.success());
    assert!(stderr_text(&decoded).contains("failed to decrypt hidden text"));
}

#[test]
fn password_stdin_requires_input_file() {
    let output = run_raphecrypt(&["--hide", "secret", "--password-stdin"], "mysecret\n");

    assert!(!output.status.success());
    assert!(stderr_text(&output).contains("--password-stdin requires --input"));
}

#[test]
fn scans_clean_text() {
    let output = run_raphecrypt(&["--scan"], "Visible café 東京\n");
    let stdout = stdout_text(&output);

    assert!(output.status.success());
    assert!(stdout.contains("Findings: 0"));
    assert!(stdout.contains("No non-visible Unicode characters found."));
}

#[test]
fn scans_hidden_payload_characters() {
    let encoded = run_raphecrypt(&["--hide", "secret"], "Visible text\n");
    assert!(encoded.status.success());

    let scan = run_raphecrypt(&["--scan"], &stdout_text(&encoded));
    let stdout = stdout_text(&scan);

    assert!(scan.status.success());
    assert!(stdout.contains("Unicode tag character"));
    assert!(stdout.contains("Findings:"));
}
