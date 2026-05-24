//! Small native static file server for the generated SPA in `dist/`.

use std::{
    env, fs, io,
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    path::{Component, Path, PathBuf},
};

fn main() -> io::Result<()> {
    let config = Config::from_args();
    let listener = TcpListener::bind(&config.addr)?;

    println!(
        "Serving {} at http://{}",
        config.root.display(),
        config.addr
    );

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(error) = handle_connection(stream, &config.root) {
                    eprintln!("request failed: {error}");
                }
            }
            Err(error) => eprintln!("connection failed: {error}"),
        }
    }

    Ok(())
}

struct Config {
    addr: String,
    root: PathBuf,
}

impl Config {
    fn from_args() -> Self {
        let mut addr = "127.0.0.1:8000".to_owned();
        let mut root = PathBuf::from("dist");
        let mut args = env::args().skip(1);

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--addr" => {
                    if let Some(value) = args.next() {
                        addr = value;
                    }
                }
                "--root" => {
                    if let Some(value) = args.next() {
                        root = PathBuf::from(value);
                    }
                }
                "--help" | "-h" => {
                    print_help();
                    std::process::exit(0);
                }
                _ => {}
            }
        }

        Self { addr, root }
    }
}

fn print_help() {
    println!(
        "Serve the raphecrypt SPA.\n\nUsage: cargo run --bin webserver -- [--addr HOST:PORT] [--root DIR]"
    );
}

fn handle_connection(mut stream: TcpStream, root: &Path) -> io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or("/");

    if method != "GET" && method != "HEAD" {
        return write_response(
            &mut stream,
            "405 Method Not Allowed",
            "text/plain; charset=utf-8",
            b"Method not allowed",
            method == "HEAD",
        );
    }

    let Some(path) = resolve_path(root, target) else {
        return write_response(
            &mut stream,
            "403 Forbidden",
            "text/plain; charset=utf-8",
            b"Forbidden",
            method == "HEAD",
        );
    };

    match fs::read(&path) {
        Ok(body) => write_response(
            &mut stream,
            "200 OK",
            content_type(&path),
            &body,
            method == "HEAD",
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => write_response(
            &mut stream,
            "404 Not Found",
            "text/plain; charset=utf-8",
            b"Not found",
            method == "HEAD",
        ),
        Err(error) => Err(error),
    }
}

fn resolve_path(root: &Path, target: &str) -> Option<PathBuf> {
    let path_without_query = target.split_once('?').map_or(target, |(path, _)| path);
    let target_path = if path_without_query == "/" {
        "index.html"
    } else {
        path_without_query.trim_start_matches('/')
    };
    let mut path = root.to_path_buf();

    for component in Path::new(target_path).components() {
        match component {
            Component::Normal(part) => path.push(part),
            Component::CurDir => {}
            Component::Prefix(_) | Component::RootDir | Component::ParentDir => return None,
        }
    }

    Some(path)
}

fn write_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
    head_only: bool,
) -> io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;

    if !head_only {
        stream.write_all(body)?;
    }

    Ok(())
}

fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("css") => "text/css; charset=utf-8",
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("wasm") => "application/wasm",
        _ => "application/octet-stream",
    }
}
