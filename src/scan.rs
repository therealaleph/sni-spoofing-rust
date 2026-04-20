use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::packet::tls;

const DEFAULT_SNIS: &str = include_str!("../data/scan-snis.txt");
const DEFAULT_TARGET: &str = "104.18.4.130:443";
const DEFAULT_TIMEOUT_SECS: u64 = 6;
const DEFAULT_CONCURRENCY: usize = 10;

pub struct ScanOpts {
    pub target: SocketAddr,
    pub timeout: Duration,
    pub concurrency: usize,
    pub snis: Vec<String>,
    pub output: Option<String>,
}

#[derive(Debug)]
enum ProbeOutcome {
    Ok,
    ConnectFailed(String),
    ConnectTimeout,
    HandshakeFailed(String),
    ReadTimeout,
    BadResponse(u8),
    EmptyResponse,
}

struct ProbeResult {
    sni: String,
    outcome: ProbeOutcome,
}

pub fn run(args: &[String]) {
    let opts = match parse_args(args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("error: {}", e);
            eprintln!();
            print_help();
            std::process::exit(2);
        }
    };

    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(async { scan_all(opts).await });
}

fn parse_args(args: &[String]) -> Result<ScanOpts, String> {
    let mut target: Option<SocketAddr> = None;
    let mut timeout_secs: u64 = DEFAULT_TIMEOUT_SECS;
    let mut concurrency: usize = DEFAULT_CONCURRENCY;
    let mut list_path: Option<String> = None;
    let mut output: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            "--target" | "-t" => {
                i += 1;
                let v = args.get(i).ok_or("missing value for --target")?;
                target = Some(v.parse().map_err(|e| format!("invalid --target '{}': {}", v, e))?);
            }
            "--timeout" => {
                i += 1;
                let v = args.get(i).ok_or("missing value for --timeout")?;
                timeout_secs = v.parse().map_err(|e| format!("invalid --timeout '{}': {}", v, e))?;
            }
            "--concurrency" | "-c" => {
                i += 1;
                let v = args.get(i).ok_or("missing value for --concurrency")?;
                concurrency = v.parse().map_err(|e| format!("invalid --concurrency '{}': {}", v, e))?;
                if concurrency == 0 {
                    return Err("--concurrency must be >= 1".into());
                }
            }
            "--list" | "-l" => {
                i += 1;
                list_path = Some(args.get(i).ok_or("missing value for --list")?.clone());
            }
            "--output" | "-o" => {
                i += 1;
                output = Some(args.get(i).ok_or("missing value for --output")?.clone());
            }
            other => {
                return Err(format!("unknown argument: {}", other));
            }
        }
        i += 1;
    }

    let snis = if let Some(path) = list_path {
        let content = std::fs::read_to_string(Path::new(&path))
            .map_err(|e| format!("failed to read list '{}': {}", path, e))?;
        parse_sni_list(&content)
    } else {
        parse_sni_list(DEFAULT_SNIS)
    };

    if snis.is_empty() {
        return Err("SNI list is empty".into());
    }

    Ok(ScanOpts {
        target: target.unwrap_or_else(|| DEFAULT_TARGET.parse().unwrap()),
        timeout: Duration::from_secs(timeout_secs),
        concurrency,
        snis,
        output,
    })
}

fn parse_sni_list(content: &str) -> Vec<String> {
    content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect()
}

fn print_help() {
    eprintln!("sni-spoof-rs scan -- probe which SNIs pass DPI as fake_sni candidates");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  sni-spoof-rs scan [OPTIONS]");
    eprintln!();
    eprintln!("OPTIONS:");
    eprintln!("  -t, --target ADDR        Cloudflare IP:port to probe against (default: {})", DEFAULT_TARGET);
    eprintln!("      --timeout SECS       per-probe timeout in seconds (default: {})", DEFAULT_TIMEOUT_SECS);
    eprintln!("  -c, --concurrency N      parallel probes (default: {})", DEFAULT_CONCURRENCY);
    eprintln!("  -l, --list FILE          custom SNI list file (one per line, # for comments)");
    eprintln!("  -o, --output FILE        write working SNIs to file (one per line)");
    eprintln!("  -h, --help               print this help");
    eprintln!();
    eprintln!("Working SNIs are printed to stdout; progress/diagnostics go to stderr.");
    eprintln!("Example: sni-spoof-rs scan -o working.txt");
}

async fn scan_all(opts: ScanOpts) {
    eprintln!(
        "scanning {} SNIs against {} (concurrency={}, timeout={}s)",
        opts.snis.len(),
        opts.target,
        opts.concurrency,
        opts.timeout.as_secs(),
    );
    eprintln!();

    let sem = Arc::new(Semaphore::new(opts.concurrency));
    let target = opts.target;
    let timeout = opts.timeout;
    let total = opts.snis.len();

    let mut handles = Vec::with_capacity(total);
    for sni in opts.snis {
        let sem = sem.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.expect("semaphore closed");
            probe(target, sni, timeout).await
        }));
    }

    let mut results: Vec<ProbeResult> = Vec::with_capacity(total);
    let mut done = 0usize;
    let mut ok = 0usize;
    for h in handles {
        match h.await {
            Ok(r) => {
                done += 1;
                if matches!(r.outcome, ProbeOutcome::Ok) {
                    ok += 1;
                    println!("{}", r.sni);
                }
                if done % 20 == 0 || done == total {
                    eprintln!("  progress: {}/{} ({} ok)", done, total, ok);
                }
                results.push(r);
            }
            Err(e) => {
                eprintln!("task panic: {}", e);
            }
        }
    }

    eprintln!();
    eprintln!("=== summary ===");
    eprintln!("total:     {}", total);
    eprintln!("ok:        {}", ok);
    eprintln!("failed:    {}", total - ok);

    if let Some(path) = opts.output {
        let working: Vec<&str> = results
            .iter()
            .filter(|r| matches!(r.outcome, ProbeOutcome::Ok))
            .map(|r| r.sni.as_str())
            .collect();
        let body = working.join("\n") + "\n";
        if let Err(e) = std::fs::write(&path, body) {
            eprintln!("failed to write {}: {}", path, e);
            std::process::exit(1);
        }
        eprintln!("wrote {} working SNIs to {}", working.len(), path);
    }
}

async fn probe(target: SocketAddr, sni: String, timeout: Duration) -> ProbeResult {
    if sni.len() > 219 {
        return ProbeResult { sni, outcome: ProbeOutcome::HandshakeFailed("sni too long".into()) };
    }

    let mut stream = match tokio::time::timeout(timeout, TcpStream::connect(target)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return ProbeResult { sni, outcome: ProbeOutcome::ConnectFailed(e.to_string()) },
        Err(_) => return ProbeResult { sni, outcome: ProbeOutcome::ConnectTimeout },
    };

    let ch = tls::build_client_hello(&sni);
    match tokio::time::timeout(timeout, stream.write_all(&ch)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return ProbeResult { sni, outcome: ProbeOutcome::HandshakeFailed(e.to_string()) },
        Err(_) => return ProbeResult { sni, outcome: ProbeOutcome::HandshakeFailed("write timeout".into()) },
    }

    let mut buf = [0u8; 5];
    match tokio::time::timeout(timeout, stream.read_exact(&mut buf)).await {
        Ok(Ok(_)) => {
            if buf[0] == 0x16 {
                ProbeResult { sni, outcome: ProbeOutcome::Ok }
            } else {
                ProbeResult { sni, outcome: ProbeOutcome::BadResponse(buf[0]) }
            }
        }
        Ok(Err(e)) => {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                ProbeResult { sni, outcome: ProbeOutcome::EmptyResponse }
            } else {
                ProbeResult { sni, outcome: ProbeOutcome::HandshakeFailed(e.to_string()) }
            }
        }
        Err(_) => ProbeResult { sni, outcome: ProbeOutcome::ReadTimeout },
    }
}
