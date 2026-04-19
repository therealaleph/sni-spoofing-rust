#![allow(dead_code)]

mod config;
mod error;
mod handler;
mod listener;
mod packet;
mod proto;
mod relay;
mod shutdown;
mod sniffer;

use std::net::IpAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use tracing::{error, info};
use tracing_subscriber::EnvFilter;
use tokio_util::sync::CancellationToken;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .init();

    let config_path = std::env::args().nth(1).unwrap_or_else(|| "config.json".into());
    let cfg = match config::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            error!("{}", e);
            std::process::exit(1);
        }
    };

    let upstream_addrs: Vec<(IpAddr, u16)> = cfg
        .listeners
        .iter()
        .map(|lc| (lc.connect.ip(), lc.connect.port()))
        .collect();

    let local_ips: Vec<IpAddr> = upstream_addrs
        .iter()
        .filter_map(|(ip, _)| resolve_local_ip(*ip).ok())
        .collect();

    if local_ips.is_empty() {
        error!("could not determine local IP for any upstream");
        std::process::exit(1);
    }

    info!(
        "config loaded: {} listener(s), local IPs: {:?}",
        cfg.listeners.len(),
        local_ips
    );

    let upstream_sockaddrs: Vec<std::net::SocketAddr> =
        cfg.listeners.iter().map(|lc| lc.connect).collect();

    #[cfg(target_os = "linux")]
    let backend = match sniffer::linux::AfPacketBackend::open(&upstream_sockaddrs) {
        Ok(b) => b,
        Err(e) => {
            error!("failed to open raw socket: {}", e);
            error!("hint: run with sudo or CAP_NET_RAW");
            std::process::exit(1);
        }
    };

    #[cfg(target_os = "macos")]
    let backend = match sniffer::macos::BpfBackend::open(&upstream_sockaddrs) {
        Ok(b) => b,
        Err(e) => {
            error!("failed to open BPF device: {}", e);
            error!("hint: run with sudo");
            std::process::exit(1);
        }
    };

    #[cfg(target_os = "windows")]
    let backend = match sniffer::windows::WinDivertBackend::open(&upstream_sockaddrs) {
        Ok(b) => b,
        Err(e) => {
            error!("failed to open WinDivert: {}", e);
            error!("hint: run as Administrator");
            std::process::exit(1);
        }
    };

    let (cmd_tx, cmd_rx) = std::sync::mpsc::channel::<proto::SnifferCommand>();

    let stop = Arc::new(AtomicBool::new(false));
    let token = CancellationToken::new();

    let sniffer_stop = stop.clone();
    let sniffer_local_ips = local_ips.clone();
    let sniffer_upstreams = upstream_addrs.clone();
    std::thread::Builder::new()
        .name("sniffer".into())
        .spawn(move || {
            sniffer::run_sniffer(backend, cmd_rx, sniffer_local_ips, sniffer_upstreams, sniffer_stop);
        })
        .expect("failed to spawn sniffer thread");

    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    let graceful_shutdown_sec = cfg.graceful_shutdown_sec;
    rt.block_on(async {
        let mut handles = Vec::new();
        for lc in cfg.listeners {
            let tx = cmd_tx.clone();
            let lip = resolve_local_ip(lc.connect.ip()).unwrap_or(local_ips[0]);
            let tk = token.clone();
            handles.push(tokio::spawn(listener::run_listener(lc, lip, tx, tk)));
        }

        shutdown::wait_for_signal(stop, token).await;

        if graceful_shutdown_sec == 0 {
            info!("graceful_shutdown_sec=0, exiting immediately");
        } else {
            info!("waiting up to {}s for active connections to drain", graceful_shutdown_sec);

            let drain_all = async {
                for h in handles {
                    let _ = h.await;
                }
            };

            if tokio::time::timeout(Duration::from_secs(graceful_shutdown_sec), drain_all).await.is_err() {
                info!("drain timeout ({}s), forcing exit", graceful_shutdown_sec);
            }
        }

        info!("shutdown complete");
    });
}

fn resolve_local_ip(dst: IpAddr) -> Result<IpAddr, String> {
    use std::net::UdpSocket;

    let target = match dst {
        IpAddr::V4(v4) => format!("{}:53", v4),
        IpAddr::V6(v6) => format!("[{}]:53", v6),
    };
    let bind = if dst.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };

    let sock = UdpSocket::bind(bind).map_err(|e| format!("bind: {}", e))?;
    sock.connect(&target).map_err(|e| format!("connect: {}", e))?;
    Ok(sock.local_addr().map_err(|e| format!("local_addr: {}", e))?.ip())
}
