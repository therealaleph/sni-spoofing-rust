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

use tracing::{error, info};
use tracing_subscriber::EnvFilter;

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
    rt.block_on(async {
        let signal_stop = stop.clone();
        tokio::spawn(async move {
            shutdown::wait_for_signal(signal_stop).await;
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            std::process::exit(0);
        });

        let mut handles = Vec::new();
        for lc in cfg.listeners {
            let tx = cmd_tx.clone();
            let lip = resolve_local_ip(lc.connect.ip()).unwrap_or(local_ips[0]);
            handles.push(tokio::spawn(listener::run_listener(lc, lip, tx, cfg.idle_timeout, cfg.buffer_size)));
        }

        for h in handles {
            let _ = h.await;
        }
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
