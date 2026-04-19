use std::net::IpAddr;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tracing::{error, info, warn};
use tokio_util::sync::CancellationToken;

use crate::config::ListenerConfig;
use crate::handler;
use crate::proto::SnifferCommand;

fn is_fd_exhausted(e: &std::io::Error) -> bool {
    #[cfg(unix)]
    {
        matches!(e.raw_os_error(), Some(libc::EMFILE) | Some(libc::ENFILE))
    }
    #[cfg(not(unix))]
    {
        let _ = e;
        false
    }
}

pub async fn run_listener(
    lc: ListenerConfig,
    local_ip: IpAddr,
    cmd_tx: std::sync::mpsc::Sender<SnifferCommand>,
    token: CancellationToken,
) {
    let listener = match TcpListener::bind(lc.listen).await {
        Ok(l) => {
            info!(listen = %lc.listen, upstream = %lc.connect, sni = %lc.fake_sni, "listener started");
            l
        }
        Err(e) => {
            error!(listen = %lc.listen, "failed to bind: {}", e);
            return;
        }
    };

    let mut tasks = JoinSet::new();

    loop {
        let accepted = tokio::select! {
            result = listener.accept() => result,
            _ = token.cancelled() => break,
        };

        match accepted {
            Ok((stream, peer)) => {
                let upstream = lc.connect;
                let sni = lc.fake_sni.clone();
                let tx = cmd_tx.clone();
                let lip = local_ip;
                let conn_timeout = lc.conn_timeout_sec;
                let handshake_timeout = lc.handshake_timeout_sec;
                let keepalive_time = lc.keepalive_time_sec;
                let keepalive_interval = lc.keepalive_interval_sec;
                tasks.spawn(async move {
                    tracing::debug!(peer = %peer, "accepted connection");
                    handler::handle_connection(stream, upstream, sni, lip, tx, conn_timeout, handshake_timeout, keepalive_time, keepalive_interval).await;
                });
            }
            Err(e) => {
                if is_fd_exhausted(&e) {
                    warn!("accept error (fd exhausted, backing off 500ms): {}", e);
                    tokio::time::sleep(Duration::from_millis(500)).await;
                } else {
                    error!("accept error: {}", e);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    }

    info!(listen = %lc.listen, "stopped accepting, draining active connections");
    while tasks.join_next().await.is_some() {}
    info!(listen = %lc.listen, "all connections drained");
}
