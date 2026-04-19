use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tracing::info;
use tokio_util::sync::CancellationToken;

pub async fn wait_for_signal(stop: Arc<AtomicBool>, token: CancellationToken) {
    wait_for_os_signal().await;
    stop.store(true, Ordering::Relaxed);
    token.cancel();
}

async fn wait_for_os_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("failed to register SIGTERM");
        tokio::select! {
            _ = ctrl_c => {
                info!("received SIGINT, shutting down");
            }
            _ = sigterm.recv() => {
                info!("received SIGTERM, shutting down");
            }
        }
    }
    #[cfg(not(unix))]
    {
        ctrl_c.await.expect("failed to listen for Ctrl+C");
        info!("received Ctrl+C, shutting down");
    }
}
