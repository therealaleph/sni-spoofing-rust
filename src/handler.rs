use std::net::SocketAddr;
use std::time::Duration;

use socket2::{SockRef, TcpKeepalive};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::error::HandlerError;
use crate::packet::tls;
use crate::proto::{ConnId, Deregistration, Registration, SnifferCommand, SnifferResult};
use crate::relay;

pub async fn handle_connection(
    client: TcpStream,
    upstream_addr: SocketAddr,
    fake_sni: String,
    local_ip: std::net::IpAddr,
    cmd_tx: std::sync::mpsc::Sender<SnifferCommand>,
    conn_timeout_sec: u64,
    handshake_timeout_sec: u64,
    keepalive_time_sec: u64,
    keepalive_interval_sec: u64,
) {
    if let Err(e) = handle_inner(client, upstream_addr, &fake_sni, local_ip, &cmd_tx, conn_timeout_sec, handshake_timeout_sec, keepalive_time_sec, keepalive_interval_sec).await {
        match &e {
            HandlerError::Timeout => {
                warn!(upstream = %upstream_addr, "timeout waiting for fake ACK");
            }
            _ => {
                warn!(upstream = %upstream_addr, "connection failed: {}", e);
            }
        }
    }
}

async fn handle_inner(
    client: TcpStream,
    upstream_addr: SocketAddr,
    fake_sni: &str,
    local_ip: std::net::IpAddr,
    cmd_tx: &std::sync::mpsc::Sender<SnifferCommand>,
    conn_timeout_sec: u64,
    handshake_timeout_sec: u64,
    keepalive_time_sec: u64,
    keepalive_interval_sec: u64,
) -> Result<(), HandlerError> {
    let fake_payload = tls::build_client_hello(fake_sni);

    let upstream_sock = if upstream_addr.is_ipv4() {
        socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
    } else {
        socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
    }
    .map_err(HandlerError::Connect)?;

    upstream_sock.set_nonblocking(true).map_err(HandlerError::Connect)?;

    let bind_addr: SocketAddr = if upstream_addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    upstream_sock
        .bind(&bind_addr.into())
        .map_err(HandlerError::Connect)?;

    let local_addr = upstream_sock
        .local_addr()
        .map_err(HandlerError::Connect)?
        .as_socket()
        .ok_or_else(|| HandlerError::Connect(std::io::Error::new(
            std::io::ErrorKind::Other,
            "failed to get local socket addr",
        )))?;

    let (result_tx, mut result_rx) = mpsc::channel::<SnifferResult>(4);

    let conn_id = ConnId {
        src_ip: local_ip,
        src_port: local_addr.port(),
        dst_ip: upstream_addr.ip(),
        dst_port: upstream_addr.port(),
    };

    let (registered_tx, registered_rx) = tokio::sync::oneshot::channel();
    cmd_tx
        .send(SnifferCommand::Register(Registration {
            conn_id,
            fake_payload,
            result_tx,
            registered_tx,
        }))
        .map_err(|_| HandlerError::Registration)?;

    let _ = registered_rx.await;

    match upstream_sock.connect(&upstream_addr.into()) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        #[cfg(unix)]
        Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(e) => {
            let _ = cmd_tx.send(SnifferCommand::Deregister(Deregistration { conn_id }));
            return Err(HandlerError::Connect(e));
        }
    }

    let std_stream: std::net::TcpStream = upstream_sock.into();
    let upstream = TcpStream::from_std(std_stream).map_err(HandlerError::Connect)?;

    let connect_result = tokio::time::timeout(Duration::from_secs(conn_timeout_sec), upstream.writable()).await;
    match connect_result {
        Ok(Ok(())) => {
            let sock_ref = SockRef::from(&upstream);
            if let Some(err) = sock_ref.take_error().map_err(HandlerError::Connect)? {
                let _ = cmd_tx.send(SnifferCommand::Deregister(Deregistration { conn_id }));
                return Err(HandlerError::Connect(err));
            }
        }
        Ok(Err(e)) => {
            let _ = cmd_tx.send(SnifferCommand::Deregister(Deregistration { conn_id }));
            return Err(HandlerError::Connect(e));
        }
        Err(_) => {
            let _ = cmd_tx.send(SnifferCommand::Deregister(Deregistration { conn_id }));
            return Err(HandlerError::Connect(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "connect timeout",
            )));
        }
    }

    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(keepalive_time_sec))
        .with_interval(Duration::from_secs(keepalive_interval_sec));
    let sock_ref = SockRef::from(&upstream);
    let _ = sock_ref.set_tcp_keepalive(&keepalive);

    let client_ref = SockRef::from(&client);
    let _ = client_ref.set_tcp_keepalive(&keepalive);

    debug!(port = local_addr.port(), "connected, waiting for sniffer confirmation");

    let confirmed = tokio::time::timeout(Duration::from_secs(handshake_timeout_sec), async {
        while let Some(result) = result_rx.recv().await {
            match result {
                SnifferResult::FakeConfirmed => return Ok(()),
                SnifferResult::Failed(e) => return Err(HandlerError::SnifferFailed(e)),
            }
        }
        Err(HandlerError::Registration)
    })
    .await;

    match confirmed {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(HandlerError::Timeout),
    }

    info!(port = local_addr.port(), "fake confirmed, starting relay");

    relay::relay(client, upstream).await.map_err(HandlerError::Relay)
}
