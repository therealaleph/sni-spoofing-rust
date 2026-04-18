use tokio::io::copy_bidirectional_with_sizes;
use tokio::net::TcpStream;

pub async fn relay(
    mut client: TcpStream,
    mut upstream: TcpStream,
    idle_timeout: Option<u64>,
    buffer_size: usize,
) -> Result<(), std::io::Error> {
    let (c2u, u2c) = if let Some(idle_timeout) = idle_timeout {
        let mut client_io_timeout = tokio_io_timeout::TimeoutStream::new(client);
        let mut upstream_io_timeout = tokio_io_timeout::TimeoutStream::new(upstream);

        client_io_timeout.set_read_timeout(Some(std::time::Duration::from_secs(idle_timeout)));
        upstream_io_timeout.set_read_timeout(Some(std::time::Duration::from_secs(idle_timeout)));

        let mut pin_client_io_timeout = std::pin::pin!(client_io_timeout);
        let mut pin_upstream_io_timeout = std::pin::pin!(upstream_io_timeout);

        copy_bidirectional_with_sizes(
            &mut pin_client_io_timeout,
            &mut pin_upstream_io_timeout,
            buffer_size * 1024,
            buffer_size * 1024,
        )
        .await
    } else {
        copy_bidirectional_with_sizes(
            &mut client,
            &mut upstream,
            buffer_size * 1024,
            buffer_size * 1024,
        )
        .await
    }?;

    tracing::debug!(c2u, u2c, "relay finished");
    Ok(())
}
