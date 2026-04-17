use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

pub async fn relay(
    mut client: TcpStream,
    mut upstream: TcpStream,
    idle_timeout: u64,
    buffer_size: usize,
) -> Result<(), std::io::Error> {
    let mut client_buf = vec![0; buffer_size * 1024];
    let mut client_buf_rb = tokio::io::ReadBuf::new(&mut client_buf);
    let mut upstream_buf = vec![0; buffer_size * 1024];
    let mut upstream_buf_rb = tokio::io::ReadBuf::new(&mut upstream_buf);

    let (mut client_r, mut client_w) = client.split();
    let (mut upstream_r, mut upstream_w) = upstream.split();
    let mut client_r_pin = std::pin::Pin::new(&mut client_r);
    let mut upstream_r_pin = std::pin::Pin::new(&mut upstream_r);

    let idle_timeout_dur = std::time::Duration::from_secs(idle_timeout);
    let mut client_closed = false;
    let err: tokio::io::Error;
    loop {
        match tokio::time::timeout(idle_timeout_dur, async {
            tokio::select! {
                read = Read(&mut client_r_pin, &mut client_buf_rb) => {
                    if read.is_err() {
                        client_closed = true;
                    }
                    read?;
                    upstream_w.write_all(client_buf_rb.filled()).await
                },
                read = Read(&mut upstream_r_pin, &mut upstream_buf_rb) => {
                    read?;
                    client_w.write_all(upstream_buf_rb.filled()).await
                }
            }
        })
        .await
        {
            Err(_) => {
                err = tokio::io::Error::other("Timeout");
                break;
            }
            Ok(Err(e)) => {
                err = e;
                break;
            }
            _ => (),
        }
    }

    // handle halfway closed
    let timeout_dur = std::time::Duration::from_secs(3);
    if client_closed {
        loop {
            match tokio::time::timeout(
                timeout_dur,
                Read(&mut upstream_r_pin, &mut upstream_buf_rb),
            )
            .await
            {
                Ok(Err(_)) | Err(_) => break,
                _ => (),
            };
            if client_w.write_all(upstream_buf_rb.filled()).await.is_err() {
                break;
            }
        }
    } else {
        loop {
            match tokio::time::timeout(
                timeout_dur,
                Read(&mut client_r_pin, &mut client_buf_rb),
            )
            .await
            {
                Ok(Err(_)) | Err(_) => break,
                _ => (),
            };
            if upstream_w.write_all(client_buf_rb.filled()).await.is_err() {
                break;
            }
        }
    }

    tracing::debug!("relay finished");
    Err(err)
}

pub struct Read<'a, 'b, R>(
    pub &'a mut std::pin::Pin<&'b mut R>,
    pub &'a mut ReadBuf<'b>,
);
impl<'a, 'b, R> std::future::Future for Read<'a, 'b, R>
where
    R: AsyncRead + Unpin,
{
    type Output = tokio::io::Result<()>;
    #[inline(always)]
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = &mut *self;
        this.1.clear();
        std::task::ready!(this.0.as_mut().poll_read(cx, this.1)).map(|_| {
            if this.1.filled().is_empty() {
                std::task::Poll::Ready(Err(tokio::io::Error::other("Pipe read EOF")))
            } else {
                std::task::Poll::Ready(Ok(()))
            }
        })?
    }
}
