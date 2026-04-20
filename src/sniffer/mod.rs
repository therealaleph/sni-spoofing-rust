#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "windows")]
pub mod windows;

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use tracing::{debug, error, info, warn};

use crate::packet::{FrameKind, IpVersion, detect_ip_version, ipv4, ipv6, tcp};
use crate::proto::{ConnId, SnifferCommand, SnifferResult};

pub trait RawBackend: Send + 'static {
    fn recv_frame(&mut self, buf: &mut [u8]) -> Result<usize, crate::error::SnifferError>;
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), crate::error::SnifferError>;
    fn frame_kind(&self) -> FrameKind;
    fn skip_checksum_on_send(&self) -> bool { false }
}

struct ConnState {
    isn: Option<u32>,
    server_isn: Option<u32>,
    fake_payload: Vec<u8>,
    fake_injected: bool,
    result_tx: tokio::sync::mpsc::Sender<SnifferResult>,
}

fn build_fake_frame(
    template: &[u8],
    isn: u32,
    fake_payload: &[u8],
    ip_ver: IpVersion,
    link_len: usize,
    skip_checksum: bool,
) -> Vec<u8> {
    let (ip_hdr_len, tcp_off) = match ip_ver {
        IpVersion::V4 => {
            let ihl = ipv4::header_len(&template[link_len..]);
            (ihl, link_len + ihl)
        }
        IpVersion::V6 => {
            (ipv6::IPV6_HEADER_LEN, link_len + ipv6::IPV6_HEADER_LEN)
        }
    };

    let tcp_hdr_len = tcp::data_offset(&template[tcp_off..]);

    let hdr_end = tcp_off + tcp_hdr_len;
    let mut out = Vec::with_capacity(hdr_end + fake_payload.len());
    out.extend_from_slice(&template[..hdr_end]);
    out.extend_from_slice(fake_payload);

    match ip_ver {
        IpVersion::V4 => {
            let ip_hdr = &mut out[link_len..];
            let new_total = (ip_hdr_len + tcp_hdr_len + fake_payload.len()) as u16;
            ipv4::set_total_length(ip_hdr, new_total);
            ipv4::increment_ident(ip_hdr);
            if !skip_checksum {
                ipv4::recompute_checksum(ip_hdr);
            }
        }
        IpVersion::V6 => {
            let ip_hdr = &mut out[link_len..];
            let new_payload = (tcp_hdr_len + fake_payload.len()) as u16;
            ipv6::set_payload_length(ip_hdr, new_payload);
        }
    }

    let tcp_hdr = &mut out[tcp_off..];
    tcp::add_flag(tcp_hdr, tcp::PSH);
    let fake_seq = isn.wrapping_add(1).wrapping_sub(fake_payload.len() as u32);
    tcp::set_seq_num(tcp_hdr, fake_seq);

    if !skip_checksum {
        match ip_ver {
            IpVersion::V4 => {
                let (ip_part, tcp_part) = out.split_at_mut(tcp_off);
                tcp::recompute_checksum_v4(&ip_part[link_len..], tcp_part);
            }
            IpVersion::V6 => {
                let (ip_part, tcp_part) = out.split_at_mut(tcp_off);
                tcp::recompute_checksum_v6(&ip_part[link_len..], tcp_part);
            }
        }
    }

    out
}

struct ParsedPacket {
    outbound_id: ConnId,
    is_outbound: bool,
    ip_version: IpVersion,
}

fn parse_frame(
    frame: &[u8],
    local_ips: &HashSet<IpAddr>,
    upstream_addrs: &HashMap<(IpAddr, u16), ()>,
    frame_kind: FrameKind,
) -> Option<ParsedPacket> {
    let ip_ver = detect_ip_version(frame, frame_kind)?;
    let link_len = frame_kind.link_header_len();

    let (src_ip, dst_ip, proto, tcp_off): (IpAddr, IpAddr, u8, usize) = match ip_ver {
        IpVersion::V4 => {
            let ip_hdr = &frame[link_len..];
            if ip_hdr.len() < ipv4::IPV4_MIN_HEADER_LEN {
                return None;
            }
            let ihl = ipv4::header_len(ip_hdr);
            (
                IpAddr::V4(ipv4::src_addr(ip_hdr)),
                IpAddr::V4(ipv4::dst_addr(ip_hdr)),
                ipv4::protocol(ip_hdr),
                link_len + ihl,
            )
        }
        IpVersion::V6 => {
            let ip_hdr = &frame[link_len..];
            if ip_hdr.len() < ipv6::IPV6_HEADER_LEN {
                return None;
            }
            (
                IpAddr::V6(ipv6::src_addr(ip_hdr)),
                IpAddr::V6(ipv6::dst_addr(ip_hdr)),
                ipv6::next_header(ip_hdr),
                link_len + ipv6::IPV6_HEADER_LEN,
            )
        }
    };

    if proto != 6 {
        return None;
    }

    if frame.len() < tcp_off + tcp::TCP_MIN_HEADER_LEN {
        return None;
    }

    let tcp_hdr = &frame[tcp_off..];
    let sport = tcp::src_port(tcp_hdr);
    let dport = tcp::dst_port(tcp_hdr);

    let src_is_local = local_ips.contains(&src_ip);
    let src_is_upstream = upstream_addrs.contains_key(&(src_ip, sport));
    let dst_is_upstream = upstream_addrs.contains_key(&(dst_ip, dport));

    if src_is_local && dst_is_upstream {
        Some(ParsedPacket {
            outbound_id: ConnId {
                src_ip,
                src_port: sport,
                dst_ip,
                dst_port: dport,
            },
            is_outbound: true,
            ip_version: ip_ver,
        })
    } else if src_is_upstream && local_ips.contains(&dst_ip) {
        Some(ParsedPacket {
            outbound_id: ConnId {
                src_ip: dst_ip,
                src_port: dport,
                dst_ip: src_ip,
                dst_port: sport,
            },
            is_outbound: false,
            ip_version: ip_ver,
        })
    } else {
        None
    }
}

pub fn run_sniffer(
    mut backend: impl RawBackend,
    cmd_rx: std::sync::mpsc::Receiver<SnifferCommand>,
    local_ips: Vec<IpAddr>,
    upstream_addrs: Vec<(IpAddr, u16)>,
    stop: Arc<AtomicBool>,
) {
    let local_ips_set: HashSet<IpAddr> = local_ips.into_iter().collect();
    let upstream_set: HashMap<(IpAddr, u16), ()> =
        upstream_addrs.iter().map(|a| (*a, ())).collect();
    let frame_kind = backend.frame_kind();
    let skip_checksum = backend.skip_checksum_on_send();
    let link_len = frame_kind.link_header_len();

    let mut connections: HashMap<ConnId, ConnState> = HashMap::new();
    let mut buf = vec![0u8; 65536];

    info!("sniffer thread started, monitoring {} upstream(s)", upstream_addrs.len());

    loop {
        if stop.load(Ordering::Relaxed) {
            info!("sniffer thread stopping");
            return;
        }

        loop {
            match cmd_rx.try_recv() {
                Ok(SnifferCommand::Register(reg)) => {
                    debug!(
                        src_ip = %reg.conn_id.src_ip,
                        src_port = reg.conn_id.src_port,
                        "registered connection"
                    );
                    let registered_tx = reg.registered_tx;
                    connections.insert(reg.conn_id, ConnState {
                        isn: None,
                        server_isn: None,
                        fake_payload: reg.fake_payload,
                        fake_injected: false,
                        result_tx: reg.result_tx,
                    });
                    let _ = registered_tx.send(());
                }
                Ok(SnifferCommand::Deregister(dereg)) => {
                    debug!(
                        src_ip = %dereg.conn_id.src_ip,
                        src_port = dereg.conn_id.src_port,
                        "deregistered connection"
                    );
                    connections.remove(&dereg.conn_id);
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    info!("command channel closed, sniffer exiting");
                    return;
                }
            }
        }

        let n = match backend.recv_frame(&mut buf) {
            Ok(n) => n,
            Err(crate::error::SnifferError::Recv(ref e))
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => {
                error!("sniffer recv error: {}", e);
                continue;
            }
        };

        let frame = &buf[..n];
        let parsed = match parse_frame(frame, &local_ips_set, &upstream_set, frame_kind) {
            Some(p) => p,
            None => continue,
        };

        let conn = match connections.get_mut(&parsed.outbound_id) {
            Some(c) => c,
            None => continue,
        };

        let tcp_off = match parsed.ip_version {
            IpVersion::V4 => link_len + ipv4::header_len(&frame[link_len..]),
            IpVersion::V6 => link_len + ipv6::IPV6_HEADER_LEN,
        };
        let tcp_hdr = &frame[tcp_off..];
        let fl = tcp::flags(tcp_hdr);
        let seq = tcp::seq_num(tcp_hdr);
        let ack = tcp::ack_num(tcp_hdr);
        let tcp_total_len = frame.len() - tcp_off;
        let plen = tcp::payload_len(tcp_hdr, tcp_total_len);

        if parsed.is_outbound {
            if fl & tcp::SYN != 0 && fl & tcp::ACK == 0 && plen == 0 {
                debug!(port = parsed.outbound_id.src_port, isn = seq, "SYN captured");
                conn.isn = Some(seq);
                continue;
            }

            if fl & tcp::ACK != 0
                && fl & (tcp::SYN | tcp::FIN | tcp::RST) == 0
                && plen == 0
                && !conn.fake_injected
            {
                if let Some(isn) = conn.isn {
                    if seq != isn.wrapping_add(1) {
                        continue;
                    }
                    conn.fake_injected = true;
                    debug!(port = parsed.outbound_id.src_port, "3rd ACK captured, injecting fake");

                    let fake_frame = build_fake_frame(
                        frame, isn, &conn.fake_payload, parsed.ip_version, link_len, skip_checksum,
                    );
                    thread::sleep(Duration::from_millis(1));

                    if let Err(e) = backend.send_frame(&fake_frame) {
                        warn!(port = parsed.outbound_id.src_port, "inject failed: {}", e);
                        let _ = conn.result_tx.blocking_send(SnifferResult::Failed(
                            format!("inject failed: {}", e),
                        ));
                        connections.remove(&parsed.outbound_id);
                    } else {
                        let fake_seq =
                            isn.wrapping_add(1).wrapping_sub(conn.fake_payload.len() as u32);
                        info!(
                            port = parsed.outbound_id.src_port,
                            fake_seq = fake_seq,
                            isn = isn,
                            "fake ClientHello injected"
                        );
                    }
                }
                continue;
            }
        } else {
            if fl & tcp::ACK != 0
                && fl & (tcp::SYN | tcp::FIN | tcp::RST) == 0
                && plen == 0
                && conn.fake_injected
            {
                if let Some(isn) = conn.isn {
                    if ack == isn.wrapping_add(1) {
                        info!(
                            port = parsed.outbound_id.src_port,
                            "server ACK confirmed, fake was ignored"
                        );
                        let _ = conn.result_tx.blocking_send(SnifferResult::FakeConfirmed);
                        connections.remove(&parsed.outbound_id);
                        continue;
                    }
                }
            }

            if fl & tcp::SYN != 0 && fl & tcp::ACK != 0 && plen == 0 {
                if let Some(isn) = conn.isn {
                    if ack == isn.wrapping_add(1) {
                        conn.server_isn = Some(seq);
                        debug!(
                            port = parsed.outbound_id.src_port,
                            server_isn = seq,
                            "SYN-ACK captured"
                        );
                    }
                }
                continue;
            }

            if fl & tcp::RST != 0 {
                warn!(port = parsed.outbound_id.src_port, "RST received from server");
                let _ = conn.result_tx.blocking_send(SnifferResult::Failed(
                    "RST from server".into(),
                ));
                connections.remove(&parsed.outbound_id);
                continue;
            }
        }
    }
}
