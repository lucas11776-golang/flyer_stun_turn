use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use flyer::utils::env::{env, load};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

///
/// Initial STUN Attributes types
/// 
const STUN_ATTRIBUTE_TYPE_RESERVED:           u16 = 0x0000; 
const STUN_ATTRIBUTE_TYPE_MAPPED_ADDRESS:     u16 = 0x0001;
const STUN_ATTRIBUTE_TYPE_RESPONSE_ADDRESS:   u16 = 0x0002;
const STUN_ATTRIBUTE_TYPE_CHANGE_ADDRESS:     u16 = 0x0003;
const STUN_ATTRIBUTE_TYPE_SOURCE_ADDRESS:     u16 = 0x0004;
const STUN_ATTRIBUTE_TYPE_CHANGED_ADDRESS:    u16 = 0x0005;
const STUN_ATTRIBUTE_TYPE_USERNAME:           u16 = 0x0006;
const STUN_ATTRIBUTE_TYPE_PASSWORD:           u16 = 0x0007;
const STUN_ATTRIBUTE_TYPE_MESSAGE_INTEGRITY:  u16 = 0x0008;
const STUN_ATTRIBUTE_TYPE_ERROR_CODE:         u16 = 0x0009;
const STUN_ATTRIBUTE_TYPE_UNKNOWN_ATTRIBUTES: u16 = 0x000A;
const STUN_ATTRIBUTE_TYPE_REFLECTED_FROM:     u16 = 0x000B;
const STUN_ATTRIBUTE_TYPE_REALM:              u16 = 0x0014;
const STUN_ATTRIBUTE_TYPE_NONCE:              u16 = 0x0015;
const STUN_ATTRIBUTE_TYPE_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const STUN_ATTRIBUTE_TYPE_SOFTWARE:           u16 = 0x8022;
const STUN_ATTRIBUTE_TYPE_ALTERNATE_SERVER:   u16 = 0x8023;
const STUN_ATTRIBUTE_TYPE_FINGERPRINT:        u16 = 0x8028;

///
/// 
/// 
const MAGIC_COOKIE: u32 = 0x2112_A442;

///
/// Channel Number
/// 
const CHANNEL_NUMBER_START: u16 = 0x4000;
const CHANNEL_NUMBER_END:   u16 = 0x4000;

struct Allocation {
    relay_socket: Arc<UdpSocket>,
    channels: HashMap<u16, SocketAddr>,
}

type Allocations = Arc<Mutex<HashMap<SocketAddr, Allocation>>>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    load(".env");

    let bind_addr = format!("{}:{}", env("HOST"), env("STUN_HOST_PORT"));
    let socket = Arc::new(UdpSocket::bind(bind_addr).await?);

    let allocations: Allocations = Arc::new(Mutex::new(HashMap::new()));
    let mut buf = [0u8; 4096];

    loop {
        let (len, client_addr) = match socket.recv_from(&mut buf).await {
            Ok(res) => res,
            Err(_) => continue,
        };

        if len < 4 {
            continue;
        }

        let first_two = u16::from_be_bytes([buf[0], buf[1]]);
        if (CHANNEL_NUMBER_START..=CHANNEL_NUMBER_END).contains(&first_two) {
            let channel_num = first_two;
            let data_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;

            if len >= 4 + data_len {
                let payload = &buf[4..4 + data_len];
                let allocs = allocations.lock().await;

                if let Some(alloc) = allocs.get(&client_addr) {
                    if let Some(peer_addr) = alloc.channels.get(&channel_num) {
                        alloc.relay_socket.send_to(payload, peer_addr).await.unwrap();
                    }
                }
            }
            
            continue;
        }

        if len < 20 {
            continue;
        }

        let magic = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);

        if magic != MAGIC_COOKIE {
            continue;
        }

        let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
        let mut tx_id = [0u8; 12];

        tx_id.copy_from_slice(&buf[8..20]);

        match msg_type {
            STUN_ATTRIBUTE_TYPE_MAPPED_ADDRESS => {
                let response = build_stun_binding_response(&tx_id, &client_addr);
                let _ = socket.send_to(&response, client_addr).await;
            }

            STUN_ATTRIBUTE_TYPE_CHANGE_ADDRESS => {
                let relay_socket = match UdpSocket::bind("0.0.0.0:0").await {
                    Ok(s) => Arc::new(s),
                    Err(_) => continue,
                };

                let relay_addr = match relay_socket.local_addr() {
                    Ok(addr) => addr,
                    Err(_) => continue,
                };

                allocations.lock().await.insert(
                    client_addr,
                    Allocation {
                        relay_socket: Arc::clone(&relay_socket),
                        channels: HashMap::new(),
                    },
                );

                let main_socket = Arc::clone(&socket);
                let allocs_clone = Arc::clone(&allocations);
                tokio::spawn(async move {
                    let mut relay_buf = [0u8; 4096];

                    loop {
                        if let Ok((r_len, peer_addr)) = relay_socket.recv_from(&mut relay_buf).await {
                            let allocs = allocs_clone.lock().await;

                            if let Some(alloc) = allocs.get(&client_addr) {
                                if let Some((&chan, _)) = alloc.channels.iter().find(|(_, addr)| **addr == peer_addr) {
                                    let mut frame = Vec::with_capacity(4 + r_len);

                                    frame.extend_from_slice(&chan.to_be_bytes());
                                    frame.extend_from_slice(&(r_len as u16).to_be_bytes());
                                    frame.extend_from_slice(&relay_buf[..r_len]);

                                    main_socket.send_to(&frame, client_addr).await.unwrap();
                                } else {
                                    let indication = build_turn_data_indication(&peer_addr, &relay_buf[..r_len]);

                                    main_socket.send_to(&indication, client_addr).await.unwrap();
                                }
                            }
                        } else {
                            break;
                        }
                    }
                });

                let response = build_turn_allocate_response(&tx_id, &client_addr, &relay_addr);

                socket.send_to(&response, client_addr).await.unwrap();
            }

            STUN_ATTRIBUTE_TYPE_MESSAGE_INTEGRITY => {
                let response = build_simple_success_response(0x0108, &tx_id);
                let _ = socket.send_to(&response, client_addr).await;
            }

            STUN_ATTRIBUTE_TYPE_ERROR_CODE => {
                if let Some((channel_num, peer_addr)) = parse_channel_bind(&buf[..len]) {
                    let mut allocs = allocations.lock().await;

                    if let Some(alloc) = allocs.get_mut(&client_addr) {
                        alloc.channels.insert(channel_num, peer_addr);
                    }
                }

                let response = build_simple_success_response(0x0109, &tx_id);

                socket.send_to(&response, client_addr).await.unwrap();
            }

            _ => {}
        }
    }
}

fn parse_channel_bind(buf: &[u8]) -> Option<(u16, SocketAddr)> {
    if buf.len() < 20 { return None; }
    let mut offset = 20;
    let mut channel_num = None;
    let mut peer_addr = None;

    while offset + 4 <= buf.len() {
        let attr_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let attr_len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
        let val_start = offset + 4;

        if val_start + attr_len > buf.len() {
            break;
        }

        if attr_type == 0x000C && attr_len >= 2 {
            channel_num = Some(u16::from_be_bytes([buf[val_start], buf[val_start + 1]]));
        } else if attr_type == 0x0012 && attr_len >= 8 {
            let val = &buf[val_start..val_start + attr_len];
            if val[1] == 0x01 {
                let port = u16::from_be_bytes([val[2], val[3]]) ^ ((MAGIC_COOKIE >> 16) as u16);
                let magic_bytes = MAGIC_COOKIE.to_be_bytes();
                let ip = [
                    val[4] ^ magic_bytes[0],
                    val[5] ^ magic_bytes[1],
                    val[6] ^ magic_bytes[2],
                    val[7] ^ magic_bytes[3],
                ];
                peer_addr = Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port)));
            }
        }
        offset += 4 + ((attr_len + 3) & !3);
    }

    let (Some(chan), Some(peer)) = (channel_num, peer_addr) else {
        return None
    };

    Some((chan, peer))
}

fn build_stun_binding_response(tx_id: &[u8; 12], client_addr: &SocketAddr) -> Vec<u8> {
    let mut payload = Vec::new();

    encode_xor_address(STUN_ATTRIBUTE_TYPE_XOR_MAPPED_ADDRESS, client_addr, &mut payload);
    build_packet(0x0101, tx_id, &payload)
}

fn build_turn_allocate_response(tx_id: &[u8; 12], client_addr: &SocketAddr, relay_addr: &SocketAddr) -> Vec<u8> {
    let mut payload = Vec::new();

    encode_xor_address(STUN_ATTRIBUTE_TYPE_XOR_MAPPED_ADDRESS, client_addr, &mut payload);
    encode_xor_address(0x0016, relay_addr, &mut payload);
    payload.extend_from_slice(&0x000Du16.to_be_bytes());
    payload.extend_from_slice(&4u16.to_be_bytes());
    payload.extend_from_slice(&600u32.to_be_bytes());
    build_packet(0x0103, tx_id, &payload)
}

fn build_simple_success_response(msg_type: u16, tx_id: &[u8; 12]) -> Vec<u8> {
    build_packet(msg_type, tx_id, &[])
}

fn build_turn_data_indication(peer_addr: &SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut attrs = Vec::new();

    encode_xor_address(0x0012, peer_addr, &mut attrs);
    attrs.extend_from_slice(&0x0013u16.to_be_bytes());
    attrs.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    attrs.extend_from_slice(payload);
    
    let pad = (4 - (payload.len() % 4)) % 4;

    attrs.extend(std::iter::repeat(0u8).take(pad));
    build_packet(0x0017, &[0u8; 12], &attrs)
}

fn encode_xor_address(attr_type: u16, addr: &SocketAddr, out: &mut Vec<u8>) {
    out.extend_from_slice(&attr_type.to_be_bytes());
    out.extend_from_slice(&8u16.to_be_bytes());
    out.push(0x00);
    out.push(0x01);

    let port = addr.port() ^ ((MAGIC_COOKIE >> 16) as u16);

    out.extend_from_slice(&port.to_be_bytes());

    let ip = match addr.ip() {
        std::net::IpAddr::V4(ip) => ip,
        _ => Ipv4Addr::UNSPECIFIED,
    };

    let magic_bytes = MAGIC_COOKIE.to_be_bytes();

    for i in 0..4 {
        out.push(ip.octets()[i] ^ magic_bytes[i]);
    }
}

fn build_packet(msg_type: u16, tx_id: &[u8; 12], payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(20 + payload.len());

    packet.extend_from_slice(&msg_type.to_be_bytes());
    packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    packet.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    packet.extend_from_slice(tx_id);
    packet.extend_from_slice(payload);

    packet
}