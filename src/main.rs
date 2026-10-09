use std::collections::HashMap;
use std::sync::Arc;
use flyer::utils::env::{env, load};
use flyer_stun_turn::{
    Allocation,
    Allocations,
    CHANNEL_NUMBER_END,
    CHANNEL_NUMBER_START,
    STUN_BINDING_RESPONSE,
    StunAttribute,
    TURN_ALLOCATE_RESPONSE,
    TURN_CHANNEL_BIND_REQUEST,
    TURN_CHANNEL_BIND_RESPONSE,
    STUN_BINDING_REQUEST,
    TURN_DATA_INDICATION,
    TURN_ALLOCATE_REQUEST,
    build_stun_packet,
    parse_stun_packet,
};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

///
/// TODO:
/// 
/// fn server     [host:String, port:u64]                          -> Server
/// fn server_tls [host:String, port:u64, key:String, cert:String] -> Server
/// 
/// 
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    load(".env");

    let bind_addr = format!("{}:{}", env("HOST"), env("STUN_HOST_PORT"));
    let socket = Arc::new(UdpSocket::bind(&bind_addr).await?);

    let allocations: Allocations = Arc::new(Mutex::new(HashMap::new()));
    let mut buf = [0u8; 4096];

    loop {
        let (len, client_addr) = match socket.recv_from(&mut buf).await {
            Ok(res) => res,
            Err(_) => continue,
        };

        if len < 4 { continue; }

        let first_two = u16::from_be_bytes([buf[0], buf[1]]);

        // ChannelData message routing
        if (CHANNEL_NUMBER_START ..=CHANNEL_NUMBER_END).contains(&first_two) {
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

        let (msg_type, tx_id, attributes) = match parse_stun_packet(&buf[..len]) {
            Some(parsed) => parsed,
            None => continue,
        };

        match msg_type {
            STUN_BINDING_REQUEST => {
                let response_attrs = vec![
                    StunAttribute::XorMappedAddress(client_addr),
                    StunAttribute::MappedAddress(client_addr),
                    StunAttribute::Software("Flyer STUN Server v1.0".to_string()),
                ];

                let response = build_stun_packet(STUN_BINDING_RESPONSE, &tx_id, &response_attrs);

                socket.send_to(&response, client_addr).await.unwrap();
            }

            TURN_ALLOCATE_REQUEST => {
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
                                    let indication_attrs = vec![
                                        StunAttribute::XorMappedAddress(peer_addr),
                                    ];
                                    let indication = build_stun_packet(TURN_DATA_INDICATION, &[0u8; 12], &indication_attrs);
                                    main_socket.send_to(&indication, client_addr).await.unwrap();
                                }
                            }
                        } else {
                            break;
                        }
                    }
                });

                let response_attrs = vec![
                    StunAttribute::XorMappedAddress(client_addr),
                    StunAttribute::XorMappedAddress(relay_addr),
                    StunAttribute::Software("Flyer TURN Relay".to_string()),
                ];

                let response = build_stun_packet(TURN_ALLOCATE_RESPONSE, &tx_id, &response_attrs);

                socket.send_to(&response, client_addr).await.unwrap();
            }

            TURN_CHANNEL_BIND_REQUEST => {
                let channel_num = None;
                let mut peer_addr = None;

                for attr in &attributes {
                    if let StunAttribute::XorMappedAddress(addr) = attr {
                        peer_addr = Some(*addr);
                    }
                }

                if let (Some(chan), Some(peer)) = (channel_num, peer_addr) {
                    let mut allocs = allocations.lock().await;
                    if let Some(alloc) = allocs.get_mut(&client_addr) {
                        alloc.channels.insert(chan, peer);
                    }
                }

                let response = build_stun_packet(TURN_CHANNEL_BIND_RESPONSE, &tx_id, &[]);

                socket.send_to(&response, client_addr).await.unwrap();
            }

            _ => {}
        }
    }
}