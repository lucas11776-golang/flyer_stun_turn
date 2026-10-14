use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::runtime::Builder;
use tokio::sync::Mutex;

//
// Initial STUN Attribute Types
//
pub const STUN_ATTRIBUTE_TYPE_RESERVED:           u16 = 0x0000;
pub const STUN_ATTRIBUTE_TYPE_MAPPED_ADDRESS:     u16 = 0x0001;
pub const STUN_ATTRIBUTE_TYPE_RESPONSE_ADDRESS:   u16 = 0x0002;
pub const STUN_ATTRIBUTE_TYPE_CHANGE_ADDRESS:     u16 = 0x0003;
pub const STUN_ATTRIBUTE_TYPE_SOURCE_ADDRESS:     u16 = 0x0004;
pub const STUN_ATTRIBUTE_TYPE_CHANGED_ADDRESS:    u16 = 0x0005;
pub const STUN_ATTRIBUTE_TYPE_USERNAME:           u16 = 0x0006;
pub const STUN_ATTRIBUTE_TYPE_PASSWORD:           u16 = 0x0007;
pub const STUN_ATTRIBUTE_TYPE_MESSAGE_INTEGRITY:  u16 = 0x0008;
pub const STUN_ATTRIBUTE_TYPE_ERROR_CODE:         u16 = 0x0009;
pub const STUN_ATTRIBUTE_TYPE_UNKNOWN_ATTRIBUTES: u16 = 0x000A;
pub const STUN_ATTRIBUTE_TYPE_REFLECTED_FROM:     u16 = 0x000B;
pub const STUN_ATTRIBUTE_TYPE_REALM:              u16 = 0x0014;
pub const STUN_ATTRIBUTE_TYPE_NONCE:              u16 = 0x0015;
pub const STUN_ATTRIBUTE_TYPE_XOR_MAPPED_ADDRESS: u16 = 0x0020;
pub const STUN_ATTRIBUTE_TYPE_SOFTWARE:           u16 = 0x8022;
pub const STUN_ATTRIBUTE_TYPE_ALTERNATE_SERVER:   u16 = 0x8023;
pub const STUN_ATTRIBUTE_TYPE_FINGERPRINT:        u16 = 0x8028;

//
// STUN/TURN Message Types
//
pub const STUN_BINDING_REQUEST:         u16 = 0x0001;
pub const STUN_BINDING_RESPONSE:        u16 = 0x0101;
pub const TURN_ALLOCATE_REQUEST:        u16 = 0x0003;
pub const TURN_ALLOCATE_RESPONSE:       u16 = 0x0103;
pub const TURN_CHANNEL_BIND_REQUEST:    u16 = 0x0009;
pub const TURN_CHANNEL_BIND_RESPONSE:   u16 = 0x0109;
pub const TURN_DATA_INDICATION:         u16 = 0x0017;

///
/// Magic Cookie [TODO: need to check generating random]
/// 
pub const MAGIC_COOKIE: u32 = 0x2112_A442;

///
/// Channel Number
/// 
pub const CHANNEL_NUMBER_START: u16 = 0x4000;
pub const CHANNEL_NUMBER_END:   u16 = 0x7FFF;

///
/// IP version family 
/// 
pub const FAMILY_IP_V4: u8 = 0x01; // IPv4
pub const FAMILY_IP_V6: u8 = 0x02; // IPv6

pub struct Allocation {
    pub relay_socket: Arc<UdpSocket>,
    pub channels: HashMap<u16, SocketAddr>,
}

pub type Allocations = Arc<Mutex<HashMap<SocketAddr, Allocation>>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StunAttribute {
    Reserved,
    MappedAddress(SocketAddr),
    ResponseAddress(SocketAddr),
    ChangeAddress { change_ip: bool, change_port: bool },
    SourceAddress(SocketAddr),
    ChangedAddress(SocketAddr),
    Username(String),
    Password(String),
    MessageIntegrity([u8; 20]),
    ErrorCode { code: u16, reason: String },
    UnknownAttributes(Vec<u16>),
    ReflectedFrom(SocketAddr),
    Realm(String),
    Nonce(String),
    XorMappedAddress(SocketAddr),
    Software(String),
    AlternateServer(SocketAddr),
    Fingerprint(u32),
}

impl StunAttribute {
    pub fn attr_type(&self) -> u16 {
        match self {
            StunAttribute::Reserved             => STUN_ATTRIBUTE_TYPE_RESERVED,
            StunAttribute::MappedAddress(_)     => STUN_ATTRIBUTE_TYPE_MAPPED_ADDRESS,
            StunAttribute::ResponseAddress(_)   => STUN_ATTRIBUTE_TYPE_RESPONSE_ADDRESS,
            StunAttribute::ChangeAddress { .. } => STUN_ATTRIBUTE_TYPE_CHANGE_ADDRESS,
            StunAttribute::SourceAddress(_)     => STUN_ATTRIBUTE_TYPE_SOURCE_ADDRESS,
            StunAttribute::ChangedAddress(_)    => STUN_ATTRIBUTE_TYPE_CHANGED_ADDRESS,
            StunAttribute::Username(_)          => STUN_ATTRIBUTE_TYPE_USERNAME,
            StunAttribute::Password(_)          => STUN_ATTRIBUTE_TYPE_PASSWORD,
            StunAttribute::MessageIntegrity(_)  => STUN_ATTRIBUTE_TYPE_MESSAGE_INTEGRITY,
            StunAttribute::ErrorCode { .. }     => STUN_ATTRIBUTE_TYPE_ERROR_CODE,
            StunAttribute::UnknownAttributes(_) => STUN_ATTRIBUTE_TYPE_UNKNOWN_ATTRIBUTES,
            StunAttribute::ReflectedFrom(_)     => STUN_ATTRIBUTE_TYPE_REFLECTED_FROM,
            StunAttribute::Realm(_)             => STUN_ATTRIBUTE_TYPE_REALM,
            StunAttribute::Nonce(_)             => STUN_ATTRIBUTE_TYPE_NONCE,
            StunAttribute::XorMappedAddress(_)  => STUN_ATTRIBUTE_TYPE_XOR_MAPPED_ADDRESS,
            StunAttribute::Software(_)          => STUN_ATTRIBUTE_TYPE_SOFTWARE,
            StunAttribute::AlternateServer(_)   => STUN_ATTRIBUTE_TYPE_ALTERNATE_SERVER,
            StunAttribute::Fingerprint(_)       => STUN_ATTRIBUTE_TYPE_FINGERPRINT,
        }
    }

    pub fn parse(attr_type: u16, data: &[u8], magic_cookie: u32, tx_id: &[u8; 12]) -> Result<Self, &'static str> {
        match attr_type {
            STUN_ATTRIBUTE_TYPE_RESERVED => {
                Ok(StunAttribute::Reserved)
            },

            STUN_ATTRIBUTE_TYPE_MAPPED_ADDRESS => {
                Ok(StunAttribute::MappedAddress(decode_address(data)?))
            },

            STUN_ATTRIBUTE_TYPE_RESPONSE_ADDRESS => {
                Ok(StunAttribute::ResponseAddress(decode_address(data)?))
            },

            STUN_ATTRIBUTE_TYPE_CHANGE_ADDRESS => {
                if data.len() < 4 {
                    return Err("Invalid CHANGE-ADDRESS payload length");
                }

                let val = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);

                Ok(StunAttribute::ChangeAddress {
                    change_ip: (val & 0x04) != 0,
                    change_port: (val & 0x02) != 0,
                })
            },

            STUN_ATTRIBUTE_TYPE_SOURCE_ADDRESS => {
                Ok(StunAttribute::SourceAddress(decode_address(data)?))
            },

            STUN_ATTRIBUTE_TYPE_CHANGED_ADDRESS => {
                Ok(StunAttribute::ChangedAddress(decode_address(data)?))
            },

            STUN_ATTRIBUTE_TYPE_USERNAME => {
                let text = std::str::from_utf8(data).map_err(|_| "Invalid UTF-8 username")?;
                Ok(StunAttribute::Username(text.to_string()))
            },

            STUN_ATTRIBUTE_TYPE_PASSWORD => {
                let text = std::str::from_utf8(data).map_err(|_| "Invalid UTF-8 password")?;
                Ok(StunAttribute::Password(text.to_string()))
            },

            STUN_ATTRIBUTE_TYPE_MESSAGE_INTEGRITY => {
                if data.len() != 20 {
                    return Err("MESSAGE-INTEGRITY must be 20 bytes");
                }

                let mut hash = [0u8; 20];

                hash.copy_from_slice(data);
                Ok(StunAttribute::MessageIntegrity(hash))
            },

            STUN_ATTRIBUTE_TYPE_ERROR_CODE => {
                if data.len() < 4 {
                    return Err("Invalid ERROR-CODE payload length");
                }

                let class = (data[2] & 0x07) as u16;
                let number = (data[3] % 100) as u16;
                let code = class * 100 + number;
                let reason = std::str::from_utf8(&data[4..])
                    .map_err(|_| "Invalid UTF-8 error reason")?
                    .to_string();

                Ok(StunAttribute::ErrorCode { code, reason })
            },

            STUN_ATTRIBUTE_TYPE_UNKNOWN_ATTRIBUTES => {
                if data.len() % 2 != 0 {
                    return Err("Invalid UNKNOWN-ATTRIBUTES payload length");
                }

                let mut attrs = Vec::with_capacity(data.len() / 2);

                for chunk in data.chunks_exact(2) {
                    attrs.push(u16::from_be_bytes([chunk[0], chunk[1]]));
                }

                Ok(StunAttribute::UnknownAttributes(attrs))
            },

            STUN_ATTRIBUTE_TYPE_REFLECTED_FROM => {
                Ok(StunAttribute::ReflectedFrom(decode_address(data)?))
            },

            STUN_ATTRIBUTE_TYPE_REALM => {
                let text = std::str::from_utf8(data).map_err(|_| "Invalid UTF-8 realm")?;

                Ok(StunAttribute::Realm(text.to_string()))
            },

            STUN_ATTRIBUTE_TYPE_NONCE => {
                let text = std::str::from_utf8(data).map_err(|_| "Invalid UTF-8 nonce")?;

                Ok(StunAttribute::Nonce(text.to_string()))
            },

            STUN_ATTRIBUTE_TYPE_XOR_MAPPED_ADDRESS => {
                Ok(StunAttribute::XorMappedAddress(
                    decode_xor_address(data, magic_cookie, tx_id)?,
                ))
            },

            STUN_ATTRIBUTE_TYPE_SOFTWARE => {
                let text = std::str::from_utf8(data).map_err(|_| "Invalid UTF-8 software string")?;

                Ok(StunAttribute::Software(text.to_string()))
            },

            STUN_ATTRIBUTE_TYPE_ALTERNATE_SERVER => {
                Ok(StunAttribute::AlternateServer(decode_address(data)?))
            },

            STUN_ATTRIBUTE_TYPE_FINGERPRINT => {
                if data.len() != 4 {
                    return Err("FINGERPRINT must be 4 bytes");
                }
                
                let val = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);

                Ok(StunAttribute::Fingerprint(val))
            }
            
            _ => Err("Unsupported STUN attribute type"),
        }
    }

    pub fn encode(&self, out: &mut Vec<u8>, magic_cookie: u32, tx_id: &[u8; 12]) {
        let attr_type = self.attr_type();
        let start_pos = out.len();

        out.extend_from_slice(&attr_type.to_be_bytes());
        out.extend_from_slice(&[0, 0]);

        let val_start = out.len();

        match self {
            StunAttribute::Reserved => {},

            StunAttribute::MappedAddress(addr)
                | StunAttribute::ResponseAddress(addr)
                | StunAttribute::SourceAddress(addr)
                | StunAttribute::ChangedAddress(addr)
                | StunAttribute::ReflectedFrom(addr)
                | StunAttribute::AlternateServer(addr) =>
            {
                encode_address(addr, out);
            },
            
            StunAttribute::ChangeAddress { change_ip, change_port } =>
            {
                let mut flags = 0u32;
                if *change_ip { flags |= 0x04; }
                if *change_port { flags |= 0x02; }
                out.extend_from_slice(&flags.to_be_bytes());
            },

            StunAttribute::Username(text)
                | StunAttribute::Password(text)
                | StunAttribute::Realm(text)
                | StunAttribute::Nonce(text)
                | StunAttribute::Software(text) =>
            {
                out.extend_from_slice(text.as_bytes());
            },

            StunAttribute::MessageIntegrity(hash) =>
            {
                out.extend_from_slice(hash);
            },

            StunAttribute::ErrorCode { code, reason } =>
            {
                out.push(0x00);
                out.push(0x00);
                out.push(((code / 100) & 0x07) as u8);
                out.push((code % 100) as u8);
                out.extend_from_slice(reason.as_bytes());
            },

            StunAttribute::UnknownAttributes(attrs) =>
            {
                for attr in attrs {
                    out.extend_from_slice(&attr.to_be_bytes());
                }
            },

            StunAttribute::XorMappedAddress(addr) =>
            {
                encode_xor_address(addr, out, magic_cookie, tx_id);
            },

            StunAttribute::Fingerprint(crc) =>
            {
                out.extend_from_slice(&crc.to_be_bytes());
            }
        }

        let val_len = out.len() - val_start;

        out[start_pos + 2..start_pos + 4].copy_from_slice(&(val_len as u16).to_be_bytes());

        let pad_len = (4 - (val_len % 4)) % 4;

        out.extend(std::iter::repeat(0u8).take(pad_len));
    }
}

pub fn decode_address(data: &[u8]) -> Result<SocketAddr, &'static str> {
    if data.len() < 4 { return Err("Address header too short"); }
    let family = data[1];
    let port = u16::from_be_bytes([data[2], data[3]]);

    match family {
        0x01 => {
            if data.len() < 8 { return Err("IPv4 address payload too short"); }
            let ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        }
        0x02 => {
            if data.len() < 20 { return Err("IPv6 address payload too short"); }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[4..20]);
            let ip = Ipv6Addr::from(octets);
            Ok(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
        }
        _ => Err("Invalid address family"),
    }
}

pub fn encode_address(addr: &SocketAddr, out: &mut Vec<u8>) {
    out.push(0x00);
    match addr {
        SocketAddr::V4(v4) => {
            out.push(FAMILY_IP_V4);
            out.extend_from_slice(&v4.port().to_be_bytes());
            out.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            out.push(FAMILY_IP_V6);
            out.extend_from_slice(&v6.port().to_be_bytes());
            out.extend_from_slice(&v6.ip().octets());
        }
    }
}

pub fn decode_xor_address(data: &[u8], magic_cookie: u32, tx_id: &[u8; 12]) -> Result<SocketAddr, &'static str> {
    if data.len() < 4 { 
        return Err("XOR Address header too short");
    }

    let family = data[1];
    let raw_port = u16::from_be_bytes([data[2], data[3]]);
    let port = raw_port ^ ((magic_cookie >> 16) as u16);

    match family {
        FAMILY_IP_V4 => {
            if data.len() < 8 {
                return Err("XOR IPv4 address payload too short"); 
            }

            let mc_bytes = magic_cookie.to_be_bytes();
            let ip = Ipv4Addr::new(
                data[4] ^ mc_bytes[0],
                data[5] ^ mc_bytes[1],
                data[6] ^ mc_bytes[2],
                data[7] ^ mc_bytes[3],
            );

            Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        },
        
        FAMILY_IP_V6 => {
            if data.len() < 20 { return Err("XOR IPv6 address payload too short"); }
            let mut xor_key = [0u8; 16];

            xor_key[..4].copy_from_slice(&magic_cookie.to_be_bytes());
            xor_key[4..16].copy_from_slice(tx_id);

            let mut octets = [0u8; 16];

            for i in 0..16 {
                octets[i] = data[4 + i] ^ xor_key[i];
            }

            let ip = Ipv6Addr::from(octets);
            
            Ok(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
        },

        _ => Err("Invalid XOR address family"),
    }
}

fn encode_xor_address(addr: &SocketAddr, out: &mut Vec<u8>, magic_cookie: u32, tx_id: &[u8; 12]) {
    out.push(0x00);
    
    let xor_port = addr.port() ^ ((magic_cookie >> 16) as u16);

    match addr {
        SocketAddr::V4(v4) => {
            out.push(FAMILY_IP_V4);
            out.extend_from_slice(&xor_port.to_be_bytes());
            
            let mc_bytes = magic_cookie.to_be_bytes();

            for (i, octet) in v4.ip().octets().iter().enumerate() {
                out.push(octet ^ mc_bytes[i]);
            }
        },

        SocketAddr::V6(v6) => {
            out.push(FAMILY_IP_V6);
            out.extend_from_slice(&xor_port.to_be_bytes());

            let mut xor_key = [0u8; 16];
            
            xor_key[..4].copy_from_slice(&magic_cookie.to_be_bytes());
            xor_key[4..16].copy_from_slice(tx_id);

            for (i, octet) in v6.ip().octets().iter().enumerate() {
                out.push(octet ^ xor_key[i]);
            }
        }
    }
}

pub fn parse_stun_packet(buf: &[u8]) -> Option<(u16, [u8; 12], Vec<StunAttribute>)> {
    if buf.len() < 20 {
        return None;
    }

    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let magic = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);

    if magic != MAGIC_COOKIE || buf.len() < 20 + msg_len {
        return None;
    }

    let mut tx_id = [0u8; 12];
    tx_id.copy_from_slice(&buf[8..20]);

    let mut offset = 20;
    let mut attributes = Vec::new();

    while offset + 4 <= 20 + msg_len {
        let attr_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let attr_len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
        let val_start = offset + 4;

        if val_start + attr_len > 20 + msg_len { break; }

        let val_slice = &buf[val_start..val_start + attr_len];
        if let Ok(attr) = StunAttribute::parse(attr_type, val_slice, MAGIC_COOKIE, &tx_id) {
            attributes.push(attr);
        }

        let pad_len = (4 - (attr_len % 4)) % 4;
        offset = val_start + attr_len + pad_len;
    }

    Some((msg_type, tx_id, attributes))
}

pub fn build_stun_packet(msg_type: u16, tx_id: &[u8; 12], attributes: &[StunAttribute]) -> Vec<u8> {
    let mut payload = Vec::new();
    
    for attr in attributes {
        attr.encode(&mut payload, MAGIC_COOKIE, tx_id);
    }

    let mut packet = Vec::with_capacity(20 + payload.len());

    packet.extend_from_slice(&msg_type.to_be_bytes());
    packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    packet.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    packet.extend_from_slice(tx_id);
    packet.extend_from_slice(&payload);

    packet
}

pub struct ServerConfig {
    host: String,
    port: u64,
    // TODO: need to add SSL
    key_path: Option<String>,
    cert_path: Option<String>,
}

pub struct Server {
    config: ServerConfig,
    allocations: Allocations,
}

impl Server {
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config: config,
            allocations: Default::default(),
        }
    }

    pub fn address(&self) -> String {
        format!("{}:{}", self.config.host, self.config.port)
    }

    async fn receive(&mut self, socket: Arc<UdpSocket>) {
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


            // ChannelData message routing
            if (CHANNEL_NUMBER_START ..=CHANNEL_NUMBER_END).contains(&first_two) {
                let channel_num = first_two;
                let data_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;

                if len >= 4 + data_len {
                    let payload = &buf[4..4 + data_len];
                    let allocs = self.allocations.lock().await;

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
                        StunAttribute::Software(String::from("Flyer STUN Server")),
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

                    self.allocations.lock().await.insert(
                        client_addr,
                        Allocation {
                            relay_socket: Arc::clone(&relay_socket),
                            channels: HashMap::new(),
                        },
                    );

                    let main_socket = Arc::clone(&socket);
                    let allocs_clone = Arc::clone(&self.allocations);

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
                        let mut allocs = self.allocations.lock().await;
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

    pub fn listen(&mut self) {
        Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                self.receive(Arc::new(UdpSocket::bind(&self.address()).await.unwrap())).await;
            });
    }
}


pub fn server(host: impl Into<String>, port: u64) -> Server {
    Server::new(ServerConfig {
        host: host.into(),
        port: port,
        key_path: None,
        cert_path: None,
    })
}


pub fn server_tls(host: impl Into<String>, port: u64, key_path: impl Into<String>, cert_path: impl Into<String>) -> Server {
    Server::new(ServerConfig {
        host: host.into(),
        port: port,
        key_path: Some(key_path.into()),
        cert_path: Some(cert_path.into()),
    })
}