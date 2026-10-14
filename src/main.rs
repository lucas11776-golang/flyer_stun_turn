use std::error::Error;
use tun_rs::DeviceBuilder;

enum Action {
    Allow,
    Drop,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let dev = DeviceBuilder::new()
        .ipv4("10.8.0.1", 24, None)
        .build_sync()?;

    let mut buf = vec![0u8; 65536];

    loop {
        let len = match dev.recv(&mut buf) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("Error reading from TUN device: {}", e);
                continue;
            }
        };

        let packet = &buf[..len];

        match is_packet_allowed(packet) {
            Action::Allow => {
                if let Err(e) = dev.send(packet) {
                    eprintln!("Failed to write packet back: {}", e);
                }
            },
            Action::Drop => {
                println!("[Packet]: blocked now allowed by rules..");
            },
        }
    }
}


fn is_packet_allowed(packet: &[u8]) -> Action {
    let slice = etherparse::SlicedPacket::from_ip(packet)
        .ok()
        .unwrap();

    println!("INCOMING PACKET");

    let Some(payload) = slice.net else {
        return Action::Drop
    };

    match payload {
        etherparse::NetSlice::Ipv4(_ipv4) => {
            Action::Allow
        },
        etherparse::NetSlice::Ipv6(_ipv6) => {
            Action::Allow
        },
        etherparse::NetSlice::Arp(_arp) => {
            Action::Allow
        },
    }
}