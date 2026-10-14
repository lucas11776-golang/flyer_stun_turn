use flyer::server;
use flyer::utils::env::{env, load};

///
/// TODO:
/// 
/// fn server     [host:String, port:u64]                          -> Server
/// fn server_tls [host:String, port:u64, key:String, cert:String] -> Server
/// fn listen     []                                               -> Void
/// 
/// 
fn main() {
    load(".env");

    let server = server(env("HOST"),  env("STUN_HOST_PORT").parse().unwrap());

    println!("\r\n\r\nRunning Server: {}\r\n\r\n", server.address());
    
    server.listen();
}
