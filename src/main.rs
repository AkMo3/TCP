extern crate tun_tap;
use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;

mod tcp;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
struct Quad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

fn main() -> io::Result<()> {

    let mut connections: HashMap<Quad, tcp::State> = Default::default();

    let mut nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)?;
    let mut buf = [0u8; 1504];
    loop {
        let nbytes = nic.recv(&mut buf[..])?;
        let _eth_flags = u16::from_be_bytes([buf[0], buf[1]]);
        let eth_proto = u16::from_be_bytes([buf[2], buf[3]]);

        if eth_proto != 0x0800 {
            // Packet received is not a ipv4 packet
            continue;
        }

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[4..nbytes]) {
            Ok(ip_header) => {
                let src = ip_header.source_addr();
                let dst = ip_header.destination_addr();
                let proto = ip_header.protocol();

                if proto != 0x06 {
                    // Packet not of TCP protocol
                    continue; 
                }

                let ip_header_size = 4 + ip_header.slice().len();

                match etherparse::TcpHeaderSlice::from_slice(&buf[4 + ip_header.slice().len()..]) {
                    Ok(tcp_slice) => {

                        let tcp_ip_header_size = ip_header_size + tcp_slice.slice().len();

                        connections.entry(Quad {
                            src: (src, tcp_slice.source_port()),
                            dst: (dst, tcp_slice.destination_port()),
                        }).or_default().on_packet(&mut nic, ip_header, tcp_slice, &buf[tcp_ip_header_size..nbytes]);

                    },
                    Err(ignore) => {
                        eprintln!("ip packet cannot be sliced into tcp {:?}", ignore);
                    }
                }

            }
            Err(e) => {
                eprintln!("ignoring weird packet {:?}", e);
            }
        }
    }
}
