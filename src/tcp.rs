use std::io;

pub enum State {
    Closed,
    Listen,
    SynRcvd,
    Estab,
}

pub struct Connection {
    state: State,
}

impl Default for Connection {
    fn default() -> Self {
        Connection { 
            state: State::Listen
        }
    }
}

impl State {
    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<usize> {
        let mut buf = [0u8; 1500];

        eprintln!(
            "{}:{} -> {}:{} {}b of tcp",
            iph.source_addr(),
            tcph.source_port(),
            iph.destination_addr(),
            tcph.destination_port(),
            data.len(),
        );

        match *self {
            State::Closed => {
                return Ok(0);
            }
            State::Estab => {
                return Ok(0);
            }
            State::SynRcvd => {
                return Ok(0);
            }
            State::Listen => {
                if !tcph.syn() {
                    // only expected SYN packet
                    return Ok(0);
                }

                // need to establish a TCP connection\
                let mut syn_ack = etherparse::TcpHeader::new(
                    tcph.destination_port(),
                    tcph.source_port(),
                    unimplemented!(),
                    unimplemented!(),
                );

                syn_ack.syn = true;
                syn_ack.ack = true;

                let mut ip_header = etherparse::Ipv4Header::new(
                    syn_ack.header_len(),
                    64,
                    etherparse::IpTrafficClass::Tcp,
                    iph.destination_addr().octets(),
                    iph.source_addr().octets(),
                );

                // write out the headers
                let unwritten = {
                    let mut unwritten = &mut buf[..];
                    ip_header.write(&mut unwritten);
                    syn_ack.write(&mut unwritten);
                    unwritten.len()
                };
                nic.send(&buf[..unwritten])
            }
        }
    }
}
