use std::io;

pub enum State {
    Closed,
    Listen,
    SynRcvd,
    Estab,
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
}

struct SendSequenceSpace {
    // Send Sequence Space

    //                1         2          3          4
    //           ----------|----------|----------|----------
    //                  SND.UNA    SND.NXT    SND.UNA
    //                                       +SND.WND

    //     1 - old sequence numbers which have been acknowledged
    //     2 - sequence numbers of unacknowledged data
    //     3 - sequence numbers allowed for new data transmission
    //     4 - future sequence numbers which are not yet allowed

    //                       Send Sequence Space

    // send unacknowledged
    una: u32,

    // send next
    nxt: u32,

    // send window
    wnd: u16,

    // send urgent pointer
    up: bool,

    // segment sequence number used for last window update
    wl1: usize,

    // segment acknowledgement number used for last window update
    wl2: usize,

    // initial send sequence number
    iss: u32,
}

struct RecvSequenceSpace {
    // Receive Sequence Space

    //                    1          2          3
    //                ----------|----------|----------
    //                       RCV.NXT    RCV.NXT
    //                                 +RCV.WND

    //     1 - old sequence numbers which have been acknowledged
    //     2 - sequence numbers allowed for new reception
    //     3 - future sequence numbers which are not yet allowed

    //                      Receive Sequence Space

    // receive next
    nxt: u32,

    // receive window
    wnd: u16,

    // receive urgent pointer
    up: bool,

    // initial receive sequence number
    irs: u32,
}

impl Connection {
    pub fn accept<'a>(
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
        eth_header: &'a [u8],
    ) -> io::Result<Option<Self>> {
        // Array to store the packet
        let mut buf = [0u8; 1500];

        let iss = 0;
        let mut c = Connection {
            state: State::SynRcvd,
            send: SendSequenceSpace {
                una: iss,
                nxt: iss + 1,
                wnd: (10),
                up: (false),
                wl1: (0),
                wl2: (0),
                iss: (0),
            },
            recv: RecvSequenceSpace {
                irs: tcph.sequence_number(),
                nxt: tcph.sequence_number() + 1,
                wnd: tcph.window_size(),
                up: false,
            },
        };

        eprintln!(
            "{}:{} -> {}:{} {}b of tcp",
            iph.source_addr(),
            tcph.source_port(),
            iph.destination_addr(),
            tcph.destination_port(),
            data.len(),
        );

        if !tcph.syn() {
            // only expected SYN packet
            return Ok(None);
        }

        // need to establish a TCP connection
        let mut syn_ack = etherparse::TcpHeader::new(
            tcph.destination_port(),
            tcph.source_port(),
            c.send.iss,
            c.send.wnd,
        );

        syn_ack.acknowledgment_number = c.recv.nxt;
        syn_ack.syn = true;
        syn_ack.ack = true;

        let ip_header = etherparse::Ipv4Header::new(
            syn_ack.header_len(),
            64,
            etherparse::IpTrafficClass::Tcp,
            iph.destination_addr().octets(),
            iph.source_addr().octets(),
        );

        // write out the headers
        let unwritten = {
            let mut unwritten = &mut buf[..];

            // writing also sets the checksum and total length of packet
            match ip_header.write(&mut unwritten) {
                Ok(_e) => {}
                Err(e) => {
                    println!("Error writting ip header {:?}", e);
                }
            }
            match syn_ack.write(&mut unwritten) {
                Ok(_e) => {}
                Err(e) => {
                    println!("Error writting tcp header {:?}", e);
                }
            }
            unwritten.len()
        };

        // Concat ethernet headers to packet
        let eth_packet = [&eth_header, &buf[..buf.len() - unwritten]].concat();
        eprintln!("responding with {:02x?}", &eth_packet);
        nic.send(&eth_packet)?;
        
        Ok(Some(c))
    }

    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<()> {
        Ok(())
    }
}
