use std::io::{self, Write};

pub enum State {
    Closed,
    SynRcvd,
    Estab,
    FinWait1,
    FinWait2,
    TimeWait,
}

impl State {
    fn is_syncronised(&self) -> bool {
        match *self {
            State::Estab => true,
            State::SynRcvd
            | State::Closed
            | State::FinWait1
            | State::TimeWait
            | State::FinWait2 => false,
        }
    }
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    ip_header: etherparse::Ipv4Header,
    tcp_header: etherparse::TcpHeader,
    eth_header: [u8; 4],
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
        eth_header: &'a [u8; 4],
    ) -> io::Result<Option<Self>> {
        let iss = 0;
        let wnd = 1024;
        let mut c = Connection {
            state: State::SynRcvd,
            send: SendSequenceSpace {
                una: iss,
                nxt: iss,
                wnd: wnd,
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

            ip_header: etherparse::Ipv4Header::new(
                0,
                64,
                etherparse::IpTrafficClass::Tcp,
                iph.destination_addr().octets(),
                iph.source_addr().octets(),
            ),

            // need to establish a TCP connection
            tcp_header: etherparse::TcpHeader::new(
                tcph.destination_port(),
                tcph.source_port(),
                iss,
                wnd,
            ),
            eth_header: *eth_header,
        };

        c.tcp_header.syn = true;
        c.tcp_header.ack = true;
        c.write(nic, &[])?;

        Ok(Some(c))
    }

    fn write(&mut self, nic: &mut tun_tap::Iface, payload: &[u8]) -> io::Result<usize> {
        // Array to store the packet
        let mut buf = [0u8; 1500];
        self.tcp_header.sequence_number = self.send.nxt;
        self.tcp_header.acknowledgment_number = self.recv.nxt;
        let size = std::cmp::min(
            buf.len(),
            self.tcp_header.header_len() as usize + self.ip_header.header_len() + payload.len(),
        );
        self.ip_header
            .set_payload_len(size - self.ip_header.header_len()).expect("Cannot set ip payload length");

        self.tcp_header.checksum = self
            .tcp_header
            .calc_checksum_ipv4(&self.ip_header, &[])
            .expect("Failed to compute checksum");

        let mut unwritten = &mut buf[..];

        // writing also sets the checksum and total length of packet
        match self.ip_header.write(&mut unwritten) {
            Ok(_e) => {}
            Err(e) => {
                println!("Error writting ip header {:?}", e);
            }
        }
        match self.tcp_header.write(&mut unwritten) {
            Ok(_e) => {}
            Err(e) => {
                println!("Error writting tcp header {:?}", e);
            }
        }
        let payload_bytes = unwritten.write(payload)?;
        let unwritten = unwritten.len();

        // Concat ethernet headers to packet
        let eth_packet = [&self.eth_header, &buf[..buf.len() - unwritten]].concat();
        // eprintln!("responding with {:02x?}", &eth_packet);

        self.send.nxt = self.send.nxt.wrapping_add(payload_bytes as u32);

        if self.tcp_header.syn {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp_header.syn = false;
        }

        if self.tcp_header.fin {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp_header.fin = false;
        }

        nic.send(&eth_packet)?;
        Ok(payload_bytes)
    }

    fn send_reset(&mut self, nic: &mut tun_tap::Iface) -> io::Result<()> {
        self.tcp_header.rst = true;
        // TODO: fix sequence numbers here
        // TODO: Handle synchronised resets
        self.tcp_header.sequence_number = 0;
        self.tcp_header.acknowledgment_number = 0;
        self.write(nic, &[])?;

        Ok(())
    }

    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<()> {
        // Perform a valid segment check
        // The segment is valid if it acknowledges atleast one byte, which rqeuires atlease one the below to be true:
        // 1. RCV.NXT =< SEG.SEQ < RCV.NXT + RCV.WND
        // 2. RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND

        let seqn = tcph.sequence_number();
        let mut slen = data.len() as u32;
        if tcph.fin() {
            slen += 1;
        }
        if tcph.syn() {
            slen += 1;
        }
        let wnd_length = self.recv.nxt.wrapping_add(self.recv.wnd as u32);

        let okay: bool = if slen == 0 {
            if self.recv.wnd == 0 {
                if seqn != self.recv.nxt {
                    return Ok(());
                } else {
                    true
                }
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wnd_length) {
                false
            } else {
                true
            }
        } else {
            if self.recv.wnd == 0 {
                false
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wnd_length)
                && !is_between_wrapped(
                    self.recv.nxt.wrapping_sub(1),
                    seqn.wrapping_add(slen - 1),
                    wnd_length,
                )
            {
                false
            } else {
                true
            }
        };

        if !okay {
            self.write(nic, &[])?;
            return Ok(());
        }

        self.recv.nxt = seqn.wrapping_add(slen);
        // TODO: if not acceptable, send ACK

        if !tcph.ack() {
            return Ok(());
        }

        let ackn = tcph.acknowledgment_number();
        if let State::SynRcvd = self.state {
            eprintln!("we are syn received state");
            
            eprint!("Param 1 {}", self.send.una.wrapping_sub(1));
            eprint!(", Param 2 {}", ackn);
            eprint!(", Param 3 {}\n", self.send.nxt.wrapping_add(1));
            if is_between_wrapped(
                self.send.una.wrapping_sub(1),
                ackn,
                self.send.nxt.wrapping_add(1),
            ) {
                // must have ACKed our SYN, since we detected atleast one acked byte,
                // and we have only sent one byte (the SYN)
                self.state = State::Estab;
            } else {
                // TODO: RST
            }
        }

        if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
            // acceptable ack check
            // SND.UNA < SEG.ACK =< SND.NXT
            if !is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
                return Ok(());
            }
            self.send.una = ackn;

            assert!(data.is_empty());

            if let State::Estab = self.state {
                eprintln!("we are established");
                dbg!(tcph.fin());
                dbg!(self.tcp_header.fin);

                // now terminate the connection
                // TODO: needs to be stored in the retransmission queue
                self.tcp_header.fin = true;
                self.write(nic, &[])?;
                self.state = State::FinWait1;
            }
        }

        if let State::FinWait1 = self.state {
            eprintln!("we are at FinWait1");
            if self.send.una == self.send.iss + 2 {
                // our FIN has been acked
                eprint!("They have acked our fin");
                self.state = State::FinWait2;
            }
        }

        if tcph.fin() {
            match self.state {
                State::FinWait2 => {
                    eprintln!("THEY HAVE FINED");
                    // we are done with the connection
                    self.write(nic, &[])?;
                    self.state = State::TimeWait;
                    eprint!("DELETING CONNECTION");
                }
                State::Closed
                | State::Estab
                | State::FinWait1
                | State::SynRcvd
                | State::TimeWait => {}
            }
        }

        Ok(())
    }
}

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    use std::cmp::Ordering;
    match start.cmp(&x) {
        Ordering::Equal => return false,
        Ordering::Less => {
            // Check is violated iff n is between u and a
            if end >= start && end <= x {
                return false;
            }
        }
        Ordering::Greater => {
            if end > x && end < start {
            }
            else {
                return false;
            }
            // if !(end < start && end > x) {
            //     return false;
            // }
        }
    }

    return true;
}
