use std::net::IpAddr;
use bitflags::bitflags;
use crate::{Fuzzable, Protocol};
use crate::attack::{Attack, AttackResult};


bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct TcpFlags: u8 {
        const FIN = 0x01;
        const SYN = 0x02;
        const RST = 0x04;
        const PSH = 0x08;
        const ACK = 0x10;
        const URG = 0x20;
    }
}

impl std::str::FromStr for TcpFlags {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut flags = TcpFlags::empty();
        
        for flag in s.split('|') {
            match flag.trim() {
                "FIN" => flags |= TcpFlags::FIN,
                "SYN" => flags |= TcpFlags::SYN,
                "RST" => flags |= TcpFlags::RST,
                "PSH" => flags |= TcpFlags::PSH,
                "ACK" => flags |= TcpFlags::ACK,
                "URG" => flags |= TcpFlags::URG,
                _ => return Err(format!("Unknown TCP flag: {}", flag)),
            }
        }
        
        Ok(flags)
    }
}

impl std::fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut flag_names = Vec::new();
        
        if self.contains(TcpFlags::FIN) { flag_names.push("FIN"); }
        if self.contains(TcpFlags::SYN) { flag_names.push("SYN"); }
        if self.contains(TcpFlags::RST) { flag_names.push("RST"); }
        if self.contains(TcpFlags::PSH) { flag_names.push("PSH"); }
        if self.contains(TcpFlags::ACK) { flag_names.push("ACK"); }
        if self.contains(TcpFlags::URG) { flag_names.push("URG"); }
        
        if flag_names.is_empty() {
            write!(f, "NONE")
        } else {
            write!(f, "{}", flag_names.join("|"))
        }
    }
}

#[derive(Fuzzable, Debug, Clone)]
pub struct TcpPacket {
    #[fuzz(skip)]
    pub version: u8,
    
    #[fuzz(range = "20..=60")]
    pub header_length: u8,
    
    #[fuzz(max_len = 1024)]
    pub payload: Vec<u8>,
    
    #[fuzz(values = "[\"GET\", \"POST\", \"PUT\", \"DELETE\"]")]
    pub method: String,
    
    #[fuzz]
    pub port: u16,
    
    #[fuzz(pattern = "u8.u8.u8.u8", delimiter = ".")]
    pub source_ip: IpAddr,
    
    #[fuzz(pattern = "u8.u8.u8.u8", delimiter = ".")]
    pub dest_ip: IpAddr,
    
    #[fuzz(values = "[\"FIN\", \"SYN\", \"RST\", \"PSH\", \"ACK\", \"URG\", \"SYN|ACK\", \"FIN|ACK\"]")]
    pub flags: TcpFlags,
}

impl Default for TcpPacket {
    fn default() -> Self {
        Self {
            version: 4,
            header_length: 20,
            payload: vec![],
            method: "GET".to_string(),
            port: 80,
            source_ip: "192.168.1.1".parse().unwrap(),
            dest_ip: "192.168.1.2".parse().unwrap(),
            flags: TcpFlags::SYN,
        }
    }
}


impl std::fmt::Display for TcpPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "TcpPacket {{")?;
        writeln!(f, "  version: {}", self.version)?;
        writeln!(f, "  header_length: {}", self.header_length)?;
        writeln!(f, "  method: \"{}\"", self.method)?;
        writeln!(f, "  port: {}", self.port)?;
        writeln!(f, "  source_ip: {}", self.source_ip)?;
        writeln!(f, "  dest_ip: {}", self.dest_ip)?;
        writeln!(f, "  flags: {}", self.flags)?;
        writeln!(f, "  payload: {} bytes", self.payload.len())?;
        write!(f, "}}")
    }
}

impl Protocol for TcpPacket {
    fn payload(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        
        buffer.extend_from_slice(&self.port.to_be_bytes());
        
        match self.source_ip {
            IpAddr::V4(ipv4) => buffer.extend_from_slice(&ipv4.octets()),
            IpAddr::V6(ipv6) => buffer.extend_from_slice(&ipv6.octets()),
        }
        
        match self.dest_ip {
            IpAddr::V4(ipv4) => buffer.extend_from_slice(&ipv4.octets()),
            IpAddr::V6(ipv6) => buffer.extend_from_slice(&ipv6.octets()),
        }
        
        buffer.extend_from_slice(&self.header_length.to_be_bytes());
        
        buffer.extend_from_slice(&[self.flags.bits()]);
        
        buffer.extend_from_slice(self.method.as_bytes());
        
        buffer.extend_from_slice(&self.payload);
        
        buffer
    }
}

#[cfg(feature = "tcpip")]
impl Attack for TcpPacket {
    type Response = Vec<u8>;
    
    fn send_payload(&self, _payload: &[u8]) -> AttackResult<()> {
        use socket2::{Socket, Domain, Type, Protocol as SocketProtocol};
        use std::net::SocketAddr;
        
        // We want control over timing and yield logic; Otherwise I'd just use TcpHandler. -S
        let socket = match Socket::new(Domain::IPV4, Type::STREAM, Some(SocketProtocol::TCP)) {
            Ok(s) => s,
            Err(e) => return AttackResult::Stop(anyhow::anyhow!("Failed to create TCP socket: {}", e)),
        };
        
        // Set non-blocking mode for fuzzing
        if let Err(e) = socket.set_nonblocking(true) {
            return AttackResult::Stop(anyhow::anyhow!("Failed to set non-blocking: {}", e));
        }
        
        // Get destination address
        let dest_addr = match self.dest_ip {
            IpAddr::V4(ipv4) => SocketAddr::new(IpAddr::V4(ipv4), self.port),
            IpAddr::V6(ipv6) => SocketAddr::new(IpAddr::V6(ipv6), self.port),
        };
        
        // Attempt to connect (non-blocking)
        match socket.connect(&dest_addr.into()) {
            Ok(_) => {
                // Connection succeeded immediately
                let packet_data = self.payload();
                match socket.send(&packet_data) {
                    Ok(_) => AttackResult::Ok(()),
                    Err(e) => AttackResult::Continue(anyhow::anyhow!("Send failed: {}", e)),
                }
            }
            Err(e) => {
                match e.kind() {
                    std::io::ErrorKind::WouldBlock => {
                        // Connection in progress - for fuzzing purposes, consider this a continue
                        AttackResult::Continue(anyhow::anyhow!("Connection in progress to {}:{}", self.dest_ip, self.port))
                    }
                    std::io::ErrorKind::ConnectionRefused => {
                        // Target port closed - continue fuzzing other ports/packets
                        AttackResult::Continue(anyhow::anyhow!("Connection refused to {}:{}", self.dest_ip, self.port))
                    }
                    std::io::ErrorKind::TimedOut => {
                        // Network timeout - continue with next packet
                        AttackResult::Continue(anyhow::anyhow!("Connection timeout to {}:{}", self.dest_ip, self.port))
                    }
                    _ => {
                        // Other connection errors - continue fuzzing
                        AttackResult::Continue(anyhow::anyhow!("Connection error to {}:{}: {}", self.dest_ip, self.port, e))
                    }
                }
            }
        }
    }
    
    fn wait_for_response(&self, timeout: std::time::Duration) -> AttackResult<Self::Response> {
        use socket2::{Socket, Domain, Type, Protocol as SocketProtocol};
        use std::net::SocketAddr;
        
        // Create socket for receiving response
        let socket = match Socket::new(Domain::IPV4, Type::STREAM, Some(SocketProtocol::TCP)) {
            Ok(s) => s,
            Err(e) => return AttackResult::Stop(anyhow::anyhow!("Failed to create response socket: {}", e)),
        };
        
        // Set timeouts
        if let Err(e) = socket.set_read_timeout(Some(timeout)) {
            return AttackResult::Stop(anyhow::anyhow!("Failed to set read timeout: {}", e));
        }
        
        if let Err(e) = socket.set_write_timeout(Some(timeout)) {
            return AttackResult::Stop(anyhow::anyhow!("Failed to set write timeout: {}", e));
        }
        
        // Get destination address
        let dest_addr = match self.dest_ip {
            IpAddr::V4(ipv4) => SocketAddr::new(IpAddr::V4(ipv4), self.port),
            IpAddr::V6(ipv6) => SocketAddr::new(IpAddr::V6(ipv6), self.port),
        };
        
        // Try to connect and receive response
        match socket.connect(&dest_addr.into()) {
            Ok(_) => {
                // Connected, try to receive data
                let mut buffer = [std::mem::MaybeUninit::new(0u8); 4096];
                
                match socket.recv(&mut buffer) {
                    Ok(bytes_received) => {
                        if bytes_received == 0 {
                            AttackResult::Continue(anyhow::anyhow!("Connection closed by peer"))
                        } else {
                            // SAFETY: socket.recv() guarantees the first bytes_received bytes are initialized
                            let initialized_data: Vec<u8> = buffer[..bytes_received]
                                .iter()
                                .map(|b| unsafe { b.assume_init() })
                                .collect();
                            AttackResult::Ok(initialized_data)
                        }
                    },
                    Err(e) => {
                        match e.kind() {
                            std::io::ErrorKind::TimedOut => {
                                AttackResult::Continue(anyhow::anyhow!("Timeout waiting for response from {}:{}", self.dest_ip, self.port))
                            }
                            std::io::ErrorKind::ConnectionReset => {
                                AttackResult::Continue(anyhow::anyhow!("Connection reset by {}:{}", self.dest_ip, self.port))
                            }
                            _ => {
                                AttackResult::Continue(anyhow::anyhow!("Receive error from {}:{}: {}", self.dest_ip, self.port, e))
                            }
                        }
                    }
                }
            }
            Err(e) => {
                match e.kind() {
                    std::io::ErrorKind::ConnectionRefused => {
                        AttackResult::Continue(anyhow::anyhow!("Connection refused by {}:{}", self.dest_ip, self.port))
                    }
                    std::io::ErrorKind::TimedOut => {
                        AttackResult::Continue(anyhow::anyhow!("Connection timeout to {}:{}", self.dest_ip, self.port))
                    }
                    _ => {
                        AttackResult::Continue(anyhow::anyhow!("Connection error to {}:{}: {}", self.dest_ip, self.port, e))
                    }
                }
            }
        }
    }
    
    fn validate_response(&self, response: &Self::Response) -> AttackResult<()> {
        // Basic validation - ensure we got some data
        if response.is_empty() {
            return AttackResult::Continue(anyhow::anyhow!("Empty response received"));
        }
        
        // Check if response looks like a valid TCP packet
        if response.len() < 20 {
            return AttackResult::Continue(anyhow::anyhow!("Response too short to be valid TCP"));
        }
        
        // Success - received what appears to be a valid response
        AttackResult::Ok(())
    }
    
    fn get_target_info(&self) -> String {
        format!("TCP {}:{} -> {}:{}", 
                self.source_ip, self.port, 
                self.dest_ip, self.port)
    }
}