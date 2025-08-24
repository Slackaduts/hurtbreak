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

impl Fuzzable for TcpPacket {
    fn fuzz(&mut self) {
        self.fuzz_all();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_flags_fuzzing() {
        let mut packet = TcpPacket::default();
        let _original_flags = packet.flags;
        
        // Test that flags can be fuzzed
        packet.fuzz_flags();
        
        // Valid flag combinations from our values list
        let valid_flags = [
            TcpFlags::FIN,
            TcpFlags::SYN,
            TcpFlags::RST,
            TcpFlags::PSH,
            TcpFlags::ACK,
            TcpFlags::URG,
            TcpFlags::SYN | TcpFlags::ACK,
            TcpFlags::FIN | TcpFlags::ACK,
        ];
        
        // The fuzzed flag should be one of the valid combinations
        assert!(valid_flags.contains(&packet.flags));
        
        // Test multiple fuzzing operations
        for _ in 0..10 {
            packet.fuzz_flags();
            assert!(valid_flags.contains(&packet.flags));
        }
    }
    
    #[test]
    fn test_tcp_flags_from_str() {
        assert_eq!("SYN".parse::<TcpFlags>().unwrap(), TcpFlags::SYN);
        assert_eq!("SYN|ACK".parse::<TcpFlags>().unwrap(), TcpFlags::SYN | TcpFlags::ACK);
        assert_eq!("FIN|ACK".parse::<TcpFlags>().unwrap(), TcpFlags::FIN | TcpFlags::ACK);
        
        // Test error case
        assert!("INVALID".parse::<TcpFlags>().is_err());
    }
    
    #[test]
    fn test_tcp_packet_protocol_payload() {
        let mut packet = TcpPacket::default();
        packet.flags = TcpFlags::SYN | TcpFlags::ACK;
        
        let payload = packet.payload();
        
        // Should contain serialized data including flag bits
        assert!(!payload.is_empty());
        
        // Check that flags are serialized correctly (SYN|ACK = 0x12)
        let flags_byte_position = 2 + 4 + 4 + 1; // port(2) + src_ip(4) + dest_ip(4) + header_length(1)
        assert_eq!(payload[flags_byte_position], 0x12); // SYN(0x02) | ACK(0x10)
    }
    
    #[test]
    fn test_ip_pattern_fuzzing() {
        let mut packet = TcpPacket::default();
        let original_source = packet.source_ip;
        let original_dest = packet.dest_ip;
        
        // Test source IP fuzzing
        packet.fuzz_source_ip();
        assert_ne!(packet.source_ip, original_source);
        
        // Test dest IP fuzzing  
        packet.fuzz_dest_ip();
        assert_ne!(packet.dest_ip, original_dest);
        
        // Test multiple rounds of fuzzing
        for _ in 0..10 {
            packet.fuzz_source_ip();
            packet.fuzz_dest_ip();
            
            // Should always be valid IP addresses
            assert!(matches!(packet.source_ip, std::net::IpAddr::V4(_) | std::net::IpAddr::V6(_)));
            assert!(matches!(packet.dest_ip, std::net::IpAddr::V4(_) | std::net::IpAddr::V6(_)));
        }
    }
    
    #[test]
    fn test_display_implementations() {
        let mut packet = TcpPacket::default();
        packet.flags = TcpFlags::SYN | TcpFlags::ACK;
        
        // Test TcpFlags Display
        assert_eq!(format!("{}", TcpFlags::SYN), "SYN");
        assert_eq!(format!("{}", TcpFlags::SYN | TcpFlags::ACK), "SYN|ACK");
        assert_eq!(format!("{}", TcpFlags::empty()), "NONE");
        
        // Test TcpPacket Display - should not panic
        let display_output = format!("{}", packet);
        assert!(display_output.contains("TcpPacket {"));
        assert!(display_output.contains("version: 4"));
        assert!(display_output.contains("flags: SYN|ACK"));
        assert!(display_output.contains("source_ip: 192.168.1.1"));
        assert!(display_output.contains("dest_ip: 192.168.1.2"));

        println!("{packet}");
    }
}

#[cfg(feature = "tcpip")]
impl Attack for TcpPacket {
    type Response = Vec<u8>;
    
    fn send_payload(&self, _payload: &[u8]) -> AttackResult<()> {
        use socket2::{Socket, Domain, Type, Protocol as SocketProtocol};
        use std::net::SocketAddr;
        
        // Create raw socket
        let socket = match Socket::new(Domain::IPV4, Type::STREAM, Some(SocketProtocol::TCP)) {
            Ok(s) => s,
            Err(e) => return AttackResult::Stop(anyhow::anyhow!("Failed to create raw socket: {}", e)),
        };
        
        // Get destination address
        let dest_addr = match self.dest_ip {
            IpAddr::V4(ipv4) => SocketAddr::new(IpAddr::V4(ipv4), self.port),
            IpAddr::V6(ipv6) => SocketAddr::new(IpAddr::V6(ipv6), self.port),
        };
        
        // Send the payload using Protocol trait
        let packet_data = self.payload();
        
        match socket.send_to(&packet_data, &dest_addr.into()) {
            Ok(_) => AttackResult::Ok(()),
            Err(e) => AttackResult::Continue(anyhow::anyhow!("Send failed, retrying: {}", e)),
        }
    }
    
    fn wait_for_response(&self, timeout: std::time::Duration) -> AttackResult<Self::Response> {
        use socket2::{Socket, Domain, Type, Protocol as SocketProtocol};
        
        // Create socket for receiving response
        let socket = match Socket::new(Domain::IPV4, Type::STREAM, Some(SocketProtocol::TCP)) {
            Ok(s) => s,
            Err(e) => return AttackResult::Stop(anyhow::anyhow!("Failed to create response socket: {}", e)),
        };
        
        // Set receive timeout
        if let Err(e) = socket.set_read_timeout(Some(timeout)) {
            return AttackResult::Stop(anyhow::anyhow!("Failed to set timeout: {}", e));
        }
        
        // Buffer for response
        let mut buffer = [std::mem::MaybeUninit::new(0u8); 4096];
        
        match socket.recv(&mut buffer) {
            Ok(bytes_received) => {
                // SAFETY: socket.recv() guarantees the first bytes_received bytes are initialized
                let initialized_data: Vec<u8> = buffer[..bytes_received]
                    .iter()
                    .map(|b| unsafe { b.assume_init() })
                    .collect();
                AttackResult::Ok(initialized_data)
            },
            Err(e) => {
                if e.kind() == std::io::ErrorKind::TimedOut {
                    AttackResult::Continue(anyhow::anyhow!("Timeout waiting for response"))
                } else {
                    AttackResult::Stop(anyhow::anyhow!("Failed to receive response: {}", e))
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