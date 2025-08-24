use crate::protocols::tcp::TcpPacket;
use crate::attack::{AsyncAttack, AttackResult};
use crate::Protocol;
use std::time::Duration;
use std::net::{IpAddr, SocketAddr};

#[cfg(feature = "async")]
impl AsyncAttack for TcpPacket {
    type Response = Vec<u8>;
    
    async fn send_payload(&self, _payload: &[u8]) -> AttackResult<()> {
        use socket2::{Socket, Domain, Type, Protocol as SocketProtocol};
        
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
        
        // Send the payload using Protocol trait - use smol for async I/O
        let packet_data = self.payload();
        
        match smol::unblock(move || socket.send_to(&packet_data, &dest_addr.into())).await {
            Ok(_) => AttackResult::Ok(()),
            Err(e) => AttackResult::Continue(anyhow::anyhow!("Send failed, retrying: {}", e)),
        }
    }
    
    async fn wait_for_response(&self, timeout: Duration) -> AttackResult<Self::Response> {
        use socket2::{Socket, Domain, Type, Protocol as SocketProtocol};
        
        // Create socket for receiving response
        let socket = match Socket::new(Domain::IPV4, Type::STREAM, Some(SocketProtocol::TCP)) {
            Ok(s) => s,
            Err(e) => return AttackResult::Stop(anyhow::anyhow!("Failed to create response socket: {}", e)),
        };
        
        // Buffer for response
        let mut buffer = [std::mem::MaybeUninit::new(0u8); 4096];
        
        // Set socket timeout and use smol's async I/O
        if let Err(e) = socket.set_read_timeout(Some(timeout)) {
            return AttackResult::Stop(anyhow::anyhow!("Failed to set timeout: {}", e));
        }
        
        match smol::unblock(move || socket.recv(&mut buffer)).await {
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
            },
        }
    }
    
    async fn validate_response(&self, response: &Self::Response) -> AttackResult<()> {
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
        format!("Async TCP {}:{} -> {}:{}", 
                self.source_ip, self.port, 
                self.dest_ip, self.port)
    }
}