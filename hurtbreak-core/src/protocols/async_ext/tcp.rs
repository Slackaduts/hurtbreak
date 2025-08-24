use crate::protocols::tcp::TcpPacket;
use crate::attack::{AsyncAttack, AttackResult};
use crate::Protocol;
use std::time::Duration;
use std::net::{IpAddr, SocketAddr};

#[cfg(feature = "async")]
#[async_trait::async_trait]
impl AsyncAttack for TcpPacket {
    type Response = Vec<u8>;
    
    async fn send_payload(&self, _payload: &[u8]) -> AttackResult<()> {
        use tokio::net::TcpStream;
        use tokio::time::timeout;
        
        // Get destination address
        let dest_addr = match self.dest_ip {
            IpAddr::V4(ipv4) => SocketAddr::new(IpAddr::V4(ipv4), self.port),
            IpAddr::V6(ipv6) => SocketAddr::new(IpAddr::V6(ipv6), self.port),
        };
        
        // Try to connect with timeout
        let connect_timeout = Duration::from_millis(1000);
        match timeout(connect_timeout, TcpStream::connect(dest_addr)).await {
            Ok(Ok(mut stream)) => {
                // Connected successfully, send the payload
                let packet_data = self.payload();
                
                use tokio::io::AsyncWriteExt;
                match stream.write_all(&packet_data).await {
                    Ok(_) => {
                        // Ensure data is sent
                        match stream.flush().await {
                            Ok(_) => AttackResult::Ok(()),
                            Err(e) => AttackResult::Continue(anyhow::anyhow!("Flush failed: {}", e)),
                        }
                    }
                    Err(e) => AttackResult::Continue(anyhow::anyhow!("Send failed: {}", e)),
                }
            }
            Ok(Err(e)) => {
                match e.kind() {
                    std::io::ErrorKind::ConnectionRefused => {
                        AttackResult::Continue(anyhow::anyhow!("Connection refused to {}:{}", self.dest_ip, self.port))
                    }
                    _ => {
                        AttackResult::Continue(anyhow::anyhow!("Connection error to {}:{}: {}", self.dest_ip, self.port, e))
                    }
                }
            }
            Err(_) => {
                AttackResult::Continue(anyhow::anyhow!("Connection timeout to {}:{}", self.dest_ip, self.port))
            }
        }
    }
    
    async fn wait_for_response(&self, response_timeout: Duration) -> AttackResult<Self::Response> {
        use tokio::net::TcpStream;
        use tokio::time::timeout;
        use tokio::io::AsyncReadExt;
        
        // Get destination address
        let dest_addr = match self.dest_ip {
            IpAddr::V4(ipv4) => SocketAddr::new(IpAddr::V4(ipv4), self.port),
            IpAddr::V6(ipv6) => SocketAddr::new(IpAddr::V6(ipv6), self.port),
        };
        
        // Try to connect with timeout
        let connect_timeout = Duration::from_millis(1000);
        match timeout(connect_timeout, TcpStream::connect(dest_addr)).await {
            Ok(Ok(mut stream)) => {
                // Connected, wait for response data
                let mut buffer = vec![0u8; 4096];
                
                match timeout(response_timeout, stream.read(&mut buffer)).await {
                    Ok(Ok(bytes_read)) => {
                        if bytes_read == 0 {
                            AttackResult::Continue(anyhow::anyhow!("Connection closed by peer"))
                        } else {
                            buffer.truncate(bytes_read);
                            AttackResult::Ok(buffer)
                        }
                    }
                    Ok(Err(e)) => {
                        AttackResult::Continue(anyhow::anyhow!("Read error from {}:{}: {}", self.dest_ip, self.port, e))
                    }
                    Err(_) => {
                        AttackResult::Continue(anyhow::anyhow!("Timeout reading response from {}:{}", self.dest_ip, self.port))
                    }
                }
            }
            Ok(Err(e)) => {
                match e.kind() {
                    std::io::ErrorKind::ConnectionRefused => {
                        AttackResult::Continue(anyhow::anyhow!("Connection refused by {}:{}", self.dest_ip, self.port))
                    }
                    _ => {
                        AttackResult::Continue(anyhow::anyhow!("Connection error to {}:{}: {}", self.dest_ip, self.port, e))
                    }
                }
            }
            Err(_) => {
                AttackResult::Continue(anyhow::anyhow!("Connection timeout to {}:{}", self.dest_ip, self.port))
            }
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