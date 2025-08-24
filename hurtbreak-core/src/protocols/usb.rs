use bitflags::bitflags;
use crate::{Fuzzable, Protocol};
use crate::attack::AttackResult;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct UsbPid: u8 {
        const OUT = 0x01;
        const IN = 0x09;
        const SOF = 0x05;
        const SETUP = 0x0D;
        const DATA0 = 0x03;
        const DATA1 = 0x0B;
        const DATA2 = 0x07;
        const MDATA = 0x0F;
        const ACK = 0x02;
        const NAK = 0x0A;
        const STALL = 0x0E;
        const NYET = 0x06;
    }
}

impl std::str::FromStr for UsbPid {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "OUT" => Ok(UsbPid::OUT),
            "IN" => Ok(UsbPid::IN),
            "SOF" => Ok(UsbPid::SOF),
            "SETUP" => Ok(UsbPid::SETUP),
            "DATA0" => Ok(UsbPid::DATA0),
            "DATA1" => Ok(UsbPid::DATA1),
            "DATA2" => Ok(UsbPid::DATA2),
            "MDATA" => Ok(UsbPid::MDATA),
            "ACK" => Ok(UsbPid::ACK),
            "NAK" => Ok(UsbPid::NAK),
            "STALL" => Ok(UsbPid::STALL),
            "NYET" => Ok(UsbPid::NYET),
            _ => Err(format!("Unknown USB PID: {}", s)),
        }
    }
}

impl std::fmt::Display for UsbPid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            UsbPid::OUT => write!(f, "OUT"),
            UsbPid::IN => write!(f, "IN"),
            UsbPid::SOF => write!(f, "SOF"),
            UsbPid::SETUP => write!(f, "SETUP"),
            UsbPid::DATA0 => write!(f, "DATA0"),
            UsbPid::DATA1 => write!(f, "DATA1"),
            UsbPid::DATA2 => write!(f, "DATA2"),
            UsbPid::MDATA => write!(f, "MDATA"),
            UsbPid::ACK => write!(f, "ACK"),
            UsbPid::NAK => write!(f, "NAK"),
            UsbPid::STALL => write!(f, "STALL"),
            UsbPid::NYET => write!(f, "NYET"),
            _ => write!(f, "UNKNOWN"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbSpeed {
    Low,    // 1.5 Mbps
    Full,   // 12 Mbps
    High,   // 480 Mbps
    Super,  // 5 Gbps
}

impl std::str::FromStr for UsbSpeed {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "low" => Ok(UsbSpeed::Low),
            "full" => Ok(UsbSpeed::Full),
            "high" => Ok(UsbSpeed::High),
            "super" => Ok(UsbSpeed::Super),
            _ => Err(format!("Unknown USB speed: {}", s)),
        }
    }
}

impl std::fmt::Display for UsbSpeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UsbSpeed::Low => write!(f, "Low"),
            UsbSpeed::Full => write!(f, "Full"),
            UsbSpeed::High => write!(f, "High"),
            UsbSpeed::Super => write!(f, "Super"),
        }
    }
}

#[derive(Fuzzable, Debug, Clone)]
pub struct UsbPacket {
    #[fuzz(skip)]
    pub sync: u8,
    
    #[fuzz(values = "[\"OUT\", \"IN\", \"SOF\", \"SETUP\", \"DATA0\", \"DATA1\", \"ACK\", \"NAK\", \"STALL\"]")]
    pub pid: UsbPid,
    
    #[fuzz(range = "0..=127")]
    pub device_address: u8,
    
    #[fuzz(range = "0..=15")]
    pub endpoint: u8,
    
    #[fuzz(range = "0..=2047")]
    pub frame_number: u16,
    
    #[fuzz(max_len = 1024)]
    pub data: Vec<u8>,
    
    #[fuzz(values = "[\"Low\", \"Full\", \"High\", \"Super\"]")]
    pub speed: UsbSpeed,
    
    #[fuzz]
    pub crc5: u8,
    
    #[fuzz]
    pub crc16: u16,
    
    #[fuzz(range = "8..=1024")]
    pub max_packet_size: u16,
    
    #[fuzz(values = "[\"Standard\", \"Class\", \"Vendor\", \"Reserved\"]")]
    pub request_type: String,
    
    #[fuzz(range = "0..=255")]
    pub request: u8,
    
    #[fuzz]
    pub value: u16,
    
    #[fuzz]
    pub index: u16,
    
    #[fuzz(range = "0..=65535")]
    pub length: u16,
}

impl Default for UsbPacket {
    fn default() -> Self {
        Self {
            sync: 0x80,
            pid: UsbPid::SETUP,
            device_address: 0,
            endpoint: 0,
            frame_number: 0,
            data: vec![],
            speed: UsbSpeed::Full,
            crc5: 0,
            crc16: 0,
            max_packet_size: 64,
            request_type: "Standard".to_string(),
            request: 0,
            value: 0,
            index: 0,
            length: 0,
        }
    }
}

impl Fuzzable for UsbPacket {
    fn fuzz(&mut self) {
        self.fuzz_all();
    }
}

impl std::fmt::Display for UsbPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "UsbPacket {{")?;
        writeln!(f, "  sync: 0x{:02X}", self.sync)?;
        writeln!(f, "  pid: {}", self.pid)?;
        writeln!(f, "  device_address: {}", self.device_address)?;
        writeln!(f, "  endpoint: {}", self.endpoint)?;
        writeln!(f, "  frame_number: {}", self.frame_number)?;
        writeln!(f, "  speed: {}", self.speed)?;
        writeln!(f, "  max_packet_size: {}", self.max_packet_size)?;
        writeln!(f, "  request_type: \"{}\"", self.request_type)?;
        writeln!(f, "  request: 0x{:02X}", self.request)?;
        writeln!(f, "  value: 0x{:04X}", self.value)?;
        writeln!(f, "  index: 0x{:04X}", self.index)?;
        writeln!(f, "  length: {}", self.length)?;
        writeln!(f, "  crc5: 0x{:02X}", self.crc5)?;
        writeln!(f, "  crc16: 0x{:04X}", self.crc16)?;
        writeln!(f, "  data: {} bytes", self.data.len())?;
        write!(f, "}}")
    }
}

impl Protocol for UsbPacket {
    fn payload(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        
        // USB packet structure
        buffer.push(self.sync);
        buffer.push(self.pid.bits());
        
        // Address and endpoint (packed into 11 bits total)
        let addr_ep = ((self.device_address as u16) & 0x7F) | (((self.endpoint as u16) & 0x0F) << 7);
        buffer.extend_from_slice(&addr_ep.to_le_bytes());
        
        // Frame number for SOF packets
        if self.pid == UsbPid::SOF {
            buffer.extend_from_slice(&self.frame_number.to_le_bytes());
        }
        
        // Control transfer setup data
        if self.pid == UsbPid::SETUP {
            // Request type (bmRequestType)
            let request_type_byte = match self.request_type.as_str() {
                "Standard" => 0x00,
                "Class" => 0x20,
                "Vendor" => 0x40,
                _ => 0x60, // Reserved
            };
            buffer.push(request_type_byte);
            
            // bRequest
            buffer.push(self.request);
            
            // wValue
            buffer.extend_from_slice(&self.value.to_le_bytes());
            
            // wIndex
            buffer.extend_from_slice(&self.index.to_le_bytes());
            
            // wLength
            buffer.extend_from_slice(&self.length.to_le_bytes());
        }
        
        // Data payload
        if matches!(self.pid, UsbPid::DATA0 | UsbPid::DATA1 | UsbPid::DATA2 | UsbPid::MDATA) {
            buffer.extend_from_slice(&self.data);
        }
        
        // CRC5 for token packets
        if matches!(self.pid, UsbPid::OUT | UsbPid::IN | UsbPid::SETUP | UsbPid::SOF) {
            buffer.push(self.crc5);
        }
        
        // CRC16 for data packets
        if matches!(self.pid, UsbPid::DATA0 | UsbPid::DATA1 | UsbPid::DATA2 | UsbPid::MDATA) {
            buffer.extend_from_slice(&self.crc16.to_le_bytes());
        }
        
        buffer
    }
}

#[cfg(feature = "usb")]
impl crate::attack::Attack for UsbPacket {
    type Response = Vec<u8>;
    
    fn send_payload(&self, _payload: &[u8]) -> AttackResult<()> {
        // USB fuzzing would typically require specialized hardware or kernel-level access
        // For simulation purposes, we'll implement a mock USB transaction
        
        // Validate device address range
        if self.device_address > 127 {
            return AttackResult::Continue(anyhow::anyhow!("Invalid device address: {}", self.device_address));
        }
        
        // Validate endpoint range
        if self.endpoint > 15 {
            return AttackResult::Continue(anyhow::anyhow!("Invalid endpoint: {}", self.endpoint));
        }
        
        // Check packet size limits based on speed
        let max_allowed = match self.speed {
            UsbSpeed::Low => 8,
            UsbSpeed::Full => 64,
            UsbSpeed::High => 512,
            UsbSpeed::Super => 1024,
        };
        
        if self.max_packet_size > max_allowed {
            return AttackResult::Continue(anyhow::anyhow!(
                "Packet size {} exceeds limit {} for {:?} speed", 
                self.max_packet_size, max_allowed, self.speed
            ));
        }
        
        // Simulate USB transaction timing
        match self.pid {
            UsbPid::SETUP => {
                // SETUP transactions require specific timing
                std::thread::sleep(std::time::Duration::from_micros(10));
                AttackResult::Ok(())
            }
            UsbPid::OUT | UsbPid::IN => {
                // Data transfer packets
                if self.data.len() > self.max_packet_size as usize {
                    AttackResult::Continue(anyhow::anyhow!(
                        "Data length {} exceeds max packet size {}", 
                        self.data.len(), self.max_packet_size
                    ))
                } else {
                    std::thread::sleep(std::time::Duration::from_micros(5));
                    AttackResult::Ok(())
                }
            }
            UsbPid::SOF => {
                // Start of Frame - check frame number validity
                if self.frame_number > 2047 {
                    AttackResult::Continue(anyhow::anyhow!("Invalid frame number: {}", self.frame_number))
                } else {
                    AttackResult::Ok(())
                }
            }
            _ => {
                // Other packet types (handshake packets)
                AttackResult::Ok(())
            }
        }
    }
    
    fn wait_for_response(&self, timeout: std::time::Duration) -> AttackResult<Self::Response> {
        // Simulate USB response based on packet type
        std::thread::sleep(std::cmp::min(timeout, std::time::Duration::from_millis(10)));
        
        match self.pid {
            UsbPid::IN => {
                // IN token expects data response
                match self.endpoint {
                    0 => {
                        // Control endpoint - return device descriptor fragment
                        let device_descriptor = vec![
                            0x12, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40,
                            0x81, 0x07, 0x01, 0x00, 0x01, 0x00, 0x01, 0x02,
                            0x03, 0x01
                        ];
                        AttackResult::Ok(device_descriptor)
                    }
                    1..=15 => {
                        // Other endpoints - return test data
                        let test_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
                        AttackResult::Ok(test_data)
                    }
                    _ => AttackResult::Continue(anyhow::anyhow!("Invalid endpoint: {}", self.endpoint))
                }
            }
            UsbPid::OUT | UsbPid::SETUP => {
                // OUT/SETUP expect handshake response
                match self.device_address {
                    0..=127 => {
                        // Valid device address - return ACK
                        AttackResult::Ok(vec![UsbPid::ACK.bits()])
                    }
                    _ => {
                        // Invalid device address - no response (timeout)
                        AttackResult::Continue(anyhow::anyhow!("No response from device {}", self.device_address))
                    }
                }
            }
            UsbPid::SOF => {
                // SOF packets don't expect responses
                AttackResult::Ok(vec![])
            }
            _ => {
                // Handshake and data packets - simulate appropriate responses
                AttackResult::Ok(vec![UsbPid::ACK.bits()])
            }
        }
    }
    
    fn validate_response(&self, response: &Self::Response) -> AttackResult<()> {
        // Validate USB response based on expected packet type
        match self.pid {
            UsbPid::IN => {
                if response.is_empty() {
                    return AttackResult::Continue(anyhow::anyhow!("Empty response to IN token"));
                }
                
                // Check if response looks like valid USB data
                if response.len() > self.max_packet_size as usize {
                    return AttackResult::Continue(anyhow::anyhow!(
                        "Response length {} exceeds max packet size {}", 
                        response.len(), self.max_packet_size
                    ));
                }
                
                AttackResult::Ok(())
            }
            UsbPid::OUT | UsbPid::SETUP => {
                if response.is_empty() {
                    return AttackResult::Continue(anyhow::anyhow!("No handshake response"));
                }
                
                // Check for valid handshake PIDs
                match response[0] {
                    0x02 => AttackResult::Ok(()), // ACK
                    0x0A => AttackResult::Continue(anyhow::anyhow!("NAK received")), // NAK
                    0x0E => AttackResult::Continue(anyhow::anyhow!("STALL received")), // STALL
                    0x06 => AttackResult::Continue(anyhow::anyhow!("NYET received")), // NYET
                    _ => AttackResult::Continue(anyhow::anyhow!("Invalid handshake PID: 0x{:02X}", response[0])),
                }
            }
            UsbPid::SOF => {
                // SOF packets typically don't expect responses
                AttackResult::Ok(())
            }
            _ => {
                // For other packet types, any response is considered valid
                AttackResult::Ok(())
            }
        }
    }
    
    fn get_target_info(&self) -> String {
        format!("USB Device {} Endpoint {} ({} speed, PID: {})", 
                self.device_address, self.endpoint, self.speed, self.pid)
    }
}

