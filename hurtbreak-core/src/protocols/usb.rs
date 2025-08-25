use bitflags::bitflags;
use crate::{Fuzzable, Protocol};
use crate::attack::AttackResult;

#[cfg(feature = "usb")]
use rusb::{Context, Device, DeviceHandle, UsbContext};
#[cfg(feature = "usb")]
use std::time::Duration as StdDuration;

bitflags! {
    /// USB Packet Identifier (PID) field values.
    /// 
    /// Represents the different types of USB packets that can be transmitted.
    /// PIDs are 4-bit values that identify the packet type and purpose in USB communication.
    /// 
    /// # Categories
    /// 
    /// * **Token PIDs**: OUT, IN, SOF, SETUP - Used to initiate transactions
    /// * **Data PIDs**: DATA0, DATA1, DATA2, MDATA - Contain payload data
    /// * **Handshake PIDs**: ACK, NAK, STALL, NYET - Acknowledge transactions
    /// 
    /// # Examples
    /// 
    /// ```rust,norun
    /// use hurtbreak_core::protocols::usb::UsbPid;
    /// 
    /// let setup_pid = UsbPid::SETUP;
    /// assert_eq!(setup_pid.bits(), 0x0D);
    /// 
    /// let combined = UsbPid::ACK | UsbPid::NAK;
    /// assert!(combined.contains(UsbPid::ACK));
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct UsbPid: u8 {
        /// OUT token - Host to device data transfer
        const OUT = 0x01;
        /// IN token - Device to host data transfer  
        const IN = 0x09;
        /// Start of Frame token - Timing reference
        const SOF = 0x05;
        /// SETUP token - Control transfer setup stage
        const SETUP = 0x0D;
        /// DATA0 packet - Even data packet
        const DATA0 = 0x03;
        /// DATA1 packet - Odd data packet
        const DATA1 = 0x0B;
        /// DATA2 packet - High-speed data packet
        const DATA2 = 0x07;
        /// MDATA packet - Multi-data packet for split transactions
        const MDATA = 0x0F;
        /// ACK handshake - Successful transaction acknowledgment
        const ACK = 0x02;
        /// NAK handshake - Not ready or busy
        const NAK = 0x0A;
        /// STALL handshake - Error condition or unsupported request
        const STALL = 0x0E;
        /// NYET handshake - Not yet ready (high-speed only)
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

/// USB communication speeds supported by the protocol.
/// 
/// Represents the different data transmission rates available in USB specifications.
/// Each speed has different timing requirements, packet size limits, and electrical
/// characteristics.
/// 
/// # Speed Classifications
/// 
/// * **Low Speed (1.5 Mbps)**: For simple devices like keyboards, mice
/// * **Full Speed (12 Mbps)**: Original USB 1.1 speed for most devices  
/// * **High Speed (480 Mbps)**: USB 2.0 high-speed mode
/// * **Super Speed (5 Gbps)**: USB 3.0+ super-speed mode
/// 
/// # Examples
/// 
/// ```rust,norun
/// use hurtbreak_core::protocols::usb::UsbSpeed;
/// 
/// let speed = UsbSpeed::High;
/// let max_packet_size = match speed {
///     UsbSpeed::Low => 8,
///     UsbSpeed::Full => 64,
///     UsbSpeed::High => 512,
///     UsbSpeed::Super => 1024,
/// };
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbSpeed {
    /// Low speed USB (1.5 Mbps) - USB 1.0 for simple HID devices
    Low,    // 1.5 Mbps
    /// Full speed USB (12 Mbps) - USB 1.1 standard speed
    Full,   // 12 Mbps
    /// High speed USB (480 Mbps) - USB 2.0 enhanced speed
    High,   // 480 Mbps
    /// Super speed USB (5 Gbps) - USB 3.0+ maximum speed
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

/// Complete USB packet representation for fuzzing and protocol simulation.
/// 
/// This struct represents a comprehensive USB packet that can be used for
/// fuzzing USB devices and protocols. It includes all major fields from
/// USB specifications and supports automatic fuzzing through derive macros.
/// 
/// # Fields
/// 
/// * `sync` - Sync field for packet framing (typically 0x80)
/// * `pid` - Packet Identifier indicating packet type and purpose
/// * `device_address` - Target USB device address (0-127)
/// * `endpoint` - Device endpoint number (0-15)
/// * `frame_number` - Frame number for SOF packets (0-2047)
/// * `data` - Variable-length data payload
/// * `speed` - USB communication speed (Low/Full/High/Super)
/// * `crc5` - 5-bit CRC for token packets
/// * `crc16` - 16-bit CRC for data packets
/// * `max_packet_size` - Maximum packet size for endpoint
/// * Control transfer specific fields for SETUP packets
/// 
/// # Fuzzing Configuration
/// 
/// Each field has specific fuzzing attributes that control how values
/// are randomly generated during fuzzing operations:
/// 
/// * Range-based fuzzing for numeric fields
/// * Value sets for enumerated fields  
/// * Length limits for variable data
/// * Skip attributes for fields that shouldn't be fuzzed
/// 
/// # Examples
/// 
/// ```rust,norun
/// use hurtbreak_core::protocols::usb::{UsbPacket, UsbPid, UsbSpeed};
/// use hurtbreak_core::{Fuzzable, Protocol};
/// 
/// let mut packet = UsbPacket {
///     sync: 0x80,
///     pid: UsbPid::SETUP,
///     device_address: 0,
///     endpoint: 0,
///     frame_number: 0,
///     data: vec![0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00],
///     speed: UsbSpeed::Full,
///     crc5: 0x1F,
///     crc16: 0x0000,
///     max_packet_size: 64,
///     request_type: "Standard".to_string(),
///     request: 0x06,
///     value: 0x0100,
///     index: 0,
///     length: 18,
/// };
/// 
/// // Fuzz the packet to generate random test cases
/// packet.fuzz();
/// 
/// // Convert to wire format for transmission
/// let wire_data = packet.payload();
/// ```
#[derive(Fuzzable, Debug, Clone)]
pub struct UsbPacket {
    /// Synchronization field for packet framing (not fuzzed for stability)
    #[fuzz(skip)]
    pub sync: u8,
    
    /// Packet Identifier - determines packet type and transaction purpose
    #[fuzz(values = "[\"OUT\", \"IN\", \"SOF\", \"SETUP\", \"DATA0\", \"DATA1\", \"ACK\", \"NAK\", \"STALL\"]")]
    pub pid: UsbPid,
    
    /// USB device address (0-127, 0 reserved for unconfigured devices)
    #[fuzz(range = "0..=127")]
    pub device_address: u8,
    
    /// Device endpoint number (0-15, 0 reserved for control transfers)
    #[fuzz(range = "0..=15")]
    pub endpoint: u8,
    
    /// Frame number for Start of Frame packets (0-2047)
    #[fuzz(range = "0..=2047")]
    pub frame_number: u16,
    
    /// Variable-length data payload (up to 1024 bytes for fuzzing)
    #[fuzz(max_len = 1024)]
    pub data: Vec<u8>,
    
    /// USB communication speed affecting timing and packet size limits
    #[fuzz(values = "[\"Low\", \"Full\", \"High\", \"Super\"]")]
    pub speed: UsbSpeed,
    
    /// 5-bit CRC for token and handshake packets
    #[fuzz]
    pub crc5: u8,
    
    /// 16-bit CRC for data packets  
    #[fuzz]
    pub crc16: u16,
    
    /// Maximum packet size for the endpoint (8-1024 bytes)
    #[fuzz(range = "8..=1024")]
    pub max_packet_size: u16,
    
    /// Control transfer request type (Standard/Class/Vendor/Reserved)
    #[fuzz(values = "[\"Standard\", \"Class\", \"Vendor\", \"Reserved\"]")]
    pub request_type: String,
    
    /// Control transfer bRequest field (0-255)
    #[fuzz(range = "0..=255")]
    pub request: u8,
    
    /// Control transfer wValue field
    #[fuzz]
    pub value: u16,
    
    /// Control transfer wIndex field  
    #[fuzz]
    pub index: u16,
    
    /// Control transfer wLength field (0-65535)
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

impl UsbPacket {
    /// Truncates the data payload to fit within the remaining packet space
    /// based on the USB speed limits and existing packet overhead.
    /// 
    /// This method calculates the overhead of the packet (sync, PID, address/endpoint,
    /// frame number for SOF, control setup data for SETUP, CRC fields) and truncates
    /// the data payload to fit within the remaining space allowed by the speed field.
    /// 
    /// # Returns
    /// 
    /// The maximum number of data bytes that can fit in the packet
    /// 
    /// # Examples
    /// 
    /// ```rust,norun
    /// use hurtbreak_core::protocols::usb::{UsbPacket, UsbPid, UsbSpeed};
    /// 
    /// let mut packet = UsbPacket {
    ///     speed: UsbSpeed::Full, // 64 byte limit
    ///     pid: UsbPid::DATA0,
    ///     data: vec![0; 100], // Too much data
    ///     // ... other fields
    /// #     sync: 0x80,
    /// #     device_address: 0,
    /// #     endpoint: 0,
    /// #     frame_number: 0,
    /// #     crc5: 0,
    /// #     crc16: 0,
    /// #     max_packet_size: 64,
    /// #     request_type: "Standard".to_string(),
    /// #     request: 0,
    /// #     value: 0,
    /// #     index: 0,
    /// #     length: 0,
    /// };
    /// 
    /// packet.truncate_payload_to_fit();
    /// assert!(packet.data.len() <= 64 - packet.calculate_packet_overhead());
    /// ```
    pub fn truncate_payload_to_fit(&mut self) {
        let max_packet_size: usize = match self.speed {
            UsbSpeed::Low => 8,
            UsbSpeed::Full => 64,
            UsbSpeed::High => 512,
            UsbSpeed::Super => 1024,
        };
        
        let overhead = self.calculate_packet_overhead();
        let max_data_size = max_packet_size.saturating_sub(overhead);
        
        if self.data.len() > max_data_size {
            self.data.truncate(max_data_size);
        }
    }
    
    /// Calculates the total overhead (non-data bytes) for this USB packet.
    /// 
    /// The overhead includes:
    /// * Sync field (1 byte)
    /// * PID field (1 byte)
    /// * Address/Endpoint fields (2 bytes)
    /// * Frame number (2 bytes, SOF packets only)
    /// * Control setup data (8 bytes, SETUP packets only)
    /// * CRC5 (1 byte, token packets)
    /// * CRC16 (2 bytes, data packets)
    /// 
    /// # Returns
    /// 
    /// The number of overhead bytes for this packet configuration
    pub fn calculate_packet_overhead(&self) -> usize {
        let mut overhead = 0;
        
        // Base overhead: sync (1) + PID (1) + address/endpoint (2)
        overhead += 4;
        
        // Frame number for SOF packets
        if self.pid == UsbPid::SOF {
            overhead += 2;
        }
        
        // Control setup data for SETUP packets
        if self.pid == UsbPid::SETUP {
            overhead += 8; // bmRequestType + bRequest + wValue + wIndex + wLength
        }
        
        // CRC5 for token packets
        if matches!(self.pid, UsbPid::OUT | UsbPid::IN | UsbPid::SETUP | UsbPid::SOF) {
            overhead += 1;
        }
        
        // CRC16 for data packets
        if matches!(self.pid, UsbPid::DATA0 | UsbPid::DATA1 | UsbPid::DATA2 | UsbPid::MDATA) {
            overhead += 2;
        }
        
        overhead
    }
}

impl Protocol for UsbPacket {
    /// Converts the USB packet to its wire-format byte representation.
    /// 
    /// This method serializes the USB packet into the binary format that would
    /// be transmitted over the USB bus. The serialization follows USB specification
    /// requirements for different packet types.
    /// 
    /// Note: This method does NOT automatically truncate the payload. If you want
    /// payload truncation based on speed limits, call `truncate_payload_to_fit()`
    /// before calling this method.
    /// 
    /// # Wire Format Structure
    /// 
    /// * Sync field (1 byte)
    /// * PID field (1 byte) 
    /// * Address/Endpoint fields (2 bytes, packed)
    /// * Frame number (2 bytes, SOF packets only)
    /// * Control setup data (8 bytes, SETUP packets only)  
    /// * Data payload (variable, DATA packets only)
    /// * CRC fields (1 or 2 bytes depending on packet type)
    /// 
    /// # Returns
    /// 
    /// A byte vector containing the complete wire-format representation
    /// of the USB packet suitable for transmission or analysis.
    /// 
    /// # Examples
    /// 
    /// ```rust,norun
    /// use hurtbreak_core::protocols::usb::{UsbPacket, UsbPid};
    /// use hurtbreak_core::Protocol;
    /// 
    /// let mut packet = UsbPacket {
    ///     sync: 0x80,
    ///     pid: UsbPid::SETUP,
    ///     device_address: 1,
    ///     endpoint: 0,
    ///     // ... other fields
    /// #     frame_number: 0,
    /// #     data: vec![],
    /// #     speed: hurtbreak_core::protocols::usb::UsbSpeed::Full,
    /// #     crc5: 0,
    /// #     crc16: 0,
    /// #     max_packet_size: 64,
    /// #     request_type: "Standard".to_string(),
    /// #     request: 0,
    /// #     value: 0,
    /// #     index: 0,
    /// #     length: 0,
    /// };
    /// 
    /// // Truncate payload to fit speed limits before serialization
    /// packet.truncate_payload_to_fit();
    /// let wire_bytes = packet.payload();
    /// println!("Wire format: {} bytes", wire_bytes.len());
    /// ```
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
/// USB device information for device enumeration
#[derive(Debug, Clone)]
pub struct UsbDeviceInfo {
    pub bus: u8,
    pub address: u8,
    pub vendor_id: u16,
    pub product_id: u16,
    pub device_class: u8,
    pub device_subclass: u8,
    pub device_protocol: u8,
    pub description: String,
}

#[cfg(feature = "usb")]
/// USB device handle wrapper for managing libusb operations
pub struct UsbDeviceHandle {
    handle: DeviceHandle<Context>,
    _context: Context, // Keep context alive for handle lifetime
}

#[cfg(feature = "usb")]
impl UsbDeviceHandle {
    /// Enumerates all available USB devices
    pub fn enumerate_devices() -> Result<Vec<UsbDeviceInfo>, anyhow::Error> {
        let context = Context::new()?;
        let devices = context.devices()?;
        let mut device_list = Vec::new();
        
        for device in devices.iter() {
            let device_desc = match device.device_descriptor() {
                Ok(desc) => desc,
                Err(_) => continue, // Skip devices we can't read
            };
            
            // Try to get string descriptor for description
            let description = match device.open() {
                Ok(handle) => {
                    let timeout = StdDuration::from_secs(1);
                    if let Ok(languages) = handle.read_languages(timeout) {
                        if let Some(language) = languages.first() {
                            if let Ok(product) = handle.read_product_string(*language, &device_desc, timeout) {
                                format!("{}", product)
                            } else {
                                format!("USB Device {:04X}:{:04X}", device_desc.vendor_id(), device_desc.product_id())
                            }
                        } else {
                            format!("USB Device {:04X}:{:04X}", device_desc.vendor_id(), device_desc.product_id())
                        }
                    } else {
                        format!("USB Device {:04X}:{:04X}", device_desc.vendor_id(), device_desc.product_id())
                    }
                }
                Err(_) => format!("USB Device {:04X}:{:04X}", device_desc.vendor_id(), device_desc.product_id()),
            };
            
            device_list.push(UsbDeviceInfo {
                bus: device.bus_number(),
                address: device.address(),
                vendor_id: device_desc.vendor_id(),
                product_id: device_desc.product_id(),
                device_class: device_desc.class_code(),
                device_subclass: device_desc.sub_class_code(),
                device_protocol: device_desc.protocol_code(),
                description,
            });
        }
        
        Ok(device_list)
    }
    /// Creates a new USB device handle for the specified device address
    pub fn new(device_address: u8) -> Result<Self, anyhow::Error> {
        let context = Context::new()?;
        
        // Find device by address
        let devices = context.devices()?;
        let mut target_device: Option<Device<Context>> = None;
        
        for device in devices.iter() {
            // For fuzzing, we'll try to match by bus address or use first available device
            // Special case: address 0 means use first available device
            if device.address() == device_address || device_address == 0 {
                target_device = Some(device);
                break;
            }
        }
        
        let device = target_device
            .ok_or_else(|| anyhow::anyhow!("USB device with address {} not found", device_address))?;
            
        let handle = device.open()?;
        
        Ok(Self { handle, _context: context })
    }
    
    /// Creates a new USB device handle by vendor and product ID
    pub fn new_by_vid_pid(vendor_id: u16, product_id: u16) -> Result<Self, anyhow::Error> {
        let context = Context::new()?;
        
        // Find device by VID:PID
        let devices = context.devices()?;
        let mut target_device: Option<Device<Context>> = None;
        
        for device in devices.iter() {
            if let Ok(device_desc) = device.device_descriptor() {
                if device_desc.vendor_id() == vendor_id && device_desc.product_id() == product_id {
                    target_device = Some(device);
                    break;
                }
            }
        }
        
        let device = target_device
            .ok_or_else(|| anyhow::anyhow!("USB device {:04X}:{:04X} not found", vendor_id, product_id))?;
            
        let handle = device.open()?;
        
        Ok(Self { handle, _context: context })
    }
    
    /// Sends a control transfer to the USB device
    pub fn control_transfer(
        &self,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        data: &[u8],
        timeout: StdDuration,
    ) -> Result<usize, anyhow::Error> {
        let bytes_written = self.handle.write_control(
            request_type,
            request,
            value,
            index,
            data,
            timeout,
        )?;
        Ok(bytes_written)
    }
    
    /// Reads a control transfer response from the USB device
    pub fn control_read(
        &self,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        length: u16,
        timeout: StdDuration,
    ) -> Result<Vec<u8>, anyhow::Error> {
        let mut buffer = vec![0u8; length as usize];
        let bytes_read = self.handle.read_control(
            request_type,
            request,
            value,
            index,
            &mut buffer,
            timeout,
        )?;
        buffer.truncate(bytes_read);
        Ok(buffer)
    }
    
    /// Sends data to a bulk endpoint
    pub fn bulk_write(
        &self,
        endpoint: u8,
        data: &[u8],
        timeout: StdDuration,
    ) -> Result<usize, anyhow::Error> {
        let bytes_written = self.handle.write_bulk(endpoint, data, timeout)?;
        Ok(bytes_written)
    }
    
    /// Reads data from a bulk endpoint
    pub fn bulk_read(
        &self,
        endpoint: u8,
        length: usize,
        timeout: StdDuration,
    ) -> Result<Vec<u8>, anyhow::Error> {
        let mut buffer = vec![0u8; length];
        let bytes_read = self.handle.read_bulk(endpoint, &mut buffer, timeout)?;
        buffer.truncate(bytes_read);
        Ok(buffer)
    }
    
    /// Claims an interface for exclusive access
    pub fn claim_interface(&mut self, interface_number: u8) -> Result<(), anyhow::Error> {
        self.handle.claim_interface(interface_number)?;
        Ok(())
    }
    
    /// Releases a claimed interface
    pub fn release_interface(&mut self, interface_number: u8) -> Result<(), anyhow::Error> {
        self.handle.release_interface(interface_number)?;
        Ok(())
    }
}

#[cfg(feature = "usb")]
impl crate::attack::Attack for UsbPacket {
    type Response = Vec<u8>;
    
    fn send_payload(&self, payload: &[u8]) -> AttackResult<()> {
        // Validate device address range
        if self.device_address > 127 {
            return AttackResult::Continue(anyhow::anyhow!("Invalid device address: {}", self.device_address));
        }
        
        // Validate endpoint range
        if self.endpoint > 15 {
            return AttackResult::Continue(anyhow::anyhow!("Invalid endpoint: {}", self.endpoint));
        }
        
        // Create USB device handle
        let usb_handle = match UsbDeviceHandle::new(self.device_address) {
            Ok(handle) => handle,
            Err(e) => {
                return AttackResult::Continue(anyhow::anyhow!(
                    "Failed to open USB device {}: {}", self.device_address, e
                ));
            }
        };
        
        let timeout = StdDuration::from_secs(5);
        
        // Send data based on packet type
        match self.pid {
            UsbPid::SETUP => {
                // SETUP control transfer
                let request_type = match self.request_type.as_str() {
                    "Standard" => 0x80, // Device-to-host, standard, device
                    "Class" => 0xA0,    // Device-to-host, class, device  
                    "Vendor" => 0xC0,   // Device-to-host, vendor, device
                    _ => 0x80,
                };
                
                match usb_handle.control_transfer(
                    request_type,
                    self.request,
                    self.value,
                    self.index,
                    &self.data,
                    timeout,
                ) {
                    Ok(_) => AttackResult::Ok(()),
                    Err(e) => AttackResult::Continue(anyhow::anyhow!(
                        "SETUP control transfer failed: {}", e
                    )),
                }
            }
            UsbPid::OUT => {
                // Bulk OUT transfer
                let endpoint = self.endpoint | 0x00; // OUT endpoint
                match usb_handle.bulk_write(endpoint, payload, timeout) {
                    Ok(_) => AttackResult::Ok(()),
                    Err(e) => AttackResult::Continue(anyhow::anyhow!(
                        "Bulk OUT transfer failed: {}", e
                    )),
                }
            }
            UsbPid::IN => {
                // IN transfers are handled in wait_for_response
                AttackResult::Ok(())
            }
            UsbPid::SOF => {
                // SOF packets are generated by host controller, not applications
                AttackResult::Continue(anyhow::anyhow!("SOF packets cannot be sent by applications"))
            }
            _ => {
                // For data packets, use bulk transfer
                if matches!(self.pid, UsbPid::DATA0 | UsbPid::DATA1 | UsbPid::DATA2 | UsbPid::MDATA) {
                    let endpoint = self.endpoint | 0x00; // OUT endpoint
                    match usb_handle.bulk_write(endpoint, payload, timeout) {
                        Ok(_) => AttackResult::Ok(()),
                        Err(e) => AttackResult::Continue(anyhow::anyhow!(
                            "Data transfer failed: {}", e
                        )),
                    }
                } else {
                    AttackResult::Continue(anyhow::anyhow!("Unsupported packet type for sending"))
                }
            }
        }
    }
    
    fn wait_for_response(&self, timeout: std::time::Duration) -> AttackResult<Self::Response> {
        // Create USB device handle
        let usb_handle = match UsbDeviceHandle::new(self.device_address) {
            Ok(handle) => handle,
            Err(e) => {
                return AttackResult::Continue(anyhow::anyhow!(
                    "Failed to open USB device {} for response: {}", self.device_address, e
                ));
            }
        };
        
        let libusb_timeout = StdDuration::from_secs(timeout.as_secs().min(30));
        
        match self.pid {
            UsbPid::IN => {
                // IN token expects data response
                if self.endpoint == 0 {
                    // Control endpoint - try to read control response
                    match self.request {
                        0x06 => {
                            // GET_DESCRIPTOR request
                            match usb_handle.control_read(
                                0x80, // Device-to-host, standard, device
                                0x06, // GET_DESCRIPTOR
                                self.value,
                                self.index,
                                self.length,
                                libusb_timeout,
                            ) {
                                Ok(data) => AttackResult::Ok(data),
                                Err(e) => AttackResult::Continue(anyhow::anyhow!(
                                    "Control read failed: {}", e
                                )),
                            }
                        }
                        _ => {
                            // Generic control read
                            let request_type = match self.request_type.as_str() {
                                "Standard" => 0x80,
                                "Class" => 0xA0,
                                "Vendor" => 0xC0,
                                _ => 0x80,
                            };
                            
                            match usb_handle.control_read(
                                request_type,
                                self.request,
                                self.value,
                                self.index,
                                self.length,
                                libusb_timeout,
                            ) {
                                Ok(data) => AttackResult::Ok(data),
                                Err(e) => AttackResult::Continue(anyhow::anyhow!(
                                    "Control read failed: {}", e
                                )),
                            }
                        }
                    }
                } else {
                    // Bulk IN endpoint
                    let endpoint = self.endpoint | 0x80; // IN endpoint
                    let read_length = self.max_packet_size.min(1024) as usize;
                    
                    match usb_handle.bulk_read(endpoint, read_length, libusb_timeout) {
                        Ok(data) => AttackResult::Ok(data),
                        Err(e) => AttackResult::Continue(anyhow::anyhow!(
                            "Bulk read failed: {}", e
                        )),
                    }
                }
            }
            UsbPid::OUT | UsbPid::SETUP => {
                // OUT/SETUP transfers typically don't return data, just status
                // The transfer status was handled in send_payload
                AttackResult::Ok(vec![]) // Empty response indicates successful transfer
            }
            UsbPid::SOF => {
                // SOF packets don't expect responses
                AttackResult::Ok(vec![])
            }
            _ => {
                // For data packets, try to read response if it's an IN endpoint
                if matches!(self.pid, UsbPid::DATA0 | UsbPid::DATA1 | UsbPid::DATA2 | UsbPid::MDATA) {
                    let endpoint = self.endpoint | 0x80; // IN endpoint
                    let read_length = self.max_packet_size.min(1024) as usize;
                    
                    match usb_handle.bulk_read(endpoint, read_length, libusb_timeout) {
                        Ok(data) => AttackResult::Ok(data),
                        Err(e) => AttackResult::Continue(anyhow::anyhow!(
                            "Data read failed: {}", e
                        )),
                    }
                } else {
                    AttackResult::Ok(vec![])
                }
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

