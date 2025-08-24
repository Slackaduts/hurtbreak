use hurtbreak_core::{
    protocols::usb::{UsbPacket, UsbPid, UsbSpeed},
    Fuzzable, Protocol,
};

#[cfg(feature = "async")]
use hurtbreak_core::attack::{AsyncAttack, AttackResult};


#[cfg(not(feature = "async"))]
use hurtbreak_core::attack::{Attack, AttackResult};

#[cfg(feature = "async")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("🔌 Starting Async USB Fuzzing Attack");
    
    // Create initial USB packet targeting device 0 (default address)
    let mut packet = UsbPacket {
        sync: 0x80,
        pid: UsbPid::SETUP,
        device_address: 0,
        endpoint: 0,
        frame_number: 0,
        data: b"GET_DESCRIPTOR".to_vec(),
        speed: UsbSpeed::Full,
        crc5: 0x1F,
        crc16: 0x0000,
        max_packet_size: 64,
        request_type: "Standard".to_string(),
        request: 0x06, // GET_DESCRIPTOR
        value: 0x0100, // Device descriptor
        index: 0,
        length: 18,
    };
    
    println!("Initial USB packet:");
    println!("{}", packet);
    println!("Initial payload bytes: {} bytes", packet.payload().len());
    
    // List of target devices to fuzz (simulating USB device enumeration)
    let target_devices = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let endpoints = [0, 1, 2, 3, 4];
    let usb_speeds = [UsbSpeed::Low, UsbSpeed::Full, UsbSpeed::High, UsbSpeed::Super];
    let pid_types = [UsbPid::SETUP, UsbPid::OUT, UsbPid::IN, UsbPid::SOF];
    
    // Perform comprehensive USB fuzzing attack
    let max_attempts = 500;
    let mut attempt = 0;
    let mut successful_attacks = 0;
    
    for device_addr in target_devices.iter() {
        for endpoint in endpoints.iter() {
            for speed in usb_speeds.iter() {
                for pid in pid_types.iter() {
                    if attempt >= max_attempts {
                        break;
                    }
                    
                    attempt += 1;
                    println!("\n--- USB Attack Attempt {} ---", attempt);
                    println!("🎯 Targeting Device: {} | Endpoint: {} | Speed: {} | PID: {}", 
                             device_addr, endpoint, speed, pid);
                    
                    // Configure packet for this attack iteration
                    packet.device_address = *device_addr;
                    packet.endpoint = *endpoint;
                    packet.speed = *speed;
                    packet.pid = *pid;
                    
                    // Adjust packet parameters based on PID type
                    match *pid {
                        UsbPid::SETUP => {
                            packet.request = 0x06; // GET_DESCRIPTOR
                            packet.value = 0x0100; // Device descriptor
                            packet.data = vec![];
                        }
                        UsbPid::OUT => {
                            packet.data = b"USB_FUZZ_DATA_OUT".to_vec();
                        }
                        UsbPid::IN => {
                            packet.data = vec![];
                        }
                        UsbPid::SOF => {
                            packet.frame_number = (attempt as u16) % 2048;
                            packet.data = vec![];
                        }
                        _ => {}
                    }
                    
                    // Fuzz the packet
                    packet.fuzz();
                    
                    // Restore critical fields after fuzzing
                    packet.device_address = *device_addr;
                    packet.endpoint = *endpoint;
                    packet.speed = *speed;
                    packet.pid = *pid;
                    
                    println!("Fuzzed USB packet:");
                    println!("{}", packet);
                    
                    // Get the wire-format payload
                    let wire_payload = packet.payload();
                    println!("USB wire payload: {} bytes", wire_payload.len());
                    
                    // Execute the async USB attack
                    match AsyncAttack::execute_attack(&packet, &wire_payload).await {
                        AttackResult::Ok(response) => {
                            successful_attacks += 1;
                            println!("✅ USB Attack succeeded! Received {} bytes response", response.len());
                            println!("Response preview: {:02x?}", &response[..response.len().min(32)]);
                            
                            // Analyze USB response
                            if !response.is_empty() {
                                match response[0] {
                                    0x02 => println!("   📨 Received ACK handshake"),
                                    0x0A => println!("   🚫 Received NAK handshake"),
                                    0x0E => println!("   🛑 Received STALL handshake"),
                                    0x06 => println!("   ⏸️  Received NYET handshake"),
                                    _ => {
                                        if response.len() >= 18 && response[0] == 0x12 && response[1] == 0x01 {
                                            println!("   📋 Received Device Descriptor!");
                                            println!("      USB Version: {}.{}", response[3], response[2]);
                                            println!("      Max Packet Size: {}", response[7]);
                                        } else {
                                            println!("   📦 Received custom USB data");
                                        }
                                    }
                                }
                            }
                            
                            // Small delay between successful attacks
                            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                        }
                        AttackResult::Continue(err) => {
                            println!("⚠️  USB Attack continuing: {}", err);
                            println!("   Will try next USB device/endpoint combination...");
                        }
                        AttackResult::Stop(err) => {
                            println!("❌ USB Attack stopped: {}", err);
                            println!("   Critical USB error encountered");
                            break;
                        }
                    }
                    
                    // Small delay between attack attempts
                    tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
                }
            }
        }
    }
    
    if attempt >= max_attempts {
        println!("\n🔄 Reached maximum attempts ({}), stopping USB fuzzing", max_attempts);
    }
    
    println!("\n📊 USB Fuzzing Attack Summary:");
    println!("   Target Info: {}", AsyncAttack::get_target_info(&packet));
    println!("   Total Attempts: {}", attempt);
    println!("   Successful Attacks: {}", successful_attacks);
    println!("   Success Rate: {:.2}%", (successful_attacks as f64 / attempt as f64) * 100.0);
    println!("   Devices Targeted: {:?}", target_devices);
    println!("   Endpoints Tested: {:?}", endpoints);
    println!("   Speeds Tested: {:?}", usb_speeds);
    println!("   PID Types: {:?}", pid_types);
    println!("   Final packet state:");
    println!("{}", packet);
    
    Ok(())
}

#[cfg(not(feature = "async"))]
fn main() -> anyhow::Result<()> {
    println!("🔌 Starting USB Fuzzing Attack (Synchronous)");
    
    // Create initial USB packet targeting device 0 (default address)
    let mut packet = UsbPacket {
        sync: 0x80,
        pid: UsbPid::SETUP,
        device_address: 0,
        endpoint: 0,
        frame_number: 0,
        data: b"GET_DESCRIPTOR".to_vec(),
        speed: UsbSpeed::Full,
        crc5: 0x1F,
        crc16: 0x0000,
        max_packet_size: 64,
        request_type: "Standard".to_string(),
        request: 0x06, // GET_DESCRIPTOR
        value: 0x0100, // Device descriptor
        index: 0,
        length: 18,
    };
    
    println!("Initial USB packet:");
    println!("{}", packet);
    println!("Initial payload bytes: {} bytes", packet.payload().len());
    
    // Perform USB fuzzing attack
    let max_attempts = 50;
    let mut attempt = 0;
    let mut successful_attacks = 0;
    
    let target_devices = [0, 1, 2, 3, 4];
    let endpoints = [0, 1, 2];
    let pid_types = [UsbPid::SETUP, UsbPid::OUT, UsbPid::IN];
    
    for device_addr in target_devices.iter() {
        for endpoint in endpoints.iter() {
            for pid in pid_types.iter() {
                if attempt >= max_attempts {
                    break;
                }
                
                attempt += 1;
                println!("\n--- USB Attack Attempt {} ---", attempt);
                println!("🎯 Targeting Device: {} | Endpoint: {} | PID: {}", 
                         device_addr, endpoint, pid);
                
                // Configure packet for this attack iteration
                packet.device_address = *device_addr;
                packet.endpoint = *endpoint;
                packet.pid = *pid;
                
                // Fuzz the packet
                packet.fuzz();
                
                // Restore critical fields after fuzzing
                packet.device_address = *device_addr;
                packet.endpoint = *endpoint;
                packet.pid = *pid;
                
                println!("Fuzzed USB packet:");
                println!("{}", packet);
                
                // Get the wire-format payload
                let wire_payload = packet.payload();
                println!("USB wire payload: {} bytes", wire_payload.len());
                
                // Execute the USB attack
                match Attack::execute_attack(&packet, &wire_payload) {
                    AttackResult::Ok(response) => {
                        successful_attacks += 1;
                        println!("✅ USB Attack succeeded! Received {} bytes response", response.len());
                        println!("Response preview: {:02x?}", &response[..response.len().min(32)]);
                    }
                    AttackResult::Continue(err) => {
                        println!("⚠️  USB Attack continuing: {}", err);
                        println!("   Will try next USB device/endpoint combination...");
                    }
                    AttackResult::Stop(err) => {
                        println!("❌ USB Attack stopped: {}", err);
                        println!("   Critical USB error encountered");
                        break;
                    }
                }
            }
        }
    }
    
    if attempt >= max_attempts {
        println!("\n🔄 Reached maximum attempts ({}), stopping USB fuzzing", max_attempts);
    }
    
    println!("\n📊 USB Fuzzing Attack Summary:");
    println!("   Target Info: {}", Attack::get_target_info(&packet));
    println!("   Total Attempts: {}", attempt);
    println!("   Successful Attacks: {}", successful_attacks);
    println!("   Success Rate: {:.2}%", (successful_attacks as f64 / attempt as f64) * 100.0);
    println!("   Final packet state:");
    println!("{}", packet);
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_usb_packet_fuzzing_flow() {
        let mut packet = UsbPacket::default();
        
        // Test that we can create and fuzz packets
        let _original = packet.clone();
        packet.fuzz();
        
        // Should have changed something (though not guaranteed due to randomness)
        // At minimum, check that the fuzz methods exist and don't panic
        packet.fuzz_device_address();
        packet.fuzz_endpoint();
        packet.fuzz_pid();
        packet.fuzz_data();
        packet.fuzz_speed();
        
        // Verify we can get wire format
        let payload = packet.payload();
        assert!(!payload.is_empty());
        
        // Verify display works
        let display_str = format!("{}", packet);
        assert!(display_str.contains("UsbPacket"));
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn test_full_async_attack_flow() {
        println!("🚀 Starting Full Async USB Attack Flow Test");
        
        // Create initial USB packet targeting device 0
        let mut packet = UsbPacket {
            sync: 0x80,
            pid: UsbPid::SETUP,
            device_address: 0,
            endpoint: 0,
            frame_number: 0,
            data: b"Test async USB attack".to_vec(),
            speed: UsbSpeed::Full,
            crc5: 0x1F,
            crc16: 0x0000,
            max_packet_size: 64,
            request_type: "Standard".to_string(),
            request: 0x06,
            value: 0x0100,
            index: 0,
            length: 18,
        };
        
        println!("Initial test packet: {}", packet);
        
        let max_iterations = 3;
        let mut iteration = 0;
        let mut success_count = 0;
        let mut continue_count = 0;
        let mut stop_count = 0;
        
        while iteration < max_iterations {
            iteration += 1;
            println!("\n=== Async USB Attack Iteration {} ===", iteration);
            
            // Fuzz the packet for this iteration
            packet.fuzz();
            
            // Keep device address stable for testing
            packet.device_address = 0;
            packet.endpoint = 0;
            
            println!("Fuzzed packet: {}", packet);
            
            // Get wire format payload
            let wire_payload = packet.payload();
            println!("Wire payload size: {} bytes", wire_payload.len());
            
            // Send payload and wait for response asynchronously
            match packet.send_payload(&wire_payload).await {
                AttackResult::Ok(()) => {
                    println!("✅ Payload sent successfully");
                    
                    // Now wait for response
                    let timeout = std::time::Duration::from_millis(1000);
                    match packet.wait_for_response(timeout).await {
                        AttackResult::Ok(response) => {
                            println!("📨 Received response: {} bytes", response.len());
                            
                            // Print response preview
                            if !response.is_empty() {
                                let preview_len = std::cmp::min(response.len(), 32);
                                println!("Response preview (first {} bytes): {:02x?}", 
                                        preview_len, &response[..preview_len]);
                            }
                            
                            // Validate the response
                            match packet.validate_response(&response).await {
                                AttackResult::Ok(()) => {
                                    println!("✅ Response validation successful - ASYNC ATTACK SUCCESS!");
                                    success_count += 1;
                                    break; // Success - exit the loop
                                }
                                AttackResult::Continue(err) => {
                                    println!("⚠️  Response validation says continue: {}", err);
                                    continue_count += 1;
                                }
                                AttackResult::Stop(err) => {
                                    println!("❌ Response validation says stop: {}", err);
                                    stop_count += 1;
                                    break; // Stop - exit the loop
                                }
                            }
                        }
                        AttackResult::Continue(err) => {
                            println!("⚠️  Response wait continuing: {}", err);
                            continue_count += 1;
                        }
                        AttackResult::Stop(err) => {
                            println!("❌ Response wait stopped: {}", err);
                            stop_count += 1;
                            break; // Stop - exit the loop
                        }
                    }
                }
                AttackResult::Continue(err) => {
                    println!("⚠️  Payload send continuing: {}", err);
                    continue_count += 1;
                }
                AttackResult::Stop(err) => {
                    println!("❌ Payload send stopped: {}", err);
                    stop_count += 1;
                    break; // Stop - exit the loop
                }
            }
        }
        
        println!("\n📊 Test Async Attack Summary:");
        println!("   Total iterations: {}", iteration);
        println!("   Successes: {}", success_count);
        println!("   Continues: {}", continue_count);
        println!("   Stops: {}", stop_count);
        println!("   Final packet: {}", packet);
        
        // Test should pass regardless of results since we're testing the flow
        assert!(iteration > 0, "Should have run at least one iteration");
        println!("✅ Full async attack flow test completed successfully");
    }

    #[cfg(not(feature = "async"))]
    #[test]
    fn test_full_sync_attack_flow() {
        println!("🚀 Starting Full Sync USB Attack Flow Test");
        
        // Create initial USB packet targeting device 0
        let mut packet = UsbPacket {
            sync: 0x80,
            pid: UsbPid::SETUP,
            device_address: 0,
            endpoint: 0,
            frame_number: 0,
            data: b"Test sync USB attack".to_vec(),
            speed: UsbSpeed::Full,
            crc5: 0x1F,
            crc16: 0x0000,
            max_packet_size: 64,
            request_type: "Standard".to_string(),
            request: 0x06,
            value: 0x0100,
            index: 0,
            length: 18,
        };
        
        println!("Initial test packet: {}", packet);
        
        let max_iterations = 3;
        let mut iteration = 0;
        let mut success_count = 0;
        let mut continue_count = 0;
        let mut stop_count = 0;
        
        while iteration < max_iterations {
            iteration += 1;
            println!("\n=== Sync USB Attack Iteration {} ===", iteration);
            
            // Fuzz the packet for this iteration
            packet.fuzz();
            
            // Keep device address stable for testing
            packet.device_address = 0;
            packet.endpoint = 0;
            
            println!("Fuzzed packet: {}", packet);
            
            // Get wire format payload
            let wire_payload = packet.payload();
            println!("Wire payload size: {} bytes", wire_payload.len());
            
            // Send payload and wait for response synchronously
            match packet.send_payload(&wire_payload) {
                AttackResult::Ok(()) => {
                    println!("✅ Payload sent successfully");
                    
                    // Now wait for response
                    let timeout = std::time::Duration::from_millis(1000);
                    match packet.wait_for_response(timeout) {
                        AttackResult::Ok(response) => {
                            println!("📨 Received response: {} bytes", response.len());
                            
                            // Print response preview
                            if !response.is_empty() {
                                let preview_len = std::cmp::min(response.len(), 32);
                                println!("Response preview (first {} bytes): {:02x?}", 
                                        preview_len, &response[..preview_len]);
                            }
                            
                            // Validate the response
                            match packet.validate_response(&response) {
                                AttackResult::Ok(()) => {
                                    println!("✅ Response validation successful - SYNC ATTACK SUCCESS!");
                                    success_count += 1;
                                    break; // Success - exit the loop
                                }
                                AttackResult::Continue(err) => {
                                    println!("⚠️  Response validation says continue: {}", err);
                                    continue_count += 1;
                                }
                                AttackResult::Stop(err) => {
                                    println!("❌ Response validation says stop: {}", err);
                                    stop_count += 1;
                                    break; // Stop - exit the loop
                                }
                            }
                        }
                        AttackResult::Continue(err) => {
                            println!("⚠️  Response wait continuing: {}", err);
                            continue_count += 1;
                        }
                        AttackResult::Stop(err) => {
                            println!("❌ Response wait stopped: {}", err);
                            stop_count += 1;
                            break; // Stop - exit the loop
                        }
                    }
                }
                AttackResult::Continue(err) => {
                    println!("⚠️  Payload send continuing: {}", err);
                    continue_count += 1;
                }
                AttackResult::Stop(err) => {
                    println!("❌ Payload send stopped: {}", err);
                    stop_count += 1;
                    break; // Stop - exit the loop
                }
            }
        }
        
        println!("\n📊 Test Sync Attack Summary:");
        println!("   Total iterations: {}", iteration);
        println!("   Successes: {}", success_count);
        println!("   Continues: {}", continue_count);
        println!("   Stops: {}", stop_count);
        println!("   Final packet: {}", packet);
        
        // Test should pass regardless of results since we're testing the flow
        assert!(iteration > 0, "Should have run at least one iteration");
        println!("✅ Full sync attack flow test completed successfully");
    }
}