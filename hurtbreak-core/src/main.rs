use hurtbreak_core::{
    protocols::tcp::{TcpPacket, TcpFlags},
    attack::{Attack, AttackResult},
    Fuzzable, Protocol,
};
use std::net::IpAddr;

fn main() -> anyhow::Result<()> {
    println!("Starting TCP Fuzzing Attack on localhost");
    
    // Create initial TCP packet targeting localhost
    let mut packet = TcpPacket {
        version: 4,
        header_length: 20,
        payload: b"Hello, fuzzing target!".to_vec(),
        method: "GET".to_string(),
        port: 8080,
        source_ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
        dest_ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
        flags: TcpFlags::SYN,
    };
    
    println!("Initial packet:");
    println!("{}", packet);
    println!("Initial payload bytes: {} bytes", packet.payload().len());
    
    // Perform fuzzing attack
    let max_attempts = 10;
    let mut attempt = 0;
    
    while attempt < max_attempts {
        attempt += 1;
        println!("\n--- Attack Attempt {} ---", attempt);
        
        // Fuzz the packet
        packet.fuzz();
        println!("Fuzzed packet:");
        println!("{}", packet);
        
        // Get the wire-format payload
        let wire_payload = packet.payload();
        println!("Wire payload: {} bytes", wire_payload.len());
        
        // Execute the attack
        match packet.execute_attack(&wire_payload) {
            AttackResult::Ok(response) => {
                println!("✅ Attack succeeded! Received {} bytes response", response.len());
                println!("Response preview: {:02x?}", &response[..response.len().min(32)]);
                break;
            }
            AttackResult::Continue(err) => {
                println!("⚠️  Attack continuing: {}", err);
                println!("   Will try next fuzzing iteration...");
            }
            AttackResult::Stop(err) => {
                println!("❌ Attack stopped: {}", err);
                println!("   Critical error encountered, stopping attack");
                break;
            }
        }
    }
    
    if attempt >= max_attempts {
        println!("\n🔄 Reached maximum attempts ({}), stopping attack", max_attempts);
    }
    
    println!("\n📊 Attack Summary:");
    println!("   Target: {}", packet.get_target_info());
    println!("   Attempts: {}", attempt);
    println!("   Final packet state:");
    println!("{}", packet);
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_tcp_packet_fuzzing_flow() {
        let mut packet = TcpPacket::default();

        packet.source_ip = "127.0.0.1".parse().unwrap();
        packet.dest_ip = "127.0.0.1".parse().unwrap();
        
        // Test that we can create and fuzz packets
        let _original = packet.clone();
        packet.fuzz();
        
        // Should have changed something (though not guaranteed due to randomness)
        // At minimum, check that the fuzz methods exist and don't panic
        packet.fuzz_source_ip();
        packet.fuzz_dest_ip();
        packet.fuzz_flags();
        packet.fuzz_payload();
        
        // Verify we can get wire format
        let payload = packet.payload();
        assert!(!payload.is_empty());
        
        // Verify display works
        let display_str = format!("{}", packet);
        assert!(display_str.contains("TcpPacket"));
    }
}