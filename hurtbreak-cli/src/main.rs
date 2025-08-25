use clap::{Parser, Subcommand};
use hurtbreak_core::{FieldIntrospection, Fuzzable, Protocol};
use hurtbreak_core::protocols::{TcpPacket, UsbPacket};
use hurtbreak_core::attack::{Attack, AttackResult};
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use serde_json::json;
use chrono::prelude::*;

#[derive(Parser)]
#[command(name = "hurtbreak")]
#[command(about = "A protocol-agnostic fuzzer.")]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Launch a fuzzing attack against a protocol
    Launch {
        /// Protocol to target (tcp, usb, etc.)
        protocol: String,
        /// Field specifications in format field_name=value
        #[arg(long = "field", value_name = "FIELD=VALUE")]
        fields: Vec<String>,
        /// Maximum number of fuzzing attempts
        #[arg(long = "max-tries", default_value = "100")]
        max_tries: usize,
        /// Output file path for JSON results
        #[arg(long = "output", value_name = "FILE")]
        output: Option<String>,
        /// Additional protocol-specific arguments
        #[arg(last = true)]
        args: Vec<String>,
    },
}

/// Parses command-line field specifications into a structured mapping.
/// 
/// Converts user-provided field specifications from the format "field_name=value"
/// into a HashMap for efficient field lookup during attack configuration. Invalid
/// specifications that do not conform to the expected format are logged as warnings
/// and excluded from the resulting mapping.
/// 
/// # Arguments
/// 
/// * `field_specs` - Array of field specification strings in "key=value" format
/// 
/// # Returns
/// 
/// A HashMap mapping field names to their corresponding string values. Malformed
/// specifications are silently discarded with warning output to stderr.
/// 
/// # Examples
/// 
/// ```rust,no_run
/// let specs = vec!["port=8080".to_string(), "device_address=1".to_string()];
/// let fields = parse_field_specifications(&specs);
/// assert_eq!(fields.get("port"), Some(&"8080".to_string()));
/// assert_eq!(fields.get("device_address"), Some(&"1".to_string()));
/// ```
fn parse_field_specifications(field_specs: &[String]) -> HashMap<String, String> {
    let mut fields = HashMap::new();
    
    for spec in field_specs {
        if let Some((field, value)) = spec.split_once('=') {
            fields.insert(field.to_string(), value.to_string());
        } else {
            eprintln!("Warning: Invalid field specification '{}', expected format 'field=value'", spec);
        }
    }
    
    fields
}

/// Application entry point for the Hurtbreak protocol fuzzer CLI.
/// 
/// Initializes command-line argument parsing, validates input parameters, and
/// dispatches execution to the appropriate attack orchestration functions based
/// on the specified subcommand. Provides centralized error handling and ensures
/// proper resource cleanup on both successful and error exit paths.
/// 
/// # Returns
/// 
/// `Ok(())` on successful execution, `Err(anyhow::Error)` on any failure condition
/// including invalid arguments, protocol errors, or I/O failures.
/// 
/// # Examples
/// 
/// ```rust,no_run
/// use std::process::Command;
/// 
/// // Launch TCP fuzzing attack with fixed port and 100 iterations
/// let output = Command::new("hurtbreak")
///     .args(&["launch", "tcp", "--field", "port=8080", "--max-tries", "100"])
///     .output()?;
/// 
/// // Launch USB fuzzing attack with JSON output
/// let output = Command::new("hurtbreak")
///     .args(&["launch", "usb", "--max-tries", "50", "--output", "results.json"])
///     .output()?;
/// ```
fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Launch { protocol, fields, max_tries, output, args } => {
            let field_map = parse_field_specifications(&fields);
            launch_attack(&protocol, field_map, max_tries, output, &args)?;
        }
    }
    
    Ok(())
}

/// Protocol-agnostic attack dispatcher that routes execution to appropriate implementations.
/// 
/// Serves as the primary routing mechanism for attack execution, mapping protocol identifiers
/// to their corresponding concrete implementations. Performs protocol validation and delegates
/// to specialized attack orchestration functions while maintaining protocol-agnostic interfaces
/// throughout the execution pipeline.
/// 
/// # Arguments
/// 
/// * `protocol` - Protocol identifier string (case-insensitive)
/// * `field_specs` - Pre-parsed field fixation mappings for attack customization
/// * `max_tries` - Maximum number of fuzzing iterations to execute
/// * `output` - Optional file path for JSON result serialization
/// * `_args` - Reserved protocol-specific arguments (currently unused)
/// 
/// # Returns
/// 
/// `Ok(())` on successful attack completion, `Err(anyhow::Error)` for unsupported
/// protocols or execution failures in downstream attack implementations.
/// 
/// # Supported Protocols
/// 
/// * `tcp` - TCP/IP network protocol fuzzing
/// * `usb` - USB device communication protocol fuzzing
/// 
/// # Examples
/// 
/// ```rust,no_run
/// let field_specs = HashMap::from([("port".to_string(), "8080".to_string())]);
/// launch_attack("tcp", field_specs, 100, Some("results.json".to_string()), &[])?;
/// 
/// let usb_specs = HashMap::from([("device_address".to_string(), "1".to_string())]);
/// launch_attack("usb", usb_specs, 50, None, &[])?;
/// ```
fn launch_attack(protocol: &str, field_specs: HashMap<String, String>, max_tries: usize, output: Option<String>, _args: &[String]) -> anyhow::Result<()> {
    match protocol.to_lowercase().as_str() {
        "tcp" => {
            launch_generic_attack::<TcpPacket>("tcp", field_specs, max_tries, output)?;
        }
        "usb" => {
            launch_generic_attack::<UsbPacket>("usb", field_specs, max_tries, output)?;
        }
        _ => {
            anyhow::bail!("Unsupported protocol: {}", protocol);
        }
    }
    
    Ok(())
}

/// Generic attack orchestration engine for trait-compliant protocol implementations.
/// 
/// Executes comprehensive fuzzing campaigns against protocol targets using trait-based
/// polymorphism for maximum code reusability. Integrates field introspection, payload
/// generation, attack execution, and result aggregation into a unified workflow that
/// operates independently of specific protocol implementations.
/// 
/// This function represents the core abstraction layer that eliminates protocol-specific
/// code duplication while maintaining full access to specialized attack behaviors through
/// the trait system. All protocol implementations that satisfy the trait bounds receive
/// identical feature sets including field fixation, progress reporting, JSON serialization,
/// and attack flow control.
/// 
/// # Type Parameters
/// 
/// * `T` - Protocol packet type that must implement all required traits for complete
///   fuzzing functionality including attack execution, field manipulation, and serialization
/// 
/// # Arguments
/// 
/// * `protocol_name` - Human-readable protocol identifier for logging and output formatting
/// * `field_specs` - Field fixation mappings that override fuzzing for specified fields
/// * `max_tries` - Upper bound on fuzzing iterations before campaign termination
/// * `output` - Optional file path for structured JSON result persistence
/// 
/// # Returns
/// 
/// `Ok(())` on successful campaign completion, `Err(anyhow::Error)` on field configuration
/// failures, I/O errors during result serialization, or other execution failures.
/// 
/// # Attack Flow Control
/// 
/// Attack execution respects `AttackResult` flow control semantics:
/// * `AttackResult::Ok` - Attack succeeded, increment success counter and continue
/// * `AttackResult::Continue` - Attack failed but campaign should continue with next iteration
/// * `AttackResult::Stop` - Fatal error encountered, immediately terminate campaign
/// 
/// # Statistical Reporting
/// 
/// Maintains comprehensive execution statistics including successful attacks, continued
/// attempts, and stopped campaigns. Results are reported both to console output and
/// JSON metadata for programmatic analysis.
/// 
/// # Examples
/// 
/// ```rust,no_run
/// // Execute TCP fuzzing campaign with port fixation
/// let tcp_fields = HashMap::from([("port".to_string(), "443".to_string())]);
/// launch_generic_attack::<TcpPacket>("tcp", tcp_fields, 1000, Some("tcp_results.json".to_string()))?;
/// 
/// // Execute USB fuzzing campaign with device addressing
/// let usb_fields = HashMap::from([
///     ("device_address".to_string(), "1".to_string()),
///     ("speed".to_string(), "High".to_string())
/// ]);
/// launch_generic_attack::<UsbPacket>("usb", usb_fields, 500, None)?;
/// ```
fn launch_generic_attack<T>(protocol_name: &str, field_specs: HashMap<String, String>, max_tries: usize, output: Option<String>) -> anyhow::Result<()>
where
    T: Fuzzable + FieldIntrospection + Protocol + Attack + Clone + Default + std::fmt::Display,
{
    println!("Launching {} fuzzing attack with max {} tries...", protocol_name.to_uppercase(), max_tries);
    
    // Display available fields
    let field_info = T::get_field_info();
    println!("Available {} fields:", protocol_name.to_uppercase());
    for info in &field_info {
        println!("  {}: {} (can be fixed: {})", info.name, info.type_name, info.can_be_fixed);
    }
    
    // Create default packet
    let mut packet = T::default();
    
    // Apply field specifications
    for (field_name, value) in &field_specs {
        println!("Setting field '{}' to '{}'", field_name, value);
        match packet.set_field(field_name, value) {
            Ok(()) => println!("✓ Successfully set {} = {}", field_name, value),
            Err(e) => {
                eprintln!("✗ Failed to set {}: {}", field_name, e);
                return Err(anyhow::anyhow!("Field setting failed"));
            }
        }
    }
    
    println!("\nInitial packet configuration:");
    println!("{}", packet);
    
    // Initialize JSON output collection and statistics
    let mut results = Vec::new();
    let mut successful_attacks = 0;
    let mut continued_attacks = 0;
    let mut stopped_attacks = 0;
    
    // Run fuzzing iterations up to max_tries
    println!("\nRunning fuzzing iterations (fields not specified will be randomized):");
    println!("Target: {}\n", packet.get_target_info());
    
    for i in 1..=max_tries {
        let iteration_start = Utc::now();
        
        let mut fuzz_packet = packet.clone();
        
        // Fuzz only the fields that weren't specified as fixed
        fuzz_packet.fuzz();
        
        // Re-apply fixed field values after fuzzing
        for (field_name, value) in &field_specs {
            let _ = fuzz_packet.set_field(field_name, value);
        }
        
        let payload = fuzz_packet.payload();
        let payload_timestamp = Utc::now();
        
        // Execute the actual attack using the Attack trait!
        let attack_result = fuzz_packet.execute_attack(&payload);
        let response_timestamp = Utc::now();
        
        // Handle the attack result according to AttackResult flow control
        let (response_data, status, should_continue) = match attack_result {
            AttackResult::Ok(_response) => {
                successful_attacks += 1;
                (serde_json::Value::String("Attack executed successfully - response received".to_string()), "SUCCESS", true)
            }
            AttackResult::Continue(err) => {
                continued_attacks += 1;
                (serde_json::Value::String(err.to_string()), "CONTINUE", true)
            }
            AttackResult::Stop(err) => {
                stopped_attacks += 1;
                (serde_json::Value::String(err.to_string()), "STOP", false)
            }
        };
        
        // Display progress for first few iterations and every 10th iteration
        if i <= 3 || i % 10 == 0 || i == max_tries {
            println!("Iteration {} [{}]:", i, status);
            println!("{}", fuzz_packet);
            println!("Payload ({} bytes): {:02x?}", payload.len(), &payload[..payload.len().min(32)]);
            println!("Response: {}", response_data);
            println!();
        } else if i % 50 == 0 {
            println!("Completed {} iterations... (Success: {}, Continue: {}, Stop: {})", i, successful_attacks, continued_attacks, stopped_attacks);
        }
        
        // Collect results for JSON output
        if output.is_some() {
            let result = json!({
                "iteration": i,
                "status": status,
                "payload": {
                    "data": payload,
                    "hex": hex::encode(&payload),
                    "timestamp": payload_timestamp.to_rfc3339()
                },
                "response": {
                    "data": response_data,
                    "timestamp": response_timestamp.to_rfc3339()
                },
                "packet_config": format!("{}", fuzz_packet),
                "target_info": fuzz_packet.get_target_info(),
                "duration_ms": (response_timestamp - iteration_start).num_milliseconds()
            });
            results.push(result);
        }
        
        // Check if we should stop the attack
        if !should_continue {
            println!("Attack stopped at iteration {} due to fatal error", i);
            break;
        }
    }
    
    // Write JSON output if specified
    if let Some(output_path) = output {
        let output_data = json!({
            "metadata": {
                "protocol": protocol_name,
                "max_tries": max_tries,
                "fixed_fields": field_specs,
                "total_iterations": results.len(),
                "start_time": Utc::now().to_rfc3339(),
                "statistics": {
                    "successful_attacks": successful_attacks,
                    "continued_attacks": continued_attacks,
                    "stopped_attacks": stopped_attacks
                }
            },
            "results": results
        });
        
        let mut file = File::create(&output_path)?;
        file.write_all(serde_json::to_string_pretty(&output_data)?.as_bytes())?;
        println!("JSON results written to: {}", output_path);
    }
    
    println!("\n{} fuzzing attack completed after {} iterations", protocol_name.to_uppercase(), results.len());
    println!("Results: {} successful, {} continued, {} stopped", successful_attacks, continued_attacks, stopped_attacks);
    
    Ok(())
}

