//! Procedural macro for automatically deriving fuzzing functionality.
//! 
//! This crate provides the `#[derive(Fuzzable)]` macro that automatically generates
//! fuzzing methods for struct fields based on their types and attributes. The generated
//! code allows for intelligent randomization of struct fields for security testing
//! and protocol fuzzing.
//! 
//! # Supported Attributes
//! 
//! * `#[fuzz(skip)]` - Skip this field during fuzzing
//! * `#[fuzz(range = "min..=max")]` - Fuzz numeric fields within a range
//! * `#[fuzz(max_len = N)]` - Fuzz Vec<u8> with maximum length N
//! * `#[fuzz(values = "[\"val1\", \"val2\"]")]` - Choose from predefined values
//! * `#[fuzz(pattern = "type.type", delimiter = ".")]` - Generate structured patterns
//! * `#[fuzz]` - Use default fuzzing behavior for the field type
//! 
//! # Examples
//! 
//! ```rust,norun
//! use hurtbreak_derive::Fuzzable;
//! 
//! #[derive(Fuzzable)]
//! struct TestStruct {
//!     #[fuzz(range = "1..=100")]
//!     numeric_field: u32,
//!     
//!     #[fuzz(max_len = 256)]
//!     data_field: Vec<u8>,
//!     
//!     #[fuzz(values = "[\"GET\", \"POST\", \"PUT\"]")]
//!     method: String,
//!     
//!     #[fuzz(skip)]
//!     dont_fuzz: bool,
//! }
//! ```

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{
    parse_macro_input, Attribute, Data, DeriveInput, Fields, Ident, Lit, Meta, Type,
};

/// Derives the `Fuzzable` trait for structs with named fields.
/// 
/// This procedural macro automatically generates fuzzing methods for each field
/// in a struct, respecting field-level `#[fuzz]` attributes for customization.
/// The generated implementation includes individual fuzzing methods for each field
/// and a `fuzz_all()` method that fuzzes all non-skipped fields.
/// 
/// # Generated Methods
/// 
/// * `fuzz_{field_name}()` - Fuzz individual fields based on their attributes
/// * `fuzz_all()` - Fuzz all fields that aren't marked with `#[fuzz(skip)]`
/// 
/// # Supported Field Types
/// 
/// * Numeric types: `u8`, `u16`, `u32`, `u64`, `i8`, `i16`, `i32`, `i64`
/// * String types: `String`
/// * Vector types: `Vec<u8>` (for binary data)
/// * Custom types that implement `FromStr`
/// 
/// # Attribute Configuration
/// 
/// See crate-level documentation for detailed attribute usage.
/// 
/// # Panics
/// 
/// Panics at compile time if applied to:
/// * Enums or unions (only structs supported)
/// * Structs without named fields (tuple structs not supported)
/// 
/// # Examples
/// 
/// ```rust,norun
/// use hurtbreak_derive::Fuzzable;
/// use hurtbreak_core::Fuzzable as FuzzableTrait;
/// 
/// #[derive(Fuzzable)]
/// struct NetworkPacket {
///     #[fuzz(range = "1..=65535")]
///     port: u16,
///     
///     #[fuzz(max_len = 1024)]
///     payload: Vec<u8>,
///     
///     #[fuzz(values = "[\"TCP\", \"UDP\", \"ICMP\"]")]
///     protocol: String,
/// }
/// 
/// let mut packet = NetworkPacket {
///     port: 80,
///     payload: vec![0x41, 0x42, 0x43],
///     protocol: "TCP".to_string(),
/// };
/// 
/// // Fuzz individual fields
/// packet.fuzz_port();
/// packet.fuzz_payload();
/// 
/// // Or fuzz all fields at once
/// packet.fuzz_all();
/// ```
#[proc_macro_derive(Fuzzable, attributes(fuzz))]
pub fn derive_fuzzable(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    
    match &input.data {
        Data::Struct(data_struct) => {
            match &data_struct.fields {
                Fields::Named(fields) => {
                    let struct_name = &input.ident;
                    let fuzz_impl = generate_fuzz_impl(struct_name, fields);
                    TokenStream::from(fuzz_impl)
                }
                _ => panic!("Fuzzable can only be derived for structs with named fields"),
            }
        }
        _ => panic!("Fuzzable can only be derived for structs"),
    }
}

/// Generates the complete fuzzing implementation for a struct.
/// 
/// Creates individual fuzzing methods for each field and a `fuzz_all()` method
/// that calls all field-specific fuzzing methods except those marked with `#[fuzz(skip)]`.
/// 
/// # Arguments
/// 
/// * `struct_name` - The identifier of the struct being processed
/// * `fields` - The named fields of the struct
/// 
/// # Returns
/// 
/// A `TokenStream` containing the complete `impl` block with fuzzing methods
fn generate_fuzz_impl(
    struct_name: &Ident,
    fields: &syn::FieldsNamed,
) -> proc_macro2::TokenStream {
    let fuzz_methods = fields.named.iter().map(|field| {
        let field_name = field.ident.as_ref().unwrap();
        let field_type = &field.ty;
        
        let fuzz_config = parse_fuzz_attributes(&field.attrs);
        
        match fuzz_config {
            FuzzConfig::Skip => {
                quote! {}
            }
            FuzzConfig::Range { min, max } => {
                let method_name = Ident::new(&format!("fuzz_{}", field_name), Span::call_site());
                generate_range_fuzz_method(field_name, field_type, method_name, min, max)
            }
            FuzzConfig::MaxLen { max_len } => {
                let method_name = Ident::new(&format!("fuzz_{}", field_name), Span::call_site());
                quote! {
                    pub fn #method_name(&mut self) {
                        use crate::random::FuzzableNumber;
                        let len = <usize as crate::random::FuzzableNumber>::fuzz(0, #max_len);
                        self.#field_name = (0..len).map(|_| <u8 as crate::random::FuzzableNumber>::fuzz(<u8 as crate::random::FuzzableNumber>::min(), <u8 as crate::random::FuzzableNumber>::max())).collect();
                    }
                }
            }
            FuzzConfig::Values { values } => {
                let method_name = Ident::new(&format!("fuzz_{}", field_name), Span::call_site());
                quote! {
                    pub fn #method_name(&mut self) {
                        use crate::random::{FuzzerRNG, DEFAULT_RNG};
                        let options = vec![#(#values.to_string()),*];
                        let selected = crate::random::DEFAULT_RNG.choice(&options).unwrap().clone();
                        self.#field_name = selected.parse().expect("Failed to parse fuzzed value");
                    }
                }
            }
            FuzzConfig::Pattern { pattern, delimiter } => {
                let method_name = Ident::new(&format!("fuzz_{}", field_name), Span::call_site());
                generate_pattern_fuzz_method(field_name, field_type, method_name, pattern, delimiter)
            }
            FuzzConfig::Default => {
                let method_name = Ident::new(&format!("fuzz_{}", field_name), Span::call_site());
                generate_default_fuzz_method(field_name, field_type, method_name)
            }
        }
    });

    let all_fuzz_methods: Vec<_> = fields.named.iter().filter_map(|field| {
        let field_name = field.ident.as_ref().unwrap();
        let fuzz_config = parse_fuzz_attributes(&field.attrs);
        
        match fuzz_config {
            FuzzConfig::Skip => None,
            _ => {
                let method_name = Ident::new(&format!("fuzz_{}", field_name), Span::call_site());
                Some(quote! { self.#method_name(); })
            }
        }
    }).collect();

    let field_info_items: Vec<_> = fields.named.iter().map(|field| {
        let field_name = field.ident.as_ref().unwrap();
        let field_type = &field.ty;
        let fuzz_config = parse_fuzz_attributes(&field.attrs);
        
        let name = field_name.to_string();
        let type_name = quote!(#field_type).to_string();
        let can_be_fixed = !matches!(fuzz_config, FuzzConfig::Skip);
        let description = format!("Field {} of type {}", name, type_name);
        
        quote! {
            crate::FieldInfo {
                name: #name.to_string(),
                type_name: #type_name.to_string(),
                can_be_fixed: #can_be_fixed,
                description: #description.to_string(),
            }
        }
    }).collect();

    let set_field_arms: Vec<_> = fields.named.iter().map(|field| {
        let field_name = field.ident.as_ref().unwrap();
        let field_name_str = field_name.to_string();
        let field_type = &field.ty;
        
        // Handle Vec<u8> specially
        if let syn::Type::Path(type_path) = field_type {
            if type_path.path.segments.len() == 1 && type_path.path.segments[0].ident == "Vec" {
                return quote! {
                    #field_name_str => {
                        // Handle Vec<u8> specially - parse as hex string or comma-separated bytes
                        if value.starts_with("0x") || value.chars().all(|c| c.is_ascii_hexdigit()) {
                            // Parse as hex string
                            let hex_str = value.trim_start_matches("0x");
                            if hex_str.len() % 2 == 0 {
                                let mut bytes = Vec::new();
                                for chunk in hex_str.as_bytes().chunks(2) {
                                    if let Ok(chunk_str) = std::str::from_utf8(chunk) {
                                        if let Ok(byte) = u8::from_str_radix(chunk_str, 16) {
                                            bytes.push(byte);
                                        } else {
                                            return Err(format!("Invalid hex byte: {}", chunk_str));
                                        }
                                    }
                                }
                                self.#field_name = bytes;
                                Ok(())
                            } else {
                                Err("Hex string must have even length".to_string())
                            }
                        } else if value.contains(',') {
                            // Parse as comma-separated bytes
                            let mut bytes = Vec::new();
                            for part in value.split(',') {
                                match part.trim().parse::<u8>() {
                                    Ok(byte) => bytes.push(byte),
                                    Err(_) => return Err(format!("Invalid byte: {}", part)),
                                }
                            }
                            self.#field_name = bytes;
                            Ok(())
                        } else {
                            // Try to parse as UTF-8 string
                            self.#field_name = value.as_bytes().to_vec();
                            Ok(())
                        }
                    }
                };
            }
        }
        
        quote! {
            #field_name_str => {
                match value.parse::<#field_type>() {
                    Ok(parsed_value) => {
                        self.#field_name = parsed_value;
                        Ok(())
                    }
                    Err(_) => Err(format!("Failed to parse '{}' as {}", value, stringify!(#field_type)))
                }
            }
        }
    }).collect();

    quote! {
        impl #struct_name {
            #(#fuzz_methods)*
            
            pub fn fuzz_all(&mut self) {
                #(#all_fuzz_methods)*
            }
        }
        
        impl crate::FieldIntrospection for #struct_name {
            fn get_field_info() -> Vec<crate::FieldInfo> {
                vec![#(#field_info_items),*]
            }
        }
        
        impl crate::Fuzzable for #struct_name {
            fn fuzz(&mut self) {
                self.fuzz_all();
            }
            
            fn set_field(&mut self, field_name: &str, value: &str) -> Result<(), String> {
                match field_name {
                    #(#set_field_arms)*
                    _ => Err(format!("Unknown field: {}", field_name))
                }
            }
        }
    }
}

fn generate_range_fuzz_method(
    field_name: &Ident,
    field_type: &Type,
    method_name: Ident,
    min: i64,
    max: i64,
) -> proc_macro2::TokenStream {
    match field_type {
        Type::Path(type_path) if type_path.path.is_ident("u8") => {
            quote! {
                pub fn #method_name(&mut self) {
                    use crate::random::FuzzableNumber;
                    self.#field_name = <u8 as crate::random::FuzzableNumber>::fuzz(#min as u8, #max as u8);
                }
            }
        }
        Type::Path(type_path) if type_path.path.is_ident("u16") => {
            quote! {
                pub fn #method_name(&mut self) {
                    use crate::random::FuzzableNumber;
                    self.#field_name = <u16 as crate::random::FuzzableNumber>::fuzz(#min as u16, #max as u16);
                }
            }
        }
        Type::Path(type_path) if type_path.path.is_ident("u32") => {
            quote! {
                pub fn #method_name(&mut self) {
                    use crate::random::FuzzableNumber;
                    self.#field_name = <u32 as crate::random::FuzzableNumber>::fuzz(#min as u32, #max as u32);
                }
            }
        }
        Type::Path(type_path) if type_path.path.is_ident("u64") => {
            quote! {
                pub fn #method_name(&mut self) {
                    use crate::random::FuzzableNumber;
                    self.#field_name = <u64 as crate::random::FuzzableNumber>::fuzz(#min as u64, #max as u64);
                }
            }
        }
        Type::Path(type_path) if type_path.path.is_ident("i8") => {
            quote! {
                pub fn #method_name(&mut self) {
                    use crate::random::FuzzableNumber;
                    self.#field_name = <i8 as crate::random::FuzzableNumber>::fuzz(#min as i8, #max as i8);
                }
            }
        }
        Type::Path(type_path) if type_path.path.is_ident("i16") => {
            quote! {
                pub fn #method_name(&mut self) {
                    use crate::random::FuzzableNumber;
                    self.#field_name = <i16 as crate::random::FuzzableNumber>::fuzz(#min as i16, #max as i16);
                }
            }
        }
        Type::Path(type_path) if type_path.path.is_ident("i32") => {
            quote! {
                pub fn #method_name(&mut self) {
                    use crate::random::FuzzableNumber;
                    self.#field_name = <i32 as crate::random::FuzzableNumber>::fuzz(#min as i32, #max as i32);
                }
            }
        }
        Type::Path(type_path) if type_path.path.is_ident("i64") => {
            quote! {
                pub fn #method_name(&mut self) {
                    use crate::random::FuzzableNumber;
                    self.#field_name = <i64 as crate::random::FuzzableNumber>::fuzz(#min as i64, #max as i64);
                }
            }
        }
        _ => {
            quote! {
                pub fn #method_name(&mut self) {
                    // Range fuzzing not implemented for this type
                }
            }
        }
    }
}

fn generate_default_fuzz_method(
    field_name: &Ident,
    field_type: &Type,
    method_name: Ident,
) -> proc_macro2::TokenStream {
    // Simple type matching for common types
    match field_type {
        Type::Path(type_path) if type_path.path.is_ident("u8") => {
            quote! {
                pub fn #method_name(&mut self) {
                    use crate::random::FuzzableNumber;
                    self.#field_name = <u8 as crate::random::FuzzableNumber>::fuzz(<u8 as crate::random::FuzzableNumber>::min(), <u8 as crate::random::FuzzableNumber>::max());
                }
            }
        }
        Type::Path(type_path) if type_path.path.is_ident("u16") => {
            quote! {
                pub fn #method_name(&mut self) {
                    use crate::random::FuzzableNumber;
                    self.#field_name = <u16 as crate::random::FuzzableNumber>::fuzz(<u16 as crate::random::FuzzableNumber>::min(), <u16 as crate::random::FuzzableNumber>::max());
                }
            }
        }
        Type::Path(type_path) if type_path.path.is_ident("u32") => {
            quote! {
                pub fn #method_name(&mut self) {
                    use crate::random::FuzzableNumber;
                    self.#field_name = <u32 as crate::random::FuzzableNumber>::fuzz(<u32 as crate::random::FuzzableNumber>::min(), <u32 as crate::random::FuzzableNumber>::max());
                }
            }
        }
        Type::Path(type_path) if type_path.path.is_ident("u64") => {
            quote! {
                pub fn #method_name(&mut self) {
                    use crate::random::FuzzableNumber;
                    self.#field_name = <u64 as crate::random::FuzzableNumber>::fuzz(<u64 as crate::random::FuzzableNumber>::min(), <u64 as crate::random::FuzzableNumber>::max());
                }
            }
        }
        Type::Path(type_path) if type_path.path.is_ident("i8") => {
            quote! {
                pub fn #method_name(&mut self) {
                    use crate::random::FuzzableNumber;
                    self.#field_name = <i8 as crate::random::FuzzableNumber>::fuzz(<i8 as crate::random::FuzzableNumber>::min(), <i8 as crate::random::FuzzableNumber>::max());
                }
            }
        }
        Type::Path(type_path) if type_path.path.is_ident("i16") => {
            quote! {
                pub fn #method_name(&mut self) {
                    use crate::random::FuzzableNumber;
                    self.#field_name = <i16 as crate::random::FuzzableNumber>::fuzz(<i16 as crate::random::FuzzableNumber>::min(), <i16 as crate::random::FuzzableNumber>::max());
                }
            }
        }
        Type::Path(type_path) if type_path.path.is_ident("i32") => {
            quote! {
                pub fn #method_name(&mut self) {
                    use crate::random::FuzzableNumber;
                    self.#field_name = <i32 as crate::random::FuzzableNumber>::fuzz(<i32 as crate::random::FuzzableNumber>::min(), <i32 as crate::random::FuzzableNumber>::max());
                }
            }
        }
        Type::Path(type_path) if type_path.path.is_ident("i64") => {
            quote! {
                pub fn #method_name(&mut self) {
                    use crate::random::FuzzableNumber;
                    self.#field_name = <i64 as crate::random::FuzzableNumber>::fuzz(<i64 as crate::random::FuzzableNumber>::min(), <i64 as crate::random::FuzzableNumber>::max());
                }
            }
        }
        Type::Path(type_path) if type_path.path.is_ident("String") => {
            quote! {
                pub fn #method_name(&mut self) {
                    use crate::random::{FuzzableNumber, FuzzerRNG, DEFAULT_RNG};
                    let len = <usize as crate::random::FuzzableNumber>::fuzz(1, 100);
                    self.#field_name = (0..len)
                        .map(|_| crate::random::DEFAULT_RNG.alphabetic() as char)
                        .collect();
                }
            }
        }
        _ => {
            quote! {
                pub fn #method_name(&mut self) {
                    // Default fuzzing not implemented for this type
                }
            }
        }
    }
}

/// Configuration options for field-level fuzzing behavior.
/// 
/// This enum represents the different fuzzing strategies that can be applied
/// to struct fields through `#[fuzz]` attributes. Each variant corresponds to
/// a specific fuzzing approach optimized for different field types and use cases.
/// 
/// # Variants
/// 
/// * `Skip` - Field should not be fuzzed (keeps original value)
/// * `Range` - Numeric fields fuzzed within specified min/max bounds  
/// * `MaxLen` - Vector fields fuzzed with random data up to max length
/// * `Values` - Field fuzzed by selecting from predefined value set
/// * `Pattern` - Field fuzzed using structured pattern generation
/// * `Default` - Use default fuzzing strategy based on field type
/// 
/// # Examples
/// 
/// ```rust,norun
/// // Skip fuzzing this field
/// #[fuzz(skip)]
/// sync_field: u8,
/// 
/// // Fuzz within numeric range
/// #[fuzz(range = "1..=1000")]
/// port: u16,
/// 
/// // Fuzz vector with max length
/// #[fuzz(max_len = 512)]
/// data: Vec<u8>,
/// 
/// // Choose from predefined values
/// #[fuzz(values = "[\"GET\", \"POST\", \"PUT\"]")]
/// method: String,
/// 
/// // Generate structured pattern
/// #[fuzz(pattern = "u8.u8.u8.u8", delimiter = ".")]
/// ip_addr: String,
/// 
/// // Use default fuzzing
/// #[fuzz]
/// generic_field: u32,
/// ```
#[derive(Debug)]
enum FuzzConfig {
    /// Skip fuzzing this field entirely
    Skip,
    /// Fuzz numeric field within the specified range [min, max]
    Range { min: i64, max: i64 },
    /// Fuzz Vec<u8> with random data up to max_len bytes
    MaxLen { max_len: usize },
    /// Choose randomly from the provided list of string values
    Values { values: Vec<String> },
    /// Generate structured data using pattern with delimiter
    Pattern { pattern: String, delimiter: String },
    /// Use default fuzzing behavior based on field type
    Default,
}

fn parse_fuzz_attributes(attrs: &[Attribute]) -> FuzzConfig {
    for attr in attrs {
        if attr.path().is_ident("fuzz") {
            if let Meta::Path(_) = &attr.meta {
                return FuzzConfig::Default;
            }
            
            if let Meta::List(_) = &attr.meta {
                let mut result = FuzzConfig::Default;
                let _ = attr.parse_nested_meta(|meta| {
                    if meta.path.is_ident("skip") {
                        result = FuzzConfig::Skip;
                        Ok(())
                    } else if meta.path.is_ident("range") {
                        let value = meta.value()?;
                        let lit: Lit = value.parse()?;
                        if let Lit::Str(lit_str) = lit {
                            if let Some((min, max)) = parse_range(&lit_str.value()) {
                                result = FuzzConfig::Range { min, max };
                            }
                        }
                        Ok(())
                    } else if meta.path.is_ident("max_len") {
                        let value = meta.value()?;
                        let lit: Lit = value.parse()?;
                        if let Lit::Int(lit_int) = lit {
                            if let Ok(max_len) = lit_int.base10_parse::<usize>() {
                                result = FuzzConfig::MaxLen { max_len };
                            }
                        }
                        Ok(())
                    } else if meta.path.is_ident("values") {
                        let value = meta.value()?;
                        let lit: Lit = value.parse()?;
                        if let Lit::Str(lit_str) = lit {
                            let values = parse_values_array(&lit_str.value());
                            result = FuzzConfig::Values { values };
                        }
                        Ok(())
                    } else if meta.path.is_ident("pattern") {
                        let value = meta.value()?;
                        let lit: Lit = value.parse()?;
                        if let Lit::Str(lit_str) = lit {
                            result = FuzzConfig::Pattern { 
                                pattern: lit_str.value(),
                                delimiter: ".".to_string() // default delimiter
                            };
                        }
                        Ok(())
                    } else if meta.path.is_ident("delimiter") {
                        let value = meta.value()?;
                        let lit: Lit = value.parse()?;
                        if let Lit::Str(lit_str) = lit {
                            if let FuzzConfig::Pattern { pattern, .. } = &result {
                                result = FuzzConfig::Pattern { 
                                    pattern: pattern.clone(),
                                    delimiter: lit_str.value()
                                };
                            }
                        }
                        Ok(())
                    } else {
                        Ok(())
                    }
                });
                return result;
            }
        }
    }
    FuzzConfig::Default
}

fn parse_range(range_str: &str) -> Option<(i64, i64)> {
    if let Some(pos) = range_str.find("..=") {
        let (min_str, max_str) = range_str.split_at(pos);
        let max_str = &max_str[3..]; // Skip "..="
        
        let min: i64 = min_str.parse().ok()?;
        let max: i64 = max_str.parse().ok()?;
        
        Some((min, max))
    } else {
        None
    }
}

fn parse_values_array(values_str: &str) -> Vec<String> {
    // Simple parsing for array format like ["GET", "POST", "PUT", "DELETE"]
    if values_str.starts_with('[') && values_str.ends_with(']') {
        let inner = &values_str[1..values_str.len()-1];
        inner
            .split(',')
            .map(|s| s.trim().trim_matches('"').to_string())
            .collect()
    } else {
        vec![]
    }
}

fn generate_pattern_fuzz_method(
    field_name: &Ident,
    _field_type: &Type,
    method_name: Ident,
    pattern: String,
    delimiter: String,
) -> proc_macro2::TokenStream {
    let field_types: Vec<&str> = pattern.split(&delimiter).collect();
    
    let fuzz_values: Vec<proc_macro2::TokenStream> = field_types.iter().map(|field_type| {
        match *field_type {
            "u8" => quote! { <u8 as crate::random::FuzzableNumber>::fuzz(<u8 as crate::random::FuzzableNumber>::min(), <u8 as crate::random::FuzzableNumber>::max()) },
            "u16" => quote! { <u16 as crate::random::FuzzableNumber>::fuzz(<u16 as crate::random::FuzzableNumber>::min(), <u16 as crate::random::FuzzableNumber>::max()) },
            "u32" => quote! { <u32 as crate::random::FuzzableNumber>::fuzz(<u32 as crate::random::FuzzableNumber>::min(), <u32 as crate::random::FuzzableNumber>::max()) },
            "u64" => quote! { <u64 as crate::random::FuzzableNumber>::fuzz(<u64 as crate::random::FuzzableNumber>::min(), <u64 as crate::random::FuzzableNumber>::max()) },
            "i8" => quote! { <i8 as crate::random::FuzzableNumber>::fuzz(<i8 as crate::random::FuzzableNumber>::min(), <i8 as crate::random::FuzzableNumber>::max()) },
            "i16" => quote! { <i16 as crate::random::FuzzableNumber>::fuzz(<i16 as crate::random::FuzzableNumber>::min(), <i16 as crate::random::FuzzableNumber>::max()) },
            "i32" => quote! { <i32 as crate::random::FuzzableNumber>::fuzz(<i32 as crate::random::FuzzableNumber>::min(), <i32 as crate::random::FuzzableNumber>::max()) },
            "i64" => quote! { <i64 as crate::random::FuzzableNumber>::fuzz(<i64 as crate::random::FuzzableNumber>::min(), <i64 as crate::random::FuzzableNumber>::max()) },
            _ => quote! { 0 }, // fallback for unknown types
        }
    }).collect();
    
    let field_count = field_types.len();
    let format_string = field_types.iter()
        .map(|_| "{}")
        .collect::<Vec<_>>()
        .join(&delimiter);
    
    let indices: Vec<proc_macro2::TokenStream> = (0..field_count).map(|i| {
        let idx = proc_macro2::Literal::usize_unsuffixed(i);
        quote! { values[#idx] }
    }).collect();
    
    quote! {
        pub fn #method_name(&mut self) {
            use crate::random::FuzzableNumber;
            let values = [#(#fuzz_values),*];
            let formatted = format!(#format_string, #(#indices),*);
            self.#field_name = formatted.parse().expect("Failed to parse fuzzed field value");
        }
    }
}

