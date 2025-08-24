use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{
    parse_macro_input, Attribute, Data, DeriveInput, Fields, Ident, Lit, Meta, Type,
};

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
                        let len = fastrand::usize(0..=#max_len);
                        self.#field_name = (0..len).map(|_| fastrand::u8(..)).collect();
                    }
                }
            }
            FuzzConfig::Values { values } => {
                let method_name = Ident::new(&format!("fuzz_{}", field_name), Span::call_site());
                quote! {
                    pub fn #method_name(&mut self) {
                        let options = vec![#(#values.to_string()),*];
                        let selected = fastrand::choice(&options).unwrap().clone();
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

    quote! {
        impl #struct_name {
            #(#fuzz_methods)*
            
            pub fn fuzz_all(&mut self) {
                #(#all_fuzz_methods)*
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
                    self.#field_name = fastrand::u8(#min as u8..=#max as u8);
                }
            }
        }
        Type::Path(type_path) if type_path.path.is_ident("u16") => {
            quote! {
                pub fn #method_name(&mut self) {
                    self.#field_name = fastrand::u16(#min as u16..=#max as u16);
                }
            }
        }
        Type::Path(type_path) if type_path.path.is_ident("u32") => {
            quote! {
                pub fn #method_name(&mut self) {
                    self.#field_name = fastrand::u32(#min as u32..=#max as u32);
                }
            }
        }
        Type::Path(type_path) if type_path.path.is_ident("u64") => {
            quote! {
                pub fn #method_name(&mut self) {
                    self.#field_name = fastrand::u64(#min as u64..=#max as u64);
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
                    self.#field_name = fastrand::u8(..);
                }
            }
        }
        Type::Path(type_path) if type_path.path.is_ident("u16") => {
            quote! {
                pub fn #method_name(&mut self) {
                    self.#field_name = fastrand::u16(..);
                }
            }
        }
        Type::Path(type_path) if type_path.path.is_ident("u32") => {
            quote! {
                pub fn #method_name(&mut self) {
                    self.#field_name = fastrand::u32(..);
                }
            }
        }
        Type::Path(type_path) if type_path.path.is_ident("u64") => {
            quote! {
                pub fn #method_name(&mut self) {
                    self.#field_name = fastrand::u64(..);
                }
            }
        }
        Type::Path(type_path) if type_path.path.is_ident("String") => {
            quote! {
                pub fn #method_name(&mut self) {
                    let len = fastrand::usize(1..=100);
                    self.#field_name = (0..len)
                        .map(|_| fastrand::alphabetic() as char)
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

#[derive(Debug)]
enum FuzzConfig {
    Skip,
    Range { min: i64, max: i64 },
    MaxLen { max_len: usize },
    Values { values: Vec<String> },
    Pattern { pattern: String, delimiter: String },
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
            "u8" => quote! { fastrand::u8(..) },
            "u16" => quote! { fastrand::u16(..) },
            "u32" => quote! { fastrand::u32(..) },
            "u64" => quote! { fastrand::u64(..) },
            "i8" => quote! { fastrand::i8(..) },
            "i16" => quote! { fastrand::i16(..) },
            "i32" => quote! { fastrand::i32(..) },
            "i64" => quote! { fastrand::i64(..) },
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
            let values = [#(#fuzz_values),*];
            let formatted = format!(#format_string, #(#indices),*);
            self.#field_name = formatted.parse().expect("Failed to parse fuzzed field value");
        }
    }
}

