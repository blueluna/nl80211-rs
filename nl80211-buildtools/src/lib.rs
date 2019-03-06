extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate quote;
extern crate proc_macro2;

use proc_macro2::{Ident, Literal, Span, TokenStream};
use quote::{ToTokens, TokenStreamExt};

use std::collections::HashMap;
use std::fmt;
use std::mem;

use std::io;
use std::io::{Read, Write};

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ValueType {
    u8,
    u16,
    u32,
    u64,
    i8,
    i16,
    i32,
    i64,
    string,
    bytes,
    nested,
    flag,
}

impl ValueType {
    pub fn type_size(&self) -> usize {
        match *self {
            ValueType::u8 => mem::size_of::<u8>(),
            ValueType::u16 => mem::size_of::<u16>(),
            ValueType::u32 => mem::size_of::<u32>(),
            ValueType::u64 => mem::size_of::<u64>(),
            ValueType::i8 => mem::size_of::<i8>(),
            ValueType::i16 => mem::size_of::<i16>(),
            ValueType::i32 => mem::size_of::<i32>(),
            ValueType::i64 => mem::size_of::<i64>(),
            ValueType::string => mem::size_of::<u8>(),
            ValueType::bytes => mem::size_of::<u8>(),
            ValueType::nested => mem::size_of::<u8>(),
            ValueType::flag => 0,
        }
    }
    pub fn token(&self) -> TokenStream {
        match *self {
            ValueType::u8 => quote!(u8),
            ValueType::u16 => quote!(u16),
            ValueType::u32 => quote!(u32),
            ValueType::u64 => quote!(u64),
            ValueType::i8 => quote!(i8),
            ValueType::i16 => quote!(i16),
            ValueType::i32 => quote!(i32),
            ValueType::i64 => quote!(i64),
            ValueType::string => quote!(&str),
            ValueType::bytes => quote!(&[u8]),
            ValueType::nested => quote!(&[u8]),
            ValueType::flag => quote!(&[u8]),
        }
    }
}

impl ToTokens for ValueType {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let token = match *self {
            ValueType::u8 => Ident::new("u8", Span::call_site()),
            ValueType::u16 => Ident::new("u16", Span::call_site()),
            ValueType::u32 => Ident::new("u32", Span::call_site()),
            ValueType::u64 => Ident::new("u64", Span::call_site()),
            ValueType::i8 => Ident::new("i8", Span::call_site()),
            ValueType::i16 => Ident::new("i16", Span::call_site()),
            ValueType::i32 => Ident::new("i32", Span::call_site()),
            ValueType::i64 => Ident::new("i64", Span::call_site()),
            ValueType::string => Ident::new("&str", Span::call_site()),
            ValueType::bytes => Ident::new("&[u8]", Span::call_site()),
            ValueType::nested => Ident::new("&[u8]", Span::call_site()),
            ValueType::flag => Ident::new("&[u8]", Span::call_site()),
        };
        tokens.append(token);
    }
}

fn make_attribute_enum(name: &TokenStream, labels: &Vec<TokenStream>) -> TokenStream {
    quote! {
        #[derive(Clone, Debug, PartialEq)]
        pub enum #name {
            #(#labels),*
        }
    }
}

fn make_attribute_from(
    name: &TokenStream,
    value_type: &TokenStream,
    labels: &Vec<TokenStream>,
    values: &Vec<TokenStream>,
) -> TokenStream {
    quote! {
        impl From<#value_type> for #name {
            fn from(value: #value_type) -> #name {
                match value {
                    #(#values => #labels),*,
                    _ => panic!("Bad value"),
                }
            }
        }
    }
}

fn make_attribute_from_reverse(
    name: &TokenStream,
    value_type: &TokenStream,
    labels: &Vec<TokenStream>,
    values: &Vec<TokenStream>,
) -> TokenStream {
    quote! {
        impl From<#name> for #value_type {
            fn from(value: #name) -> #value_type {
                match value {
                    #(#labels => #values),*
                }
            }
        }
    }
}

fn make_attribute_partialeq(
    name: &TokenStream,
    value_type: &TokenStream,
    labels: &Vec<TokenStream>,
    values: &Vec<TokenStream>,
) -> TokenStream {
    quote! {
        impl PartialEq<#value_type> for #name {
            fn eq(&self, other: &#value_type) -> bool {
                match *self {
                    #(#labels => #values == *other),*
                }
            }
        }
    }
}

fn make_attribute_partialeq_reverse(
    name: &TokenStream,
    value_type: &TokenStream,
    labels: &Vec<TokenStream>,
    values: &Vec<TokenStream>,
) -> TokenStream {
    quote! {
        impl PartialEq<#name> for #value_type {
            fn eq(&self, other: &#name) -> bool {
                match *other {
                    #(#labels => #values == *self),*
                }
            }
        }
    }
}

fn make_attribute_convert_from(
    name: &TokenStream,
    value_type: &TokenStream,
    labels: &Vec<TokenStream>,
    values: &Vec<TokenStream>,
) -> TokenStream {
    quote! {
        impl ConvertFrom<#value_type> for #name {
            fn convert_from(value: #value_type) -> Option<#name> {
                match value {
                    #(#values => Some(#labels)),*,
                    _ => None,
                }
            }
        }
    }
}

fn make_attribute_fmt(
    name: &TokenStream,
    long_labels: &Vec<TokenStream>,
    labels: &Vec<TokenStream>,
) -> TokenStream {
    quote! {
        impl fmt::Display for #name {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                match *self {
                    #(#long_labels => write!(f, "{}", #labels)),*,
                }
            }
        }
    }
}

pub fn make_attribute(
    name: &str,
    value_type: ValueType,
    labels: Vec<Ident>,
    values: Vec<Literal>,
) -> TokenStream {
    let vt = quote!(#value_type);
    let name_i = Ident::new(name, Span::call_site());
    let name_ts = quote!(#name_i);
    let labels_ts = labels.iter().map(|l| quote!(#l)).collect();
    let values_ts = values.iter().map(|v| quote!(#v)).collect();

    let mut code = TokenStream::new();

    code.extend(make_attribute_enum(&name_ts, &labels_ts));
    let long_labels_ts = labels.iter().map(|l| quote!(#name_ts::#l)).collect();
    code.extend(make_attribute_from(
        &name_ts,
        &vt,
        &long_labels_ts,
        &values_ts,
    ));
    code.extend(make_attribute_from_reverse(
        &name_ts,
        &vt,
        &long_labels_ts,
        &values_ts,
    ));
    code.extend(make_attribute_partialeq(
        &name_ts,
        &vt,
        &long_labels_ts,
        &values_ts,
    ));
    code.extend(make_attribute_partialeq_reverse(
        &name_ts,
        &vt,
        &long_labels_ts,
        &values_ts,
    ));
    code.extend(make_attribute_convert_from(
        &name_ts,
        &vt,
        &long_labels_ts,
        &values_ts,
    ));
    let txt_labels_ts = labels
        .iter()
        .map(|l| {
            let lit = Literal::string(&l.to_string());
            quote!(#lit)
        })
        .collect();
    code.extend(make_attribute_fmt(
        &name_ts,
        &long_labels_ts,
        &txt_labels_ts,
    ));
    code
}

trait Enumeration {
    type T: fmt::Display;
    fn value(&self) -> Self::T;
    fn original_name(&self) -> Option<String>;
}

#[derive(Serialize, Deserialize)]
pub struct EnumerationItem {
    pub value: i64,
    pub original_name: Option<String>,
}

impl Enumeration for EnumerationItem {
    type T = i64;
    fn value(&self) -> i64 {
        self.value
    }
    fn original_name(&self) -> Option<String> {
        self.original_name.clone()
    }
}

#[derive(Serialize, Deserialize)]
pub struct EnumerationSpecification {
    pub original_name: Option<String>,
    pub value_type: ValueType,
    pub default: Option<String>,
    pub items: HashMap<String, EnumerationItem>,
}

impl EnumerationSpecification {
    fn value_to_literal(&self, value: i64) -> Literal {
        match self.value_type {
            ValueType::u8 => Literal::u8_suffixed(value as u8),
            ValueType::u16 => Literal::u16_suffixed(value as u16),
            ValueType::u32 => Literal::u32_suffixed(value as u32),
            ValueType::u64 => Literal::u64_suffixed(value as u64),
            ValueType::i8 => Literal::i8_suffixed(value as i8),
            ValueType::i16 => Literal::i16_suffixed(value as i16),
            ValueType::i32 => Literal::i32_suffixed(value as i32),
            ValueType::i64 => Literal::i64_suffixed(value as i64),
            _ => panic!("Bad value type"),
        }
    }

    fn generate_enum<W: Write>(&self, name: &str, writer: &mut W) -> io::Result<()> {
        let labels = self
            .items
            .keys()
            .map(|k| Ident::new(&k, Span::call_site()))
            .collect();
        let values = self
            .items
            .values()
            .map(|v| self.value_to_literal(v.value))
            .collect();

        let ts = make_attribute(name, self.value_type, labels, values);
        let data = ts.to_string();
        writer.write_all(data.as_bytes())?;

        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct AttributeItem {
    pub value: u16,
    pub original_name: String,
    pub data_type: ValueType,
    pub data_length: Option<usize>,
    pub max_length: Option<usize>,
}

impl Enumeration for AttributeItem {
    type T = u16;
    fn value(&self) -> u16 {
        self.value
    }
    fn original_name(&self) -> Option<String> {
        Some(self.original_name.clone())
    }
}

#[derive(Serialize, Deserialize)]
pub struct AttributeSpecification {
    pub original_name: String,
    pub value_type: ValueType,
    pub default: Option<String>,
    pub items: HashMap<String, AttributeItem>,
}

impl AttributeSpecification {
    fn generate_enum<W: Write>(&self, name: &str, writer: &mut W) -> io::Result<()> {
        let labels = self
            .items
            .keys()
            .map(|k| Ident::new(&k, Span::call_site()))
            .collect();
        let values = self
            .items
            .values()
            .map(|v| Literal::u16_suffixed(v.value))
            .collect();

        let ts = make_attribute(name, self.value_type, labels, values);
        let data = ts.to_string();
        writer.write_all(data.as_bytes())?;

        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct Specification {
    pub input_filepath: String,
    pub datetime: u64,
    pub enumerations: HashMap<String, EnumerationSpecification>,
    pub attributes: HashMap<String, AttributeSpecification>,
}

impl Specification {
    pub fn read<R: Read>(reader: R) -> serde_json::Result<Specification> {
        serde_json::from_reader(reader)
    }

    pub fn write<W: Write>(&self, w: W) -> serde_json::Result<()> {
        serde_json::to_writer_pretty(w, self)
    }

    pub fn generate(&self, filepath: &str) -> io::Result<()> {
        let mut out_file = std::fs::File::create(filepath)?;
        let header = quote!(
            use std::convert::From;
            use std::fmt;
            use netlink_rust::ConvertFrom;
        );
        writeln!(out_file, "{}", header.to_string())?;

        for (name, item) in &self.enumerations {
            item.generate_enum(&name, &mut out_file)?;
        }

        for (name, item) in &self.attributes {
            item.generate_enum(&name, &mut out_file)?;
        }
        Ok(())
    }
}
