extern crate serde;
extern crate serde_json;

#[macro_use]
extern crate serde_derive;

use std::fmt;
use std::mem;
use std::collections::HashMap;

use std::io;
use std::io::{Write, Read};

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ValueType {
    u8, u16, u32, u64,
    i8, i16, i32, i64,
    string, bytes, nested, flag,
}

impl ValueType {
    pub fn type_size(&self) -> usize {
        match *self {
            ValueType::u8 => { mem::size_of::<u8>() }
            ValueType::u16 => { mem::size_of::<u16>() }
            ValueType::u32 => { mem::size_of::<u32>() }
            ValueType::u64 => { mem::size_of::<u64>() }
            ValueType::i8 => { mem::size_of::<i8>() }
            ValueType::i16 => { mem::size_of::<i16>() }
            ValueType::i32 => { mem::size_of::<i32>() }
            ValueType::i64 => { mem::size_of::<i64>() }
            ValueType::string => { mem::size_of::<u8>() }
            ValueType::bytes => { mem::size_of::<u8>() }
            ValueType::nested => { mem::size_of::<u8>() }
            ValueType::flag => { 0 }
        }
    }
}

impl fmt::Display for ValueType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ValueType::u8 => { write!(f, "u8") }
            ValueType::u16 => { write!(f, "u16") }
            ValueType::u32 => { write!(f, "u32") }
            ValueType::u64 => { write!(f, "u64") }
            ValueType::i8 => { write!(f, "i8") }
            ValueType::i16 => { write!(f, "i16") }
            ValueType::i32 => { write!(f, "i32") }
            ValueType::i64 => { write!(f, "i64") }
            ValueType::string => { write!(f, "string") }
            ValueType::bytes => { write!(f, "bytes") }
            ValueType::nested => { write!(f, "nested") }
            ValueType::flag => { write!(f, "flag") }
        }
    }
}

trait Enumeration {
    type T: fmt::Display;
    fn value(&self) -> Self::T;
    fn original_name(&self) -> Option<String>;
}

fn generate_enum<E: Enumeration, W: Write>(name: &str, value_type: ValueType, items: &HashMap<String, E>, mut writer: W) -> io::Result<()> {
    writeln!(writer, "#[derive(Clone, PartialEq, Debug)]")?;
    writeln!(writer, "#[repr({})]", value_type)?;
    writeln!(writer, "pub enum {} {{", name)?;
    for (value_name, item) in items.iter() {
        let mut line = format!("  {} = {},", value_name, &item.value());
        if let Some(ref original_name) = item.original_name() {
            line.push_str(&format!(" // {}", original_name));
        }
        writeln!(writer, "{}", line)?;
    }
    writeln!(writer, "}}")?;

    writeln!(writer, "impl Into<{datatype}> for {name} {{
  fn into(self) -> {datatype} {{
    match self {{",
    datatype=value_type, name=name)?;
    for (value_name, item) in items.iter() {
        writeln!(writer, "      {enum_name}::{name} => {value},",
            enum_name=name, value=&item.value(), name=value_name)?;
    }
    writeln!(writer, "    }}\n  }}\n}}")?;

    writeln!(writer, "impl From<{datatype}> for {name} {{
  fn from(v: {datatype}) -> {name} {{
    match v {{",
    datatype=value_type, name=name)?;
    for (value_name, item) in items.iter() {
        writeln!(writer, "      {value} => {enum_name}::{name},",
            enum_name=name, value=&item.value(), name=value_name)?;
    }
    writeln!(writer, "      _ => panic!(\"Bad value\"),")?;
    writeln!(writer, "    }}\n  }}\n}}")?;

    writeln!(writer, "impl ConvertFrom<{datatype}> for {name} {{
  fn convert_from(v: {datatype}) -> Option<{name}> {{
    match v {{",
    datatype=value_type, name=name)?;
    for (value_name, item) in items.iter() {
        writeln!(writer, "      {value} => Some({enum_name}::{name}),",
            enum_name=name, value=&item.value(), name=value_name)?;
    }
    writeln!(writer, "      _ => None,")?;
    writeln!(writer, "    }}\n  }}\n}}")?;

    Ok(())
}

#[derive(Serialize, Deserialize)]
pub struct EnumerationItem
{
    pub value: i64,
    pub original_name: Option<String>,
}

impl Enumeration for EnumerationItem {
    type T = i64;
    fn value(&self) -> i64 { self.value }
    fn original_name(&self) -> Option<String> { self.original_name.clone() }
}

#[derive(Serialize, Deserialize)]
pub struct AttributeItem
{
    pub value: u16,
    pub original_name: String,
    pub data_type: ValueType,
    pub data_length: Option<usize>,
    pub max_length: Option<usize>,
}

impl Enumeration for AttributeItem {
    type T = u16;
    fn value(&self) -> u16 { self.value }
    fn original_name(&self) -> Option<String> { Some(self.original_name.clone()) }
}

#[derive(Serialize, Deserialize)]
pub struct EnumerationSpecification
{
    pub original_name: Option<String>,
    pub value_type: ValueType,
    pub default: Option<String>,
    pub items: HashMap<String, EnumerationItem>
}

impl EnumerationSpecification {
    fn generate_enum<W: Write>(&self, name: &str, writer: W) -> io::Result<()> {
        generate_enum(name, self.value_type, &self.items, writer)
    }
}

#[derive(Serialize, Deserialize)]
pub struct AttributeSpecification
{
    pub original_name: String,
    pub value_type: ValueType,
    pub default: Option<String>,
    pub items: HashMap<String, AttributeItem>
}

impl AttributeSpecification {
    fn generate_enum<W: Write>(&self, name: &str, writer: W) -> io::Result<()> {
        generate_enum(name, self.value_type, &self.items, writer)
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
        let out_file = std::fs::File::create(filepath)?;
        writeln!(&out_file, "use std::convert::{{From, Into}};")?;
        writeln!(&out_file, "use netlink::ConvertFrom;")?;
        writeln!(&out_file, "")?;

        for (name, item) in &self.enumerations {
            item.generate_enum(&name, &out_file)?;
        }

        for (name, item) in &self.attributes {
            item.generate_enum(&name, &out_file)?;
        }
        Ok(())
    }
}

