extern crate clap;
extern crate nl80211_buildtools;
extern crate regex;
extern crate serde_json;

use std::fs::{File};
use std::io::{BufReader, BufRead};
use std::collections::HashMap;
use std::time;

use clap::{Arg, App};
use regex::{Regex};

use nl80211_buildtools::{ValueType, EnumerationItem, AttributeItem,
    EnumerationSpecification, AttributeSpecification, Specification};

struct KernelEnum {
    pub name: String,
    pub value: i64,
}

fn snake_to_camel(source: &str) -> String {
    let src = source.to_string().to_uppercase();
    let re = Regex::new(r"_?([0-9]*)([A-Z0-9]+)").unwrap();
    let mut name = String::new();
    for cap in re.captures_iter(&src) {
        let mut ci = cap[2].chars();
        let mut word = ci.next().unwrap().to_uppercase().to_string();
        for c in ci {
            word.push_str(&c.to_lowercase().to_string());
        }
        name.push_str(&word);
    }
    return name;
}

fn kernel_datatype<R: BufRead>(reader: R, name: &str) -> Option<(ValueType, usize)> {
    let mut lines = vec![];
    {
        let start_pattern = format!("^\\s*\\*\\s*@{}\\s*.*$", name);
        let start_re = Regex::new(&start_pattern).unwrap();
        let end_re = Regex::new(r"^\s*\*\s*@.*$").unwrap();
        let mut capture_state = 0;
        for line in reader.lines().map(|l| l.unwrap()) {
            match capture_state {
                1 => {
                    if end_re.is_match(&line) {
                        capture_state = 2;
                    }
                    else {
                        lines.push(line);
                    }
                }
                2 => {
                    break;
                }
                _ => {
                    if start_re.is_match(&line) {
                        lines.push(line);
                        capture_state = 1;
                    }
                }
            }
        }
    }
    let mut data_type = None;
    let mut type_size = 0;
    let mut text = String::new();
    for line in lines.iter() {
        text.push_str(&line.to_lowercase());
    }
    match text.find("u64") {
        Some(_) => {
            data_type = Some(ValueType::u64);
        },
        None => {},
    }
    match text.find("u32") {
        Some(_) => {
            data_type = Some(ValueType::u32);
        },
        None => {},
    }
    match text.find("u16") {
        Some(_) => {
            data_type = Some(ValueType::u16);
        },
        None => {},
    }
    match text.find("u8") {
        Some(_) => {
            data_type = Some(ValueType::u8);
        },
        None => {},
    }
    match text.find("octet") {
        Some(_) => {
            data_type = Some(ValueType::bytes);
        },
        None => {},
    }
    match text.find("bytes") {
        Some(_) => {
            data_type = Some(ValueType::bytes);
        },
        None => {},
    }
    match text.find("nested") {
        Some(_) => {
            data_type = Some(ValueType::nested);
        },
        None => {},
    }
    let bits_re = Regex::new(r"\s+(\d+)-bits?\s+").unwrap();
    match bits_re.captures(&text) {
        Some(cap) => {
            let bits = cap.get(1).unwrap().as_str();
            if bits == "8" {
                data_type = Some(ValueType::u8);
            }
            if bits == "16" {
                data_type = Some(ValueType::u16);
            }
            else if bits == "24" {
                type_size = 3;
                data_type = Some(ValueType::bytes);
            }
            else if bits == "32" {
                data_type = Some(ValueType::u32);
            }
            else if bits == "64" {
                data_type = Some(ValueType::u64);
            }
        },
        None => {},
    }
    match text.find("enum") {
        Some(_) => {
            data_type = Some(ValueType::u32);
        },
        None => {},
    }
    match text.find("flag") {
        Some(_) => {
            data_type = Some(ValueType::flag);
        },
        None => {},
    }
    if data_type != None {
        let dt = data_type.unwrap();
        if type_size == 0 {
            type_size = dt.type_size();
        }
        return Some((dt, type_size));
    }
    None
}

fn lookup_kernel_names(filename: &str, pattern: &str) -> Option<Vec<KernelEnum>> {
    let file = File::open(filename).unwrap();
    let mut capture_state = 0;
    let start_pattern = format!("^\\s*enum\\s*({})\\s*\\{{\\s*$", pattern);
    let start_re = Regex::new(&start_pattern).unwrap();
    let value_re = Regex::new(r"^\s*([A-Z][A-Z0-9_]+)\s*,.*$").unwrap();
    let end_re = Regex::new(r"^\s*\}\s*;\s*$").unwrap();
    // Whitespace and comments
    let empty_re = Regex::new(r"^(\s*|\s*/\*.*\*/\s*)$").unwrap();
    let reader = BufReader::new(file);
    let mut values = vec![];
    let mut index = 0;
    for line in reader.lines().map(|l| l.unwrap()) {
        match capture_state {
            1 => {
                if let Some(c) = value_re.captures(&line) {
                    let name = c.get(1).unwrap().as_str();
                    values.push( KernelEnum { name: String::from(name), value: index } );
                    index = index + 1;
                }
                else if end_re.is_match(&line) {
                    capture_state = 2;
                }
                else if empty_re.is_match(&line) {
                }
                else {
                    index = index + 1;
                    println!("X {}", &line);
                }
            }
            2 => {
                break;
            }
            _ => {
                if start_re.is_match(&line) {
                    capture_state = 1;
                }
            }
        }
    }
    if values.is_empty() {
        return None;
    }
    Some(values)
}

enum GeneratorType {
    Enum,
    Attribute,
}

fn main() {
    // -i /usr/include/linux/nl80211.h -p nl80211_attrs -o spec.json
    let matches = App::new("Specification generator")
        .version("0.1")
        .author("Erik Svensson <erik.public@gmail.com>")
        .arg(Arg::with_name("input")
            .short("i")
            .required(true)
            .takes_value(true))
        .arg(Arg::with_name("name")
            .short("n")
            .required(true)
            .takes_value(true))
        .arg(Arg::with_name("type")
            .short("t")
            .required(false)
            .takes_value(true))
        .arg(Arg::with_name("output")
            .short("o")
            .required(true)
            .takes_value(true))
        .get_matches();

    let input_filepath = matches.value_of("input").unwrap();
    let output_filepath = matches.value_of("output").unwrap();
    let enum_name = matches.value_of("name").unwrap();

    let generator_type = match matches.value_of("type") {
        Some(t) => {
            if t == "attribute" {
                GeneratorType::Attribute
            }
            else {
                GeneratorType::Enum
            }
        }
        None => {
            GeneratorType::Enum
        }
    };

    let mut enumerations = HashMap::new();
    let mut attributes = HashMap::new();
    let mut attribute_items = HashMap::new();
    let mut enumeration_items = HashMap::new();

    let new_enum_name = snake_to_camel(&enum_name);
    let values = lookup_kernel_names(&input_filepath, &enum_name).unwrap();
    let prefix = String::from(values[0].name.clone());
    let mut prefix_len = prefix.len();
    for value in values.iter() {
        if value.name.len() < prefix_len {
            prefix_len = value.name.len();
        }
        for n in 0..prefix_len {
            let end = prefix_len - n;
            if value.name[0..end] == prefix[0..end] {
                prefix_len = end;
                break;
            }
        }
    }
    let mut max_value = 0i64;
    for value in values.iter() {
        let original_name = &value.name;
        let new_name = snake_to_camel(&original_name[prefix_len..]);
        match generator_type {
            GeneratorType::Attribute => {
                let data_type;
                {
                    let file = File::open(&input_filepath).unwrap();
                    let reader = BufReader::new(file);
                    data_type = match kernel_datatype(reader, original_name) {
                        Some(dt) => Some(dt.0),
                        None => None,
                    };
                }
                let data_type_length = match data_type {
                    Some(dt) => {
                        match dt {
                            ValueType::string | ValueType::nested | ValueType::bytes =>
                            {
                                Some(0)
                            }
                            _ => { None }
                        }
                    },
                    None => None,
                };
                if value.value > max_value {
                    max_value = value.value;
                }
                attribute_items.insert(new_name,
                    AttributeItem {
                        value: value.value as u16,
                        original_name: original_name.to_owned(),
                        data_type: data_type.unwrap(),
                        data_length: data_type_length,
                        max_length: None,
                    });
            }
            GeneratorType::Enum => {
                enumeration_items.insert(new_name,
                    EnumerationItem {
                        value: value.value,
                        original_name: Some(original_name.to_owned()),
                    });
            }
        }
    }
    let enum_data_type;
    if max_value > u32::max_value() as i64 {
        enum_data_type = ValueType::u64;
    }
    else if max_value > u16::max_value() as i64 {
        enum_data_type = ValueType::u32;
    }
    else if max_value > u8::max_value() as i64 {
        enum_data_type = ValueType::u16;
    }
    else {
        enum_data_type = ValueType::u8;
    }
    if !attribute_items.is_empty() {
        attributes.insert(new_enum_name.clone(), 
            AttributeSpecification {
                original_name: enum_name.to_owned(),
                value_type: ValueType::u16,
                default: None,
                items: attribute_items,
            });
    }
    if !enumeration_items.is_empty() {
        enumerations.insert(new_enum_name.clone(), 
            EnumerationSpecification {
                original_name: Some(enum_name.to_owned()),
                value_type: enum_data_type,
                default: None,
                items: enumeration_items,
            });
    }
    let sys_time = time::SystemTime::now();
    let elapsed = sys_time.duration_since(time::UNIX_EPOCH).unwrap();
    let spec = Specification {
            input_filepath: String::from(input_filepath),
            datetime: elapsed.as_secs(),
            enumerations: enumerations,
            attributes: attributes,
        };
    let mut out_file = File::create(output_filepath).unwrap();
    serde_json::to_writer_pretty(&mut out_file, &spec).unwrap();
}
