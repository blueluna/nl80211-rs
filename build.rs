extern crate netlink_buildtools;

use std::fs::File;

use netlink_buildtools::Specification;

fn main() {
    let file = File::open("specifications/nl80211_commands.json").unwrap();
    match Specification::read(file) {
        Ok(spec) => {
            spec.generate("src/commands.rs").unwrap()
        }
        Err(error) => {
            panic!("Failed to load specification, {}", error);
        }
    }

    let file = File::open("specifications/nl80211_attributes.json").unwrap();
    match Specification::read(file) {
        Ok(spec) => {
            spec.generate("src/attributes.rs").unwrap();
        }
        Err(error) => {
            panic!("Failed to load specification, {}", error);
        }
    }

    let file = File::open("specifications/information_element_id.json").unwrap();
    match Specification::read(file) {
        Ok(spec) => {
            spec.generate("src/information_element_ids.rs").unwrap();
        }
        Err(error) => {
            panic!("Failed to load specification, {}", error);
        }
    }
}
