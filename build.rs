extern crate nl80211_buildtools;

use std::fs::File;

use nl80211_buildtools::Specification;

fn main() {
    use std::env;
    let out_dir = env::var("OUT_DIR").unwrap();

    let file = File::open("specifications/nl80211_commands.json").unwrap();
    match Specification::read(file) {
        Ok(spec) => {
            spec.generate(&format!("{}/commands.rs", out_dir)).unwrap()
        }
        Err(error) => {
            panic!("Failed to load specification, {}", error);
        }
    }

    let file = File::open("specifications/nl80211_attributes.json").unwrap();
    match Specification::read(file) {
        Ok(spec) => {
            spec.generate(&format!("{}/attributes.rs", out_dir)).unwrap();
        }
        Err(error) => {
            panic!("Failed to load specification, {}", error);
        }
    }

    let file = File::open("specifications/information_element_id.json").unwrap();
    match Specification::read(file) {
        Ok(spec) => {
            spec.generate(&format!("{}/information_element_ids.rs", out_dir)).unwrap();
        }
        Err(error) => {
            panic!("Failed to load specification, {}", error);
        }
    }
}
