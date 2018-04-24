extern crate bindgen;

use std::io::Write;

use bindgen::builder;

const KERNEL_HEADERS: &'static str = "kernel-includes.h";

fn generate_netlink() {
    match std::fs::File::create(KERNEL_HEADERS) {
        Ok(mut file) => {
            writeln!(file, "#include <unistd.h>\n").unwrap();
            writeln!(file, "#include <linux/netlink.h>\n").unwrap();
            writeln!(file, "#include <linux/rtnetlink.h>\n").unwrap();
            writeln!(file, "#include <linux/genetlink.h>\n").unwrap();
        },
        Err(error) => {
            panic!("Failed to open file \"{}\": {}", KERNEL_HEADERS, error);
        }
    }
    {
        let bindings = builder().layout_tests(false).header(KERNEL_HEADERS).generate().unwrap();
        bindings.write_to_file("src/kernel/netlink.rs").unwrap();
    }
    std::fs::remove_file(KERNEL_HEADERS).unwrap();
}

fn main() {
    generate_netlink();
}
