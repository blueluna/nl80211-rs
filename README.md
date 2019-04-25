# nl80211 in Rust

Handling nl80211, IEEE 802.11 Netlink protocol, in Rust. Work in progress.

## Example

If run without arguments the example program will listen for nl80211 events.
If a new scan event is received the scan results will be fetched.

```bash
$ cargo run --release --example nl80211
```

It is also possible to initiate a scan as super user.

```bash
sudo ./target/release/examples/nl80211 scan
```

## Compatability

Rust 1.30.0 or later is needed.

Tested on following platforms,
 - Linux 4.18 x86_64, Fedora 28
 - Linux 4.1 ARMv7
 - Linux 4.9 AArch64

## License

 Licensed under the MIT license.

[![Build Status](https://travis-ci.org/blueluna/nl80211-rs.svg?branch=master)](https://travis-ci.org/blueluna/nl80211-rs) [![Crates.io](https://img.shields.io/crates/v/nl80211-rs.svg)](https://crates.io/crates/nl80211-rs)
