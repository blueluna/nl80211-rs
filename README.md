# Experiments with netlink and nl80211 in Rust

Licensed under the MIT license.

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
