
//! ## Information Elements
//!
//! Somewhat structured data with 802.11 information data.
//!
//! ### References
//!
//! * 802.11-2012 standard
//! * Wireshark 802.11 dissector, <https://raw.githubusercontent.com/wireshark/wireshark/master/epan/dissectors/packet-ieee80211.c>
//! * Hostapd, <https://w1.fi/cgit/hostap/tree/src/common/ieee802_11_defs.h>

#![recursion_limit = "1024"]

extern crate netlink_rust;
#[macro_use] extern crate bitflags;

mod commands;
mod attributes;
mod information_element;
mod information_element_ids;
mod wireless_interface;
mod wireless_phy;

pub use commands::Command;
pub use attributes::{Attribute, BssAttribute};
pub use information_element::{RawInformationElement, InformationElements,
    RobustSecurityNetwork, CipherSuite, AuthenticationKeyManagement,
    ProtectedManagementFramesMode};
pub use information_element_ids::InformationElementId;
pub use wireless_interface::{WirelessInterface, get_wireless_interfaces};
pub use wireless_phy::get_wireless_phys;
