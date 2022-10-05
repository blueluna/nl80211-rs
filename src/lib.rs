//! # Netlink 802.11
//!
//!

#![recursion_limit = "1024"]

extern crate byteorder;
#[macro_use]
extern crate bitflags;
extern crate encoding;
extern crate netlink_rust;

mod attributes;
mod commands;
mod frame;
pub mod information_element;
mod information_element_ids;
mod regulatory;
mod unpack;
mod wireless_interface;
mod wireless_phy;

pub use crate::attributes::{Attribute, BssAttribute, InterfaceType};
pub use crate::commands::Command;
pub use crate::frame::Frame;
pub use crate::information_element_ids::InformationElementId;
pub use crate::regulatory::{
    RegulatoryChange, RegulatoryInformation, RegulatoryInitiator, RegulatoryRegion,
};
pub use crate::wireless_interface::{get_wireless_interfaces, WirelessDeviceId, WirelessInterface};
pub use crate::wireless_phy::get_wireless_phys;

fn join_to_string<T>(values: T, separator: &str) -> String
where
    T: Iterator,
    T::Item: ToString,
{
    values
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(separator)
}
