use std::fmt;

use netlink_rust as netlink;
use netlink_rust::generic;
use netlink_rust::Result;
use attributes::{Attribute, RegulatoryRuleAttribute};

bitflags! {
    pub struct RegulatoryFlags: u32 {
        const NO_OFDM       = 1 << 0;
        const NO_CCK        = 1 << 1;
        const NO_INDOOR     = 1 << 2;
        const NO_OUTDOOR    = 1 << 3;
        const DFS           = 1 << 4;
        const PTP_ONLY      = 1 << 5;
        const PTMP_ONLY     = 1 << 6;
        const NO_IR         = 1 << 7;
        const NO_IBSS       = 1 << 8;
        const AUTO_BW       = 1 << 11;
        const IR_CONCURRENT = 1 << 12;
        const HT40MINUS     = 1 << 13;
        const HT40PLUS      = 1 << 14;
        const NO_80MHZ      = 1 << 15;
        const NO_160MHZ     = 1 << 16;
    }
}

#[derive(Debug, PartialEq)]
enum RegulatoryRegion {
    Unset,
    FederalCommunicationsCommission,
    EuropeanTelecommunicationsStandardsInstitute,
    Japan,
}

impl From<u8> for RegulatoryRegion {
    fn from(value: u8) -> Self {
        match value {
            1 => RegulatoryRegion::FederalCommunicationsCommission,
            2 => RegulatoryRegion::EuropeanTelecommunicationsStandardsInstitute,
            3 => RegulatoryRegion::Japan,
            _ => RegulatoryRegion::Unset,
        }
    }
}

struct RegulatoryRule {
    start: u32,
    end: u32,
    flags: RegulatoryFlags,
    bandwidth: u32,
    effective_power: u32,
    antenna_gain: u32,
    channel_available_check_time: u32,
}

impl fmt::Display for RegulatoryRule {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}-{} BW {:3.0} PWR {:3.1} GAIN {:4} {:4} {:?}",
            self.start as f64 / 1000.0, self.end as f64 / 1000.0,
            self.bandwidth as f64 / 1000.0,
            self.effective_power as f64 / 1000.0,
            self.antenna_gain,
            self.channel_available_check_time,
            self.flags)
    }
}

impl RegulatoryRule {
    fn from_attributes(attributes: Vec<netlink::Attribute>)
        -> Result<RegulatoryRule> {
        let mut start = 0u32;
        let mut end = 0u32;
        let mut bandwidth = 0u32;
        let mut antenna_gain = 0u32;
        let mut flags = 0u32;
        let mut effective_power = 0u32;
        let mut channel_available_check_time = 0u32;
        for attribute in attributes {
            let id = RegulatoryRuleAttribute::from(attribute.identifier);
            match id {
                RegulatoryRuleAttribute::RangeStart => {
                    start = attribute.as_u32()?;
                }
                RegulatoryRuleAttribute::RangeEnd => {
                    end = attribute.as_u32()?;
                }
                RegulatoryRuleAttribute::MaximumBandwidth => {
                    bandwidth = attribute.as_u32()?;
                }
                RegulatoryRuleAttribute::MaximumAntennaGain => {
                    antenna_gain = attribute.as_u32()?;
                }
                RegulatoryRuleAttribute::Flags => {
                    flags = attribute.as_u32()?;
                }
                RegulatoryRuleAttribute::MaximumEffectiveIsotropicRadiatedPower => {
                    effective_power = attribute.as_u32()?;
                }
                RegulatoryRuleAttribute::ChannelAvailableCheckTime => {
                    channel_available_check_time = attribute.as_u32()?;
                }
                _ => ()
            }
        }
        Ok(RegulatoryRule {
            start: start,
            end: end,
            flags: RegulatoryFlags::from_bits_truncate(flags),
            bandwidth: bandwidth,
            antenna_gain: antenna_gain,
            effective_power: effective_power,
            channel_available_check_time: channel_available_check_time,
        })
    }
    fn from_nested_attribute_array(buffer: &[u8]) -> Vec<RegulatoryRule> {
        let mut rules = vec![];
        for attributes in netlink::nested_attribute_array(buffer) {
            match RegulatoryRule::from_attributes(attributes) {
                Ok(rule) => rules.push(rule),
                Err(_) => ()
            }
        }
        rules
    }
}

pub struct RegulatoryInformation {
    country: String,
    region: RegulatoryRegion,
    rules: Vec<RegulatoryRule>,
}

impl fmt::Display for RegulatoryInformation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{0} {1:?}\n", self.country, self.region)?;
        for ref rule in &self.rules {
            write!(f, "  {}\n", rule)?;
        }
        Ok(())
    }
}

impl RegulatoryInformation {
    pub fn from_message(message: &generic::Message)
        -> Result<RegulatoryInformation>
    {
        let mut country = String::new();
        let mut region = 0u8;
        let mut rules = vec![];
        for ref attribute in &message.attributes {
            let id = Attribute::from(attribute.identifier);
            match id {
                Attribute::RegAlpha2 => {
                    country = attribute.as_string()?;
                }
                Attribute::DfsRegion => {
                    region = attribute.as_u8()?;
                }
                Attribute::RegRules => {
                    rules = RegulatoryRule::from_nested_attribute_array(
                        &attribute.as_bytes());
                }
                _ => ()
            }
        }
        Ok(RegulatoryInformation{
            country: country,
            region: RegulatoryRegion::from(region),
            rules: rules,
        })
    }
}