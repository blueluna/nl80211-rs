
//! ## Information Elements
//!
//! Somewhat structured data with 802.11 information data.
//!
//! ### References
//!
//! * 802.11-2012 standard
//! * Wireshark 802.11 dissector, <https://raw.githubusercontent.com/wireshark/wireshark/master/epan/dissectors/packet-ieee80211.c>
//! * Hostapd, <https://w1.fi/cgit/hostap/tree/src/common/ieee802_11_defs.h>

use std::io;
use std::fmt;
use std::convert::{Into};

use encoding::{Encoding, DecoderTrap};
use encoding::all::ISO_8859_1;

use netlink_rust::{Error, ConvertFrom};
use unpack::{Unpack, unpack_vec};
use information_element_ids::InformationElementId;

pub struct RawInformationElement<'a>
{
    pub identifier: u8,
    pub data: &'a [u8],
}

impl<'a> RawInformationElement<'a> {
    pub fn parse(data: &'a [u8]) -> Result<RawInformationElement<'a>, Error> {
        if data.len() < 2 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "").into());
        }
        let (identifier, data) = u8::unpack(data);
        let (length, data) = u8::unpack(data);
        let length = length as usize;
        if data.len() < length {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "").into());
        }
        Ok(RawInformationElement { identifier: identifier,
            data: &data[..length] })
    }
}

pub struct InformationElements<'a>
{
    pub elements: Vec<RawInformationElement<'a>>,
}

impl<'a> InformationElements<'a> {
    pub fn parse(data: &'a [u8]) -> InformationElements<'a>
    {
        let mut elements = vec![];
        let mut slice = data;
        loop {
            match RawInformationElement::parse(slice) {
                Ok(ie) => {
                    slice = &slice[(ie.data.len() + 2)..];
                    elements.push(ie);
                },
                Err(_) => break,
            }
        }
        InformationElements {
            elements: elements,
        }
    }
}

pub struct Ssid
{
    pub ssid: String
}

impl Ssid {
    pub fn parse(data: &[u8]) -> Result<Ssid, Error>
    {
        let ssid = ISO_8859_1.decode(data, DecoderTrap::Strict)
            .or_else(|_| {
                String::from_utf8(data.to_vec())
            })?;
        return Ok(Ssid { ssid: ssid });
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum CipherSuite {
    UseGroupCipherSuite,
    WiredEquivalentPrivacy40,
    TemporalKeyIntegrityProtocol,
    CounterModeCbcMacProtocol,
    WiredEquivalentPrivacy104,
    BroadcastIntegrityProtocol,
    GroupAddressedTrafficNotAllowed,
    Reserved(u8),
    Vendor(u32),
}

impl From<u32> for CipherSuite {
    fn from(v: u32) -> Self {
        if v & 0x00ffffff == 0x00ac0f00 {
            let c = (v >> 24) as u8;
            match c {
                0 => CipherSuite::UseGroupCipherSuite,
                1 => CipherSuite::WiredEquivalentPrivacy40,
                2 => CipherSuite::TemporalKeyIntegrityProtocol,
                4 => CipherSuite::CounterModeCbcMacProtocol,
                5 => CipherSuite::WiredEquivalentPrivacy104,
                6 => CipherSuite::BroadcastIntegrityProtocol,
                7 => CipherSuite::GroupAddressedTrafficNotAllowed,
                _ => CipherSuite::Reserved(c),
            }
        }
        else {
            CipherSuite::Vendor(v)
        }
    }
}

impl From<CipherSuite> for u32 {
    fn from(v: CipherSuite) -> Self {
        match v {
            CipherSuite::UseGroupCipherSuite => 0x00ac0f00,
            CipherSuite::WiredEquivalentPrivacy40 => 0x01ac0f00,
            CipherSuite::TemporalKeyIntegrityProtocol => 0x02ac0f00,
            CipherSuite::CounterModeCbcMacProtocol => 0x04ac0f00,
            CipherSuite::WiredEquivalentPrivacy104 => 0x05ac0f00,
            CipherSuite::BroadcastIntegrityProtocol => 0x06ac0f00,
            CipherSuite::GroupAddressedTrafficNotAllowed => 0x07ac0f00,
            CipherSuite::Reserved(v) => 0x00ac0f00 | (v as u32) << 24,
            CipherSuite::Vendor(v) => v,
        }
    }
}

impl fmt::Display for CipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CipherSuite::UseGroupCipherSuite => write!(f, "GroupCipher"),
            CipherSuite::WiredEquivalentPrivacy40 => write!(f, "WEP40"),
            CipherSuite::TemporalKeyIntegrityProtocol => write!(f, "TKIP"),
            CipherSuite::CounterModeCbcMacProtocol => write!(f, "CCMP"),
            CipherSuite::WiredEquivalentPrivacy104 => write!(f, "WEP104"),
            CipherSuite::BroadcastIntegrityProtocol => write!(f, "BIP"),
            CipherSuite::GroupAddressedTrafficNotAllowed => write!(f, "GroupAddressedTrafficNotAllowed"),
            CipherSuite::Reserved(v) => write!(f, "Reserved {:x}", v),
            CipherSuite::Vendor(v) => write!(f, "Vendor {:x}", v),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum AuthenticationKeyManagement {
    PairwiseMasterKeySecurityAssociation,
    PreSharedKey,
    FastTransitionPMKSA,
    FastTransitionPreSharedKey,
    PMKSASha256,
    PreSharedKeySha256,
    TunneledDirectLinkSetup,
    SimultaneousAuthenticationOfEquals,
    FastTransitionSAE,
    Reserved(u8),
    Vendor(u32),
}

impl From<u32> for AuthenticationKeyManagement {
    fn from(v: u32) -> Self {
        if v & 0x00ffffff == 0x00ac0f00 {
            let c = (v >> 24) as u8;
            match c {
                1 => AuthenticationKeyManagement::PairwiseMasterKeySecurityAssociation,
                2 => AuthenticationKeyManagement::PreSharedKey,
                3 => AuthenticationKeyManagement::FastTransitionPMKSA,
                4 => AuthenticationKeyManagement::FastTransitionPreSharedKey,
                5 => AuthenticationKeyManagement::PMKSASha256,
                6 => AuthenticationKeyManagement::PreSharedKeySha256,
                7 => AuthenticationKeyManagement::TunneledDirectLinkSetup,
                8 => AuthenticationKeyManagement::SimultaneousAuthenticationOfEquals,
                9 => AuthenticationKeyManagement::FastTransitionSAE,
                _ => AuthenticationKeyManagement::Reserved(c),
            }
        }
        else {
            AuthenticationKeyManagement::Vendor(v)
        }
    }
}

impl From<AuthenticationKeyManagement> for u32 {
    fn from(v: AuthenticationKeyManagement) -> Self {
        match v {
            AuthenticationKeyManagement::PairwiseMasterKeySecurityAssociation => 0x01ac0f00,
            AuthenticationKeyManagement::PreSharedKey => 0x02ac0f00,
            AuthenticationKeyManagement::FastTransitionPMKSA => 0x03ac0f00,
            AuthenticationKeyManagement::FastTransitionPreSharedKey => 0x04ac0f00,
            AuthenticationKeyManagement::PMKSASha256 => 0x05ac0f00,
            AuthenticationKeyManagement::PreSharedKeySha256 => 0x06ac0f00,
            AuthenticationKeyManagement::TunneledDirectLinkSetup => 0x07ac0f00,
            AuthenticationKeyManagement::SimultaneousAuthenticationOfEquals => 0x08ac0f00,
            AuthenticationKeyManagement::FastTransitionSAE => 0x09ac0f00,
            AuthenticationKeyManagement::Reserved(v) => 0x00ac0f00 | (v as u32) << 24,
            AuthenticationKeyManagement::Vendor(v) => v,
        }
    }
}

impl fmt::Display for AuthenticationKeyManagement {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            AuthenticationKeyManagement::PairwiseMasterKeySecurityAssociation => write!(f, "PMKSA"),
            AuthenticationKeyManagement::PreSharedKey => write!(f, "PSK"),
            AuthenticationKeyManagement::FastTransitionPMKSA => write!(f, "FTPMKSA"),
            AuthenticationKeyManagement::FastTransitionPreSharedKey => write!(f, "FTPSK"),
            AuthenticationKeyManagement::PMKSASha256 => write!(f, "PMKSA_SHA256"),
            AuthenticationKeyManagement::PreSharedKeySha256 => write!(f, "PSK_SHA256"),
            AuthenticationKeyManagement::TunneledDirectLinkSetup => write!(f, "TDLS"),
            AuthenticationKeyManagement::SimultaneousAuthenticationOfEquals => write!(f, "SAE"),
            AuthenticationKeyManagement::FastTransitionSAE => write!(f, "FTSAE"),
            AuthenticationKeyManagement::Reserved(v) => write!(f, "Reserved {:x}", v),
            AuthenticationKeyManagement::Vendor(v) => write!(f, "Vendor {:x}", v),
        }
    }
}

bitflags! {
    pub struct RsnCapabilities: u16 {
        const PREAUTHENTICATION = 0x0001;
        const NO_PAIRWISE = 0x0002;
        const PMF_REQUIRED = 0x0040;
        const PMF_CAPABLE = 0x0080;
        const PEER_KEY_ENABLED = 0x0200;
        const SPP_AMSDU_CAPABLE = 0x0400;
        const SPP_AMSDU_REQUIRED = 0x0800;
        const PBAC = 0x1000;
        const EXTENDED_KEY_ID = 0x2000;
    }
}


#[derive(Debug, PartialEq)]
pub enum ProtectedManagementFramesMode {
    Disabled,
    Capable,
    Required,
}

impl fmt::Display for ProtectedManagementFramesMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ProtectedManagementFramesMode::Disabled => write!(f, "Disabled"),
            ProtectedManagementFramesMode::Capable => write!(f, "Capable"),
            ProtectedManagementFramesMode::Required => write!(f, "Required"),
        }
    }
}

#[derive(Debug)]
pub struct RobustSecurityNetwork {
    version: u16,
    cipher_suite: CipherSuite,
    pub ciphers: Vec<CipherSuite>,
    pub akms: Vec<AuthenticationKeyManagement>,
    capabilities: RsnCapabilities,
    ptksa_counters: u8,
    gtksa_counters: u8,
}

impl RobustSecurityNetwork {
    pub fn parse(data: &[u8]) -> Result<RobustSecurityNetwork, Error> {
        if data.len() > 12 {
            let (version, data) = u16::unpack(data);
            let (value, data) = u32::unpack(data);
            let suite = CipherSuite::from(value);
            let (count, data) = u16::unpack(data);
            let (values, data) = unpack_vec::<u32>(data, count as usize)?;
            let ciphers = values.into_iter()
                .map(|v| CipherSuite::from(v)).collect();
            let (count, data) = u16::unpack(data);
            let (values, data) = unpack_vec::<u32>(data, count as usize)?;
            let akms = values.into_iter()
                .map(|v| AuthenticationKeyManagement::from(v)).collect();
            let (count, _data) = u16::unpack(data);
            let ptksa_counters = match count & 0x000c {
                0x0004 => 2,
                0x0008 => 4,
                0x000c => 16,
                _ => 1,
            };
            let gtksa_counters = match count & 0x0030 {
                0x0010 => 2,
                0x0020 => 4,
                0x0030 => 16,
                _ => 1,
            };
            return Ok(RobustSecurityNetwork {
                version: version,
                cipher_suite: suite,
                ciphers: ciphers,
                akms: akms,
                capabilities: RsnCapabilities::from_bits_truncate(count),
                ptksa_counters: ptksa_counters,
                gtksa_counters: gtksa_counters,
            });
        }
	    return Err(io::Error::new(io::ErrorKind::InvalidData,
            "Invalid RSN element").into());
    }

    pub fn pmf_mode(&self) -> ProtectedManagementFramesMode
    {
        if self.capabilities.intersects(RsnCapabilities::PMF_REQUIRED) {
            return ProtectedManagementFramesMode::Required;
        }
        else if self.capabilities.intersects(RsnCapabilities::PMF_CAPABLE) {
            return ProtectedManagementFramesMode::Capable;
        }
        ProtectedManagementFramesMode::Disabled
    }
}

pub struct HighThroughputOperation
{
    pub width: u32,
    pub primary_channel: u8,
    pub secondary_channel: u8,
}

impl HighThroughputOperation {
    pub fn parse(data: &[u8]) -> Result<HighThroughputOperation, Error> {
        if data.len() == 22 {
            let secondary_channel = match data[1] & 0x03 {
                1 => data[0] + 1,
                3 => data[0] - 1,
                _ => 0,
            };
            let width = if data[1] & 0x04 == 0 { 20 } else { 40 };
            // There are lots of other information in this IE
            return Ok(HighThroughputOperation {
                primary_channel: data[0],
                secondary_channel: secondary_channel,
                width: width,
            });
        }
	    return Err(io::Error::new(io::ErrorKind::InvalidData,
            "Invalid VHT element").into());
    }
}

pub struct VeryHighThroughputOperation
{
    pub width: u32,
    pub channel: u8,
    pub secondary_channel: u8,
}

impl VeryHighThroughputOperation {
    pub fn parse(data: &[u8]) -> Result<VeryHighThroughputOperation, Error> {
        if data.len() == 5 {
            let width = match data[0] & 0x03 {
                1 => 80,
                2 => 160,
                3 => 80,
                _ => 40,
            };
            // Skipping VHT-MCS set, 2 octets
            return Ok(VeryHighThroughputOperation {
                width: width,
                channel: data[1],
                secondary_channel: data[2],
            });
        }
	    return Err(io::Error::new(io::ErrorKind::InvalidData,
            "Invalid VHT element").into());
    }
}

pub enum ChannelSwitchMode {
    NoRestriction = 0,
    NoTransmission = 1,
}

impl From<u8> for ChannelSwitchMode {
    fn from(v: u8) -> Self
    {
        match v {
            1 => ChannelSwitchMode::NoRestriction,
            _ => ChannelSwitchMode::NoTransmission,
        }
    }
}

pub struct ExtendedChannelSwitchAnnouncement {
    pub switch_mode: ChannelSwitchMode,
    pub new_operating_class: u8,
    pub new_channel: u8,
    pub switch_count: u8,
}

impl ExtendedChannelSwitchAnnouncement {
    pub fn parse(data: &[u8])
        -> Result<ExtendedChannelSwitchAnnouncement, Error>
    {
        if data.len() == 4 {
            return Ok(ExtendedChannelSwitchAnnouncement {
                switch_mode: ChannelSwitchMode::from(data[0]),
                new_operating_class: data[1],
                new_channel: data[2],
                switch_count: data[3]
            });
        }
	    return Err(io::Error::new(io::ErrorKind::InvalidData,
            "Invalid ECSA element").into());
    }
}

pub enum InformationElement<'a> {
    Ssid(Ssid),
    RobustSecurityNetwork(RobustSecurityNetwork),
    HighThroughputOperation(HighThroughputOperation),
    VeryHighThroughputOperation(VeryHighThroughputOperation),
    Other(RawInformationElement<'a>),
}

impl<'a> InformationElement<'a> {
    pub fn parse(data: &'a [u8]) -> Result<InformationElement<'a>, Error>
    {
        let raw = RawInformationElement::parse(data)?;
        let id = InformationElementId::convert_from(raw.identifier);
        if let Some(id) = id {
            return Self::from(id, raw.data);
        }
        else {
            return Ok(InformationElement::Other(raw));
        }
    }

    pub fn from(id: InformationElementId, data: &'a [u8])
        -> Result<InformationElement<'a>, Error>
    {
        let ie = match id {
            InformationElementId::Ssid => {
                let ie = Ssid::parse(data)?;
                InformationElement::Ssid(ie)
            },
            InformationElementId::HighThroughputOperation => {
                let ie = HighThroughputOperation::parse(data)?;
                InformationElement::HighThroughputOperation(ie)
            },
            InformationElementId::VeryHighThroughputOperation => {
                let ie = VeryHighThroughputOperation::parse(data)?;
                InformationElement::VeryHighThroughputOperation(ie)
            },
            InformationElementId::RobustSecurityNetwork => {
                let ie = RobustSecurityNetwork::parse(data)?;
                InformationElement::RobustSecurityNetwork(ie)
            }
            _ => {
                InformationElement::Other(
                    RawInformationElement { identifier: id.into(),data: data }
                )
            }
        };
        Ok(ie)
    }

    pub fn parse_all(data: &'a [u8])
        -> Result<Vec<InformationElement<'a>>, Error>
    {
        let mut ies = vec![];
        let mut slice = data;
        loop {
            let raw = match RawInformationElement::parse(slice) {
                Ok(raw) => raw,
                Err(_) => break,
            };
            slice = &slice[raw.data.len() + 2..];
            let id = InformationElementId::convert_from(raw.identifier);
            let ie = if let Some(id) = id {
                Self::from(id, raw.data)?
            }
            else {
                InformationElement::Other(raw)
            };
            ies.push(ie);
        }
        return Ok(ies);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ie() {
        let bytes = [48, 6, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let ie = RawInformationElement::parse(&bytes).unwrap();
        assert_eq!(ie.identifier, 48u8);
        assert_eq!(ie.data.len(), 6);
        assert_eq!(ie.data, &bytes[2..]);
    }

    #[test]
    fn test_parse_ies() {
        let bytes = [
            48, 6, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            4, 0,
            1, 2, 0x55, 0xaa, ];
        let ies = InformationElements::parse(&bytes);
        assert_eq!(ies.elements.len(), 3);
    }
}