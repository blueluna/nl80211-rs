
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
use unpack::{LittleUnpack, unpack_vec};
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
        let identifier = u8::unpack_unchecked(data);
        let length = u8::unpack_unchecked(&data[1..]);
        let length = length as usize;
        if data.len() < length {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "").into());
        }
        Ok(RawInformationElement { identifier, data: &data[2..(length + 2)] })
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
        while let Ok(ie) = RawInformationElement::parse(slice) {
            slice = &slice[(ie.data.len() + 2)..];
            elements.push(ie);
        }
        InformationElements { elements }
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
        Ok(Ssid { ssid })
    }
}

impl fmt::Display for Ssid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.ssid)
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
        use CipherSuite::*;
        if v & 0x00ff_ffff == 0x00ac_0f00 {
            let c = (v >> 24) as u8;
            match c {
                0 => UseGroupCipherSuite,
                1 => WiredEquivalentPrivacy40,
                2 => TemporalKeyIntegrityProtocol,
                4 => CounterModeCbcMacProtocol,
                5 => WiredEquivalentPrivacy104,
                6 => BroadcastIntegrityProtocol,
                7 => GroupAddressedTrafficNotAllowed,
                _ => Reserved(c),
            }
        }
        else {
            Vendor(v)
        }
    }
}

impl From<CipherSuite> for u32 {
    fn from(v: CipherSuite) -> Self {
        use CipherSuite::*;
        match v {
            UseGroupCipherSuite => 0x00ac_0f00,
            WiredEquivalentPrivacy40 => 0x01ac_0f00,
            TemporalKeyIntegrityProtocol => 0x02ac_0f00,
            CounterModeCbcMacProtocol => 0x04ac_0f00,
            WiredEquivalentPrivacy104 => 0x05ac_0f00,
            BroadcastIntegrityProtocol => 0x06ac_0f00,
            GroupAddressedTrafficNotAllowed => 0x07ac_0f00,
            Reserved(v) => 0x00ac_0f00 | u32::from(v) << 24,
            Vendor(v) => v,
        }
    }
}

impl fmt::Display for CipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use CipherSuite::*;
        match *self {
            UseGroupCipherSuite => write!(f, "GroupCipher"),
            WiredEquivalentPrivacy40 => write!(f, "WEP40"),
            TemporalKeyIntegrityProtocol => write!(f, "TKIP"),
            CounterModeCbcMacProtocol => write!(f, "CCMP"),
            WiredEquivalentPrivacy104 => write!(f, "WEP104"),
            BroadcastIntegrityProtocol => write!(f, "BIP"),
            GroupAddressedTrafficNotAllowed =>
                write!(f, "GroupAddressedTrafficNotAllowed"),
            Reserved(v) => write!(f, "Reserved {:02x}", v),
            Vendor(v) => write!(f, "Vendor {:08x}", v),
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
        if v & 0x00ff_ffff == 0x00ac_0f00 {
            let c = (v >> 24) as u8;
            use AuthenticationKeyManagement::*;
            match c {
                1 => PairwiseMasterKeySecurityAssociation,
                2 => PreSharedKey,
                3 => FastTransitionPMKSA,
                4 => FastTransitionPreSharedKey,
                5 => PMKSASha256,
                6 => PreSharedKeySha256,
                7 => TunneledDirectLinkSetup,
                8 => SimultaneousAuthenticationOfEquals,
                9 => FastTransitionSAE,
                _ => Reserved(c),
            }
        }
        else {
            AuthenticationKeyManagement::Vendor(v)
        }
    }
}

impl From<AuthenticationKeyManagement> for u32 {
    fn from(v: AuthenticationKeyManagement) -> Self {
        use AuthenticationKeyManagement::*;
        match v {
            PairwiseMasterKeySecurityAssociation => 0x01ac_0f00,
            PreSharedKey => 0x02ac_0f00,
            FastTransitionPMKSA => 0x03ac_0f00,
            FastTransitionPreSharedKey => 0x04ac_0f00,
            PMKSASha256 => 0x05ac_0f00,
            PreSharedKeySha256 => 0x06ac_0f00,
            TunneledDirectLinkSetup => 0x07ac_0f00,
            SimultaneousAuthenticationOfEquals => 0x08ac_0f00,
            FastTransitionSAE => 0x09ac_0f00,
            Reserved(v) => 0x00ac_0f00 | u32::from(v) << 24,
            Vendor(v) => v,
        }
    }
}

impl fmt::Display for AuthenticationKeyManagement {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use AuthenticationKeyManagement::*;
        match *self {
            PairwiseMasterKeySecurityAssociation => write!(f, "PMKSA"),
            PreSharedKey => write!(f, "PSK"),
            FastTransitionPMKSA => write!(f, "FTPMKSA"),
            FastTransitionPreSharedKey => write!(f, "FTPSK"),
            PMKSASha256 => write!(f, "PMKSA_SHA256"),
            PreSharedKeySha256 => write!(f, "PSK_SHA256"),
            TunneledDirectLinkSetup => write!(f, "TDLS"),
            SimultaneousAuthenticationOfEquals => write!(f, "SAE"),
            FastTransitionSAE => write!(f, "FTSAE"),
            Reserved(v) => write!(f, "Reserved {:x}", v),
            Vendor(v) => write!(f, "Vendor {:x}", v),
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
        if data.len() > 8 {
            let version = u16::unpack_unchecked(data);
            let value = u32::unpack_unchecked(&data[2..]);
            let suite = CipherSuite::from(value);
            let count = u16::unpack_unchecked(&data[6..]);
            let (used, values) = unpack_vec::<u32>(&data[8..],
                count as usize)?;
            let mut offset = 8 + used;
            let ciphers = values.into_iter()
                .map(CipherSuite::from).collect();
            let (used, count) = u16::unpack_with_size(&data[offset..])?;
            offset += used;
            let (used, values) = unpack_vec::<u32>(&data[offset..],
                count as usize)?;
            offset += used;
            let akms = values.into_iter()
                .map(AuthenticationKeyManagement::from).collect();
            let (_used, count) = u16::unpack_with_size(&data[offset..])?;
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
                version,
                cipher_suite: suite,
                ciphers,
                akms,
                capabilities: RsnCapabilities::from_bits_truncate(count),
                ptksa_counters,
                gtksa_counters,
            });
        }
	    Err(io::Error::new(io::ErrorKind::InvalidData,
            "Invalid RSN element").into())
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

impl fmt::Display for RobustSecurityNetwork {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Cipher Suite {} Protected Management Frames {}",
            self.cipher_suite, self.pmf_mode())
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
                secondary_channel,
                width,
            });
        }
	    Err(io::Error::new(io::ErrorKind::InvalidData,
            "Invalid VHT element").into())
    }
}

impl fmt::Display for HighThroughputOperation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Primary Channel {} Secondary Channel {} Bandwidth {}",
            self.primary_channel, self.secondary_channel, self.width)
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
                width,
                channel: data[1],
                secondary_channel: data[2],
            });
        }
	    Err(io::Error::new(io::ErrorKind::InvalidData,
            "Invalid VHT element").into())
    }
}

impl fmt::Display for VeryHighThroughputOperation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Primary Channel {} Secondary Channel {} Bandwidth {}",
            self.channel, self.secondary_channel, self.width)
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
	    Err(io::Error::new(io::ErrorKind::InvalidData,
            "Invalid ECSA element").into())
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
                    RawInformationElement { identifier: id.into(), data }
                )
            }
        };
        Ok(ie)
    }

    pub fn identifier(&self)
        -> Option<InformationElementId>
    {
        let id = match *self {
            InformationElement::Ssid(_) => {
                InformationElementId::Ssid
            },
            InformationElement::HighThroughputOperation(_) => {
                InformationElementId::HighThroughputOperation
            },
            InformationElement::VeryHighThroughputOperation(_) => {
                InformationElementId::VeryHighThroughputOperation
            },
            InformationElement::RobustSecurityNetwork(_) => {
                InformationElementId::RobustSecurityNetwork
            }
            InformationElement::Other(ref ie) => {
                InformationElementId::from(ie.identifier)
            }
        };
        Some(id)
    }

    pub fn parse_all(data: &'a [u8])
        -> Result<Vec<InformationElement<'a>>, Error>
    {
        let mut ies = vec![];
        let mut slice = data;
        while let Ok(raw) = RawInformationElement::parse(slice) {
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
        Ok(ies)
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