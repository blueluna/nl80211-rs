//! ## Information Elements
//!
//! Somewhat structured data with 802.11 information data.
//!
//! ### References
//!
//! * 802.11-2012 standard
//! * Wireshark 802.11 dissector, <https://raw.githubusercontent.com/wireshark/wireshark/master/epan/dissectors/packet-ieee80211.c>
//! * Hostapd, <https://w1.fi/cgit/hostap/tree/src/common/ieee802_11_defs.h>

use std::convert::Into;
use std::fmt;
use std::io;

use encoding::all::ISO_8859_1;
use encoding::{DecoderTrap, Encoding};

use crate::information_element_ids::InformationElementId;
use netlink_rust::{ConvertFrom, Error};
use crate::unpack::{unpack_vec, LittleUnpack};

/// Unprocessed information element
///
/// ```notrust
/// +------------+--------+-------------+
/// | identifier | length | payload ... |
/// +------------+--------+-------------+
///       1           1         n          octets
/// ```
/// An information element has a identifier, length and payload. The first two octets is the
/// identifier and length respectively. The payload comes at the end and contains length number of
/// octets.
///
pub struct RawInformationElement<'a> {
    pub identifier: u8,
    pub data: &'a [u8],
}

impl<'a> RawInformationElement<'a> {
    /// Parse information element from byte slice
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
        Ok(RawInformationElement {
            identifier,
            data: &data[2..(length + 2)],
        })
    }
    /// Get the information element identifier if the identifier is known
    pub fn ie_id(&self) -> Option<InformationElementId> {
        InformationElementId::convert_from(self.identifier)
    }
}

/// Multiple information elements
pub struct InformationElements<'a> {
    pub elements: Vec<RawInformationElement<'a>>,
}

impl<'a> InformationElements<'a> {
    pub fn parse(data: &'a [u8]) -> InformationElements<'a> {
        let mut elements = vec![];
        let mut slice = data;
        while let Ok(ie) = RawInformationElement::parse(slice) {
            slice = &slice[(ie.data.len() + 2)..];
            elements.push(ie);
        }
        InformationElements { elements }
    }
}

/// Service set identifier (SSID) information element
///
/// A SSID is a string which contains a name for the entity.
pub struct Ssid {
    pub ssid: String,
}

impl Ssid {
    /// Parse information payload as SSID
    ///
    /// This function will try to decode the string as UTF-8 first, if UTF-8 decoding fails
    /// try to decode using ISO-8859-1 dedoding, if all fails return an emty string,
    ///
    pub fn parse(data: &[u8]) -> Result<Ssid, Error> {
        // First try to decode utf8
        let ssid = String::from_utf8(data.to_vec()).unwrap_or_else(|_|
            // Then try ISO 8859-1
            ISO_8859_1.decode(data, DecoderTrap::Strict)
                .unwrap_or_default());
        let ssid = ssid.trim_end_matches('\0').to_string();
        Ok(Ssid { ssid })
    }
}

impl fmt::Display for Ssid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.ssid)
    }
}

/// Cipher suites used in 802.11
#[derive(Debug, PartialEq, Clone)]
pub enum CipherSuite {
    /// Use group cipher suite
    UseGroupCipherSuite,
    /// Wired equivalent privacy (WEP)
    WiredEquivalentPrivacy40,
    /// Temporal key integrity protocol (TKIP)
    TemporalKeyIntegrityProtocol,
    /// Counter mode CBC-MAC protocol
    CounterModeCbcMacProtocol,
    /// Wired equivalent privacy (WEP104)
    WiredEquivalentPrivacy104,
    /// Broadcast integrity protocol (BIP)
    BroadcastIntegrityProtocol,
    /// Group traffic not allowed
    GroupAddressedTrafficNotAllowed,
    /// 802.11 reserved cipher suites
    Reserved(u8),
    /// Vendor cipher suite
    Vendor(u32),
}

impl From<u32> for CipherSuite {
    /// Decode 32-bit unsigned integer as a cipher suite value
    fn from(v: u32) -> Self {
        use self::CipherSuite::*;
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
        } else {
            Vendor(v)
        }
    }
}

impl From<CipherSuite> for u32 {
    /// Encode cipher suite into 32-bit unsigned value
    fn from(v: CipherSuite) -> Self {
        use self::CipherSuite::*;
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
        use self::CipherSuite::*;
        match *self {
            UseGroupCipherSuite => write!(f, "GroupCipher"),
            WiredEquivalentPrivacy40 => write!(f, "WEP40"),
            TemporalKeyIntegrityProtocol => write!(f, "TKIP"),
            CounterModeCbcMacProtocol => write!(f, "CCMP"),
            WiredEquivalentPrivacy104 => write!(f, "WEP104"),
            BroadcastIntegrityProtocol => write!(f, "BIP"),
            GroupAddressedTrafficNotAllowed => write!(f, "GroupAddressedTrafficNotAllowed"),
            Reserved(v) => write!(f, "Reserved {:02x}", v),
            Vendor(v) => write!(f, "Vendor {:08x}", v),
        }
    }
}

/// Authentication and key management (AKM) mode used in 802.11
#[derive(Debug, PartialEq, Clone)]
pub enum AuthenticationKeyManagement {
    /// Pairwise master key security association (PMKSA)
    PairwiseMasterKeySecurityAssociation,
    /// Pre-shared key (PSK)
    PreSharedKey,
    /// Fast transition pairwise master key security association (FT-PMKSA)
    FastTransitionPMKSA,
    /// Fast transition pre-shared key (FT-PSK)
    FastTransitionPreSharedKey,
    /// Pairwise master key security association SHA256 (PMKSA-SHA256)
    PMKSASha256,
    /// Pre-shared key SHA256 (PSK-SHA256)
    PreSharedKeySha256,
    /// Tunneled direct link setup (TDLS)
    TunneledDirectLinkSetup,
    /// Simultaneous authentication of equals (SAE)
    SimultaneousAuthenticationOfEquals,
    /// Fast transition simultaneous authentication of equals (FT-SAE)
    FastTransitionSAE,
    /// 802.11 reserved authentication key management
    Reserved(u8),
    /// Vendor authentication key management
    Vendor(u32),
}

impl From<u32> for AuthenticationKeyManagement {
    fn from(v: u32) -> Self {
        if v & 0x00ff_ffff == 0x00ac_0f00 {
            let c = (v >> 24) as u8;
            use self::AuthenticationKeyManagement::*;
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
        } else {
            AuthenticationKeyManagement::Vendor(v)
        }
    }
}

impl From<AuthenticationKeyManagement> for u32 {
    fn from(v: AuthenticationKeyManagement) -> Self {
        use self::AuthenticationKeyManagement::*;
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
        use self::AuthenticationKeyManagement::*;
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
    /// Robust security network (RSN) capabilities
    pub struct RsnCapabilities: u16 {
        /// Signals support for pre-authentication
        const PREAUTHENTICATION = 0x0001;
        /// Signals that simultanious WEP and pairwise key is not supported
        const NO_PAIRWISE = 0x0002;
        /// Requires protected management frames
        const PMF_REQUIRED = 0x0040;
        /// Capable of protected management frames
        const PMF_CAPABLE = 0x0080;
        /// Support peer key handshake
        const PEER_KEY_ENABLED = 0x0200;
        /// Capable of signaling and payload protected (SPP) A-MSDUs
        const SPP_AMSDU_CAPABLE = 0x0400;
        /// Requires signaling and payload protected (SPP) A-MSDUs
        const SPP_AMSDU_REQUIRED = 0x0800;
        /// protected block acknowledgement agreement capable
        const PBAC = 0x1000;
        /// Support key id 0 or 1 for PTKSA or STKSA in CCMP mode, otherwise only key id 0 is
        /// supported
        const EXTENDED_KEY_ID = 0x2000;
    }
}

/// Protected management frames selector
#[derive(Debug, PartialEq)]
pub enum ProtectedManagementFramesMode {
    /// Protected management frames is disabled
    Disabled,
    /// Capable of handling protected management frames
    Capable,
    /// Protected management frames is required
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

/// Robust security network (RSN) information element data
#[derive(Debug)]
pub struct RobustSecurityNetwork {
    /// RSNA protocol version
    version: u16,
    /// Group data cipher suit
    cipher_suite: CipherSuite,
    /// Supported cipher suits
    pub ciphers: Vec<CipherSuite>,
    /// Supported authentication key management
    pub akms: Vec<AuthenticationKeyManagement>,
    /// Capabilities
    capabilities: RsnCapabilities,
    /// Pairwise transient key security association replay counters
    ptksa_counters: u8,
    /// group temporal key security association replay counters
    gtksa_counters: u8,
}

impl RobustSecurityNetwork {
    /// Parse robust security network from information element payload
    pub fn parse(data: &[u8]) -> Result<RobustSecurityNetwork, Error> {
        if data.len() > 8 {
            let version = u16::unpack_unchecked(data);
            let value = u32::unpack_unchecked(&data[2..]);
            let suite = CipherSuite::from(value);
            let count = u16::unpack_unchecked(&data[6..]);
            let (used, values) = unpack_vec::<u32>(&data[8..], count as usize)?;
            let mut offset = 8 + used;
            let ciphers = values.into_iter().map(CipherSuite::from).collect();
            let (used, count) = u16::unpack_with_size(&data[offset..])?;
            offset += used;
            let (used, values) = unpack_vec::<u32>(&data[offset..], count as usize)?;
            offset += used;
            let akms = values
                .into_iter()
                .map(AuthenticationKeyManagement::from)
                .collect();
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
        Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid RSN element").into())
    }
    /// Get the protected management frame mode of the robust security network element
    pub fn pmf_mode(&self) -> ProtectedManagementFramesMode {
        if self.capabilities.intersects(RsnCapabilities::PMF_REQUIRED) {
            return ProtectedManagementFramesMode::Required;
        } else if self.capabilities.intersects(RsnCapabilities::PMF_CAPABLE) {
            return ProtectedManagementFramesMode::Capable;
        }
        ProtectedManagementFramesMode::Disabled
    }
}

impl fmt::Display for RobustSecurityNetwork {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Cipher Suite {} Protected Management Frames {}",
            self.cipher_suite,
            self.pmf_mode()
        )
    }
}

/// High throughput (HT) operation information element data
pub struct HighThroughputOperation {
    /// Channel width in MHz
    pub width: u32,
    /// Primary channel number
    pub primary_channel: u8,
    /// Secondary channel number
    pub secondary_channel: u8,
}

impl HighThroughputOperation {
    /// Parse high throughput operation from information element payload
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
        Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid VHT element").into())
    }
}

impl fmt::Display for HighThroughputOperation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Primary Channel {} Secondary Channel {} Bandwidth {}",
            self.primary_channel, self.secondary_channel, self.width
        )
    }
}

/// Maximum VHT MCS supported by a spatial stream
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MaxVhtMcs {
    /// Support for VHT-MCS 0 - 7 for spatial stream n
    VhtMcs0to7 = 0,
    /// Support for VHT-MCS 0 - 8 for spatial stream n
    VhtMcs0to8 = 1,
    /// Support for VHT-MCS 0 - 9 for spatial stream n
    VhtMcs0to9 = 2,
    /// Spatial stream not supported
    NotSupported = 3,
}

impl From<u8> for MaxVhtMcs {
    fn from(v: u8) -> Self {
        match v {
            0 => MaxVhtMcs::VhtMcs0to7,
            1 => MaxVhtMcs::VhtMcs0to8,
            2 => MaxVhtMcs::VhtMcs0to9,
            _ => MaxVhtMcs::NotSupported,
        }
    }
}

/// Very high throughput (VHT) operation information element data
pub struct VeryHighThroughputOperation {
    /// Channel width in MHx
    pub width: u32,
    /// Channel number
    pub channel: u8,
    /// Secondary channel number
    pub secondary_channel: u8,
    /// Maxumum very high throughput modulation and coding scheme (VHT-MCS) for each spatial stream (SS)
    pub max_vht_mcs_ss: [MaxVhtMcs; 8],
}

impl VeryHighThroughputOperation {
    /// Parse very high throughput operation from information element payload
    pub fn parse(data: &[u8]) -> Result<VeryHighThroughputOperation, Error> {
        if data.len() == 5 {
            let width = match data[0] & 0x03 {
                1 => 80,
                2 => 160,
                3 => 80,
                _ => 40,
            };
            let mut max_vht_mcs_ss = [MaxVhtMcs::NotSupported; 8];
            max_vht_mcs_ss[0] = MaxVhtMcs::from((data[3] & 0b0000_0011) >> 0);
            max_vht_mcs_ss[1] = MaxVhtMcs::from((data[3] & 0b0000_1100) >> 2);
            max_vht_mcs_ss[2] = MaxVhtMcs::from((data[3] & 0b0011_0000) >> 4);
            max_vht_mcs_ss[3] = MaxVhtMcs::from((data[3] & 0b1100_0000) >> 6);
            max_vht_mcs_ss[4] = MaxVhtMcs::from((data[4] & 0b0000_0011) >> 0);
            max_vht_mcs_ss[5] = MaxVhtMcs::from((data[4] & 0b0000_1100) >> 2);
            max_vht_mcs_ss[6] = MaxVhtMcs::from((data[4] & 0b0011_0000) >> 4);
            max_vht_mcs_ss[7] = MaxVhtMcs::from((data[4] & 0b1100_0000) >> 6);
            return Ok(VeryHighThroughputOperation {
                width,
                channel: data[1],
                secondary_channel: data[2],
                max_vht_mcs_ss,
            });
        }
        Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid VHT element").into())
    }
}

impl fmt::Display for VeryHighThroughputOperation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Primary Channel {} Secondary Channel {} Bandwidth {}",
            self.channel, self.secondary_channel, self.width
        )
    }
}

/// Channel switch mode information element data
pub enum ChannelSwitchMode {
    /// No restrictions during channel switch
    NoRestriction = 0,
    /// No transmission during channel switch
    NoTransmission = 1,
}

impl From<u8> for ChannelSwitchMode {
    fn from(v: u8) -> Self {
        match v {
            1 => ChannelSwitchMode::NoTransmission,
            _ => ChannelSwitchMode::NoRestriction,
        }
    }
}

/// Channel switch announcement (CSA) information element data
pub struct ChannelSwitchAnnouncement {
    /// Channel switch mode
    pub switch_mode: ChannelSwitchMode,
    /// New channel to operate on
    pub new_channel: u8,
    /// Countdown to switch
    pub switch_count: u8,
}

impl ChannelSwitchAnnouncement {
    /// Parse channel switch announcement from information element payload
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        if data.len() == 4 {
            return Ok(ChannelSwitchAnnouncement {
                switch_mode: ChannelSwitchMode::from(data[0]),
                new_channel: data[1],
                switch_count: data[2],
            });
        }
        Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid CSA element").into())
    }
}

/// Extended channel switch (ECSA) information element data
pub struct ExtendedChannelSwitchAnnouncement {
    /// Channel switch mode
    pub switch_mode: ChannelSwitchMode,
    /// New operating class
    pub new_operating_class: u8,
    /// New channel to operate on
    pub new_channel: u8,
    /// Countdown to switch
    pub switch_count: u8,
}

impl ExtendedChannelSwitchAnnouncement {
    /// Parse extended channel switch announcement from information element payload
    pub fn parse(data: &[u8]) -> Result<ExtendedChannelSwitchAnnouncement, Error> {
        if data.len() == 4 {
            return Ok(ExtendedChannelSwitchAnnouncement {
                switch_mode: ChannelSwitchMode::from(data[0]),
                new_operating_class: data[1],
                new_channel: data[2],
                switch_count: data[3],
            });
        }
        Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid ECSA element").into())
    }
}

/// Country information element data
pub struct Country {
    /// Country code as ISO-3166 alpha-2
    pub alpha2: String,
}

impl Country {
    /// Parse country from information element payload
    pub fn parse(data: &[u8]) -> Result<Country, Error> {
        if data.len() >= 6 {
            let alpha2 = String::from_utf8(data[..2].to_vec()).unwrap();
            return Ok(Country { alpha2 });
        }
        println!("Bad country element {}", data.len());
        Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid Country element").into())
    }
}

/// Information element with processed payload
pub enum InformationElement<'a> {
    /// SSID information element
    Ssid(Ssid),
    /// Country information element
    Country(Country),
    /// Channel switsh announcement information element
    ChannelSwitchAnnouncement(ChannelSwitchAnnouncement),
    /// Robust security network information element
    RobustSecurityNetwork(RobustSecurityNetwork),
    /// Extended channel switsh announcement information element
    ExtendedChannelSwitchAnnouncement(ExtendedChannelSwitchAnnouncement),
    /// High throughput operation information element
    HighThroughputOperation(HighThroughputOperation),
    /// Very high throughput operation information element
    VeryHighThroughputOperation(VeryHighThroughputOperation),
    /// Unprocessed information element
    Other(RawInformationElement<'a>),
}

impl<'a> InformationElement<'a> {
    /// Parse byte slice into information element
    pub fn parse(data: &'a [u8]) -> Result<InformationElement<'a>, Error> {
        let raw = RawInformationElement::parse(data)?;
        if let Some(id) = raw.ie_id() {
            return Self::from(id, raw.data);
        } else {
            return Ok(InformationElement::Other(raw));
        }
    }

    ///  Parse identifier and payload into information element
    pub fn from(id: InformationElementId, data: &'a [u8]) -> Result<InformationElement<'a>, Error> {
        let ie = match id {
            InformationElementId::Ssid => {
                let ie = Ssid::parse(data)?;
                InformationElement::Ssid(ie)
            }
            InformationElementId::Country => {
                let ie = Country::parse(data)?;
                InformationElement::Country(ie)
            }
            InformationElementId::ChannelSwitchAnnouncement => {
                let ie = ChannelSwitchAnnouncement::parse(data)?;
                InformationElement::ChannelSwitchAnnouncement(ie)
            }
            InformationElementId::RobustSecurityNetwork => {
                let ie = RobustSecurityNetwork::parse(data)?;
                InformationElement::RobustSecurityNetwork(ie)
            }
            InformationElementId::ExtendedChannelSwitchAnnouncement => {
                let ie = ExtendedChannelSwitchAnnouncement::parse(data)?;
                InformationElement::ExtendedChannelSwitchAnnouncement(ie)
            }
            InformationElementId::HighThroughputOperation => {
                let ie = HighThroughputOperation::parse(data)?;
                InformationElement::HighThroughputOperation(ie)
            }
            InformationElementId::VeryHighThroughputOperation => {
                let ie = VeryHighThroughputOperation::parse(data)?;
                InformationElement::VeryHighThroughputOperation(ie)
            }
            _ => InformationElement::Other(RawInformationElement {
                identifier: id.into(),
                data,
            }),
        };
        Ok(ie)
    }
    /// Get identifier for information element
    pub fn identifier(&self) -> Option<InformationElementId> {
        let id = match *self {
            InformationElement::Ssid(_) => InformationElementId::Ssid,
            InformationElement::Country(_) => InformationElementId::Country,
            InformationElement::ChannelSwitchAnnouncement(_) => {
                InformationElementId::ChannelSwitchAnnouncement
            }
            InformationElement::RobustSecurityNetwork(_) => {
                InformationElementId::RobustSecurityNetwork
            }
            InformationElement::ExtendedChannelSwitchAnnouncement(_) => {
                InformationElementId::ExtendedChannelSwitchAnnouncement
            }
            InformationElement::HighThroughputOperation(_) => {
                InformationElementId::HighThroughputOperation
            }
            InformationElement::VeryHighThroughputOperation(_) => {
                InformationElementId::VeryHighThroughputOperation
            }
            InformationElement::Other(ref ie) => InformationElementId::from(ie.identifier),
        };
        Some(id)
    }
    /// Parse sloce into a vector of information elements
    pub fn parse_all(data: &'a [u8]) -> Result<Vec<InformationElement<'a>>, Error> {
        let mut ies = vec![];
        let mut slice = data;
        while let Ok(raw) = RawInformationElement::parse(slice) {
            slice = &slice[raw.data.len() + 2..];
            let id = InformationElementId::convert_from(raw.identifier);
            let ie = if let Some(id) = id {
                Self::from(id, raw.data)?
            } else {
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
            48, 6, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 4, 0, 1, 2, 0x55, 0xaa,
        ];
        let ies = InformationElements::parse(&bytes);
        assert_eq!(ies.elements.len(), 3);
    }
}
