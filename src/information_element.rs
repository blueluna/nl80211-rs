
use std::io::Read;
use std::io;
use std::fmt;
use netlink_rust::{NativeRead, Error};

/// Raw Information Element data
pub struct RawInformationElement
{
    pub identifier: u8,
    pub data: Vec<u8>,
}

impl RawInformationElement {
    pub fn parse<R: Read>(reader: &mut R) -> Result<RawInformationElement, Error> {
        let identifier = u8::read(reader)?;
        let length = u8::read(reader)? as usize;
        let mut data = vec![0u8; length];
        reader.read_exact(&mut data)?;
        Ok(RawInformationElement { identifier: identifier, data: data })
    }
}

pub struct InformationElements
{
    pub elements: Vec<RawInformationElement>,
}

impl InformationElements {
    pub fn parse<R: Read>(reader: &mut R) -> InformationElements {
        let mut elements = vec![];
        loop {
            match RawInformationElement::parse(reader) {
                Ok(ie) => elements.push(ie),
                Err(_) => break,
            }
        }
        InformationElements {
            elements: elements,
        }
    }
}

#[derive(Debug, PartialEq)]
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

#[derive(Debug, PartialEq)]
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
    pub fn from_bytes(data: &[u8]) -> Result<RobustSecurityNetwork, Error> {
        if data.len() > 12 {
            let mut reader = io::Cursor::new(data);
            let version = u16::read(&mut reader)?;
            let value = u32::read(&mut reader)?;
            let suite = CipherSuite::from(value);
            let count = u16::read(&mut reader)?;
            let mut ciphers = vec![];
            for _ in 0..count {
                let value = u32::read(&mut reader)?;
                ciphers.push(CipherSuite::from(value));
            }
            let count = u16::read(&mut reader)?;
            let mut akms = vec![];
            for _ in 0..count {
                let value = u32::read(&mut reader)?;
                akms.push(AuthenticationKeyManagement::from(value));
            }
            let count = u16::read(&mut reader)?;
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
	    return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid RSN element").into());
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
