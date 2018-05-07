
use std::io::Read;
use std::io;
use netlink::{NativeRead, Error};

pub struct InformationElement
{
    pub identifier: u8,
    pub data: Vec<u8>,
}

impl InformationElement {
    pub fn parse<R: Read>(reader: &mut R) -> Result<InformationElement, Error> {
        let identifier = u8::read(reader)?;
        let length = u8::read(reader)? as usize;
        let mut data = vec![0u8; length];
        reader.read_exact(&mut data)?;
        Ok(InformationElement { identifier: identifier, data: data })
    }
}

pub struct InformationElements
{
    pub elements: Vec<InformationElement>,
}

impl InformationElements {
    pub fn parse<R: Read>(reader: &mut R) -> InformationElements {
        let mut elements = vec![];
        loop {
            match InformationElement::parse(reader) {
                Ok(ie) => elements.push(ie),
                Err(_) => break,
            }
        }
        InformationElements {
            elements: elements,
        }
    }
}

#[derive(Debug)]
enum CipherSuite {
    UseGroupCipherSuite,
    WEP40, // 
    TKIP, // Temporal Key Integrity Protocol
    CCMP,
    WEP104,
    BIP,
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
                1 => CipherSuite::WEP40,
                2 => CipherSuite::TKIP,
                4 => CipherSuite::CCMP,
                5 => CipherSuite::WEP104,
                6 => CipherSuite::BIP,
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
            CipherSuite::WEP40 => 0x01ac0f00,
            CipherSuite::TKIP => 0x02ac0f00,
            CipherSuite::CCMP => 0x04ac0f00,
            CipherSuite::WEP104 => 0x05ac0f00,
            CipherSuite::BIP => 0x06ac0f00,
            CipherSuite::GroupAddressedTrafficNotAllowed => 0x07ac0f00,
            CipherSuite::Reserved(v) => 0x00ac0f00 | (v as u32) << 24,
            CipherSuite::Vendor(v) => v,
        }
    }
}

#[derive(Debug)]
enum AuthenticationKeyManagement {
    PMKSA,
    PSK, 
    FT8021X,
    FTPSK,
    PMSKASHA256,
    PSKSHA256,
    TDLS,
    SAE,
    FTSAE,
    Reserved(u8),
    Vendor(u32),
}

impl From<u32> for AuthenticationKeyManagement {
    fn from(v: u32) -> Self {
        if v & 0x00ffffff == 0x00ac0f00 {
            let c = (v >> 24) as u8;
            match c {
                1 => AuthenticationKeyManagement::PMKSA,
                2 => AuthenticationKeyManagement::PSK,
                3 => AuthenticationKeyManagement::FT8021X,
                4 => AuthenticationKeyManagement::FTPSK,
                5 => AuthenticationKeyManagement::PMSKASHA256,
                6 => AuthenticationKeyManagement::PSKSHA256,
                7 => AuthenticationKeyManagement::TDLS,
                8 => AuthenticationKeyManagement::SAE,
                9 => AuthenticationKeyManagement::FTSAE,
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
            AuthenticationKeyManagement::PMKSA => 0x01ac0f00,
            AuthenticationKeyManagement::PSK => 0x02ac0f00,
            AuthenticationKeyManagement::FT8021X => 0x03ac0f00,
            AuthenticationKeyManagement::FTPSK => 0x04ac0f00,
            AuthenticationKeyManagement::PMSKASHA256 => 0x05ac0f00,
            AuthenticationKeyManagement::PSKSHA256 => 0x06ac0f00,
            AuthenticationKeyManagement::TDLS => 0x07ac0f00,
            AuthenticationKeyManagement::SAE => 0x08ac0f00,
            AuthenticationKeyManagement::FTSAE => 0x09ac0f00,
            AuthenticationKeyManagement::Reserved(v) => 0x00ac0f00 | (v as u32) << 24,
            AuthenticationKeyManagement::Vendor(v) => v,
        }
    }
}


bitflags! {
    pub struct RsnCapabilities: u16 {
        const PREAUTHENTICATION = 0x0001;
        const NO_PAIRWISE = 0x0002;
        const MPF_REQUIRED = 0x0040;
        const MPF_CAPABLE = 0x0080;
        const PEER_KEY_ENABLED = 0x0200;
        const SPP_AMSDU_CAPABLE = 0x0400;
        const SPP_AMSDU_REQUIRED = 0x0800;
        const PBAC = 0x1000;
        const EXTENDED_KEY_ID = 0x2000;
    }
}

#[derive(Debug)]
pub struct RobustSecurityNetwork {
    version: u16,
    cipher_suite: CipherSuite,
    ciphers: Vec<CipherSuite>,
    akms: Vec<AuthenticationKeyManagement>,
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
        panic!("Bad Data");
    }
}
