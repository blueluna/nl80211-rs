use std::io;
use std::fmt;
use netlink_rust as netlink;
use netlink_rust::{Error, ConvertFrom};
// use netlink_rust::NativeUnpack;
use netlink_rust::generic;
// use attributes;
use attributes::{Attribute};
use commands::Command;

pub struct WirelessPhy {
    identifier: u32,
    name: String,
    commands: Vec<Command>,
}

bitflags! {
    pub struct FeatureFlags: u32 {
	    const SK_TX_STATUS = 1 << 0;
        const HT_IBSS				= 1 << 1;
        const INACTIVITY_TIMER		= 1 << 2;
        const CELL_BASE_REG_HINTS		= 1 << 3;
        const P2P_DEVICE_NEEDS_CHANNEL	= 1 << 4;
        const SAE				= 1 << 5;
        const LOW_PRIORITY_SCAN		= 1 << 6;
        const SCAN_FLUSH			= 1 << 7;
        const AP_SCAN				= 1 << 8;
        const VIF_TXPOWER			= 1 << 9;
        const NEED_OBSS_SCAN			= 1 << 10;
        const P2P_GO_CTWIN			= 1 << 11;
        const P2P_GO_OPPPS			= 1 << 12;
        /* bit 13 is reserved */
        const ADVERTISE_CHAN_LIMITS		= 1 << 14;
        const FULL_AP_CLIENT_STATE		= 1 << 15;
        const USERSPACE_MPM			= 1 << 16;
        const ACTIVE_MONITOR			= 1 << 17;
        const AP_MODE_CHAN_WIDTH_CHANGE	= 1 << 18;
        const DS_PARAM_SET_IE_IN_PROBES	= 1 << 19;
        const WFA_TPC_IE_IN_PROBES		= 1 << 20;
        const QUIET				= 1 << 21;
        const TX_POWER_INSERTION		= 1 << 22;
        const ACKTO_ESTIMATION		= 1 << 23;
        const STATIC_SMPS			= 1 << 24;
        const DYNAMIC_SMPS			= 1 << 25;
        const SUPPORTS_WMM_ADMISSION		= 1 << 26;
        const MAC_ON_CREATE			= 1 << 27;
        const TDLS_CHANNEL_SWITCH		= 1 << 28;
        const SCAN_RANDOM_MAC_ADDR		= 1 << 29;
        const SCHED_SCAN_RANDOM_MAC_ADDR	= 1 << 30;
        const ND_RANDOM_MAC_ADDR		= 1 << 31;
    }
}

/// This is the same as attributes::InterfaceType but as bit flags
bitflags! {
    pub struct InterfaceTypeFlags: u32 {
	    const Unspecified = 1 << 0;
        const Adhoc = 1 << 1;
        const Station = 1 << 2;
        const Ap = 1 << 3;
        const ApVlan = 1 << 4;
        const Wds = 1 << 5;
        const Monitor = 1 << 6;
        const MeshPoint = 1 << 7;
        const P2pClient = 1 << 8;
        const P2pGo = 1 << 9;
        const P2pDevice = 1 << 10;
        const Ocb = 1 << 11;
        const Nan = 1 << 12;
    }
}

impl WirelessPhy {
    pub fn from_message(message: generic::Message)
        -> Result<WirelessPhy, Error>
    {
        let mut phy_id = None;
        let mut commands = vec![];
        let mut phy_name = String::new();
        for attr in message.attributes {
            let identifier = Attribute::from(attr.identifier);
            match identifier {
                Attribute::Wiphy => {
                    phy_id = Some(attr.as_u32()?);
                }
                Attribute::WiphyName => {
                    if let Ok(name) = attr.as_string() {
                        phy_name = name;
                    }
                }
                Attribute::SupportedCommands => {
                    let (_, attrs) = netlink::Attribute::unpack_all(
                        &attr.as_bytes());
                    for attr in attrs {
                        if let Some(cmd) =
                            Command::convert_from(attr.as_u32()? as u8) {
                            commands.push(cmd);
                        }
                    }
                }
                _ => {
                    println!("Skipping {:?} {}", identifier, attr.len());
                },
            }
        }
        if phy_id.is_some() {
            Ok(WirelessPhy{
                identifier: phy_id.unwrap(),
                name: phy_name,
                commands,
            })
        }
        else {
            Err(io::Error::new(io::ErrorKind::NotFound,
                "Wireless Phy Not Found").into())
        }
    }
    pub fn from_attributes(attributes: &Vec<netlink_rust::Attribute>)
        -> Result<WirelessPhy, Error>
    {
        let mut phy_id = None;
        let mut commands = vec![];
        let mut phy_name = String::new();
        for attr in attributes {
            let identifier = Attribute::from(attr.identifier);
            match identifier {
                Attribute::Generation => (),
                Attribute::MaxNumScanSsids => {
                    println!("[{:?}] {:?} {}", phy_id, identifier, attr.as_u8()?);
                }
                Attribute::MaxScanIeLen | Attribute::MaxSchedScanIeLen => {
                    println!("[{:?}] {:?} {}", phy_id, identifier, attr.as_u16()?);
                }
                Attribute::Bands | Attribute::ExtFeatures => {
                    println!("[{:?}] {:?} {}", phy_id, identifier, attr.as_u32()?);
                }
                Attribute::SoftwareIftypes => {
                    let it = InterfaceTypeFlags::from_bits_truncate(attr.as_u32()?);
                    println!("[{:?}] {:?} {:?}", phy_id, identifier, it);
                }
                /*
                Attribute::SupportedIftypes => {
                    let num = attr.len() / 4;
                    let bytes = attr.as_bytes();
                    for n in 0..num {
                        let offset = (n * 4) as usize;
                        let it = u32::unpack(&bytes[offset..])?;
                        println!("[{:?}] {:?} {:08x}", phy_id, identifier, it);
                        let it = InterfaceTypeFlags::from_bits_truncate(it);
                        println!("[{:?}] {:?} {:?}", phy_id, identifier, it);
                    }
                }
                */
                Attribute::FeatureFlags => {
                    let ff = FeatureFlags::from_bits_truncate(attr.as_u32()?);
                    println!("[{:?}] {:?} {:?}", phy_id, identifier, ff);
                }
                Attribute::Wiphy => {
                    phy_id = Some(attr.as_u32()?);
                }
                Attribute::WiphyName => {
                    if let Ok(name) = attr.as_string() {
                        phy_name = name;
                    }
                }
                Attribute::SupportedCommands => {
                    let (_, attrs) = netlink::Attribute::unpack_all(
                        &attr.as_bytes());
                    for attr in attrs {
                        if let Some(cmd) =
                            Command::convert_from(attr.as_u32()? as u8) {
                            commands.push(cmd);
                        }
                    }
                }
                _ => (),
            }
        }
        if phy_id.is_some() {
            Ok(WirelessPhy{
                identifier: phy_id.unwrap(),
                name: phy_name,
                commands,
            })
        }
        else {
            Err(io::Error::new(io::ErrorKind::NotFound,
                "Wireless Phy Not Found").into())
        }
    }
}

impl PartialEq for WirelessPhy {
    fn eq(&self, other: &WirelessPhy) -> bool {
        self.identifier == other.identifier
    }
}

impl fmt::Display for WirelessPhy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
            "Wireless Phy\n  Identifier: {}\n  Name: {}\n  Commands: {:?}",
            self.identifier, self.name, self.commands)

    }
}

pub fn get_wireless_phys(socket: &mut netlink::Socket, family_id: u16)
    -> Result<Vec<WirelessPhy>, Error>
{
    {
        let tx_msg = generic::Message::new(family_id, Command::GetWiphy,
            netlink::MessageMode::Dump);
        socket.send_message(&tx_msg)?;
    }
    let mut phys = vec![];
    let mut old_phy_id = None;
    let mut attributes = Vec::new();
    let mut new_attributes = Vec::new();
    let mut more = true;

    while more {
        if let Ok(messages) = socket.receive_messages() {
            if messages.is_empty() { break; }
            for m in messages {
                if m.header.identifier == family_id {
                    let (_, gmsg) = generic::Message::unpack(&m.data)?;
                    let mut phy_id = None;
                    new_attributes.clear();
                    for attr in gmsg.attributes {
                        let identifier = Attribute::from(attr.identifier);
                        match identifier {
                            Attribute::Wiphy => {
                                phy_id = Some(attr.as_u32()?);
                                new_attributes.push(attr);
                            }
                            _ => {
                                new_attributes.push(attr);
                            }
                        }
                    }
                    if let Some(id) = phy_id {
                        if let Some(old_id) = old_phy_id {
                            if old_id != id {
                                if let Ok(phy) = WirelessPhy::from_attributes(&attributes) {
                                    phys.push(phy)
                                }
                                attributes.clear();
                            }
                        }
                        attributes.append(&mut new_attributes);
                    }
                    old_phy_id = phy_id;
                }
            }
        }
        else {
            more = false;
        }
    }
    if let Ok(phy) = WirelessPhy::from_attributes(&attributes) {
        phys.push(phy)
    }
    Ok(phys)
}