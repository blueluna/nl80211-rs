use std::io;
use std::fmt;
use netlink_rust as netlink;
use netlink_rust::{Error, ConvertFrom, NativeUnpack};
use netlink_rust::generic;
use attributes::{Attribute, InterfaceType};
use information_element::CipherSuite;
use commands::Command;

pub struct WirelessPhy {
    identifier: u32,
    name: String,
    commands: Vec<Command>,
}

bitflags! {
    pub struct FeatureFlags: u32 {
        const SK_TX_STATUS               = 1 << 0;
        const HT_IBSS                    = 1 << 1;
        const INACTIVITY_TIMER           = 1 << 2;
        const CELL_BASE_REG_HINTS        = 1 << 3;
        const P2P_DEVICE_NEEDS_CHANNEL   = 1 << 4;
        const SAE                        = 1 << 5;
        const LOW_PRIORITY_SCAN          = 1 << 6;
        const SCAN_FLUSH                 = 1 << 7;
        const AP_SCAN                    = 1 << 8;
        const VIF_TXPOWER                = 1 << 9;
        const NEED_OBSS_SCAN             = 1 << 10;
        const P2P_GO_CTWIN               = 1 << 11;
        const P2P_GO_OPPPS               = 1 << 12;
        /* bit 13 is reserved */
        const ADVERTISE_CHAN_LIMITS      = 1 << 14;
        const FULL_AP_CLIENT_STATE       = 1 << 15;
        const USERSPACE_MPM              = 1 << 16;
        const ACTIVE_MONITOR             = 1 << 17;
        const AP_MODE_CHAN_WIDTH_CHANGE  = 1 << 18;
        const DS_PARAM_SET_IE_IN_PROBES  = 1 << 19;
        const WFA_TPC_IE_IN_PROBES       = 1 << 20;
        const QUIET                      = 1 << 21;
        const TX_POWER_INSERTION         = 1 << 22;
        const ACKTO_ESTIMATION           = 1 << 23;
        const STATIC_SMPS                = 1 << 24;
        const DYNAMIC_SMPS               = 1 << 25;
        const SUPPORTS_WMM_ADMISSION     = 1 << 26;
        const MAC_ON_CREATE              = 1 << 27;
        const TDLS_CHANNEL_SWITCH        = 1 << 28;
        const SCAN_RANDOM_MAC_ADDR       = 1 << 29;
        const SCHED_SCAN_RANDOM_MAC_ADDR = 1 << 30;
        const ND_RANDOM_MAC_ADDR         = 1 << 31;
    }
}

/// This is the same as attributes::InterfaceType but as bit flags
bitflags! {
    pub struct InterfaceTypeFlags: u32 {
        const UNSPECIFIED = 1 << 0;
        const ADHOC       = 1 << 1;
        const STATION     = 1 << 2;
        const AP          = 1 << 3;
        const AP_VLAN     = 1 << 4;
        const WDS         = 1 << 5;
        const MONITOR     = 1 << 6;
        const MESHPOINT   = 1 << 7;
        const P2P_CLIENT  = 1 << 8;
        const P2P_GO      = 1 << 9;
        const P2P_DEVICE  = 1 << 10;
        const OCB         = 1 << 11;
        const NAN         = 1 << 12;
    }
}

impl From<InterfaceType> for InterfaceTypeFlags {
    fn from(value: InterfaceType) -> InterfaceTypeFlags {
        use InterfaceType::*;
        match value {
            Unspecified => { InterfaceTypeFlags::UNSPECIFIED }
            Adhoc => { InterfaceTypeFlags::ADHOC }
            Station => { InterfaceTypeFlags::STATION }
            Ap => { InterfaceTypeFlags::AP }
            ApVlan => { InterfaceTypeFlags::AP_VLAN }
            Wds => { InterfaceTypeFlags::WDS }
            Monitor => { InterfaceTypeFlags::MONITOR }
            MeshPoint => { InterfaceTypeFlags::MESHPOINT }
            P2pClient => { InterfaceTypeFlags::P2P_CLIENT }
            P2pGo => { InterfaceTypeFlags::P2P_GO }
            P2pDevice => { InterfaceTypeFlags::P2P_DEVICE }
            Ocb => { InterfaceTypeFlags::OCB }
            Nan => { InterfaceTypeFlags::NAN }
        }
    }
}

/// This is the same as attributes::InterfaceType but as bit flags
bitflags! {
    pub struct ExtendedFeaturesFlags: u32 {
        const VHT_IBSS                           = 1 << 0;
        const RRM                                = 1 << 1;
        const MU_MIMO_AIR_SNIFFER                = 1 << 2;
        const SCAN_START_TIME                    = 1 << 3;
        const BSS_PARENT_TSF                     = 1 << 4;
        const SET_SCAN_DWELL                     = 1 << 5;
        const BEACON_RATE_LEGACY                 = 1 << 6;
        const BEACON_RATE_HT                     = 1 << 7;
        const BEACON_RATE_VHT                    = 1 << 8;
        const BEACON_FILS_STA                    = 1 << 9;
        const MGMT_TX_RANDOM_TA                  = 1 << 10;
        const MGMT_TX_RANDOM_TA_CONNECTED        = 1 << 11;
        const SCHED_SCAN_RELATIVE_RSSI           = 1 << 12;
        const CQM_RSSI_LIST                      = 1 << 13;
        const FILS_SK_OFFLOAD                    = 1 << 14;
        const FOUR_WAY_HANDSHAKE_STA_PSK         = 1 << 15;
        const FOUR_WAY_HANDSHAKE_STA_1X          = 1 << 16;
        const FILS_MAX_CHANNEL_TIME              = 1 << 17;
        const ACCEPT_BCAST_PROBE_RESP            = 1 << 18;
        const OCE_PROBE_REQ_HIGH_TX_RATE         = 1 << 19;
        const OCE_PROBE_REQ_DEFERRAL_SUPPRESSION = 1 << 20;
        const MFP_OPTIONAL                       = 1 << 21;
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
    pub fn from_attributes(attributes: &Vec<netlink::Attribute>)
        -> Result<WirelessPhy, Error>
    {
        let mut phy_id = None;
        let mut commands = vec![];
        let mut phy_name = String::new();
        for attr in attributes {
            let identifier = Attribute::from(attr.identifier);
            match identifier {
                Attribute::Generation => (),
                Attribute::RoamSupport | Attribute::TdlsSupport |
                Attribute::OffchannelTxOk => {
                    if attr.len() != 0 {
                        println!("[{:?}] {:?} {} Invalid type", phy_id,
                            identifier, attr.len());
                    }
                }
                Attribute::MaxNumScanSsids |
                Attribute::MaxNumSchedScanSsids |
                Attribute::MaxMatchSets | Attribute::WiphyRetryShort |
                Attribute::WiphyRetryLong | Attribute::MaxNumPmkids |
                Attribute::WiphyCoverageClass => {
                    if let Err(_) = attr.as_u8() {
                        println!("[{:?}] {:?} {} Invalid type", phy_id,
                            identifier, attr.len());
                    }
                }
                Attribute::MaxScanIeLen | Attribute::MaxSchedScanIeLen |
                Attribute::MacAclMax |
                Attribute::MaxRemainOnChannelDuration => {
                    if let Err(_) = attr.as_u16() {
                        println!("[{:?}] {:?} {} Invalid type", phy_id,
                            identifier, attr.len());
                    }
                }
                Attribute::Bands | Attribute::MaxNumSchedScanPlans |
                Attribute::MaxScanPlanInterval |
                Attribute::MaxScanPlanIterations |
                Attribute::WiphyFragThreshold |
                Attribute::WiphyRtsThreshold | 
                Attribute::WiphyAntennaAvailTx |
                Attribute::WiphyAntennaAvailRx |
                Attribute::DeviceApSme => {
                    if let Err(_) = attr.as_u32() {
                        println!("[{:?}] {:?} {} Invalid type", phy_id,
                            identifier, attr.len());
                    }
                }
                Attribute::ExtFeatures => {
                    assert!(attr.len() <= 4);
                    let mut flags = 0u32;
                    for b in attr.as_bytes() {
                        flags |= b as u32;
                        flags <<= 8;
                    }
                    let _flags =
                        ExtendedFeaturesFlags::from_bits_truncate(flags);
                }
                Attribute::SoftwareIftypes => {
                    if let Ok(v) = attr.as_u32() {
                        let _it = InterfaceTypeFlags::from_bits_truncate(v);
                    }
                }
                Attribute::SupportedIftypes => {
                    let (_, attrs) = netlink::Attribute::unpack_all(
                        &attr.as_bytes());
                    let mut flags = InterfaceTypeFlags::empty();
                    for attr in attrs {
                        if let Some(it) =
                            InterfaceType::convert_from(attr.identifier as u32)
                        {
                            let itf = InterfaceTypeFlags::from(it);
                            flags |= itf;
                        }
                    }
                }
                Attribute::FeatureFlags => {
                    let _ff = FeatureFlags::from_bits_truncate(attr.as_u32()?);
                }
                Attribute::CipherSuites => {
                    let values = Vec::<u32>::unpack(&attr.as_bytes())?;
                    let _ciphers: Vec<CipherSuite> = values.into_iter()
                        .map(u32::to_be).map(CipherSuite::from).collect();
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
                Attribute::BssSelect => { /* TODO: Parse BssSelect */ }
                Attribute::WiphyBands => { /* TODO: Parse WiphyBands */ }
                Attribute::WowlanTriggersSupported => { /* TODO: Parse WowlanTriggersSupported */ }
                Attribute::TxFrameTypes => { /* TODO: Parse TxFrameTypes */ }
                Attribute::RxFrameTypes => { /* TODO: Parse RxFrameTypes */ }
                Attribute::InterfaceCombinations => { /* TODO: Parse InterfaceCombinations */ }
                Attribute::VendorData => { /* TODO: Parse VendorData */ }
                Attribute::VendorEvents => { /* TODO: Parse VendorEvents */ }
                _ => {
                    println!("[{:?}] {:?} LEN: {}",
                        phy_id, identifier, attr.len());
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
                                let phy =
                                    WirelessPhy::from_attributes(&attributes)?;
                                phys.push(phy);
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
    if attributes.len() > 0 {
        let phy = WirelessPhy::from_attributes(&attributes)?;
        phys.push(phy);
    }
    Ok(phys)
}