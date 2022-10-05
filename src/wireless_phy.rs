use super::join_to_string;
use crate::attributes::{self, Attribute, InterfaceType};
use crate::commands::Command;
use crate::information_element::CipherSuite;
use netlink_rust as netlink;
use netlink_rust::generic;
use netlink_rust::{ConvertFrom, Error, NativeUnpack};
use std::fmt;
use std::io;

#[allow(dead_code)]
fn show_slice(slice: &[u8]) {
    print!("{} bytes\n", slice.len());
    for byte in slice.iter() {
        print!("{:02X} ", byte);
    }
    print!("\n");
}

pub struct WirelessPhy {
    identifier: u32,
    name: String,
    commands: Vec<Command>,
    if_types: InterfaceTypeFlags,
    software_if_types: InterfaceTypeFlags,
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

// This is the same as attributes::InterfaceType but as bit flags
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
        use crate::InterfaceType::*;
        match value {
            Unspecified => InterfaceTypeFlags::UNSPECIFIED,
            Adhoc => InterfaceTypeFlags::ADHOC,
            Station => InterfaceTypeFlags::STATION,
            Ap => InterfaceTypeFlags::AP,
            ApVlan => InterfaceTypeFlags::AP_VLAN,
            Wds => InterfaceTypeFlags::WDS,
            Monitor => InterfaceTypeFlags::MONITOR,
            MeshPoint => InterfaceTypeFlags::MESHPOINT,
            P2pClient => InterfaceTypeFlags::P2P_CLIENT,
            P2pGo => InterfaceTypeFlags::P2P_GO,
            P2pDevice => InterfaceTypeFlags::P2P_DEVICE,
            Ocb => InterfaceTypeFlags::OCB,
            Nan => InterfaceTypeFlags::NAN,
        }
    }
}

bitflags! {
    pub struct ExtendedFeaturesFlags: u64 {
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
        const LOW_SPAN_SCAN                      = 1 << 22;
        const LOW_POWER_SCAN                     = 1 << 23;
        const HIGH_ACCURACY_SCAN                 = 1 << 24;
        const DFS_OFFLOAD                        = 1 << 25;
        const CONTROL_PORT_OVER_NL80211          = 1 << 26;
        const DATA_ACK_SIGNAL_SUPPORT            = 1 << 27;
        const TXQS                               = 1 << 28;
        const SCAN_RANDOM_SN                     = 1 << 29;
        const SCAN_MIN_PREQ_CONTENT              = 1 << 30;
        const CAN_REPLACE_PTK0                   = 1 << 31;
        const ENABLE_FTM_RESPONDER               = 1 << 32;
    }
}

impl WirelessPhy {
    pub fn from_attributes(attributes: &[netlink::Attribute]) -> Result<WirelessPhy, Error> {
        let mut phy_id = None;
        let mut commands = vec![];
        let mut phy_name = String::new();
        let mut if_types = InterfaceTypeFlags::empty();
        let mut software_if_types = InterfaceTypeFlags::empty();
        for attr in attributes {
            let identifier = Attribute::convert_from(attr.identifier);
            if let Some(identifier) = identifier {
                match identifier {
                    Attribute::Wiphy => {
                        phy_id = Some(attr.as_u32()?);
                    }
                    Attribute::WiphyName => {
                        if let Ok(name) = attr.as_string() {
                            phy_name = name;
                        }
                    }
                    Attribute::Generation => (),
                    Attribute::RoamSupport
                    | Attribute::TdlsSupport
                    | Attribute::OffchannelTxOk
                    | Attribute::SupportIbssRsn
                    | Attribute::ControlPortEthertype
                    | Attribute::SupportApUapsd
                    | Attribute::TdlsExternalSetup
                    | Attribute::WiphySelfManagedReg => {
                        if attr.len() != 0 {
                            println!(
                                "[{:?}] {:?} {} Invalid type",
                                phy_id,
                                identifier,
                                attr.len()
                            );
                        }
                    }
                    Attribute::MaxNumScanSsids
                    | Attribute::MaxNumSchedScanSsids
                    | Attribute::MaxMatchSets
                    | Attribute::WiphyRetryShort
                    | Attribute::WiphyRetryLong
                    | Attribute::MaxNumPmkids
                    | Attribute::WiphyCoverageClass
                    | Attribute::MaxCsaCounters => {
                        if attr.as_u8().is_err() {
                            println!(
                                "[{:?}] {:?} {} Invalid type",
                                phy_id,
                                identifier,
                                attr.len()
                            );
                        }
                    }
                    Attribute::MaxScanIeLen
                    | Attribute::MaxSchedScanIeLen
                    | Attribute::MacAclMax
                    | Attribute::MaxRemainOnChannelDuration => {
                        if attr.as_u16().is_err() {
                            println!(
                                "[{:?}] {:?} {} Invalid type",
                                phy_id,
                                identifier,
                                attr.len()
                            );
                        }
                    }
                    Attribute::Bands
                    | Attribute::MaxNumSchedScanPlans
                    | Attribute::MaxScanPlanInterval
                    | Attribute::MaxScanPlanIterations
                    | Attribute::WiphyFragThreshold
                    | Attribute::WiphyRtsThreshold
                    | Attribute::WiphyAntennaAvailTx
                    | Attribute::WiphyAntennaAvailRx
                    | Attribute::DeviceApSme
                    | Attribute::TransmitQueueLimit
                    | Attribute::TransmitQueueMemoryLimit
                    | Attribute::TransmitQueueSchedulerBytes
                    | Attribute::SchedScanMaxReqs => {
                        if attr.as_u32().is_err() {
                            println!(
                                "[{:?}] {:?} {} Invalid type",
                                phy_id,
                                identifier,
                                attr.len()
                            );
                        }
                    }
                    Attribute::ExtFeatures => {
                        let mut flags = 0u64;
                        if attr.len() >= 1 {
                            for b in attr.as_bytes() {
                                flags <<= 8;
                                flags |= u64::from(b);
                            }
                        }
                        let extended_features = ExtendedFeaturesFlags::from_bits_truncate(flags);
                        println!(
                            "[{:?}] {:?} LEN: {} {:#x} {:?}",
                            phy_id,
                            identifier,
                            attr.len(),
                            flags,
                            extended_features
                        );
                    }
                    Attribute::SoftwareIftypes => {
                        if let Ok(v) = attr.as_u32() {
                            software_if_types = InterfaceTypeFlags::from_bits_truncate(v);
                        }
                    }
                    Attribute::SupportedIftypes => {
                        let (_, attrs) = netlink::Attribute::unpack_all(&attr.as_bytes());
                        let mut flags = InterfaceTypeFlags::empty();
                        for attr in attrs {
                            if let Some(it) =
                                InterfaceType::convert_from(u32::from(attr.identifier))
                            {
                                let itf = InterfaceTypeFlags::from(it);
                                flags |= itf;
                            }
                        }
                        if_types = flags;
                    }
                    Attribute::FeatureFlags => {
                        let ff = FeatureFlags::from_bits_truncate(attr.as_u32()?);
                        println!(
                            "[{:?}] {:?} LEN: {} {:?}",
                            phy_id,
                            identifier,
                            attr.len(),
                            ff
                        );
                    }
                    Attribute::CipherSuites => {
                        let values = Vec::<u32>::unpack(&attr.as_bytes())?;
                        let _ciphers: Vec<CipherSuite> = values
                            .into_iter()
                            .map(u32::to_be)
                            .map(CipherSuite::from)
                            .collect();
                    }
                    Attribute::SupportedCommands => {
                        let (_, attrs) = netlink::Attribute::unpack_all(&attr.as_bytes());
                        for attr in attrs {
                            if let Some(cmd) = Command::convert_from(attr.as_u32()? as u8) {
                                commands.push(cmd);
                            }
                        }
                    }
                    Attribute::BssSelect => { /* TODO: Parse BssSelect */ }
                    Attribute::ExtCapa => { /* TODO: Parse ExtCapa */ }
                    Attribute::ExtCapaMask => { /* TODO: Parse ExtCapaMask */ }
                    Attribute::HtCapabilityMask => {
                        println!("[{:?}] {:?} LEN: {}", phy_id, identifier, attr.len());
                        /* TODO: Parse HtCapabilityMask */
                    }
                    Attribute::VhtCapabilityMask => {
                        println!("[{:?}] {:?} LEN: {}", phy_id, identifier, attr.len());
                        /* TODO: Parse VhtCapabilityMask */
                    }
                    Attribute::WiphyBands => {
                        for band_attrs in netlink::nested_attribute_array(&attr.as_bytes()) {
                            for band_attr in band_attrs {
                                let band_id =
                                    attributes::BandAttributes::convert_from(band_attr.identifier);
                                if let Some(id) = band_id {
                                    let data = band_attr.as_bytes();
                                    match id {
                                        attributes::BandAttributes::HtMcsSet => {
                                            for (n, b) in data[0..10].iter().enumerate() {
                                                println!("{:02x} {}", b, n);
                                                for m in 0..7 {
                                                    let i = n * 8 + m;
                                                    let mask = 1u8 << m;
                                                    if b & mask == mask {
                                                        println!(" MSC{}", i);
                                                    } else {
                                                        println!("!MSC{}", i);
                                                    }
                                                }
                                            }
                                        }
                                        attributes::BandAttributes::Frequencies => {
                                            for freq_attrs in netlink::nested_attribute_array(&data)
                                            {
                                                for freq_attr in freq_attrs {
                                                    if let Some(id) =
                                                        attributes::FrequencyAttribute::convert_from(
                                                            freq_attr.identifier,
                                                        )
                                                    {
                                                        match id {
                                                            attributes::FrequencyAttribute::Frequency => {
                                                                let frequency = match freq_attr.as_u32() { Ok(f) => f, Err(_) => 0 };
                                                                println!("{} {} MHz", id, frequency);
                                                            }
                                                            attributes::FrequencyAttribute::TransmissionPower => {
                                                                let power = match freq_attr.as_u32() { Ok(p) => p, Err(_) => 0 };
                                                                let power = f64::from(power) / 100.0;
                                                                println!("{} {} dBm", id, power);
                                                            }
                                                            _ => {
                                                                println!("{:04x} {} {}", freq_attr.identifier, id, freq_attr.len());
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        attributes::BandAttributes::Rates => {
                                            for rate_attrs in netlink::nested_attribute_array(&data)
                                            {
                                                for rate_attr in rate_attrs {
                                                    match rate_attr.identifier {
                                                        1 => {
                                                            let rate = match rate_attr.as_u32() {
                                                                Ok(f) => f,
                                                                Err(_) => 0,
                                                            };
                                                            let rate = u64::from(rate) * 100;
                                                            println!("{} Khz", rate);
                                                        }
                                                        2 => {
                                                            println!("Short preamble");
                                                        }
                                                        _ => {
                                                            println!(
                                                                "{:04x} {}",
                                                                rate_attr.identifier,
                                                                rate_attr.len()
                                                            );
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        _ => {
                                            println!("Wiphy band {:?} LEN {}", id, band_attr.len());
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Attribute::WowlanTriggersSupported => {
                        /* TODO: Parse WowlanTriggersSupported */
                    }
                    Attribute::TxFrameTypes => { /* TODO: Parse TxFrameTypes */ }
                    Attribute::RxFrameTypes => { /* TODO: Parse RxFrameTypes */ }
                    Attribute::InterfaceCombinations => { /* TODO: Parse InterfaceCombinations */ }
                    Attribute::VendorData => { /* TODO: Parse VendorData */ }
                    Attribute::VendorEvents => { /* TODO: Parse VendorEvents */ }
                    Attribute::TransmitQueueStatistics => {
                        /* TODO: Parse TransmitQueueStatistics */
                    }
                    _ => {
                        println!("[{:?}] {:?} LEN: {}", phy_id, identifier, attr.len());
                    }
                }
            } else {
                println!("Unknown identifier {}", attr.identifier);
            }
        }
        if phy_id.is_some() {
            Ok(WirelessPhy {
                identifier: phy_id.unwrap(),
                name: phy_name,
                commands,
                if_types,
                software_if_types,
            })
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "Wireless Phy Not Found").into())
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
        let commands = join_to_string(self.commands.iter(), " | ");
        write!(
            f,
            "Wireless Phy\n  Identifier: {}\n  Name: {}\n  Commands: {}\n\
             Interfaces: {:?}\n  Software Interfaces: {:?}",
            self.identifier, self.name, commands, self.if_types, self.software_if_types
        )
    }
}

pub fn get_wireless_phys(
    socket: &mut netlink::Socket,
    family_id: u16,
) -> Result<Vec<WirelessPhy>, Error> {
    {
        let tx_msg =
            generic::Message::new(family_id, Command::GetWiphy, netlink::MessageMode::Dump);
        socket.send_message(&tx_msg)?;
    }
    let mut phys = vec![];
    let mut old_phy_id = None;
    let mut attributes = Vec::new();
    let mut new_attributes = Vec::new();
    let mut more = true;

    while more {
        if let Ok(messages) = socket.receive_messages() {
            if messages.is_empty() {
                break;
            }
            for m in messages {
                if m.header.identifier == family_id {
                    let (_, gmsg) = generic::Message::unpack(&m.data)?;
                    let mut phy_id = None;
                    new_attributes.clear();
                    for attr in gmsg.attributes {
                        let identifier = Attribute::convert_from(attr.identifier);
                        match identifier {
                            Some(Attribute::Wiphy) => {
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
                                let phy = WirelessPhy::from_attributes(&attributes)?;
                                phys.push(phy);
                                attributes.clear();
                            }
                        }
                        attributes.append(&mut new_attributes);
                    }
                    old_phy_id = phy_id;
                }
            }
        } else {
            more = false;
        }
    }
    if !attributes.is_empty() {
        let phy = WirelessPhy::from_attributes(&attributes)?;
        phys.push(phy);
    }
    Ok(phys)
}
