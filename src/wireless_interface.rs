use std::fmt;
use std::io;
use netlink_rust::{Attribute, Error, HardwareAddress, MessageMode, Socket, ConvertFrom};
use netlink_rust::generic;
use attributes;
use commands::Command;
use regulatory::RegulatoryInformation;

#[derive(PartialEq)]
pub enum WirelessDeviceId
{
    None,
    InterfaceIndex(u32),
    DeviceIdentifier(u64),
}

impl fmt::Display for WirelessDeviceId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            WirelessDeviceId::None => write!(f, "None"),
            WirelessDeviceId::InterfaceIndex(i) => write!(f, "{}", i),
            WirelessDeviceId::DeviceIdentifier(i) => write!(f, "{}", i),
        }
    }
}

pub struct WirelessInterface { 
    pub family: generic::Family,
    pub phy_id: u32,
    pub interface_name: String,
    pub interface_index: u32,
    pub device_id: Option<u64>,
    pub mac: HardwareAddress,
    pub interface_type: attributes::InterfaceType,
    pub tx_power_level: u32,
    pub ssid: Option<String>,
    pub channel_width: Option<u32>,
    wireless_device_id: WirelessDeviceId,
}

impl fmt::Display for WirelessInterface {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Name: {} Index: {} Address: {} Interface Type: \"{:?}\"",
            self.interface_name, self.interface_index, self.mac,
            self.interface_type)?;
        if let Some(id) = self.device_id { write!(f, " Wireless Device Id: {}", id)?; };
        if let Some(ref ssid) = self.ssid { write!(f, " SSID: {}", ssid)?; };
        Ok(())
    }
}

impl WirelessInterface {
    pub fn from_message(message: generic::Message, family: generic::Family)
        -> Result<WirelessInterface, Error>
    {
        let mut interface_name = None;
        let mut phy_id = None;
        let mut interface_index = None;
        let mut device_id = None;
        let mut mac = None;
        let mut interface_type = attributes::InterfaceType::Unspecified;
        let mut tx_power_level = 0;
        let mut ssid = None;
        let mut channel_width = None;
        let mut wdev_id = WirelessDeviceId::None;
        for attr in message.attributes {
            let identifier = attributes::Attribute::convert_from(attr.identifier);
            if let Some(identifier) = identifier {
                match identifier {
                    attributes::Attribute::Wiphy => {
                        phy_id = Some(attr.as_u32()?);
                    }
                    attributes::Attribute::Ifindex => {
                        interface_index = Some(attr.as_u32()?);
                    }
                    attributes::Attribute::Wdev => {
                        device_id = Some(attr.as_u64()?);
                    }
                    attributes::Attribute::Ifname => {
                        interface_name = Some(attr.as_string()?);
                    }
                    attributes::Attribute::Mac => {
                        mac = Some(attr.as_hardware_address()?);
                    }
                    attributes::Attribute::Iftype => {
                        interface_type = attributes::InterfaceType::from(
                            attr.as_u32().unwrap_or(0));
                    }
                    attributes::Attribute::WiphyTxPowerLevel => {
                        tx_power_level = attr.as_u32().unwrap_or(0);
                    }
                    attributes::Attribute::Ssid => {
                        ssid = Some(attr.as_string()?);
                    }
                    attributes::Attribute::ChannelWidth => {
                        channel_width = Some(attr.as_u32()?);
                    }
                    attributes::Attribute::FourAddr => {
                        let value = attr.as_u8()?;
                        let _four_addr = match value {
                            0 => false,
                            1 => true,
                            _ => panic!("Unknown 4addr value"),
                        };
                    }
                    attributes::Attribute::CenterFreq1 => {} // u32
                    attributes::Attribute::WiphyFreq => {} // u32
                    attributes::Attribute::Generation => (), // u32
                    attributes::Attribute::WiphyChannelType => {
                        let channel_type = attr.as_u32()?;
                        let mut cw = 0;
                        match channel_type {
                            0 => { cw = 20; }, // NL80211_CHAN_NO_HT
                            1 => { cw = 20; }, // NL80211_CHAN_HT20
                            2 => { cw = 40; }, // NL80211_CHAN_HT40MINUS
                            3 => { cw = 40; }, // NL80211_CHAN_HT40PLUS
                            _ => { println!("CT: other {}", channel_type); },
                        }
                        if channel_width != None {
                            channel_width = Some(cw);
                            println!("CT: {:?}", channel_width);
                        }
                    }
                    attributes::Attribute::TransmitQueueStatistics => {
                        /* TODO: Parse TransmitQueueStatistics */
                    }
                    identifier => {
                        println!("Skipping {:?} {}", identifier, attr.len());
                    },
                }
            }
            else {
                println!("Unknown identifier {}", attr.identifier);
            }
        }
        if let Some(id) = interface_index {
            wdev_id = WirelessDeviceId::InterfaceIndex(id);
        }
        if let Some(id) = device_id {
            wdev_id = WirelessDeviceId::DeviceIdentifier(id);
        }
        if phy_id.is_some() && interface_name.is_some() && interface_index.is_some() && mac.is_some() {
            Ok(WirelessInterface{
                family,
                phy_id: phy_id.unwrap(),
                interface_name: interface_name.unwrap(),
                interface_index: interface_index.unwrap(),
                device_id,
                mac: mac.unwrap(),
                interface_type,
                tx_power_level,
                ssid,
                channel_width,
                wireless_device_id: wdev_id,
            })
        }
        else {
            Err(io::Error::new(io::ErrorKind::NotFound, "Wireless Interface Not Found").into())
        }
    }

    pub fn prepare_message(&self, command: Command, mode: MessageMode)
         -> Result<generic::Message, Error>
    {
        let mut tx_msg = generic::Message::new(self.family.id, command, mode);
        match self.wireless_device_id {
            WirelessDeviceId::DeviceIdentifier(id) => {
                tx_msg.append_attribute(Attribute::new(attributes::Attribute::Wdev, id));
            }
            WirelessDeviceId::InterfaceIndex(id) => {
                tx_msg.append_attribute(Attribute::new(attributes::Attribute::Ifindex, id));
            }
            _ => {
                return Err(io::Error::new(io::ErrorKind::Other, "No interface identifier").into());
            }
        }
        Ok(tx_msg)
    }

    fn prepare_device_message(&self, command: Command, mode: MessageMode)
        -> Result<generic::Message, Error>
    {
        let mut tx_msg = self.prepare_message(command, mode)?;
        tx_msg.append_attribute(Attribute::new(attributes::Attribute::Mac, self.mac));
        Ok(tx_msg)
    }

    pub fn trigger_scan(&self, socket: &mut Socket) -> Result<(), Error>
    {
        let msg = self.prepare_message(Command::TriggerScan,
            MessageMode::Acknowledge)?;
        socket.send_message(&msg)?;
        loop {
            let messages = socket.receive_messages()?;
            if messages.is_empty() {
                break;
            }
        }
        Ok(())
    }

    pub fn abort_scan(&self, socket: &mut Socket) -> Result<(), Error>
    {
        let msg = self.prepare_message(Command::AbortScan,
            MessageMode::Acknowledge)?;
        socket.send_message(&msg)?;
        loop {
            let messages = socket.receive_messages()?;
            if messages.is_empty() {
                break;
            }
        }
        Ok(())
    }

    pub fn start_interval_scan(&self, socket: &mut Socket, interval: u32) -> Result<(), Error>
    {
        let mut msg = self.prepare_message(Command::StartScheduledScan,
            MessageMode::Acknowledge)?;
        msg.append_attribute(Attribute::new(attributes::Attribute::SchedScanInterval, interval));
        socket.send_message(&msg)?;
        loop {
            let messages = socket.receive_messages()?;
            if messages.is_empty() {
                break;
            }
        }
        Ok(())
    }

    pub fn stop_interval_scan(&self, socket: &mut Socket) -> Result<(), Error>
    {
        socket.send_message(&self.prepare_message(Command::StopScheduledScan,
            MessageMode::None)?)?;
        loop {
            let messages = socket.receive_messages()?;
            if messages.is_empty() {
                break;
            }
        }
        Ok(())
    }

    pub fn get_survey(&self, socket: &mut Socket) -> Result<(), Error>
    {
        let msg = self.prepare_message(Command::GetSurvey,
            MessageMode::Dump)?;
        socket.send_message(&msg)?;
        loop {
            let messages = socket.receive_messages()?;
            if messages.is_empty() {
                break;
            }
        }
        Ok(())
    }

    pub fn disconnect(&self, socket: &mut Socket) -> Result<(), Error>
    {
        socket.send_message(&self.prepare_device_message(Command::Disconnect,
            MessageMode::Acknowledge)?)?;
        loop {
            let messages = socket.receive_messages()?;
            if messages.is_empty() {
                break;
            }
        }
        Ok(())
    }

    pub fn connect(&self, socket: &mut Socket, ssid: &str, _: &str)
        -> Result<(), Error>
    {
        let mut tx_msg = self.prepare_device_message(Command::Connect,
            MessageMode::Acknowledge)?;
        tx_msg.append_attribute(Attribute::new_string_with_nul(
            attributes::Attribute::Ssid, ssid));
        socket.send_message(&tx_msg)?;
        loop {
            let messages = socket.receive_messages()?;
            if messages.is_empty() {
                break;
            }
        }
        Ok(())
    }

    pub fn get_regulatory(&self, socket: &mut Socket) -> Result<(), Error>
    {
        let msg = generic::Message::new(self.family.id, Command::GetRegulatory,
            MessageMode::Dump);
        /* let msg = self.prepare_message(Command::GetRegulatory,
            MessageMode::Dump)?; */
        socket.send_message(&msg)?;
        loop {
            let messages = socket.receive_messages()?;
            if messages.is_empty() {
                break;
            }
            for m in messages {
                let (_, msg) = generic::Message::unpack(&m.data)?;
                let cmd = Command::from(msg.command);
                if cmd == Command::GetRegulatory {
                    let info = RegulatoryInformation::from_message(
                        &msg)?;
                    println!("{}", info);
                }
                else {
                    println!("{:?}", cmd);
                }
            }
        }
        Ok(())
    }

    pub fn set_regulatory(&self, socket: &mut Socket, alpha2: &str)
        -> Result<(), Error> {
        {
            assert!(alpha2.len() == 2);
            let mut msg = self.prepare_message(Command::RequestSetRegulatory,
                MessageMode::Acknowledge)?;
            let attr = Attribute::new_string_with_nul(
                attributes::Attribute::RegAlpha2, alpha2);
            msg.append_attribute(attr);
            socket.send_message(&msg)?;
        }
        loop {
            let messages = socket.receive_messages()?;
            if messages.is_empty() {
                break;
            }
            for m in messages {
                let (_, msg) = generic::Message::unpack(&m.data)?;
                let cmd = Command::from(msg.command);
                println!("{:?}", cmd);
            }
        }
        Ok(())
    }
}

pub fn get_wireless_interfaces(socket: &mut Socket, family: &generic::Family)
    -> Result<Vec<WirelessInterface>, Error>
{
    {
        let tx_msg = generic::Message::new(family.id, Command::GetInterface,
            MessageMode::Dump);
        socket.send_message(&tx_msg)?;
    }
    let mut devices = vec![];
    loop {
        let messages = socket.receive_messages()?;
        if messages.is_empty() {
            break;
        }
        for m in messages {
            if m.header.identifier == family.id {
                let (_, gmsg) = generic::Message::unpack(&m.data)?;
                if let Ok(wi) = WirelessInterface::from_message(gmsg,
                    family.clone()) {
                    devices.push(wi);
                }
            }
        }
    }
    Ok(devices)
}
