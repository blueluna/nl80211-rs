use std::fmt;
use std::io;
use netlink_rust::{Socket, Attribute, Message, MessageMode, HardwareAddress, Error};
use netlink_rust::generic;
use attributes;
use commands::Command;

pub struct WirelessInterface { 
    pub netlink_family: u16,
    pub phy_id: u32,
    pub interface_name: String,
    pub interface_index: u32,
    pub device_id: Option<u64>,
    pub mac: HardwareAddress,
    pub interface_type: attributes::InterfaceType,
    pub tx_power_level: u32,
    pub ssid: Option<String>,
    pub channel_width: Option<u32>,
}

impl fmt::Display for WirelessInterface {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Wireless Device: Phy: {} Interface Name: {} Interface Index: {} MAC Address: {} Interface Type: {:?} Tx Power Level: {}",
            self.phy_id, self.interface_name, self.interface_index, self.mac, self.interface_type, self.tx_power_level)?;
        if let Some(id) = self.device_id { write!(f, " Wireless Device Id: {}", id)?; };
        if let Some(ref ssid) = self.ssid { write!(f, " SSID: {}", ssid)?; };
        Ok(())
    }
}

impl WirelessInterface {
    pub fn from_message(message: generic::Message, family_id: u16) -> Result<WirelessInterface, Error>
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
        for attr in message.attributes {
            let identifier = attributes::Attribute::from(attr.identifier);
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
                },
                _ => {
                    println!("Skipping {:?} {}", identifier, attr.len());
                },
            }
        }
        if phy_id.is_some() && interface_name.is_some() && interface_index.is_some() && mac.is_some() {
            Ok(WirelessInterface{
                netlink_family: family_id,
                phy_id: phy_id.unwrap(),
                interface_name: interface_name.unwrap(),
                interface_index: interface_index.unwrap(),
                device_id: device_id,
                mac: mac.unwrap(),
                interface_type: interface_type,
                tx_power_level: tx_power_level,
                ssid: ssid,
                channel_width: channel_width,
            })
        }
        else {
            Err(io::Error::new(io::ErrorKind::NotFound, "Wireless Interface Not Found").into())
        }
    }

    pub fn prepare_message(&self, command: Command, mode: MessageMode)
        -> generic::Message
    {
        let mut tx_msg = generic::Message::new(self.netlink_family, command, mode);
        match self.device_id {
            Some(id) => {
                tx_msg.append_attribute(Attribute::new(attributes::Attribute::Wdev, id));
            },
            None => {
                tx_msg.append_attribute(Attribute::new(attributes::Attribute::Ifindex, self.interface_index)
                );
            },
        }
        tx_msg
    }

    fn prepare_device_message(&self, command: Command, mode: MessageMode)
        -> generic::Message
    {
        let mut tx_msg = self.prepare_message(command, mode);
        tx_msg.append_attribute(Attribute::new(attributes::Attribute::Mac, self.mac));
        tx_msg
    }

    pub fn trigger_scan(&self, socket: &mut Socket) -> Result<(), Error>
    {
        let msg = self.prepare_message(Command::TriggerScan,
            MessageMode::Acknowledge);
        socket.send_message(&msg)?;
        loop {
            let messages = socket.receive_messages()?;
            if messages.is_empty() {
                break;
            }
            for message in messages {
                match message {
                    Message::Data(m) => {
                        println!("Data, {}", m.header);
                    },
                    Message::Acknowledge => {
                        println!("Acknowledge");
                    },
                    Message::Done => {
                        println!("Done");
                    },
                }
            }
        }
        Ok(())
    }

    pub fn abort_scan(&self, socket: &mut Socket) -> Result<(), Error>
    {
        let msg = self.prepare_message(Command::AbortScan,
            MessageMode::Acknowledge);
        socket.send_message(&msg)?;
        loop {
            let messages = socket.receive_messages()?;
            if messages.is_empty() {
                break;
            }
            for message in messages {
                match message {
                    Message::Data(m) => {
                        println!("Data, {}", m.header);
                    },
                    Message::Acknowledge => {
                        println!("Acknowledge");
                    },
                    Message::Done => {
                        println!("Done");
                    },
                }
            }
        }
        Ok(())
    }

    pub fn start_interval_scan(&self, socket: &mut Socket, interval: u32) -> Result<(), Error>
    {
        let mut msg = self.prepare_message(Command::StartScheduledScan,
            MessageMode::Acknowledge);
        msg.append_attribute(Attribute::new(attributes::Attribute::SchedScanInterval, interval));
        socket.send_message(&msg)?;
        loop {
            let messages = socket.receive_messages()?;
            if messages.is_empty() {
                break;
            }
            for message in messages {
                match message {
                    Message::Data(m) => {
                        println!("Data, {}", m.header);
                    },
                    Message::Acknowledge => {
                        println!("Acknowledge");
                    },
                    Message::Done => {
                        println!("Done");
                    },
                }
            }
        }
        Ok(())
    }

    pub fn stop_interval_scan(&self, socket: &mut Socket) -> Result<(), Error>
    {
        socket.send_message(&self.prepare_message(Command::StopScheduledScan, MessageMode::None))?;
        loop {
            let messages = socket.receive_messages()?;
            if messages.is_empty() {
                break;
            }
            for message in messages {
                match message {
                    Message::Data(m) => {
                        println!("Data, {}", m.header);
                    },
                    Message::Acknowledge => {
                        println!("Acknowledge");
                    },
                    Message::Done => {
                        println!("Done");
                    },
                }
            }
        }
        Ok(())
    }

    pub fn get_survey(&self, socket: &mut Socket) -> Result<(), Error>
    {
        let msg = self.prepare_message(Command::GetSurvey,
            MessageMode::Dump);
        socket.send_message(&msg)?;
        loop {
            let messages = socket.receive_messages()?;
            if messages.is_empty() {
                break;
            }
            for message in messages {
                match message {
                    Message::Data(m) => {
                        println!("Data, {}", m.header);
                    },
                    Message::Acknowledge => {
                        println!("Acknowledge");
                    },
                    Message::Done => {
                        println!("Done");
                    },
                }
            }
        }
        Ok(())
    }

    pub fn disconnect(&self, socket: &mut Socket) -> Result<(), Error>
    {
        socket.send_message(&self.prepare_device_message(Command::Disconnect,
            MessageMode::Acknowledge))?;
        loop {
            let messages = socket.receive_messages()?;
            if messages.is_empty() {
                break;
            }
            for message in messages {
                match message {
                    Message::Data(m) => {
                        println!("Data, {}", m.header);
                    },
                    Message::Acknowledge => {
                        println!("Acknowledge");
                    },
                    Message::Done => {
                        println!("Done");
                    },
                }
            }
        }
        Ok(())
    }

    pub fn connect(&self, socket: &mut Socket, ssid: &str, _: &str) -> Result<(), Error>
    {
        let mut tx_msg = self.prepare_device_message(Command::Connect, MessageMode::Acknowledge);
        tx_msg.append_attribute(Attribute::new_string(attributes::Attribute::Ssid, ssid));
        socket.send_message(&tx_msg)?;
        loop {
            let messages = socket.receive_messages()?;
            if messages.is_empty() {
                break;
            }
            for message in messages {
                match message {
                    Message::Data(m) => {
                        println!("Data, {}", m.header);
                    },
                    Message::Acknowledge => {
                        println!("Acknowledge");
                    },
                    Message::Done => {
                        println!("Done");
                    },
                }
            }
        }
        Ok(())
    }
}

pub fn get_wireless_interfaces(socket: &mut Socket, family_id: u16) -> Result<Vec<WirelessInterface>, Error>
{
    {
        let tx_msg = generic::Message::new(family_id, Command::GetInterface, MessageMode::Dump);
        socket.send_message(&tx_msg)?;
    }
    let mut devices = vec![];
    loop {
        let messages = socket.receive_messages()?;
        if messages.is_empty() {
            break;
        }
        for message in messages {
            match message {
                Message::Data(m) => {
                    if m.header.identifier == family_id {
                        let gmsg = generic::Message::parse(&mut io::Cursor::new(m.data))?;
                        match WirelessInterface::from_message(gmsg, family_id) {
                            Ok(wi) => devices.push(wi),
                            Err(_) => (),
                        }
                    }
                },
                _ => (),
            }
        }
    }
    Ok(devices)
}
