extern crate libc;
extern crate mio;
extern crate netlink_rust;
extern crate nl80211_rs;
// following is macro_use is needed for at leas rust 1.24 but gives a warning on 1.30
#[allow(unused_imports)]
#[macro_use]
extern crate structopt;

/*
use std::alloc::System;
#[global_allocator]
static GLOBAL: System = System;
*/

use std::convert::From;
use std::fmt;
use std::io;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::time::{Duration, Instant};

use mio::unix::EventedFd;
use mio::{Events, Poll, PollOpt, Ready, Token};

use netlink_rust as netlink;
use netlink_rust::generic;
use netlink_rust::{ConvertFrom, Error, HardwareAddress, Message, MessageMode, Protocol, Socket};

use nl80211_rs as nl80211;
use nl80211_rs::InformationElement;
use nl80211_rs::*;

use structopt::StructOpt;

#[allow(dead_code)]
fn show_slice(slice: &[u8]) {
    print!("{} bytes\n", slice.len());
    for byte in slice.iter() {
        print!("{:02X} ", byte);
    }
    print!("\n");
}

fn join_to_string<T>(values: T, separator: &str) -> String
where
    T: IntoIterator,
    T::Item: ToString,
{
    values
        .into_iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(separator)
}

enum AccessPointStatus {
    None,
    Authenticated,
    Associated,
    Joined,
}

enum ChannelSwitchAnnouncement {
    None,
    Announcement(u8),
}

struct AccessPoint {
    bssid: HardwareAddress,
    ssid: String,
    alpha2: String,
    signal: i32,
    frequency: u32,
    channel_1: u8,
    channel_2: u8,
    channel_width: u32,
    status: AccessPointStatus,
    ciphers: Vec<CipherSuite>,
    akms: Vec<AuthenticationKeyManagement>,
    pmf: ProtectedManagementFramesMode,
    csa: ChannelSwitchAnnouncement,
}

impl AccessPoint {
    fn channel(&self) -> u32 {
        if self.frequency >= 2412 && self.frequency <= 2472 {
            return (self.frequency - 2407) / 5;
        }
        if self.frequency == 2484 {
            return 14;
        }
        if self.frequency >= 5000 && self.frequency < 6000 {
            return (self.frequency - 5000) / 5;
        } else {
            return 0xffffffff;
        }
    }

    fn num_bars(&self) -> usize {
        let signal = self.signal as f64 / 100.0;
        let num_bars = signal + 100.0;
        let num_bars = if num_bars < 0.0 {
            0.0
        } else if num_bars > 100.0 {
            100.0
        } else {
            num_bars
        };
        let num_bars = (num_bars / 10.0).round() as usize;
        if num_bars > 7 {
            7
        } else {
            num_bars
        }
    }
}

impl fmt::Display for AccessPoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let signal = self.signal as f64 / 100.0;
        let num_bars = 7u8 - self.num_bars() as u8;
        let octet = 0x88 + num_bars;
        let components = [0xE2, 0x96, octet];
        let bar_char = std::str::from_utf8(&components).unwrap();
        let status_symbol = match self.status {
            AccessPointStatus::None => " ",
            AccessPointStatus::Authenticated => "⇹",
            AccessPointStatus::Associated => "⮂",
            AccessPointStatus::Joined => "→",
        };
        let pmf_symbol = match self.pmf {
            ProtectedManagementFramesMode::Disabled => " ",
            ProtectedManagementFramesMode::Capable => "C",
            ProtectedManagementFramesMode::Required => "R",
        };
        let akms = join_to_string(&self.akms, " ");
        let ciphers = join_to_string(&self.ciphers, " ");
        let csa = if let ChannelSwitchAnnouncement::Announcement(channel) = self.csa {
            format!("CSA {}", channel)
        } else {
            String::new()
        };
        write!(
            f,
            "{} {:32} {} {:4} {:3} {:3} {:3} {:3} {:2} {:4.0} {} {} {}-{} {}",
            self.bssid,
            self.ssid,
            status_symbol,
            self.frequency,
            self.channel(),
            self.channel_1,
            self.channel_2,
            self.channel_width,
            self.alpha2,
            signal,
            bar_char,
            pmf_symbol,
            akms,
            ciphers,
            csa
        )
    }
}

fn parse_bss(data: &[u8]) -> Result<AccessPoint, Error> {
    use nl80211::BssAttribute;
    let mut bssid = None;
    let mut ssid = None;
    let mut alpha2 = None;
    let mut signal = None;
    let mut frequency = None;
    let mut channel_1 = 0;
    let mut channel_2 = 0;
    let mut channel_width = 0;
    let mut status = AccessPointStatus::None;
    let (_, attrs) = netlink::Attribute::unpack_all(&data);
    let mut ciphers = vec![];
    let mut akms = vec![];
    let mut pmf = ProtectedManagementFramesMode::Disabled;
    let mut csa = ChannelSwitchAnnouncement::None;

    for attr in attrs {
        let id = BssAttribute::from(attr.identifier);
        match id {
            BssAttribute::Frequency => {
                frequency = attr.as_u32().ok();
            }
            BssAttribute::ChanWidth => (),
            BssAttribute::SeenMsAgo => (),
            BssAttribute::SignalMbm => {
                signal = attr.as_i32().ok();
            }
            BssAttribute::Status => match attr.as_u32() {
                Ok(value) => {
                    status = match value {
                        0 => AccessPointStatus::Authenticated,
                        1 => AccessPointStatus::Associated,
                        2 => AccessPointStatus::Joined,
                        _ => AccessPointStatus::None,
                    }
                }
                Err(_) => (),
            },
            BssAttribute::Capability => (),
            BssAttribute::Tsf => (),
            BssAttribute::ParentTsf => (),
            BssAttribute::BeaconInterval => (),
            BssAttribute::BeaconTsf => (),
            BssAttribute::Bssid => {
                bssid = attr.as_hardware_address().ok();
            }
            BssAttribute::ParentBssid => (),
            /* Last seen receive in CLOCK_BOOTTIME */
            BssAttribute::LastSeenBootTime => (),
            BssAttribute::PrespData => (),
            BssAttribute::BeaconIes => {
                let attr_data = &attr.as_bytes();
                let ies = InformationElements::parse(attr_data);
                for ref ie in ies.elements {
                    if let Some(ie_id) = nl80211::InformationElementId::convert_from(ie.identifier)
                    {
                        match ie_id {
                            nl80211::InformationElementId::ExtendedChannelSwitchAnnouncement => {
                                if ie.data.len() == 4 {
                                    let new_channel = ie.data[2];
                                    println!("Beacon: Channel Switch: {:?} {}", ssid, new_channel);
                                    csa = ChannelSwitchAnnouncement::Announcement(new_channel);
                                }
                            }
                            nl80211::InformationElementId::ChannelSwitchAnnouncement => {
                                if ie.data.len() == 3 {
                                    let mode = ie.data[0];
                                    let new_channel = ie.data[1];
                                    let count = ie.data[2];
                                    println!(
                                        "Beacon: Channel Switch: {:?} {} {} {}",
                                        ssid, mode, new_channel, count
                                    );
                                    csa = ChannelSwitchAnnouncement::Announcement(new_channel);
                                }
                            }
                            nl80211::InformationElementId::RobustSecurityNetwork => {
                                let _ie_rsn = nl80211::RobustSecurityNetwork::parse(&ie.data)?;
                            }
                            _ => (),
                        }
                    } else {
                        println!("Beacon: {}", ie.identifier);
                    }
                }
            }
            BssAttribute::InformationElements => {
                // Write a parser
                let attr_data = &attr.as_bytes();
                let ies = InformationElement::parse_all(attr_data)?;
                for ref ie in ies {
                    match *ie {
                        InformationElement::Ssid(ref ie) => {
                            ssid = Some(ie.ssid.clone());
                        }
                        InformationElement::Country(ref ie) => {
                            alpha2 = Some(ie.alpha2.clone());
                        }
                        InformationElement::HighThroughputOperation(ref ie) => {
                            if channel_width < ie.width {
                                channel_width = ie.width;
                            }
                            channel_1 = ie.primary_channel;
                            channel_2 = ie.secondary_channel;
                        }
                        InformationElement::VeryHighThroughputOperation(ref ie) => {
                            if channel_width < ie.width {
                                channel_width = ie.width;
                            }
                            channel_1 = ie.channel;
                            channel_2 = ie.secondary_channel;
                        }
                        InformationElement::RobustSecurityNetwork(ref ie) => {
                            pmf = ie.pmf_mode();
                            for c in ie.ciphers.iter() {
                                ciphers.push(c.clone());
                            }
                            for a in ie.akms.iter() {
                                akms.push(a.clone());
                            }
                        }
                        InformationElement::Other(_) => {}
                    }
                }
            }
            _ => {
                println!("Attribute: {:?}, Len: {}", id, attr.len());
            }
        }
    }
    if bssid.is_some() && ssid.is_some() && signal.is_some() && frequency.is_some() {
        let alpha2 = alpha2.unwrap_or(String::from("  "));
        return Ok(AccessPoint {
            bssid: bssid.unwrap(),
            ssid: ssid.unwrap(),
            alpha2,
            signal: signal.unwrap(),
            frequency: frequency.unwrap(),
            channel_1,
            channel_2,
            channel_width,
            status,
            ciphers,
            akms,
            pmf,
            csa,
        });
    }
    Err(io::Error::new(io::ErrorKind::NotFound, "Failed").into())
}

fn parse_scan_result(message: &generic::Message) -> Result<AccessPoint, Error> {
    let command = nl80211::Command::from(message.command);
    if command == nl80211::Command::NewScanResults {
        for ref attr in &message.attributes {
            let attr_id = nl80211::Attribute::from(attr.identifier);
            match attr_id {
                nl80211::Attribute::Bss => {
                    return parse_bss(&attr.as_bytes());
                }
                nl80211::Attribute::Generation => (),
                nl80211::Attribute::Ifindex => (),
                nl80211::Attribute::Wdev => (),
                _ => {
                    println!("Attribute: {:?}, Len: {}", attr_id, attr.len());
                }
            }
        }
    }
    Err(io::Error::new(io::ErrorKind::NotFound, "Failed").into())
}

fn print_scan_results(access_points: &mut Vec<AccessPoint>) -> Result<(), Error> {
    let out = io::stdout();
    let mut handle = out.lock();
    let num_aps = access_points.len();
    handle.write(b"Scan Results ---\n")?;
    access_points.sort_by(|a, b| b.signal.cmp(&a.signal).then(a.ssid.cmp(&b.ssid)));
    for ap in access_points {
        handle.write_fmt(format_args!("{}\n", ap))?;
    }
    handle.write(format!("{} APs\n", num_aps).as_bytes())?;
    Ok(())
}

fn scan_request_result(
    socket: &mut Socket,
    wireless_device: &WirelessInterface,
) -> Result<(), Error> {
    println!("Get Scan for {}", wireless_device.interface_name);
    {
        let tx_msg =
            wireless_device.prepare_message(nl80211::Command::GetScan, MessageMode::Dump)?;
        socket.send_message(&tx_msg)?;
    }
    let mut aps = vec![];
    loop {
        let messages = socket.receive_messages()?;
        if messages.is_empty() {
            break;
        } else {
            for m in messages {
                if m.header.identifier == wireless_device.family.id {
                    let (_, msg) = generic::Message::unpack(&m.data)?;
                    aps.push(parse_scan_result(&msg)?);
                } else {
                    println!("Unknown message {}", m.header);
                }
            }
        }
    }
    print_scan_results(&mut aps)
}

struct Monitor {
    can_scan: bool,
    scan_triggered: bool,
    device: WirelessInterface,
    event_socket: Socket,
    control_socket: Socket,
    receive_sequence: u32,
    scan_results: Vec<AccessPoint>,
}

impl Monitor {
    fn new(can_scan: bool, device: WirelessInterface) -> Result<Monitor, Error> {
        let control_socket = Socket::new(Protocol::Generic)?;
        let mut event_socket = Socket::new(Protocol::Generic)?;

        for ref group in &device.family.multicast_groups {
            event_socket.multicast_group_subscribe(group.id)?;
        }

        Ok(Monitor {
            can_scan: can_scan,
            scan_triggered: false,
            device: device,
            event_socket: event_socket,
            control_socket: control_socket,
            receive_sequence: u32::max_value(),
            scan_results: vec![],
        })
    }

    fn run(&mut self) -> Result<(), Error> {
        println!("Monitor events");
        let mut start = Instant::now();
        let timeout = Duration::from_millis(500);
        const EVENT: Token = Token(1);
        const CONTROL: Token = Token(2);
        let poll = Poll::new()?;
        poll.register(
            &EventedFd(&self.event_socket.as_raw_fd()),
            EVENT,
            Ready::readable(),
            PollOpt::edge(),
        )?;
        poll.register(
            &EventedFd(&self.control_socket.as_raw_fd()),
            CONTROL,
            Ready::readable(),
            PollOpt::edge(),
        )?;
        let mut events = Events::with_capacity(1024);
        loop {
            poll.poll(&mut events, Some(timeout))?;
            for event in events.iter() {
                match event.token() {
                    EVENT => loop {
                        match self.event_socket.receive_messages() {
                            Ok(messages) => {
                                if !messages.is_empty() {
                                    self.handle_event_messages(messages)?;
                                } else {
                                    break;
                                }
                            }
                            Err(e) => {
                                println!("Failed to receive messages \"{}\"", e);
                                break;
                            }
                        }
                    },
                    CONTROL => loop {
                        match self.control_socket.receive_messages() {
                            Ok(messages) => {
                                if !messages.is_empty() {
                                    self.handle_control_messages(messages)?;
                                } else {
                                    break;
                                }
                            }
                            Err(e) => {
                                println!("Failed to receive messages \"{}\"", e);
                                break;
                            }
                        }
                    },
                    _ => println!("Other event"),
                }
            }
            let elapsed = start.elapsed();
            if elapsed > Duration::from_secs(1) {
                if self.can_scan && !self.scan_triggered {
                    println!("Trigger Scan");
                    let tx_msg = self
                        .device
                        .prepare_message(nl80211::Command::TriggerScan, MessageMode::None)?;
                    match self.control_socket.send_message(&tx_msg) {
                        Err(e) => {
                            println!("Scan Failed {}", e);
                        }
                        Ok(_) => (),
                    }
                    self.scan_triggered = true;
                }
                start = Instant::now();
            }
        }
    }

    fn device_id_from_attributes(
        attributes: &Vec<netlink_rust::Attribute>,
    ) -> Result<WirelessDeviceId, Error> {
        let mut interface_index = None;
        let mut device_identifier = None;
        for attr in attributes {
            let id = nl80211::Attribute::from(attr.identifier);
            match id {
                nl80211::Attribute::Ifindex => {
                    interface_index = Some(attr.as_u32()?);
                }
                nl80211::Attribute::Wdev => {
                    device_identifier = Some(attr.as_u64()?);
                }
                _ => (),
            }
            if interface_index.is_some() && device_identifier.is_some() {
                break;
            }
        }
        if device_identifier.is_some() {
            return Ok(WirelessDeviceId::DeviceIdentifier(
                device_identifier.unwrap(),
            ));
        }
        if interface_index.is_some() {
            return Ok(WirelessDeviceId::InterfaceIndex(interface_index.unwrap()));
        }
        Ok(WirelessDeviceId::None)
    }

    fn handle_event_nl80211_message(&mut self, message: &generic::Message) -> Result<(), Error> {
        let command = nl80211::Command::from(message.command);
        let device_id = Self::device_id_from_attributes(&message.attributes)?;
        match command {
            nl80211::Command::TriggerScan => (),
            nl80211::Command::NewScanResults => {
                let tx_msg = self
                    .device
                    .prepare_message(nl80211::Command::GetScan, MessageMode::Dump)?;
                match self.control_socket.send_message(&tx_msg) {
                    Ok(_) => (),
                    Err(ref e) => {
                        println!("Failed to start scan {}", e);
                    }
                }
            }
            nl80211::Command::GetRegulatory => {
                let info = nl80211::RegulatoryInformation::from_message(&message)?;
                println!("[{}] Regulatory Domain\n{}", device_id, info);
            }
            nl80211::Command::RegulatoryChange => {
                let change = nl80211::RegulatoryChange::from_message(&message)?;
                println!("[{}] Regulatory Change {}", device_id, change);
            }
            nl80211::Command::Connect => {
                for ref attr in &message.attributes {
                    let id = nl80211::Attribute::from(attr.identifier);
                    match id {
                        nl80211::Attribute::StatusCode => {
                            let status = attr.as_u16()?;
                            if status == 0 {
                                println!("[{}] Connect status: OK", device_id);
                            } else {
                                println!("[{}] Connect status: {}", device_id, status);
                            }
                        }
                        _ => (),
                    }
                }
            }
            nl80211::Command::Disconnect => {
                println!("[{}] Disconnect", device_id);
            }
            _ => {
                println!("[{}] Event Command: {:?}", device_id, command);
                for ref attr in &message.attributes {
                    let attr_id = nl80211::Attribute::from(attr.identifier);
                    match attr_id {
                        nl80211::Attribute::Generation => (),
                        nl80211::Attribute::Ifindex => (),
                        nl80211::Attribute::Wdev => (),
                        nl80211::Attribute::Wiphy => (),
                        nl80211::Attribute::Iftype => {
                            let if_type = nl80211::InterfaceType::from(attr.as_u32().unwrap_or(0));
                            println!("  Attribute: Interface Type: {:?}", if_type);
                        }
                        Attribute::RegAlpha2 => {
                            let country = attr.as_string().unwrap_or(String::new());
                            println!("  Attribute: Country: {}", country);
                        }
                        Attribute::RegType => {
                            let region = attr.as_u8().unwrap_or(0);
                            let region = RegulatoryRegion::from(region);
                            println!("  Attribute: Regulatory Region: {:?}", region);
                        }
                        Attribute::RegInitiator => {
                            let initiator = attr.as_u8().unwrap_or(0);
                            let initiator = RegulatoryInitiator::from(initiator);
                            println!("  Attribute: Regulatory Initiator: {:?}", initiator);
                        }
                        nl80211::Attribute::Mac => {
                            let hw = attr.as_hardware_address()?;
                            println!("  Attribute: MAC: {}", hw);
                        }
                        nl80211::Attribute::Frame => {
                            let frame = Frame::unpack(&attr.as_bytes())?;
                            println!("  Attribute: Frame: {}", frame);
                        }
                        nl80211::Attribute::InformationElement => {
                            println!("  Attribute: Information Element");
                            let attr_data = &attr.as_bytes();
                            let ies = InformationElement::parse_all(attr_data)?;
                            for ref ie in ies {
                                if let Some(id) = ie.identifier() {
                                    print!("    Information Element {:?}", id);
                                } else {
                                    println!("    Information Element Unknown");
                                    continue;
                                }
                                match *ie {
                                    InformationElement::Ssid(ref ie) => {
                                        print!(" {}", ie);
                                    }
                                    InformationElement::RobustSecurityNetwork(ref ie) => {
                                        print!(" {}", ie);
                                    }
                                    InformationElement::HighThroughputOperation(ref ie) => {
                                        print!(" {}", ie);
                                    }
                                    InformationElement::VeryHighThroughputOperation(ref ie) => {
                                        print!(" {}", ie);
                                    }
                                    _ => (),
                                }
                                println!("");
                            }
                        }
                        nl80211::Attribute::WiphyTxPowerLevel => {
                            println!(
                                "  Attribute: Tx Power: {:6.3} dBm",
                                attr.as_u32().unwrap_or(0) as f64 / 1000.0
                            );
                        }
                        _ => {
                            println!("  Attribute: {:?} Len: {}", attr_id, attr.len());
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn handle_event_messages(&mut self, messages: Vec<Message>) -> Result<(), Error> {
        for m in messages {
            if m.header.identifier == self.device.family.id {
                let (_, msg) = generic::Message::unpack(&m.data)?;
                self.handle_event_nl80211_message(&msg)?;
            } else {
                println!("Other message: {}", m.header);
            }
        }
        Ok(())
    }

    fn handle_control_messages(&mut self, messages: Vec<Message>) -> Result<(), Error> {
        let mut scan_result = false;
        for m in messages {
            if m.header.identifier == self.device.family.id {
                let (_, msg) = generic::Message::unpack(&m.data)?;
                let command = nl80211::Command::from(msg.command);
                match command {
                    nl80211::Command::TriggerScan => {}
                    nl80211::Command::NewScanResults => {
                        scan_result = true;
                        if self.receive_sequence != m.header.sequence {
                            self.scan_results.clear();
                        }
                        self.scan_results.push(parse_scan_result(&msg)?);
                        self.scan_triggered = false;
                    }
                    _ => {
                        println!("Control Command: {:?}", command);
                        for attr in &msg.attributes {
                            let attr_id = nl80211::Attribute::from(attr.identifier);
                            println!("Attribute: {:?} Len: {}", attr_id, attr.len());
                        }
                    }
                }
            } else {
                println!("Other message: {}", m.header);
            }
            self.receive_sequence = m.header.sequence;
        }
        if scan_result {
            print_scan_results(&mut self.scan_results)?;
        }
        Ok(())
    }
}

#[derive(StructOpt)]
#[structopt(name = "nl80211", about = "nl80211 example")]
struct Arguments {
    #[structopt(name = "interface", short = "i", long = "interface")]
    interface: Option<String>,
    #[structopt(subcommand)]
    user_command: Option<UserCommand>,
}

#[derive(StructOpt)]
enum UserCommand {
    #[structopt(name = "monitor")]
    Monitor,
    #[structopt(name = "phy-information")]
    PhyInformation,
    #[structopt(name = "device-information")]
    DeviceInformation,
    #[structopt(name = "scan")]
    Scan,
    #[structopt(name = "scan-results")]
    ScanResults,
    #[structopt(name = "disconnect")]
    Disconnect,
    #[structopt(name = "get-regulatory")]
    GetRegulatory,
    #[structopt(name = "set-regulatory")]
    SetRegulatory { alpha: String },
    #[structopt(name = "get-survey")]
    GetSurvey,
    #[structopt(name = "set-channel")]
    SetChannel { channel: u32 },
    #[structopt(name = "get-station")]
    GetStation,
}

impl UserCommand {
    fn requires_root(&self) -> bool {
        use UserCommand::*;
        match *self {
            Scan => true,
            Disconnect => true,
            SetRegulatory { .. } => true,
            _ => false,
        }
    }
    fn requires_device(&self) -> bool {
        use UserCommand::*;
        match *self {
            PhyInformation | DeviceInformation => false,
            _ => true,
        }
    }
}

fn main() {
    let opt = Arguments::from_args();
    let uid = unsafe { libc::getuid() };

    let user_command = opt.user_command.unwrap_or(UserCommand::Monitor);

    if uid != 0 && user_command.requires_root() {
        println!("Need to be root");
        return;
    }

    let mut control_socket = Socket::new(Protocol::Generic).expect("Failed to open control socket");
    let family = generic::Family::from_name(&mut control_socket, "nl80211")
        .expect("Failed to get nl80211 family");
    let device = if user_command.requires_device() {
        let mut devices = nl80211::get_wireless_interfaces(&mut control_socket, &family)
            .expect("Failed to get nl80211 wireless interfaces");
        if let Some(if_name) = opt.interface {
            devices.into_iter().find(|d| d.interface_name == if_name)
        } else {
            if devices.is_empty() {
                None
            } else {
                Some(devices.remove(0))
            }
        }
    } else {
        None
    };
    if user_command.requires_device() && device.is_none() {
        println!("Failed to find the device");
        return;
    }
    if user_command.requires_device() {
        if let Some(dev) = device {
            println!("Using interface {}", dev.interface_name);
            match user_command {
                UserCommand::Monitor => {
                    let mut monitor = Monitor::new(uid == 0, dev).unwrap();
                    monitor.run().unwrap();
                }
                UserCommand::Scan => {
                    dev.trigger_scan(&mut control_socket).unwrap();
                }
                UserCommand::ScanResults => {
                    scan_request_result(&mut control_socket, &dev).unwrap();
                }
                UserCommand::Disconnect => {
                    println!("Disconnect");
                    dev.disconnect(&mut control_socket).unwrap();
                }
                UserCommand::GetRegulatory => {
                    dev.get_regulatory(&mut control_socket).unwrap();
                }
                UserCommand::SetRegulatory { alpha } => {
                    dev.set_regulatory(&mut control_socket, &alpha)
                        .expect("Failed to set regulatory domain");
                }
                UserCommand::GetSurvey => {
                    dev.get_survey(&mut control_socket).unwrap();
                }
                UserCommand::SetChannel { channel } => {
                    dev.set_channel(&mut control_socket, channel).unwrap();
                }
                UserCommand::GetStation => {
                    dev.get_station(&mut control_socket).unwrap();
                }
                _ => (),
            }
        }
    } else {
        match user_command {
            UserCommand::PhyInformation => {
                let phys = nl80211::get_wireless_phys(&mut control_socket, family.id)
                    .expect("Failed to get nl80211 wireless phys");
                for phy in phys {
                    println!("{}", phy);
                }
            }
            UserCommand::DeviceInformation => {
                let mut devices = nl80211::get_wireless_interfaces(&mut control_socket, &family)
                    .expect("Failed to get nl80211 wireless interfaces");
                for dev in devices.into_iter() {
                    println!("{}", dev);
                }
            }
            _ => (),
        }
    }
}
