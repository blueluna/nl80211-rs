extern crate libc;
extern crate netlink_rust;
extern crate mio;
extern crate clap;
extern crate nl80211_rs;

use std::io;
use std::io::{Write};
use std::fmt;
use std::convert::{From};
use std::os::unix::io::AsRawFd;
use std::time::{Duration, Instant};

use mio::{Ready, Poll, PollOpt, Token, Events};
use mio::unix::EventedFd;

use netlink_rust as netlink;
use netlink_rust::{HardwareAddress, Socket, Protocol, Message,
    MessageMode, Error, NativeUnpack, ConvertFrom};
use netlink_rust::generic;

use nl80211_rs as nl80211;
use nl80211_rs::*;
use nl80211_rs::InformationElement;

use clap::{Arg, App, SubCommand};

fn show_slice(slice: &[u8])
{
    print!("{} bytes\n", slice.len());
    for byte in slice.iter() {
        print!("{:02X} ", byte);
    }
    print!("\n");
}

fn join_to_string<T>(values: T, separator: &str) -> String
    where T: IntoIterator,
          T::Item: ToString,
{
    values.into_iter().map(|v| v.to_string()).collect::<Vec<_>>()
        .join(separator)
}

enum AccessPointStatus {
    None,
    Authenticated,
    Associated,
    Joined,
}

struct AccessPoint {
    bssid: HardwareAddress,
    ssid: String,
    signal: i32,
    frequency: u32,
    channel_1: u8,
    channel_2: u8,
    channel_width: u32,
    status: AccessPointStatus,
    ciphers: Vec<CipherSuite>,
    akms: Vec<AuthenticationKeyManagement>,
    pmf: ProtectedManagementFramesMode,
}

impl AccessPoint {
    fn channel(&self) -> u32
    {
        if self.frequency >= 2412 && self.frequency <= 2472 {
            return (self.frequency - 2407) / 5
        }
        if self.frequency == 2484 {
            return 14
        }
        if self.frequency >= 5000 && self.frequency < 6000 {
            return (self.frequency - 5000) / 5
        }
        else {
            return 0xffffffff
        }
    }

    fn num_bars(&self) -> usize
    {
        let signal = self.signal as f64 / 100.0;
        let num_bars = signal + 100.0;
        let num_bars = if num_bars < 0.0 { 0.0 } else if num_bars > 100.0 { 100.0 } else { num_bars };
        let num_bars = (num_bars / 10.0).round() as usize;
        if num_bars > 7 { 7 } else { num_bars }
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
            ProtectedManagementFramesMode::Capable => "🔑",
            ProtectedManagementFramesMode::Required => "🔒",
        };
	let akms = join_to_string(&self.akms, " ");
	let ciphers = join_to_string(&self.ciphers, " ");
        write!(f, "{} {:32} {} {:4} {:3} {:3} {:3} {:3} {:4.0} {} {} {}-{}",
            self.bssid, self.ssid, status_symbol, self.frequency,
            self.channel(), self.channel_1, self.channel_2,
            self.channel_width, signal, bar_char, pmf_symbol, akms, ciphers)
    }
}

fn parse_bss(data: &[u8]) -> Result<AccessPoint, Error>
{
    use nl80211::BssAttribute;
    let mut bssid = None;
    let mut ssid = None;
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

    for attr in attrs {
        let id = BssAttribute::from(attr.identifier);
        match id {
            BssAttribute::Frequency => {
                frequency = attr.as_u32().ok();
            },
            BssAttribute::ChanWidth => (),
            BssAttribute::SeenMsAgo => (),
            BssAttribute::SignalMbm => {
                signal = attr.as_i32().ok();
            },
            BssAttribute::Status => {
                match attr.as_u32() {
                    Ok(value) => {
                        status = match value {
                            0 => AccessPointStatus::Authenticated,
                            1 => AccessPointStatus::Associated,
                            2 => AccessPointStatus::Joined,
                            _ => AccessPointStatus::None,
                        }
                    },
                    Err(_) => (),
                }
            },
            BssAttribute::Capability => (),
            BssAttribute::Tsf => (),
            BssAttribute::ParentTsf => (),
            BssAttribute::BeaconInterval => (),
            BssAttribute::BeaconTsf => (),
            BssAttribute::Bssid => {
                bssid = attr.as_hardware_address().ok();
            },
            BssAttribute::ParentBssid => (),
            /* Last seen receive in CLOCK_BOOTTIME */
            BssAttribute::LastSeenBootTime => (),
            BssAttribute::PrespData => (),
            BssAttribute::BeaconIes => {
                let attr_data = &attr.as_bytes();
                let ies = InformationElements::parse(attr_data);
                for ref ie in ies.elements {
                    if let Some(ie_id) = nl80211::InformationElementId::convert_from(ie.identifier) {
                        match ie_id {
                            nl80211::InformationElementId::ExtendedChannelSwitchAnnouncement => {
                                if ie.data.len() == 4 {
                                    let new_channel = ie.data[2];
                                    println!("Beacon: Channel Switch: {:?} {}", ssid, new_channel);
                                }
                            }
                            nl80211::InformationElementId::RobustSecurityNetwork => {
                                let _ie_rsn = nl80211::RobustSecurityNetwork::parse(&ie.data)?;
                            }
                            _ => (),
                        }
                                
                    }
                    else {
                        println!("Beacon: {}", ie.identifier);
                    }
                }
            },
            BssAttribute::InformationElements => {
                // Write a parser
                let attr_data = &attr.as_bytes();
                let ies = InformationElement::parse_all(attr_data)?;
                for ref ie in ies {
                    match ie {
                        InformationElement::Ssid(ie) => {
                            ssid = Some(ie.ssid.clone());
                        },
                        InformationElement::HighThroughputOperation(ie) => {
                            if channel_width < ie.width {
                                channel_width = ie.width;
                            }
                            channel_1 = ie.primary_channel;
                            channel_2 = ie.secondary_channel;
                        },
                        InformationElement::VeryHighThroughputOperation(ie) => {
                            if channel_width < ie.width {
                                channel_width = ie.width;
                            }
                            channel_1 = ie.channel;
                            channel_2 = ie.secondary_channel;
                        },
                        InformationElement::RobustSecurityNetwork(ie) => {
                            pmf = ie.pmf_mode();
                            for c in ie.ciphers.iter() {
                                ciphers.push(c.clone());
                            }
                            for a in ie.akms.iter() {
                                akms.push(a.clone());
                            }
                        },
                        _ => (),
                    }
                }
            },
            _ => {
                println!("Attribute: {:?}, Len: {}", id, attr.len());
            }
        }
    }
    if bssid.is_some() && ssid.is_some() && signal.is_some() && frequency.is_some()
    {
        return Ok(AccessPoint {
            bssid: bssid.unwrap(),
            ssid: ssid.unwrap(),
            signal: signal.unwrap(),
            frequency: frequency.unwrap(),
            channel_1: channel_1,
            channel_2: channel_2,
            channel_width: channel_width,
            status: status,
            ciphers: ciphers,
            akms: akms,
            pmf: pmf,
        });
    }
    Err(io::Error::new(io::ErrorKind::NotFound, "Failed").into())
}

fn parse_scan_result(message: &generic::Message) -> Result<AccessPoint, Error>
{
    let command = nl80211::Command::from(message.command);
    if command == nl80211::Command::NewScanResults {
        for ref attr in &message.attributes {
            let attr_id = nl80211::Attribute::from(attr.identifier);
            match attr_id {
                nl80211::Attribute::Bss => {
                    return parse_bss(&attr.as_bytes());
                },
                nl80211::Attribute::Generation => (),
                nl80211::Attribute::Ifindex => (),
                nl80211::Attribute::Wdev => (),
                _ => {
                    println!("Attribute: {:?}, Len: {}", attr_id, attr.len());
                },
            }
        }
    }
    Err(io::Error::new(io::ErrorKind::NotFound, "Failed").into())
}

fn print_scan_results(access_points: &mut Vec<AccessPoint>) -> Result<(), Error>
{
    let out = io::stdout();
    let mut handle = out.lock();
    handle.write(b"Scan Results ---\n")?;
    access_points.sort_by(|a, b| b.signal.cmp(&a.signal).then(a.ssid.cmp(&b.ssid)));
    for ap in access_points {
        handle.write_fmt(format_args!("{}\n", ap))?;
    }
    Ok(())
}

fn scan_request_result(socket: &mut Socket, wireless_device: &WirelessInterface) -> Result<(), Error>
{
    println!("Get Scan for {}", wireless_device.interface_name);
    {
        let tx_msg = wireless_device.prepare_message(
            nl80211::Command::GetScan, MessageMode::Dump)?;
        socket.send_message(&tx_msg)?;
    }
    let mut aps = vec![];
    loop {
        let messages = socket.receive_messages()?;
        if messages.is_empty() {
            break;
        }
        else {
            for message in messages {
                match message {
                    Message::Data(m) => {
                        if m.header.identifier ==  wireless_device.family.id {
                            let (_, msg) = generic::Message::unpack(&m.data)?;
                            aps.push(parse_scan_result(&msg)?);
                        }
                        else {
                            println!("Unknown message {}", m.header);
                        }
                    },
                    Message::Acknowledge => (),
                    Message::Done => (),
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
    control_command: nl80211::Command,
    scan_results: Vec<AccessPoint>,
}

impl Monitor {
    fn new(can_scan: bool, device: WirelessInterface) -> Result<Monitor, Error>
    {
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
            control_command: nl80211::Command::Unspecified,
            scan_results: vec![]
            })
    }

    fn run(&mut self) -> Result<(), Error>
    {
        println!("Monitor events");
        let mut start = Instant::now();
        let timeout = Duration::from_millis(500);
        const EVENT: Token = Token(1);
        const CONTROL: Token = Token(2);
        let poll = Poll::new()?;
        poll.register(&EventedFd(&self.event_socket.as_raw_fd()), EVENT, Ready::readable(), PollOpt::edge())?;
        poll.register(&EventedFd(&self.control_socket.as_raw_fd()), CONTROL, Ready::readable(), PollOpt::edge())?;
        let mut events = Events::with_capacity(1024);
        loop {
            poll.poll(&mut events, Some(timeout))?;
            for event in events.iter() {
                match event.token() {
                    EVENT => {
                        loop {
                            let messages = self.event_socket.receive_messages()?;
                            if !messages.is_empty() {
                                self.handle_event_messages(messages)?;
                            }
                            else {
                                break;
                            }
                        }
                    },
                    CONTROL => {
                        loop {
                            let messages = self.control_socket.receive_messages()?;
                            if !messages.is_empty() {
                                self.handle_control_messages(messages)?;
                            }
                            else {
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
                    let tx_msg = self.device.prepare_message(
                        nl80211::Command::TriggerScan, MessageMode::None)?;
                    match self.control_socket.send_message(&tx_msg) {
                        Err(e) => {
                            println!("Scan Failed {}", e);
                        },
                        Ok(_) => (),
                    }
                    self.scan_triggered = true;
                }
                start = Instant::now();
            }
        }
    }

    fn handle_event_messages(&mut self, messages: Vec<Message>) -> Result<(), Error>
    {
        for message in messages {
            match message {
                Message::Data(m) => {
                    if m.header.identifier ==  self.device.family.id {
                        let (_, msg) = generic::Message::unpack(&m.data)?;
                        let command = nl80211::Command::from(msg.command);
                        match command {
                            nl80211::Command::TriggerScan => (),
                            nl80211::Command::NewScanResults => {
                                let tx_msg = self.device.prepare_message(
                                    nl80211::Command::GetScan,
                                    MessageMode::Dump)?;
                                self.control_socket.send_message(&tx_msg)?;
                            }
                            _ => {
                                println!("Command: {:?}", command);
                                for ref attr in &msg.attributes {
                                    let attr_id = nl80211::Attribute::from(attr.identifier);
                                    println!("Attribute: {:?} Len: {}", attr_id, attr.len());
                                    match attr_id {
                                        nl80211::Attribute::Frame => {
                                            let data = &attr.as_bytes();
                                            show_slice(&data);
                                            if data.len() > 22 {
                                                // See 8.2.3 in 802.11-2012.pdf
                                                let frame_control = u16::unpack_unchecked(&data);
                                                let duration_id = u16::unpack_unchecked(&data[2..]);
                                                let da = HardwareAddress::unpack_unchecked(&data[4..]);
                                                let sa = HardwareAddress::unpack_unchecked(&data[10..]);
                                                let bssid = HardwareAddress::unpack_unchecked(&data[16..]);
                                                println!("{:04x} {:04x} {} {} {}", frame_control, duration_id, da, sa, bssid);
                                            }
                                        },
                                        _ => (),
                                    }
                                }
                            }
                        }
                    }
                    else {
                        println!("Other message: {}", m.header);
                    }
                },
                Message::Acknowledge => (),
                Message::Done => (),
            }
        }
        Ok(())
    }

    fn handle_control_messages(&mut self, messages: Vec<Message>) -> Result<(), Error>
    {
        for message in messages {
            match message {
                Message::Data(m) => {
                    if m.header.identifier ==  self.device.family.id {
                        let (_, msg) = generic::Message::unpack(&m.data)?;
                        let command = nl80211::Command::from(msg.command);
                        match command {
                            nl80211::Command::TriggerScan => {},
                            nl80211::Command::NewScanResults => {
                                if self.control_command != command {
                                    self.scan_results.clear();
                                }
                                self.scan_results.push(parse_scan_result(&msg)?);
                                self.scan_triggered = false;
                            }
                            _ => {
                                println!("Control Command: {:?}", command);
                                for ref attr in &msg.attributes {
                                    let attr_id = nl80211::Attribute::from(attr.identifier);
                                    println!("Attribute: {:?} Len: {}", attr_id, attr.len());
                                }
                            }
                        }
                        self.control_command = command;
                    }
                    else {
                        println!("Other message: {}", m.header);
                    }
                },
                Message::Acknowledge => {
                    println!("ACK {:?}", self.control_command);
                    self.control_command = nl80211::Command::Unspecified;
                },
                Message::Done => {
                    if self.control_command == nl80211::Command::NewScanResults {
      		            print_scan_results(&mut self.scan_results)?;
                    }
                    else {
                        println!("DONE {:?}", self.control_command);
                    }
                    self.control_command = nl80211::Command::Unspecified;
                },
            }
        }
        Ok(())
    }
}

#[derive(PartialEq, Debug)]
enum UserCommand {
    Scan,
    ScheduleScan,
    ScanResults,
    Survey,
    Disconnect,
    Monitor,
    GetRegulatory,
}

impl UserCommand {
    fn requires_root(&self) -> bool {
        match *self {
            UserCommand::Scan => true,
            UserCommand::ScheduleScan => true,
            UserCommand::ScanResults => false,
            UserCommand::Survey => false,
            UserCommand::Disconnect => true,
            UserCommand::Monitor => false,
            UserCommand::GetRegulatory => false,
        }
    }
}

fn main() {
    let matches = App::new("nl80211 example")
        .version("0.1")
        .author("Erik Svensson <erik.public@gmail.com>")
        .arg(Arg::with_name("interface").long("interface").short("i").takes_value(true))
        .subcommand(SubCommand::with_name("scan"))
        .subcommand(SubCommand::with_name("schedule-scan"))
        .subcommand(SubCommand::with_name("scan-results"))
        .subcommand(SubCommand::with_name("disconnect"))
        .subcommand(SubCommand::with_name("survey"))
        .subcommand(SubCommand::with_name("get-regulatory"))
        .get_matches();

    let uid = unsafe { libc::getuid() };

    let interface = matches.value_of("interface");

    let user_command = match matches.subcommand() {
        ("disconnect", _) => { UserCommand::Disconnect },
        ("scan", _) => { UserCommand::Scan },
        ("scan-results", _) => { UserCommand::ScanResults },
        ("schedule-scan", _) => { UserCommand::ScheduleScan },
        ("survey", _) => { UserCommand::Survey },
        ("get-regulatory", _) => { UserCommand::GetRegulatory },
        _ => { UserCommand::Monitor },
    };

    if uid != 0 && user_command.requires_root() {
        println!("Need to be root");
        return;
    }

    let mut control_socket = Socket::new(Protocol::Generic)
        .expect("Failed to open control socket");
    let family = generic::Family::from_name(&mut control_socket, "nl80211")
        .expect("Failed to get nl80211 family");
    let mut devices = nl80211::get_wireless_interfaces(&mut control_socket, family)
        .expect("Failed to get nl80211 wireless interfaces");
    let mut device = None;
    if let Some(if_name) = interface {
        for dev in devices.into_iter() {
            if dev.interface_name == if_name {
                device = Some(dev);
                break;
            }
        }
    }
    else {
        device = Some(devices.remove(0));
    }
    if let Some(dev) = device {
        println!("Using interface {}", dev.interface_name);
        match user_command {
            UserCommand::Disconnect => {
                println!("Disconnect");
                dev.disconnect(&mut control_socket).unwrap();
            }
            UserCommand::Scan => {
                dev.trigger_scan(&mut control_socket).unwrap();
            }
            UserCommand::ScheduleScan => {
                println!("~~~ Stop Scheduled Scan");
                match dev.stop_interval_scan(&mut control_socket) {
                    Ok(_) => (),
                    Err(err) => println!("{}", err),
                }
                println!("~~~ Start Scheduled Scan");
                dev.start_interval_scan(&mut control_socket, 1000).unwrap();
            }
            UserCommand::ScanResults => {
                scan_request_result(&mut control_socket, &dev).unwrap();
            }
            UserCommand::Survey => {
                dev.get_survey(&mut control_socket).unwrap();
            }
            UserCommand::GetRegulatory => {
                dev.get_regulatory(&mut control_socket).unwrap();
            }
            UserCommand::Monitor => {
                let mut monitor = Monitor::new(uid == 0, dev).unwrap();
                monitor.run().unwrap();
            }
        }
    }
    else {
        println!("Failed to find the device");
    }
}
