use std::io;
use std::fmt;
use netlink_rust as netlink;
use netlink_rust::{Error, ConvertFrom};
use netlink_rust::generic;
use attributes::{Attribute};
use commands::Command;

pub struct WirelessPhy {
    identifier: u32,
    commands: Vec<Command>,
}

impl WirelessPhy {
    pub fn from_message(message: generic::Message)
        -> Result<WirelessPhy, Error>
    {
        let mut phy_id = None;
        let mut commands = vec![];
        for attr in message.attributes {
            let identifier = Attribute::from(attr.identifier);
            match identifier {
                Attribute::Wiphy => {
                    phy_id = Some(attr.as_u32()?);
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
                commands,
            })
        }
        else {
            Err(io::Error::new(io::ErrorKind::NotFound,
                "Wireless Phy Not Found").into())
        }
    }
}

impl fmt::Display for WirelessPhy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Wireless Phy\n  Identifier: {}\n  Commands: {:?}",
        self.identifier, self.commands)

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
    loop {
        let messages = socket.receive_messages()?;
        if messages.is_empty() {
            break;
        }
        else {
            for message in messages {
                if let netlink::Message::Data(m) = message {
                    if m.header.identifier == family_id {
                        let (_, gmsg) = generic::Message::unpack(&m.data)?;
                        if let  Ok(phy) = WirelessPhy::from_message(gmsg) {
                            phys.push(phy)
                        }
                    }
                }
            }
        }
    }
    Ok(phys)
}