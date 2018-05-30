use std::io;
use std::fmt;
use netlink;
use netlink::{Error, ConvertFrom}   ;
use netlink::generic;
use attributes::{Attribute};
use commands::Command;

pub struct WirelessPhy {
    identifier: u32,
    commands: Vec<Command>,
}

impl WirelessPhy {
    pub fn from_message(message: generic::Message) -> Result<WirelessPhy, Error>
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
                    let attrs = netlink::parse_attributes(&mut io::Cursor::new(attr.as_bytes()));
                    for attr in attrs {
                        match Command::convert_from(attr.as_u32()? as u8) {
                            Some(cmd) => commands.push(cmd),
                            None => (),
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
                commands: commands,
            })
        }
        else {
            Err(io::Error::new(io::ErrorKind::NotFound, "Wireless Phy Not Found").into())
        }
    }
}

impl fmt::Display for WirelessPhy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Wireless Phy\n  Identifier: {}\n  Commands: {:?}",
        self.identifier, self.commands)

    }
}

pub fn get_wireless_phys(socket: &mut netlink::Socket, family_id: u16) -> Result<Vec<WirelessPhy>, Error>
{
    {
        let tx_msg = generic::Message::new(family_id, Command::GetWiphy, netlink::MessageMode::Dump);
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
                match message {
                    netlink::Message::Data(m) => {
                        if m.header.identifier == family_id {
                            let gmsg = generic::Message::parse(&mut io::Cursor::new(m.data))?;
                            match WirelessPhy::from_message(gmsg) {
                                Ok(phy) => phys.push(phy),
                                Err(_) => (),
                            }
                        }
                    },
                    _ => (),
                }
            }
        }
    }
    Ok(phys)
}