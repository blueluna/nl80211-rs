use std::io;
use netlink;
use netlink::{Socket, Message, MessageMode, Error};
use netlink::generic;
use attributes::{Attribute, InterfaceType};
use commands::Command;

pub fn get_wireless_phys(socket: &mut Socket, family_id: u16) -> Result<(), Error>
{
    {
        let tx_msg = generic::Message::new(family_id, Command::GetWiphy, MessageMode::Dump);
        socket.send_message(&tx_msg)?;
    }
    loop {
        let messages = socket.receive_messages()?;
        if messages.is_empty() {
            break;
        }
        else {
            for message in messages {
                match message {
                    Message::Data(m) => {
                        if m.header.identifier == family_id {
                            match generic::Message::parse(&mut io::Cursor::new(m.data)) {
                                Ok(message) => {
                                    for attr in message.attributes {
                                        let id = Attribute::from(attr.identifier);
                                        match id {
                                            Attribute::SupportedIftypes => {
                                                println!("Supported Interface Types {}", attr.len());

                                                let sas = netlink::parse_attributes(&mut io::Cursor::new(attr.as_bytes()));
                                                for sa in sas {
                                                    let sa_id = InterfaceType::from(sa.identifier as u32);
                                                    println!("    {:?} {}", sa_id, sa.len());
                                                }
                                            }
                                            Attribute::SoftwareIftypes => {
                                                println!("Software Interface Types {}", attr.len());
                                                let sas = netlink::parse_attributes(&mut io::Cursor::new(attr.as_bytes()));
                                                for sa in sas {
                                                    let sa_id = InterfaceType::from(sa.identifier as u32);
                                                    println!("    {:?} {}", sa_id, sa.len());
                                                }
                                            }
                                            _ => {
                                                println!("  {:?} {}", id, attr.len());
                                            }
                                        }
                                    }
                                },
                                Err(error) => println!("Failed to parse message, {}", error),
                            }
                        }
                    },
                    _ => (),
                }
            }
        }
    }
    Ok(())
}