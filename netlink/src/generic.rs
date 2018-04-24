use std::fmt;
use std::io;
use std::io::{Read, Seek, Write};

use std::convert::{From, Into};

use errors::Result;

use core;
use core::{Attribute, Sendable, MessageFlags, MessageMode,
    NativeRead, NativeWrite, ConvertFrom};

extended_enum!(FamilyId, u16,
    Control => 16,
    VirtualFileSystemDiskQuota => 17,
    Raid => 18,
);

extended_enum_default!(Command, u8,
    Unspecified => 0,
    NewFamily => 1,
    DelFamily => 2,
    GetFamily => 3,
    NewOps => 4,
    DelOps => 5,
    GetOps => 6,
    NewMulticastGroup => 7,
    DelMulticastGroup => 8,
    GetMulticastGroup => 9,
);

extended_enum_default!(AttributeId, u16,
    Unspecified => 0,
    FamilyId => 1,
    FamilyName => 2,
    Version => 3,
    HeaderSize => 4,
    MaximumAttributes => 5,
    Operations => 6,
    MulticastGroups => 7,
);

extended_enum_default!(OperationAttributeId, u16,
    Unspecified => 0,
    Id => 1,
    Flags => 2,
);

extended_enum_default!(MulticastAttributeId, u16,
    Unspecified => 0,
    Name => 1,
    Id => 2,
);

pub struct Message {
    pub family: u16,
    pub command: u8,
    pub version: u8,
    pub flags: MessageFlags,
    pub attributes: Vec<Attribute>,
}

impl Message {
    pub fn new<F: Into<u16>, C: Into<u8>, M: Into<MessageFlags>>
        (family: F, command: C, mode: M) -> Message {
        return Message {
            family: family.into(),
            command: command.into(),
            version: 1u8,
            flags: mode.into(),
            attributes: vec!(),
            };
    }

    pub fn parse<R: Read + Seek>(reader: &mut R) -> Result<Message> {
        let command = u8::read(reader)?;
        let version = u8::read(reader)?;
        let _ = u16::read(reader)?;
        let attributes = core::parse_attributes(reader);
        Ok(Message {
            family: 0xffff,
            command: command,
            version: version,
            flags: MessageFlags::from_bits_truncate(0),
            attributes: attributes,
            })
    }

    pub fn family(&self) -> u16 { self.family.clone().into() }

    pub fn set_flags(&mut self, flags: MessageFlags) { self.flags = flags; }

    pub fn append_attribute(&mut self, attr: Attribute)
    {
        self.attributes.push(attr);
    }
}

impl Sendable for Message {
    fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        self.command.write(writer)?;
        self.version.write(writer)?;
        0u16.write(writer)?;
        for attr in self.attributes.iter() {
            attr.write(writer)?;
        }
        Ok(())
    }
    fn message_type(&self) -> u16 { self.family.clone().into() }
    fn query_flags(&self) -> MessageFlags { self.flags }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
            "Family: {} Command: {} Version: {} Flags: {:x} Attribute Count: {}",
            self.family, self.command, self.version, self.flags.bits(),
            self.attributes.len()
        )
    }
}

/// Netlink generic Multi-cast group
/// 
/// Contains identifier, name for a Netlink multi-cast group.
pub struct MultiCastGroup {
    pub id: u32,
    pub name: String,
}

impl MultiCastGroup {
    fn from_bytes(bytes: &[u8]) -> Result<MultiCastGroup>
    {
        let attributes = core::parse_attributes(&mut io::Cursor::new(bytes));
        let mut group_name = String::new();
        let mut group_id = None;
        for attribute in attributes {
            match MulticastAttributeId::from(attribute.identifier) {
                MulticastAttributeId::Unspecified => {}
                MulticastAttributeId::Id => {
                    group_id = attribute.as_u32().ok();
                }
                MulticastAttributeId::Name => {
                    group_name = attribute.as_string()?;
                }
            }
        }
        if let Some(id) = group_id {
            return Ok(MultiCastGroup {
                id: id,
                name: group_name,
            });
        }
        Err(io::Error::new(io::ErrorKind::InvalidData, "").into())
    }
}

impl fmt::Display for MultiCastGroup {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "MultiCast Group: {} Name: {}", self.id, self.name)
    }
}

/// Netlink generic family
/// 
/// Contains identifier, name and multi-cast groups for a Netlink family.
pub struct Family {
    pub id: u16,
    pub name: String,
    pub multicast_groups: Vec<MultiCastGroup>,
}

impl Family {
    fn from_message(message: Message) -> Result<Family>
    {
        let mut family_name = String::new();
        let mut family_id = 0u16;
        let mut groups = vec![];
        for attr in message.attributes {
            match AttributeId::from(attr.identifier) {
                AttributeId::Unspecified => {}
                AttributeId::FamilyName => {
                    family_name = attr.as_string()?;
                }
                AttributeId::FamilyId => {
                    family_id = attr.as_u16()?;
                }
                AttributeId::MulticastGroups => {
                    let mcs_attributes = core::parse_attributes(&mut io::Cursor::new(attr.as_bytes()));
                    for mcs_attr in mcs_attributes {
                        groups.push(MultiCastGroup::from_bytes(&mcs_attr.as_bytes())?);
                    }
                }
                _ => {}
            }
        }
        if family_id > 0 {
            return Ok(Family { id: family_id, name: family_name, multicast_groups: groups });
        }
        Err(io::Error::new(io::ErrorKind::NotFound, "Family Not Found").into())
    }
}

impl fmt::Display for Family {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Generic Family: {} Name: {}", self.id, self.name)
    }
}

pub fn get_generic_families(socket: &mut core::Socket) -> Result<Vec<Family>>
{
    {
        let tx_msg = Message::new(FamilyId::Control, Command::GetFamily, MessageMode::Dump);
        socket.send_message(&tx_msg)?;
    }
    let messages = socket.receive_messages()?;
    let mut families = vec![];
    for message in messages {
        match message {
            core::Message::Data(m) => {
                if FamilyId::from(m.header.identifier) == FamilyId::Control {
                    let msg = Message::parse(&mut io::Cursor::new(m.data))?;
                    families.push(Family::from_message(msg)?);
                }
            },
            core::Message::Acknowledge => (),
            core::Message::Done => { break; }
        }
    }
    return Ok(families)
}

pub fn get_generic_family(socket: &mut core::Socket, name: &str) -> Result<Family>
{
    {
        let mut tx_msg = Message::new(FamilyId::Control, Command::GetFamily, MessageMode::Acknowledge);
        tx_msg.attributes.push(Attribute::new_string(AttributeId::FamilyName, name));
        socket.send_message(&tx_msg)?;
    }
    loop {
        let messages = socket.receive_messages()?;
        if messages.is_empty() {
            break;
        }
        for message in messages {
            match message {
                core::Message::Data(m) => {
                    if FamilyId::convert_from(m.header.identifier) == Some(FamilyId::Control) {
                        let msg = Message::parse(&mut io::Cursor::new(m.data))?;
                        let family = Family::from_message(msg)?;
                        if family.name == name {
                            return Ok(family);
                        }
                    }
                },
                _ => (),
            }
        }
    }
    Err(io::Error::new(io::ErrorKind::NotFound, "Generic family not found").into())
}
