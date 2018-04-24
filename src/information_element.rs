
use std::io::Read;
use netlink::{NativeRead, Error};

pub struct InformationElement
{
    pub identifier: u8,
    pub data: Vec<u8>,
}

impl InformationElement {
    pub fn parse<R: Read>(reader: &mut R) -> Result<InformationElement, Error> {
        let identifier = u8::read(reader)?;
        let length = u8::read(reader)? as usize;
        let mut data = vec![0u8; length];
        reader.read_exact(&mut data)?;
        Ok(InformationElement { identifier: identifier, data: data })
    }
}

pub struct InformationElements
{
    pub elements: Vec<InformationElement>,
}

impl InformationElements {
    pub fn parse<R: Read>(reader: &mut R) -> InformationElements {
        let mut elements = vec![];
        loop {
            match InformationElement::parse(reader) {
                Ok(ie) => elements.push(ie),
                Err(_) => break,
            }
        }
        InformationElements {
            elements: elements,
        }
    }
}