use std::convert::From;
use std::io;
use std::fmt;

use netlink_rust::{Result, HardwareAddress};

use unpack::{LittleUnpack};

#[derive(Debug, PartialEq)]
pub enum FrameType {
    Management,
    Control,
    Data,
    Reserved,
}

#[derive(Debug, PartialEq)]
pub enum FrameSubtype {
    Reserved,
    // Management
    AssociationRequest,
    AssociationResponse,
    ReassociationRequest,
    ReassociationResponse,
    ProbeRequest,
    ProbeResponse,
    TimingAdvertisment,
    Beacon,
    AnnouncementTrafficIndication,
    Disassociation,
    Authentication,
    Deauthentication,
    Action,
    ActionNoAcknowledge,
    // Control
    ControlWrapper,
    BlockAcknowledgeRequest,
    BlockAcknowledge,
    PowerSavePoll,
    RequestToSend,
    ClearToSend,
    Acknowledge,
    ContentionFreeEnd,
    ContentionFreeEndAcknowledge,
    // Data
    Data,
    DataContentionFreeAcknowledge,
    DataContentionFreePoll,
    DataContentionFreeAcknowledgePoll,
    Null,
    NullContentionFreeAcknowledge,
    NullContentionFreePoll,
    NullContentionFreeAcknowledgePoll,
    QualityOfService,
    QualityOfServiceContentionFreeAcknowledge,
    QualityOfServiceContentionFreePoll,
    QualityOfServiceContentionFreeAcknowledgePoll,
    NullQualityOfService,
    NullQualityOfServiceContentionFreeAcknowledge,
    NullQualityOfServiceContentionFreePoll,
    NullQualityOfServiceContentionFreeAcknowledgePoll,
}

#[derive(Debug, PartialEq)]
pub struct FrameControl {
    field: u16,
}

impl From<FrameControl> for u16 {
    fn from(value: FrameControl) -> Self { value.field }
}

impl From<u16> for FrameControl {
    fn from(value: u16) -> Self { FrameControl { field: value } }
}

impl FrameControl {
    pub fn get_type(&self) -> FrameType {
        match (self.field >> 2) & 0x0003 {
            0 => FrameType::Management,
            1 => FrameType::Control,
            2 => FrameType::Data,
            _ => FrameType::Reserved,
        }
    }
    pub fn get_subtype(&self) -> FrameSubtype {
        let subtype = (self.field >> 4) & 0x000f;
        match self.get_type() {
            FrameType::Management => {
                match subtype {
                    0b0000 => FrameSubtype::AssociationRequest,
                    0b0001 => FrameSubtype::AssociationResponse,
                    0b0010 => FrameSubtype::ReassociationRequest,
                    0b0011 => FrameSubtype::ReassociationResponse,
                    0b0100 => FrameSubtype::ProbeRequest,
                    0b0101 => FrameSubtype::ProbeResponse,
                    0b0110 => FrameSubtype::TimingAdvertisment,
                    0b1000 => FrameSubtype::Beacon,
                    0b1001 => FrameSubtype::AnnouncementTrafficIndication,
                    0b1010 => FrameSubtype::Disassociation,
                    0b1011 => FrameSubtype::Authentication,
                    0b1100 => FrameSubtype::Deauthentication,
                    0b1101 => FrameSubtype::Action,
                    0b1110 => FrameSubtype::ActionNoAcknowledge,
                    _ => FrameSubtype::Reserved,
                }
            }
            FrameType::Control => {
                match subtype {
                    0b0111 => FrameSubtype::ControlWrapper,
                    0b1000 => FrameSubtype::BlockAcknowledgeRequest,
                    0b1001 => FrameSubtype::BlockAcknowledge,
                    0b1010 => FrameSubtype::PowerSavePoll,
                    0b1011 => FrameSubtype::RequestToSend,
                    0b1100 => FrameSubtype::ClearToSend,
                    0b1101 => FrameSubtype::Acknowledge,
                    0b1110 => FrameSubtype::ContentionFreeEnd,
                    0b1111 => FrameSubtype::ContentionFreeEndAcknowledge,
                    _ => FrameSubtype::Reserved,
                }
            }
            FrameType::Data => {
                match subtype {
                    0b0000 => FrameSubtype::Data,
                    0b0001 => FrameSubtype::DataContentionFreeAcknowledge,
                    0b0010 => FrameSubtype::DataContentionFreePoll,
                    0b0011 => FrameSubtype::DataContentionFreeAcknowledgePoll,
                    0b0100 => FrameSubtype::Null,
                    0b0101 => FrameSubtype::NullContentionFreeAcknowledge,
                    0b0110 => FrameSubtype::NullContentionFreePoll,
                    0b0111 => FrameSubtype::NullContentionFreeAcknowledgePoll,
                    0b1000 => FrameSubtype::QualityOfService,
                    0b1001 => FrameSubtype::QualityOfServiceContentionFreeAcknowledge,
                    0b1010 => FrameSubtype::QualityOfServiceContentionFreePoll,
                    0b1011 => FrameSubtype::QualityOfServiceContentionFreeAcknowledgePoll,
                    0b1100 => FrameSubtype::NullQualityOfService,
                    0b1101 => FrameSubtype::NullQualityOfServiceContentionFreeAcknowledge,
                    0b1110 => FrameSubtype::NullQualityOfServiceContentionFreePoll,
                    0b1111 => FrameSubtype::NullQualityOfServiceContentionFreeAcknowledgePoll,
                    _ => FrameSubtype::Reserved,
                }
            }
            FrameType::Reserved => {
                FrameSubtype::Reserved
            }
        }
    }
    pub fn get_to_ds(&self) -> bool {
        self.field & 0x0100 == 0x0100
    }
    pub fn get_from_ds(&self) -> bool {
        self.field & 0x0200 == 0x0200
    }
    pub fn get_more_fragments(&self) -> bool {
        self.field & 0x0400 == 0x0400
    }
    pub fn get_retry(&self) -> bool {
        self.field & 0x0800 == 0x0800
    }
    pub fn get_power_management(&self) -> bool {
        self.field & 0x1000 == 0x1000
    }
    pub fn get_more_data(&self) -> bool {
        self.field & 0x2000 == 0x2000
    }
    pub fn get_protected(&self) -> bool {
        self.field & 0x4000 == 0x4000
    }
    pub fn get_order(&self) -> bool {
        self.field & 0x8000 == 0x8000
    }
}

impl fmt::Display for FrameControl {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{0:04x} {1:?}", self.field, self.get_subtype())
    }
}

#[derive(Debug, PartialEq)]
pub struct FrameDuration {
    field: u16,
}

impl From<FrameDuration> for u16 {
    fn from(value: FrameDuration) -> Self { value.field }
}

impl From<u16> for FrameDuration {
    fn from(value: u16) -> Self { FrameDuration { field: value } }
}

#[derive(Debug, PartialEq)]
pub struct FrameSequence {
    field: u16,
}

impl From<FrameSequence> for u16 {
    fn from(value: FrameSequence) -> Self { value.field }
}

impl From<u16> for FrameSequence {
    fn from(value: u16) -> Self { FrameSequence { field: value } }
}

#[derive(Debug, PartialEq)]
pub struct ManagementFrame {
    control: FrameControl,
    duration: FrameDuration,
    address1: HardwareAddress,
    address2: HardwareAddress,
    address3: HardwareAddress,
    sequence: FrameSequence,
    high_throughput_control: Option<u32>,
}

impl ManagementFrame {
    fn unpack(control: FrameControl, duration: FrameDuration, buffer: &[u8])
        -> Result<Self> {
        let order = control.get_order();
        let length = if order { 24 } else { 20 };
        if buffer.len() > length {
            let a1 = HardwareAddress::unpack_unchecked(&buffer[..]);
            let a2 = HardwareAddress::unpack_unchecked(&buffer[6..]);
            let a3 = HardwareAddress::unpack_unchecked(&buffer[12..]);
            let sequence = FrameSequence::from(
                u16::unpack_unchecked(&buffer[18..]));
            let htc = if order {
                Some(u32::unpack_unchecked(&buffer[20..]))
            } else { None };
            return Ok(ManagementFrame {
                control,
                duration,
                address1: a1,
                address2: a2,
                address3: a3,
                sequence,
                high_throughput_control: htc,
            });
        }
        Err(io::Error::new(io::ErrorKind::InvalidData, "").into())
    }
}

impl fmt::Display for ManagementFrame {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} {} {}", self.control, self.address1, self.address2,
            self.address3)
    }
}

#[derive(Debug, PartialEq)]
pub struct ControlFrame {
    control: FrameControl,
    duration: FrameDuration,
    address1: HardwareAddress,
}

impl fmt::Display for ControlFrame {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}", self.control, self.address1)
    }
}

impl ControlFrame {
    fn unpack(control: FrameControl, duration: FrameDuration, buffer: &[u8])
        -> Result<Self> {
        if buffer.len() > 6 {
            let a1 = HardwareAddress::unpack_unchecked(&buffer[..]);
            return Ok(ControlFrame {
                control,
                duration,
                address1: a1,
            });
        }
        Err(io::Error::new(io::ErrorKind::InvalidData, "").into())
    }
}

#[derive(Debug, PartialEq)]
pub struct DataFrame {
    control: FrameControl,
    duration: FrameDuration,
    address1: HardwareAddress,
    address2: HardwareAddress,
    address3: HardwareAddress,
    sequence: FrameSequence,
    address4: HardwareAddress,
    quality_of_service_control: u16,
    high_throughput_control: u32,
}

impl fmt::Display for DataFrame {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}", self.control, self.address1)
    }
}

impl DataFrame {
    fn unpack(control: FrameControl, duration: FrameDuration, buffer: &[u8])
        -> Result<Self> {
        if buffer.len() > 32 {
            let a1 = HardwareAddress::unpack_unchecked(&buffer[..]);
            let a2 = HardwareAddress::unpack_unchecked(&buffer[6..]);
            let a3 = HardwareAddress::unpack_unchecked(&buffer[12..]);
            let sequence = u16::unpack_unchecked(&buffer[18..]);
            let a4 = HardwareAddress::unpack_unchecked(&buffer[20..]);
            let qos = u16::unpack_unchecked(&buffer[26..]);
            let ht = u32::unpack_unchecked(&buffer[28..]);
            return Ok(DataFrame {
                control,
                duration,
                address1: a1,
                address2: a2,
                address3: a3,
                sequence: FrameSequence::from(sequence),
                address4: a4,
                quality_of_service_control: qos,
                high_throughput_control: ht,
            });
        }
        Err(io::Error::new(io::ErrorKind::InvalidData, "").into())
    }
}

#[derive(Debug, PartialEq)]
pub enum Frame {
    Management(ManagementFrame),
    Control(ControlFrame),
    Data(DataFrame),
}

impl Frame {
    pub fn unpack(buffer: &[u8]) -> Result<Frame> {
        if buffer.len() > 4 {
            let control = FrameControl::from(u16::unpack_unchecked(&buffer[..]));
            let duration = FrameDuration::from(u16::unpack_unchecked(&buffer[2..]));
            match control.get_type() {
                FrameType::Management => {
                    let management = ManagementFrame::unpack(control,
                        duration, &buffer[4..])?;
                    return Ok(Frame::Management(management));
                },
                FrameType::Control => {
                    let control = ControlFrame::unpack(control,
                        duration, &buffer[4..])?;
                    return Ok(Frame::Control(control));
                },
                FrameType::Data => {
                    let data = DataFrame::unpack(control,
                        duration, &buffer[4..])?;
                    return Ok(Frame::Data(data));
                },
                _ => ()
            }
        }
        Err(io::Error::new(io::ErrorKind::InvalidData, "").into())
    }
}

impl fmt::Display for Frame {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Frame::Management(ref frame) => {
                write!(f, "{}", frame)
            },
            Frame::Control(ref frame) => {
                write!(f, "{}", frame)
            },
            Frame::Data(ref frame) => {
                write!(f, "{}", frame)
            },
        }
    }
}
