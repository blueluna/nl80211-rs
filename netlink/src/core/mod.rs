mod system;
mod hardware_address;
mod variant;
#[macro_use] mod helpers;

use errors::Result;
use kernel;
use libc;
use std::fmt;
use std::str;
use std::io;
use std::io::{Read, Write, Seek, SeekFrom};
use std::mem::size_of;
use std::ffi::{CStr, CString};
use std::os::unix::io::{RawFd, AsRawFd};

pub use self::hardware_address::HardwareAddress;

pub use self::variant::{NativeRead, NativeWrite, NativeParse};

/// A trait for converting a value from one type to another.
/// Any failure in converting will return None.
pub trait ConvertFrom<T: Sized>
    where Self: Sized
{
    fn convert_from(value: T) -> Option<Self>;
}

extended_enum!(Protocol, i32,
    Route => 0,
    Unused => 1,
    Usersock => 2,
    Firewall => 3,
    SockDiag => 4,
    Nflog => 5,
    Xfrm => 6,
    SELinux => 7,
    ISCSI => 8,
    Audit => 9,
    FibLookup => 10,
    Connector => 11,
    Netfilter => 12,
    IP6Fw => 13,
    DNRtMsg => 14,
    KObjectUevent => 15,
    Generic => 16,
    SCSITransport => 17,
    ECryptFs => 18,
    RDMA => 19,
    Crypto => 20,
    SMC => 21
);

const NLMSG_NOOP: u16 = kernel::NLMSG_NOOP as u16;
const NLMSG_ERROR: u16 = kernel::NLMSG_ERROR as u16;
const NLMSG_DONE: u16 = kernel::NLMSG_DONE as u16;

bitflags! {
    pub struct MessageFlags: u16 {
        const REQUEST     = kernel::NLM_F_REQUEST as u16;
        const MULTIPART   = kernel::NLM_F_MULTI as u16;
        const ACKNOWLEDGE = kernel::NLM_F_ACK as u16;
        const DUMP        = kernel::NLM_F_DUMP as u16;
    }
}

pub enum MessageMode {
    None,
    Acknowledge,
    Dump,
}

impl Into<MessageFlags> for MessageMode {
    fn into(self) -> MessageFlags {
        let flags = MessageFlags::REQUEST;
        match self {
            MessageMode::None => flags,
            MessageMode::Acknowledge => flags | MessageFlags::ACKNOWLEDGE,
            MessageMode::Dump => flags | MessageFlags::DUMP,
        }
    }
}

#[inline]
fn align_to(len: usize, align_to: usize) -> usize
{
    (len + align_to - 1) & !(align_to - 1)
}

#[inline]
fn netlink_align(len: usize) -> usize
{
    align_to(len, kernel::NLMSG_ALIGNTO as usize)
}

#[inline]
fn netlink_padding(len: usize) -> usize
{
    netlink_align(len) - len
}

pub trait Sendable {
    fn write<W: Write>(&self, writer: &mut W) -> Result<()>;
    fn message_type(&self) -> u16;
    fn query_flags(&self) -> MessageFlags;
}

pub struct Header {
    pub length: u32,
    pub identifier: u16,
    pub flags: u16,
    pub sequence: u32,
    pub pid: u32,
}

impl Header {
    pub fn parse<R: Read + Seek>(reader: &mut R) -> Result<Header> {
        let length = u32::read(reader)?;
        let identifier = u16::read(reader)?;
        let flags = u16::read(reader)?;
        let sequence = u32::read(reader)?;
        let pid = u32::read(reader)?;
        Ok(Header {
            length: length,
            identifier: identifier,
            flags: flags,
            sequence: sequence,
            pid: pid,
            })
    }

    pub fn length(&self) -> usize {
        self.length as usize
    }

    pub fn data_length(&self) -> usize {
        self.length() - size_of::<Header>()
    }

    pub fn padding(&self) -> usize {
        netlink_padding(self.length())
    }

    pub fn aligned_length(&self) -> usize {
        netlink_align(self.length())
    }

    pub fn aligned_data_length(&self) -> usize {
        netlink_align(self.data_length())
    }

    pub fn check_pid(&self, pid: u32) -> bool {
        self.pid == 0 || self.pid == pid
    }

    pub fn check_sequence(&self, sequence: u32) -> bool {
        self.pid == 0 || self.sequence == sequence
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
            "Length: {0:08x} {0}\nIdentifier: {1:04x}\nFlags: {2:04x}\n\
            Sequence: {3:08x} {3}\nPID: {4:08x} {4}",
            self.length,
            self.identifier,
            self.flags,
            self.sequence,
            self.pid,
        )
    }
}

pub struct DataMessage {
    pub header: Header,
    pub data: Vec<u8>,
}

impl DataMessage {
    pub fn parse<R: Read + Seek>(reader: &mut R, header: Header) -> Result<DataMessage> {
        let mut data = vec![0u8; header.data_length()];
        reader.read_exact(&mut data)?;
        Ok(DataMessage { header: header, data: data })
    }
}

pub struct ErrorMessage {
    pub header: Header,
    pub code: i32,
    pub original_header: Header,
}

impl ErrorMessage {
    pub fn parse<R: Read + Seek>(reader: &mut R, header: Header) -> Result<ErrorMessage> {
        let code = i32::read(reader)?;
        let original_header = Header::parse(reader)?;
        Ok(ErrorMessage { header: header, code: code,
            original_header: original_header })
    }
}

pub enum Message {
    Data(DataMessage),
    Acknowledge,
    Done,
}

pub struct Attribute {
    pub identifier: u16,
    data: Vec<u8>,
}

impl Attribute {
    const HEADER_SIZE: u16 = 4;

    pub fn parse<R: Read + Seek>(reader: &mut R) -> Result<Attribute> {
        let length = u16::read(reader)?;
        let padding = netlink_padding(length as usize) as i64;
        let data_length = (length - Attribute::HEADER_SIZE) as usize;
        let identifier = u16::read(reader)?;
        let mut data = vec![0u8; data_length];
        reader.read_exact(&mut data)?;
        reader.seek(SeekFrom::Current(padding))?;
        Ok(Attribute { identifier: identifier, data: data })
    }
    pub fn new_string<ID: Into<u16>>(identifier: ID, value: &str) -> Attribute {
        let c_string = CString::new(value).unwrap();
        Attribute { identifier: identifier.into(), data: c_string.into_bytes_with_nul() }
    }
    pub fn new<ID: Into<u16>, V: NativeWrite>(identifier: ID, value: V) -> Attribute {
        let mut writer = io::Cursor::new(Vec::new());
        value.write(&mut writer).unwrap();
        Attribute { identifier: identifier.into(), data: writer.into_inner() }
    }
    pub fn len(&self) -> u16 {
        self.data.len() as u16
    }
    pub fn total_len(&self) -> usize {
        netlink_align(self.data.len() + 4)
    }
    pub fn as_u16(&self) -> Result<u16> {
        u16::parse(&self.data)
    }
    pub fn as_i32(&self) -> Result<i32> {
        i32::parse(&self.data)
    }
    pub fn as_u32(&self) -> Result<u32> {
        u32::parse(&self.data)
    }
    pub fn as_u64(&self) -> Result<u64> {
        u64::parse(&self.data)
    }
    pub fn as_string(&self) -> Result<String> {
        match CStr::from_bytes_with_nul(&self.data) {
            Ok(bytes) => {
                let s = bytes.to_str()?;
                Ok(String::from(s))
            },
            Err(_) => {
                let s = str::from_utf8(&self.data)?;
                Ok(String::from(s))
            }
        }
    }
    pub fn as_hardware_address(&self) -> Result<HardwareAddress> {
        HardwareAddress::parse(&self.data)
    }
    pub fn as_bytes(&self) -> Vec<u8> {
        self.data.clone()
    }
    pub fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        let length = (self.len() + Attribute::HEADER_SIZE) as u16;
        length.write(writer)?;
        self.identifier.write(writer)?;
        writer.write_all(&self.data)?;
        Ok(())
    }
}

pub fn parse_attributes<R: Read + Seek>(reader: &mut R) -> Vec<Attribute>
{
    let mut attrs = vec![];
    let mut run = true;
    while run {
        match Attribute::parse(reader) {
            Ok(attr) => { attrs.push(attr); },
            Err(_) => { run = false; },
        }
    }
    attrs
}

/// Netlink Socket can be used to communicate with the Linux kernel using the
/// netlink protocol.
pub struct Socket {
    local: kernel::sockaddr_nl,
    peer: kernel::sockaddr_nl,
    socket: RawFd,
    sequence_next: u32,
    sequence_expected: u32,
    page_size: usize,
    receive_buffer: Vec<u8>,
    send_buffer: Vec<u8>,
    acknowledge_expected: bool,
}

impl Socket {
    /// Create a new Socket
    pub fn new(protocol: Protocol) -> Result<Socket>
    {
        Socket::new_multicast(protocol, 0)
    }

    /// Create a new Socket which subscribes to the provided multi-cast groups
    pub fn new_multicast(protocol: Protocol, groups: u32) -> Result<Socket>
    {
        let socket = system::netlink_socket(protocol as i32)?;
        system::set_socket_option(socket, libc::SOL_SOCKET, libc::SO_SNDBUF, 32768)?;
        system::set_socket_option(socket, libc::SOL_SOCKET, libc::SO_RCVBUF, 32768)?;
        let mut local_addr = kernel::sockaddr_nl {
            nl_family: libc::AF_NETLINK as u16,
            nl_pad: 0,
            nl_pid: 0,
            nl_groups: groups,
        };
        system::bind(socket, local_addr)?;
        system::get_socket_address(socket, &mut local_addr)?;
        let page_size = netlink_align(system::get_page_size());
        let peer_addr = kernel::sockaddr_nl {
            nl_family: libc::AF_NETLINK as u16,
            nl_pad: 0,
            nl_pid: 0,
            nl_groups: groups,
        };
        Ok(Socket {
            local: local_addr,
            peer: peer_addr,
            socket: socket,
            sequence_next: 1,
            sequence_expected: 0,
            page_size: page_size,
            receive_buffer: vec![0u8; page_size],
            send_buffer: vec![0u8; page_size],
            acknowledge_expected: false,
        })
    }

    /// Subscribe to the multi-cast group provided
    pub fn multicast_group_subscribe(&mut self, group: u32) -> Result<()>
    {
        system::set_socket_option(self.socket, libc::SOL_NETLINK,
            kernel::NETLINK_ADD_MEMBERSHIP as i32, group as i32)?;
        Ok(())
    }

    #[cfg(not(target_env = "musl"))]
    fn message_header(&mut self, iov: &mut [libc::iovec]) -> libc::msghdr
    {
        let addr_ptr = &mut self.peer as *mut kernel::sockaddr_nl;
        libc::msghdr {
            msg_iovlen: iov.len(),
            msg_iov: iov.as_mut_ptr(),
            msg_namelen: size_of::<kernel::sockaddr_nl>() as u32,
            msg_name: addr_ptr as *mut libc::c_void,
            msg_flags: 0,
            msg_controllen: 0,
            msg_control: 0 as *mut libc::c_void,
        }
    }

    #[cfg(target_env = "musl")]
    fn message_header(&mut self, iov: &mut [libc::iovec]) -> libc::msghdr
    {
        let addr_ptr = &mut self.peer as *mut kernel::sockaddr_nl;
        libc::msghdr {
            msg_iovlen: iov.len() as i32,
            msg_iov: iov.as_mut_ptr(),
            msg_namelen: size_of::<kernel::sockaddr_nl>() as u32,
            msg_name: addr_ptr as *mut libc::c_void,
            msg_flags: 0,
            msg_controllen: 0,
            msg_control: 0 as *mut libc::c_void,
        }
    }

    /// Send the provided package on the socket
    pub fn send_message<S: Sendable>(&mut self, payload: &S) -> Result<usize>
    {
        self.send_buffer.clear();
        let mut writer = io::Cursor::new(vec![0u8; self.page_size]);
        let hdr_size = netlink_align(size_of::<kernel::nlmsghdr>());
        writer.seek(SeekFrom::Start(hdr_size as u64))?;
        payload.write(&mut writer)?;
        let payload_size = writer.seek(SeekFrom::Current(0))? as usize;
        writer.seek(SeekFrom::Start(0))?;
        (payload_size as u32).write(&mut writer)?;
        payload.message_type().write(&mut writer)?;
        let flags = payload.query_flags();
        flags.bits().write(&mut writer)?;
        self.sequence_next.write(&mut writer)?;
        self.local.nl_pid.write(&mut writer)?;

        let mut iov = [
            libc::iovec {
                iov_base: writer.get_mut().as_mut_ptr() as *mut libc::c_void,
                iov_len: payload_size, 
            },
        ];

        let msg_header = self.message_header(&mut iov);
        
        self.acknowledge_expected = flags.contains(MessageFlags::ACKNOWLEDGE);
        self.sequence_expected = self.sequence_next;
        self.sequence_next += 1;

        Ok(system::send_message(self.socket, &msg_header, 0)?)
    }

    fn receive_bytes(&mut self) -> Result<usize>
    {
        let mut iov = [
            libc::iovec {
                iov_base: self.receive_buffer.as_mut_ptr() as *mut libc::c_void,
                iov_len: self.page_size,
            },
        ];
        let mut msg_header = self.message_header(&mut iov);
        let result = system::receive_message(self.socket, &mut msg_header);
        match result {
            Err(err) => {
                if err.raw_os_error() == Some(libc::EAGAIN) {
                    return Ok(0);
                }
                Err(err.into())
            }
            Ok(bytes) => {
                Ok(bytes)
            }
        }
    }

    /// Receive binary data on the socket
    pub fn receive(&mut self) -> Result<Vec<u8>>
    {
        let bytes = self.receive_bytes()?;
        Ok(self.receive_buffer[0..bytes].to_vec())
    }

    /// Receive Messages pending on the socket
    pub fn receive_messages(&mut self) -> Result<Vec<Message>>
    {
        let mut more_messages = true;
        let mut result_messages = Vec::new();
        while more_messages {
            match self.receive_bytes() {
                Err(err) => {
                    return Err(err);
                }
                Ok(bytes) => {
                    if bytes == 0 {
                        break;
                    }
                    more_messages = self.parse_data(bytes, &mut result_messages)?;
                }
            }
        }
        Ok(result_messages)
    }

    fn parse_data(&self, bytes: usize, messages: &mut Vec<Message>) -> Result<bool>
    {
        let mut more_messages = false;
        let mut reader = io::Cursor::new(&self.receive_buffer[0..bytes]);
        let mut pos = 0;
        while pos < bytes {
            reader.seek(SeekFrom::Start(pos as u64))?;
            let header = Header::parse(&mut reader)?;
            pos = pos + header.aligned_length();
            if !header.check_pid(self.local.nl_pid) {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid PID").into());
            }
            if !header.check_sequence(self.sequence_expected) {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid Sequence").into());
            }
            if header.identifier == NLMSG_NOOP {
                continue;
            }
            else if header.identifier == NLMSG_ERROR {
                let emsg = ErrorMessage::parse(&mut reader, header)?;
                if emsg.code != 0 {
                    return Err(io::Error::from_raw_os_error(-emsg.code).into());
                }
                else {
                    messages.push(Message::Acknowledge);
                }
            }
            else if header.identifier == NLMSG_DONE {
                messages.push(Message::Done);
            }
            else {
                let flags = MessageFlags::from_bits(header.flags).unwrap_or(MessageFlags::empty());
                messages.push(Message::Data(DataMessage::parse(&mut reader, header)?));
                if flags.contains(MessageFlags::MULTIPART) || self.acknowledge_expected {
                    more_messages = true;
                }
            }
        }
        return Ok(more_messages);
    }
}

impl AsRawFd for Socket {
    fn as_raw_fd(&self) -> RawFd
    {
        self.socket
    }
}
