use libc;
use std::mem::size_of;
use std::io;
use std::os::unix::io::RawFd;

#[repr(C)]
pub struct Address {
    pub family: u16,
    pub _pad: u16,
    pub pid: u32,
    pub groups: u32,
}

macro_rules! ccall {
    ( $x:expr ) => {{
        let value = unsafe { $x };
        if value < 0 {
            return Err(io::Error::last_os_error());
        }
        value
    }};
}

pub fn get_page_size() -> usize
{
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

pub fn netlink_socket(service: i32) -> io::Result<RawFd>
{
    Ok(ccall!(libc::socket(libc::AF_NETLINK,
        libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
        service)))
}

pub fn set_socket_option(socket: RawFd, level: i32, name: i32, value: i32) -> io::Result<()>
{
    let value_ptr: *const i32 = &value;
    ccall!(libc::setsockopt(socket, level, name, value_ptr as *mut libc::c_void,
        size_of::<i32>() as u32));
    Ok(())
}

pub fn bind(socket: RawFd, address: &Address) -> io::Result<()>
{
    let addr_ptr: *const Address = address;
    ccall!(libc::bind(socket, addr_ptr as *const libc::sockaddr,
        size_of::<Address>() as u32));
    Ok(())
}

pub fn get_socket_address(socket: RawFd, address: &mut Address) -> io::Result<()>
{
    let addr_ptr = address as *mut Address as *mut libc::sockaddr;
    let mut addr_len = size_of::<Address>() as libc::socklen_t;
    let addr_len_ptr: *mut libc::socklen_t = &mut addr_len;
    ccall!(libc::getsockname(socket, addr_ptr, addr_len_ptr));
    Ok(())
}

pub fn send_message(socket: RawFd, header: &libc::msghdr, flags: i32) -> io::Result<usize>
{
    Ok(ccall!(libc::sendmsg(socket, header as *const libc::msghdr, flags)) as usize)
}

pub fn receive_message(socket: RawFd, header: &mut libc::msghdr) -> io::Result<usize>
{
    Ok(ccall!(libc::recvmsg(socket, header as *mut libc::msghdr, 0)) as usize)
}
