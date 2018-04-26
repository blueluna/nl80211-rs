#![recursion_limit = "1024"]

extern crate libc;
extern crate byteorder;
#[macro_use] extern crate bitflags;
#[macro_use] extern crate error_chain;

mod errors;
mod kernel;
#[macro_use] mod core;
pub mod route;
pub mod generic;

pub use errors::{Error, Result};
pub use core::{HardwareAddress, Socket, Message, Attribute, Protocol,
    MessageMode, parse_attributes, NativeRead, NativeWrite, ConvertFrom};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_get_link() {
        let mut socket = Socket::new(Protocol::Route).unwrap();
        let msg = route::Message::new(route::FamilyId::GetLink);
        socket.send_message(&msg).unwrap();
        let _ = socket.receive_messages().unwrap();
    }
}