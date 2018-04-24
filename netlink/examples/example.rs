extern crate netlink;

use std::io;

use netlink::{Socket, Protocol, Message};
use netlink::route;
use netlink::route::InterfaceInformationMessage;
use netlink::generic;

fn get_network_interfaces(socket: &mut Socket)
{
    {
        let tx_msg = route::Message::new(route::FamilyId::GetLink);
        socket.send_message(&tx_msg).unwrap();
    }
    let messages = socket.receive_messages().unwrap();
    for message in messages {
        match message {
            Message::Data(m) => {
                if m.header.identifier == route::FamilyId::NewLink {
                    let msg = InterfaceInformationMessage::parse(&mut io::Cursor::new(m.data)).unwrap();
                    for attr in msg.attributes {
                        if attr.identifier == route::AddressFamilyAttribute::InterfaceName {
                            let name = attr.as_string().unwrap();
                            println!("{}", name);
                        }
                    }
                }
                else {
                    println!("Header: {}", m.header);
                }
            },
            Message::Acknowledge => {
                println!("Acknowledge");
            },
            Message::Done => {
                println!("Done");
            }
        }
    }
}

fn main() {
    let mut gen_socket = Socket::new(Protocol::Generic).unwrap();
    let mut rt_socket = Socket::new(Protocol::Route).unwrap();
    println!("----------------------------------------------------------------");
    println!("get_network_interfaces");
    println!("----------------------------------------------------------------");
    get_network_interfaces(&mut rt_socket);
    println!("----------------------------------------------------------------");
    println!("get_generic_families");
    println!("----------------------------------------------------------------");
    for family in generic::get_generic_families(&mut gen_socket).unwrap() {
        println!("{}", family);
    }
    println!("----------------------------------------------------------------");
    match generic::get_generic_family(&mut gen_socket, "nl80211") {
        Ok(id) => { println!("Found nl80211, {}", id); },
        Err(_) => { println!("Failed to find nl80211"); },
    }
    println!("----------------------------------------------------------------");
    match generic::get_generic_family(&mut gen_socket, "HELLO_THERE") {
        Ok(id) => { println!("Found HELLO_THERE, {}", id); },
        Err(_) => { println!("Failed to find HELLO_THERE"); },
    }
}