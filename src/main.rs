extern crate pnet;

use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::*;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::net::IpAddr;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "netspeeder", about = "Resend tcp/udp packets.")]
struct Opt {
    interface_name: String,
    target: String,
    #[structopt(default_value = "0")]
    count: i32,
}

const SPECIAL_TTL: u8 = 88;

fn main() {
    let opt = Opt::from_args();
    let interface_name = opt.interface_name;
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(|iface| iface.name == interface_name)
        .next()
        .unwrap();

    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type: {}"),
        Err(e) => panic!("Unable to create channel: {}", e),
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                let ethernet = EthernetPacket::new(packet).unwrap();
                match ethernet.get_ethertype() {
                    EtherTypes::Ipv4 => {
                        if let Some(header) = Ipv4Packet::new(ethernet.payload()) {
                            if header.get_ttl() == SPECIAL_TTL {
                                continue;
                            }
                            let source = IpAddr::V4(header.get_source());
                            let destination = IpAddr::V4(header.get_destination());
                            let protocol = header.get_next_level_protocol();
                            match protocol {
                                IpNextHeaderProtocols::Udp => {
                                    let udp = UdpPacket::new(packet);
                                    if let Some(udp) = udp {
                                        if destination.to_string() == opt.target {
                                            println!(
                                                "[{}]: UDP Packet: {}:{} > {}:{}; length: {}",
                                                interface_name,
                                                source,
                                                udp.get_source(),
                                                destination,
                                                udp.get_destination(),
                                                udp.get_length()
                                            );
                                            let mut replay_ethernet =
                                                MutableEthernetPacket::owned(packet.to_vec())
                                                    .unwrap();
                                            let mut replay_ip = MutableIpv4Packet::owned(
                                                replay_ethernet.payload().to_vec(),
                                            )
                                            .unwrap();
                                            replay_ip.set_ttl(SPECIAL_TTL);
                                            replay_ethernet.set_payload(replay_ip.packet());
                                            for i in 0..opt.count {
                                                match tx
                                                    .send_to(replay_ethernet.packet(), None)
                                                    .unwrap()
                                                {
                                                    Ok(()) => println!("Replay succeed({})", i),
                                                    Err(e) => println!("Replay failure: {}", e),
                                                }
                                            }
                                        }
                                    } else {
                                        println!("[{}]: Malformed UDP Packet", interface_name);
                                    }
                                }
                                IpNextHeaderProtocols::Tcp => {
                                    let tcp = TcpPacket::new(packet);
                                    if let Some(tcp) = tcp {
                                        if destination.to_string() == opt.target {
                                            println!(
                                                "[{}]: TCP Packet: {}:{} > {}:{}; length: {}",
                                                interface_name,
                                                source,
                                                tcp.get_source(),
                                                destination,
                                                tcp.get_destination(),
                                                packet.len()
                                            );
                                            let mut replay_ethernet =
                                                MutableEthernetPacket::owned(packet.to_vec())
                                                    .unwrap();
                                            let mut replay_ip = MutableIpv4Packet::owned(
                                                replay_ethernet.payload().to_vec(),
                                            )
                                            .unwrap();
                                            replay_ip.set_ttl(SPECIAL_TTL);
                                            replay_ethernet.set_payload(replay_ip.packet());
                                            for i in 0..opt.count {
                                                match tx
                                                    .send_to(replay_ethernet.packet(), None)
                                                    .unwrap()
                                                {
                                                    Ok(()) => println!("Replay succeed({})", i),
                                                    Err(e) => println!("Replay failure: {}", e),
                                                }
                                            }
                                        }
                                    } else {
                                        println!("[{}]: Malformed TCP Packet", interface_name);
                                    }
                                }
                                _ => {}
                            }
                        } else {
                            println!("[{}]: Malformed IPv4 Packet", interface_name);
                        }
                    }
                    _ => {}
                }
            }
            Err(e) => panic!("Error to receive packet: {}", e),
        }
    }
}
