#![feature(ip_from)]
use nfq::{Queue, Verdict};

const PROTO_ICMP: u8 = 0x1;
const PROTO_TCP: u8 = 0x6;
const PROTO_UDP: u8 = 0x11;

const QUE: u16 = 444;

use std::{
    net::{Ipv4Addr, SocketAddrV4},
    str::FromStr,
};

fn calculate_checksum(buffer: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;

    while i < buffer.len() - 1 {
        let word = u16::from_be_bytes([buffer[i], buffer[i + 1]]);
        sum = sum.wrapping_add(u32::from(word));
        i += 2;
    }

    if buffer.len() % 2 == 1 {
        sum = sum.wrapping_add(u32::from(buffer[buffer.len() - 1]) << 8);
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !(sum as u16)
}

fn put_checksum(data: &mut [u8], offset: usize) {
    data[offset] = 0;
    data[offset + 1] = 0;
    let checksum = calculate_checksum(data).to_be_bytes();
    data[offset] = checksum[0];
    data[offset + 1] = checksum[1];
}

fn add_wrapper(packet: &mut [u8]) {
    // IPv4 Header
    match packet[9] {
        PROTO_TCP => {}
        PROTO_UDP => {
            packet[6] |= 0x80;
        }
        _ => unreachable!("Can only wrap TCP or UDP packets"),
    }
    packet[9] = PROTO_ICMP; // Protocol (ICMP)
    put_checksum(&mut packet[..20], 10);
}

#[inline]
fn rm_wrapper(packet: &mut [u8]) {
    match packet[6] & 0x80 {
        0 => {
            packet[9] = PROTO_TCP;
        }
        _ => {
            packet[9] = PROTO_UDP;
        }
    }
    packet[6] &= 0x7f;
    put_checksum(&mut packet[..20], 10);
}

#[inline]
fn should_warp(packet: &[u8]) -> bool {
    packet[9] == PROTO_UDP || packet[9] == PROTO_TCP
}

#[inline]
fn is_wrapped(packet: &[u8]) -> bool {
    packet[9] == PROTO_ICMP
}

#[inline]
fn is_broadcast(packet: &[u8]) -> bool {
    let dst = std::net::Ipv4Addr::from_octets(*packet[16..].first_chunk().unwrap());
    dst.octets()[3] == 255
}

fn display(packet: &[u8]) {
    // unsafe {
    //     if DISPLAY_CD < 0 {
    //         return;
    //     } else {
    //         DISPLAY_CD -= 1;
    //     }
    // }
    let src = Ipv4Addr::from_octets(*packet[12..].first_chunk().unwrap());
    let dst = Ipv4Addr::from_octets(*packet[16..].first_chunk().unwrap());
    match packet[9] {
        PROTO_ICMP => {
            print!(
                "ICMP {:>20} -> {:>20} {}",
                src,
                dst,
                match packet[20] {
                    0 => "Echo Reply  ",
                    8 => "Echo Request",
                    _ => "Unknown     ",
                }
            );
        }
        PROTO_TCP => {
            let src = SocketAddrV4::new(src, u16::from_be_bytes([packet[20], packet[21]]));
            let dst = SocketAddrV4::new(dst, u16::from_be_bytes([packet[22], packet[23]]));
            print!("TCP  {:>20} -> {:<20}", src, dst);
        }
        PROTO_UDP => {
            let src = SocketAddrV4::new(src, u16::from_be_bytes([packet[20], packet[21]]));
            let dst = SocketAddrV4::new(dst, u16::from_be_bytes([packet[22], packet[23]]));
            print!("UDP  {:>20} -> {:<20}", src, dst);
        }
        _ => {
            print!("Unknown protocol {:X}", packet[9]);
        }
    }
    println!("\tlen:[{}]", packet.len());
}
fn handle(packet: &mut [u8], broadcast: Option<Ipv4Addr>) {
    if is_wrapped(packet) {
        rm_wrapper(packet);
        display(packet);
    } else if should_warp(packet) {
        display(packet);
        if is_broadcast(packet) {
            if let Some(broadcast) = broadcast {
                packet[16] = broadcast.octets()[0];
                packet[17] = broadcast.octets()[1];
                packet[18] = broadcast.octets()[2];
                packet[19] = broadcast.octets()[3];
            }
        }
        add_wrapper(packet);
    } else {
        display(packet);
    }
}

fn main() {
    let broadcast4 = std::env::args()
        .nth(1)
        .and_then(|ip: String| Ipv4Addr::from_str(&ip).ok());
    println!("[info] broadcast redirect to {:?}", broadcast4);

    let mut queue = Queue::open().expect("Failed to open queue");
    queue.bind(QUE).expect("Run as admin?");
    println!("[info] listen to queue {}", QUE);

    while let Ok(mut msg) = queue.recv() {
        let payload = msg.get_payload_mut();
        match payload[0] >> 4 {
            4 => handle(payload, broadcast4),
            6 => println!("Unimplemented IPv6"),
            x @ _ => {
                println!("Unknown IP protocol {}", x);
            }
        }
        msg.set_verdict(Verdict::Accept);
        queue.verdict(msg).unwrap();
    }
}
