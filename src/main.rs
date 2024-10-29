use nfq::{Queue, Verdict};

const PROTO_ICMP: u8 = 0x1;
const PROTO_TCP: u8 = 0x6;
const PROTO_UDP: u8 = 0x11;

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

fn display(packet: &[u8]) {
    use std::net::Ipv4Addr;
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

    match packet[9] {
        0x1 => {
            println!(
                "ICMP {} -> {} ==>{}",
                src,
                dst,
                String::from_utf8_lossy(&packet[20..])
            );
        }
        0x6 => {
            let src_port = u16::from_be_bytes([packet[20], packet[21]]);
            let dst_port = u16::from_be_bytes([packet[22], packet[23]]);
            println!("TCP {}:{} -> {}:{}", src, src_port, dst, dst_port);
        }
        0x17 => {
            let src_port = u16::from_be_bytes([packet[20], packet[21]]);
            let dst_port = u16::from_be_bytes([packet[22], packet[23]]);
            println!("UDP {}:{} -> {}:{}", src, src_port, dst, dst_port);
        }
        _ => {
            println!("Unknown protocol");
        }
    }
}

fn handle_in() {
    let mut queue = Queue::open().expect("Failed to open queue");
    queue.bind(444).expect("Failed to bind queue");

    while let Ok(mut msg) = queue.recv() {
        let payload = msg.get_payload_mut();
        if is_wrapped(payload) {
            rm_wrapper(payload);
        }
        display(payload);
        println!("Recv {:X?}", payload);
        msg.set_verdict(Verdict::Accept);
        queue.verdict(msg).unwrap();
    }
    println!("Exiting In");
}

fn handle_out() {
    let mut queue = Queue::open().expect("Failed to open queue");
    queue.bind(445).expect("Failed to bind queue");

    while let Ok(mut msg) = queue.recv() {
        let payload = msg.get_payload_mut();
        display(payload);
        println!("Send {:X?}", payload);
        if should_warp(payload) {
            add_wrapper(payload);
        }
        msg.set_verdict(Verdict::Accept);
        queue.verdict(msg).unwrap();
    }
    println!("Exiting Out");
}

fn main() {
    let handle1 = std::thread::spawn(handle_in);
    let handle2 = std::thread::spawn(handle_out);

    handle1.join().expect("Thread 1 panicked");
    handle2.join().expect("Thread 2 panicked");
}
