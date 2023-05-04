use pcap::Capture;
use pcap::Device;
use pktparse::{ethernet, ipv4, tcp};
use std::process::Command;

fn main() {
    let main_device = Device::lookup().unwrap();
    let mut cap = Capture::from_device(main_device.unwrap())
        .unwrap()
        .promisc(true)
        .snaplen(5000)
        .open()
        .unwrap();

    while let Ok(packet) = cap.next_packet() {
        // Slice out the ethernet frame information from the packet
        if let Ok((remaining, eth_frame)) = ethernet::parse_ethernet_frame(packet.data) {
            if eth_frame.ethertype != pktparse::ethernet::EtherType::IPv4 {
                // is not ipv4 - in this case, skip over the packet
                continue;
            }

            // Slice out the IPv4 header
            if let Ok((remaining, ip4hdr)) = ipv4::parse_ipv4_header(remaining) {

                if let Ok((packet_data, tcp_hdr)) = tcp::parse_tcp_header(remaining) {
                        println!("Ethernet Frame:\n{:?}",eth_frame);
                        println!("TCP Header:\n{:?}",tcp_hdr);
                        hexdump::hexdump(packet_data);
                }
            } else {
                // We could not parse the ipv4 header, so for now just skip over it.
                continue;
            }
        }
    }
}