extern crate crossbeam;
extern crate docopt;
extern crate redis;

use std::thread;
use crossbeam::sync::MsQueue;
use redis::{Client, Commands, Connection, RedisResult};

#[derive(Debug)]
enum Protocol {
    TCP,
    UDP,
    ICMP,
}

#[derive(Debug)]
struct Netflow {
    proto: Protocol,
    src_ip: u32,
    src_pt: u16,
    dst_ip: u32,
    dst_pt: u16,
}

fn listener() {
    let client = Client::open("redis://10.0.0.13/").unwrap();
    let conn = client.get_connection().unwrap();
    let mut pubsub = client.get_pubsub().unwrap();
    pubsub.subscribe("suricata").unwrap();
    loop {
        let msg = pubsub.get_message().unwrap();
        let payload: String = msg.get_payload().unwrap();
        println!("channel '{}': {}", msg.get_channel_name(), payload);
    }
}

fn main() {
    let mut queue: MsQueue<Netflow> = MsQueue::new();
    let nf = Netflow {
        proto: Protocol::ICMP,
        src_ip: 0u32,
        src_pt: 0u16,
        dst_ip: 0u32,
        dst_pt: 0u16,
    };
    queue.push(nf);
    println!("Got: {:?}", queue.pop());
}
