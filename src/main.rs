extern crate crossbeam;
extern crate docopt;
extern crate redis;
extern crate rustc_serialize;

use std::result;
use std::thread;
use std::sync::Arc;
use crossbeam::sync::MsQueue;
use redis::{Client, Commands, Connection, RedisResult};
use rustc_serialize::json;
use rustc_serialize::json::DecodeResult;


#[derive(Debug,RustcDecodable)]
struct SuricataRecord {
    timestamp: String,
    flow_id: u64,
    event_type: String,
    src_ip: String,
    src_port: u64,
    dest_ip: String,
    dest_port: u64,
    proto: String,
    netflow: Option<NetflowRecord>,
    tcp: Option<TcpInfo>,
    host: String,
}

#[derive(Debug,RustcDecodable)]
struct NetflowRecord {
    pkts: u64,
    bytes: u64,
    start: String,
    end: String,
    age: u64,
}

#[derive(Debug,RustcDecodable)]
struct TcpInfo {
    tcp_flags: String,
    syn: Option<bool>,
    fin: Option<bool>,
    psh: Option<bool>,
    ack: Option<bool>,
}


fn main() {
    let queue: Arc<MsQueue<SuricataRecord>> = Arc::new(MsQueue::new());

    let producer = queue.clone();
    let listener = thread::spawn(move || {
        let client = Client::open("redis://10.0.0.13/").unwrap();
        let mut pubsub = client.get_pubsub().unwrap();
        pubsub.subscribe("suricata").unwrap();
        loop {
            let msg = pubsub.get_message().unwrap();
            let payload: String = msg.get_payload().unwrap();
            match json::decode::<SuricataRecord>(&payload) {
                Ok(data) => producer.push(data),
                Err(msg) => println!("Error parsing {}: {}", payload, msg),
            }
        }
    });

    for i in 0..7 {
        let consumer = queue.clone();
        thread::spawn(move || {
            loop {
                let record = consumer.pop();
                println!("Thread#{}: {:?}", i, record);
            }
        });
    }

    listener.join().unwrap();
}
