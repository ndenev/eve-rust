extern crate crossbeam;
extern crate docopt;
extern crate redis;
extern crate rustc_serialize;

use std::thread;
use std::sync::Arc;
use crossbeam::sync::MsQueue;
use redis::Client;
use rustc_serialize::json;


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
    let queue: Arc<MsQueue<String>> = Arc::new(MsQueue::new());
    let channel = "suricata";

    let producer = queue.clone();
    let listener = thread::spawn(move || {
        let client = Client::open("redis://10.0.0.13/").unwrap();
        let mut pubsub = client.get_pubsub().unwrap();
        match pubsub.subscribe(channel) {
            Ok(_) => println!("Subscribed to pubsub channel {}", channel),
            Err(msg) => panic!("Unable to subscribe to {}: {}", channel, msg),
        }
        loop {
            match pubsub.get_message() {
                Ok(msg) => {
                    match msg.get_payload() {
                        Ok(payload) => producer.push(payload),
                        Err(msg) => println!("Error extracting payload: {}", msg),
                    }
                }
                Err(msg) => println!("Error getting message: {}", msg),
            }
        }
    });

    for i in 0..7 {
        let consumer = queue.clone();
        thread::spawn(move || {
            loop {
                let record = consumer.pop();
                match json::decode::<SuricataRecord>(&record) {
                    Ok(data) => println!("Thread#{}: {:?}", i, data),
                    Err(msg) => println!("Parse error: {}", msg),
                }
            }
        });
    }

    listener.join().unwrap();
}
