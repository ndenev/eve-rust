extern crate crossbeam;
extern crate chrono;
extern crate docopt;
extern crate redis;
extern crate serde;
extern crate serde_json;

use std::thread;
use std::sync::Arc;
use std::net::IpAddr;
use std::str::FromStr;
use crossbeam::sync::MsQueue;
use chrono::DateTime;
use chrono::offset::utc::UTC;
use redis::Client;

include!(concat!(env!("OUT_DIR"), "/serde_types.rs"));

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

    for _ in 0..1 {
        let consumer = queue.clone();
        thread::spawn(move || {
            loop {
                let record = consumer.pop();
                match serde_json::from_str::<EveJsonRecord>(&record) {
                    Ok(event) => {
                        println!("***********************************");
                        match event.event_type {
                            EventType::Netflow => println!("* NETFLOW"),
                            EventType::Alert => println!("* ALERT"),
							EventType::Dns => println!("* DNS"),
							EventType::Http => println!("* HTTP"),
							EventType::Tcp => println!("* TCP"),
							EventType::Tls => println!("* TLS"),
							EventType::Fileinfo => println!("* FILEINFO"),
                        }
                        println!("***********************************");
						println!("{:?}", event);
						println!("");
						println!("");
                    },
                    Err(msg) => {
                        println!("Parse error: {}", msg);
                        println!("Failed to parse: {}", record);
                    }
                }
            }
        });
    }

    listener.join().unwrap();
}

