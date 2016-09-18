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
use std::io::prelude::*;
use std::io::BufReader;
use std::fs::File;

include!(concat!(env!("OUT_DIR"), "/serde_types.rs"));

fn main() {
    let queue: Arc<MsQueue<String>> = Arc::new(MsQueue::new());


    let redis_producer_queue = queue.clone();
    let listener = thread::spawn(move || {
        let channel = "suricata";
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
                        Ok(payload) => redis_producer_queue.push(payload),
                        Err(msg) => println!("Error extracting payload: {}", msg),
                    }
                }
                Err(msg) => println!("Error getting message: {}", msg),
            }
        }
    });


    let file_producer_queue = queue.clone();
    let reader = thread::spawn(move || {
        return;
        let eve_file = File::open("eve.json").unwrap();
        let mut eve_reader = BufReader::new(&eve_file);
        for event in eve_reader.lines() {
            file_producer_queue.push(event.unwrap());
        }
    });

    for t in 0..1 {
        let consumer = queue.clone();
        thread::spawn(move || {
            println!("consumer thread {} started", t);
            loop {
                let record = consumer.pop();
                match serde_json::from_str::<EveJsonRecord>(&record) {
                    Ok(event) => {
                        match event.event_type {
                            EventType::Dns => println!("* DNS"),
                            EventType::Fileinfo => println!("* FILEINFO"),
                            EventType::Http => println!("* HTTP"),
                            EventType::Tcp => println!("* TCP"),
                            EventType::Tls => println!("* TLS"),
                            EventType::Alert => println!("* ALERT"),
                            EventType::Flow => println!("* FLOW"),
                            EventType::Netflow => println!("* NETFLOW"),
                            EventType::Ssh => println!("* SSH"),
                        }
                        println!("{}", serde_json::to_string_pretty(&event).unwrap());
                    },
                    Err(msg) => {
                        println!("Parse error: {}", msg);
                        println!("Failed to parse: {}", record);
                    }
                }
            }
        });
    }

    reader.join().unwrap();
    listener.join().unwrap();
}

