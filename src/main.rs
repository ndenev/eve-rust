extern crate crossbeam;
extern crate chrono;
extern crate docopt;
extern crate redis;
extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;

use std::thread;
use std::sync::Arc;
use std::net::IpAddr;
use std::str::FromStr;
use std::fmt::{Display, Debug};
use crossbeam::sync::MsQueue;
use chrono::{DateTime, UTC, NaiveDateTime, Datelike, Timelike};
use redis::Client;
use std::io::prelude::*;
use std::io::BufReader;
use std::fs::File;

include!(concat!(env!("OUT_DIR"), "/serde_types.rs"));

fn main() {

    println!("Lift Off!");

    let queue: Arc<MsQueue<Option<String>>> = Arc::new(MsQueue::new());

    let redis_producer_queue = queue.clone();
    let listener = thread::spawn(move || {
        let channel = "suricata";
        let client = Client::open("redis://10.0.0.1/").unwrap();
        let mut pubsub = client.get_pubsub().unwrap();
        match pubsub.subscribe(channel) {
            Ok(_) => println!("Subscribed to pubsub channel {}", channel),
            Err(msg) => panic!("Unable to subscribe to {}: {}", channel, msg),
        }
        loop {
            match pubsub.get_message() {
                Ok(msg) => {
                    match msg.get_payload() {
                        Ok(payload) => redis_producer_queue.push(Some(payload)),
                        Err(msg) => println!("Error extracting payload: {}", msg),
                    }
                }
                Err(msg) => println!("Error getting message: {}", msg),
            }
        }
    });

    let file_producer_queue = queue.clone();
    let reader = thread::spawn(move || {
        let eve_file = File::open("eve.json").unwrap();
        let eve_reader = BufReader::new(&eve_file);
        for event in eve_reader.lines() {
            file_producer_queue.push(Some(event.unwrap()));
        }
        for _ in 0..4 {
           file_producer_queue.push(None);
        }
    });

    let mut consumers = Vec::new();
    for i in 0..4 {
        let consumer = queue.clone();
        let t = thread::spawn(move || {
            let mut processed: usize = 0;
            println!("[{}] consumer started", i);
            loop {
                let record = match consumer.pop() {
                    Some(r) => { processed=processed+1; r },
                    None => {
                        println!("[{}] processed {} messages", i, processed);
                        break;
                    },
                };
                match serde_json::from_str::<EveJsonRecord>(&record) {
                    Ok(event) => {
                        match event.event_type {
                            EventType::Dns => {
                                // println!("* DNS"),
                            },
                            EventType::Fileinfo => {
                                // println!("* FILEINFO"),
                            },
                            EventType::Http => {
                                // println!("* HTTP"),
                            },
                            EventType::Tcp => {
                                // println!("* TCP"),
                            }, 
                            EventType::Tls => {
                                // println!("* TLS");
                                // println!("{}", serde_json::to_string_pretty(&event).unwrap());
                            },
                            EventType::Alert => {
                                // println!("* ALERT"),
                                // println!("{}", serde_json::to_string_pretty(&event).unwrap());
                            }, 
                            EventType::Drop => {
                                // println!("* Drop"),
                                // println!("{}", serde_json::to_string_pretty(&event).unwrap());
                            }, 
                            EventType::Flow => {
                                // println!("* FLOW"),
                            },
                            EventType::Netflow => {
                                // println!("* NETFLOW"),
                            },
                            EventType::Ssh => {
                                // println!("* SSH"),
                            },
                        }
                        // println!("{:?} {}", event.event_type, serde_json::to_string_pretty(&event).unwrap());
                    },
                    Err(msg) => {
                        println!("[thr {}] Parse error: {} while parsing:\n{}", i, msg, record);
                    }
                }
            }
        });
        consumers.push(t);
    }

    for t in consumers.into_iter() {
        t.join().unwrap();
    }

    reader.join().unwrap();
    listener.join().unwrap();
}

