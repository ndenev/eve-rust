extern crate crossbeam;
extern crate docopt;
extern crate redis;
extern crate serde;
extern crate serde_json;

use std::thread;
use std::sync::Arc;
use crossbeam::sync::MsQueue;
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
                    Ok(data) => {
                        match &data.event_type as &str {
                            //"netflow" => {}, //println!("Thread#{}: {:?}", i, d),
                            //"http" => {}, //println!("Thread#{}: {:?}", i, d),
                            //"tls" => {}, //println!("Thread#{}: {:?}", i, d),
                            _ => {
                                //println!("*********************************");
                                //println!("RECORD: {:?}", record);
                                //println!("PARSED: {:?}", data);
                                //println!("*********************************");
                                //println!("");
                            }
                        }
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

