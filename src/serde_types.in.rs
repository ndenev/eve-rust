#[derive(Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct EveJsonRecord {
    dest_ip: IpAddr,
    dest_port: Option<u64>,
    event_type: EventType,
    flow_id: u64,
    #[serde(skip_serializing_if="Option::is_none")]
    host: Option<String>,
    proto: EventProtocol,
    src_ip: IpAddr,
    src_port: Option<u64>,
    #[serde(skip_serializing_if="Option::is_none")]
    icmp_type: Option<u8>,
    #[serde(skip_serializing_if="Option::is_none")]
    icmp_code: Option<u8>,
    timestamp: DateTime<UTC>,
    #[serde(skip_serializing_if="Option::is_none")]
    app_proto: Option<String>,
    in_iface: Option<String>,
    tx_id: Option<u64>,

    #[serde(skip_serializing_if="Option::is_none")]
    payload: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    payload_printable: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    stream: Option<u64>,
    #[serde(skip_serializing_if="Option::is_none")]
    packet: Option<String>,

    #[serde(skip_serializing_if="Option::is_none")]
    alert: Option<Box<AlertInfo>>,
    #[serde(skip_serializing_if="Option::is_none")]
    drop: Option<Box<DropInfo>>,
    #[serde(skip_serializing_if="Option::is_none")]
    dns: Option<Box<DnsInfo>>,
    #[serde(skip_serializing_if="Option::is_none")]
    http: Option<Box<HttpInfo>>,
    #[serde(skip_serializing_if="Option::is_none")]
    netflow: Option<Box<NetflowInfo>>,
    #[serde(skip_serializing_if="Option::is_none")]
    flow: Option<Box<FlowInfo>>,
    #[serde(skip_serializing_if="Option::is_none")]
    tcp: Option<Box<TcpInfo>>,
    #[serde(skip_serializing_if="Option::is_none")]
    tls: Option<Box<TlsInfo>>,
    #[serde(skip_serializing_if="Option::is_none")]
    fileinfo: Option<Box<FileInfo>>,
    #[serde(skip_serializing_if="Option::is_none")]
    ssh: Option<Box<SshInfo>>,
} 

#[derive(Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
enum EventData {
    Alert { alert: AlertInfo },
    Drop { drop: DropInfo },
    Dns { dns: DnsInfo },
    Http { http: HttpInfo },
    Netflow { netflow: NetflowInfo },
    Flow { flow: FlowInfo },
    Tcp { tcp: TcpInfo },
    Tls { tls: TlsInfo },
    Fileinfo { fileinfo: FileInfo },
    Ssh { ssh: SshInfo },
}

// const FORMAT: &'static str = "%Y-%m-%d %H:%M:%S";

// fn serialize_datetime_naive_optional<S>(date: &Option<DateTime<UTC>>, serializer: S) -> Result<(), S::Error>
//     where S: serde::Serializer
// {
//     let s = format!("{}", date.format(FORMAT));
//     serializer.serialize_str(&s)
// }

// fn serialize_datetime_naive_optional<S, D>(dt: Option<D>, se: &mut S) -> Result<(), S::Error>
//     where S: serde::Serializer, D: Datelike + Timelike + Display + Debug {
//     //se.serialize_str(&format!("{:?}", dt.format("%Y-%m-%dT%H:%M:%S")))
//     se.serialize_str(&format!("{}", dt))
// }

// fn deserialize_datetime_naive_optional<D>(deserializer: D) -> Result<Option<DateTime<UTC>>, D::Error>
//     where D: serde::Deserializer
// {
//     let s = String::deserialize(deserializer)?;
//     UTC.datetime_from_str(&s, FORMAT).map_err(serde::de::Error::custom)
// }

// fn deserialize_datetime_naive_optional<D>(de: &mut D) -> Result<DateTime<UTC>, D::Error> where D: serde::Deserializer {
//     let deser_result: serde_json::Value = serde::Deserialize::deserialize(de).unwrap();
//     match deser_result {
//         serde_json::Value::String(ref s) => {
//             match NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
//                 Ok(dt) => Ok(DateTime::<UTC>::from_utc(dt, UTC)),
//                 Err(m) => Err(serde::de::Error::custom(format!("Unable to parse datetime: {}", m))),
//             }
//         },
//         _ => Err(serde::de::Error::custom("Expected string containing datetime.")),
//     }
// }

#[derive(Debug,Serialize,Deserialize)]
enum EventType {
    #[serde(rename="alert")]
    Alert,
    #[serde(rename="drop")]
    Drop,
    #[serde(rename="dns")]
    Dns,
    #[serde(rename="http")]
    Http,
    #[serde(rename="netflow")]
    Netflow,
    #[serde(rename="flow")]
    Flow,
    #[serde(rename="tcp")]
    Tcp,
    #[serde(rename="tls")]
    Tls,
    #[serde(rename="fileinfo")]
    Fileinfo,
    #[serde(rename="ssh")]
    Ssh,
}

#[derive(Debug,Serialize,Deserialize)]
enum EventProtocol {
    #[serde(rename="TCP")]
    Tcp,
    #[serde(rename="UDP")]
    Udp,
    #[serde(rename="ICMP")]
    Icmp,
    #[serde(rename="IPV6-ICMP")]
    Ipv6Icmp,
}

#[derive(Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct NetflowInfo {
    age: u64,
    bytes: u64,
    pkts: u64,
    start: DateTime<UTC>,
    end: DateTime<UTC>,
}

#[derive(Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct FlowInfo {
    pkts_toserver: u64,
    pkts_toclient: u64,
    bytes_toserver: u64,
    bytes_toclient: u64,
    start: DateTime<UTC>,
    end: DateTime<UTC>,
    age: u64,
    state: String,
    reason: String,
}

#[derive(Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct DropInfo {
    len: u64,
    tos: u8,
    ttl: u8,
    ipid: u64,
    tcpseq: u64,
    tcpack: u64,
    tcpwin: u64,
    syn: bool,
    ack: bool,
    psh: bool,
    rst: bool,
    urg: bool,
    fin: bool,
    tcpres: u64,
    tcpurgp: u64,
}

#[derive(Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct TcpInfo {
    tcp_flags: String,
    tcp_flags_ts: Option<String>,
    tcp_flags_tc: Option<String>,
    state: Option<String>,
    #[serde(default)]
    ack: bool,
    #[serde(default)]
    cwr: bool,
    #[serde(default)]
    ecn: bool,
    #[serde(default)]
    fin: bool,
    #[serde(default)]
    psh: bool,
    #[serde(default)]
    rst: bool,
    #[serde(default)]
    syn: bool,
}

#[derive(Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct DnsInfo {
    #[serde(rename="type")]
    _type: String,
    id: u64,
    rrname: Option<String>,
    rrtype: Option<String>,
    rtype: Option<String>,
    rcode: Option<String>,
    rdata: Option<String>,
    ttl: Option<u64>,
    tx_id: Option<u64>,
}

#[derive(Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct TlsInfo {
    subject: Option<String>,
    issuerdn: Option<String>,
    fingerprint: Option<String>,
    sni: Option<String>,
    version: String,
    #[serde(skip_serializing_if="Option::is_none",deserialize_with="tls_date::deserialize",serialize_with="tls_date::serialize")]
    notbefore: Option<DateTime<UTC>>,
    #[serde(skip_serializing_if="Option::is_none",deserialize_with="tls_date::deserialize",serialize_with="tls_date::serialize")]
    notafter: Option<DateTime<UTC>>,
}

// #[serde(serialize_with = "path")]
// Serialize this field using a function that is different from its implementation of Serialize. The given function must be callable as fn<S>(&T, S) -> Result<S::Ok, S::Error> where S: Serializer, although it may also be generic over T. Fields used with serialize_with do not need to implement Serialize.

// #[serde(deserialize_with = "path")]
// Deserialize this field using a function that is different from its implementation of Deserialize. The given function must be callable as fn<D>(D) -> Result<T, D::Error> where D: Deserializer, although it may also be generic over T. Fields used with deserialize_with do not need to implement Deserialize.

mod tls_date {
    use chrono::{DateTime, UTC, TimeZone};
    use serde::{self, Deserialize, Serializer, Deserializer};

    const FORMAT: &'static str = "%Y-%m-%dT%H:%M:%S";

    // The signature of a serialize_with function must follow the pattern:
    //
    //    fn serialize<S>(&T, S) -> Result<S::Ok, S::Error> where S: Serializer
    //
    // although it may also be generic over the input types T.
    pub fn serialize<S>(date: &DateTime<UTC>, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
            let s = format!("{}", date.format(FORMAT));
            serializer.serialize_str(&s)
    }

    // The signature of a deserialize_with function must follow the pattern:
    //
    //    fn deserialize<D>(D) -> Result<T, D::Error> where D: Deserializer
    //
    // although it may also be generic over the output types T.
    pub fn deserialize<D>(deserializer: D) -> Result<DateTime<UTC>, D::Error>
        where D: Deserializer
    {
        let s = String::deserialize(deserializer)?;
        UTC.datetime_from_str(&s, FORMAT).map_err(serde::de::Error::custom)
    }
}



#[derive(Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpInfo {
    hostname: String,
    url: String,
    http_user_agent: Option<String>,
    http_content_type: Option<String>,
    http_method: String,
    http_refer: Option<String>,
    redirect: Option<String>,
    protocol: String,
    status: Option<u64>,
    length: u64,
    tx_id: Option<u64>,
}


#[derive(Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
enum RuleAction {
    #[serde(rename = "allowed")]
    Allowed,
    #[serde(rename = "blocked")]
    Blocked,
}

#[derive(Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct AlertInfo {
    action: RuleAction,
    gid: u64,
    signature_id: u64,
    rev: u64,
    signature: String,
    category: String,
    severity: u64,
    tls: Option<TlsInfo>,
}

#[derive(Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct FileInfo {
    filename: String,
    magic: Option<String>,
    md5: Option<String>,
    state: String,
    stored: bool,
    size: u64,
    tx_id: u64,
}


#[derive(Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct SshEndpointInfo {
    proto_version: String,
    software_version: String,
}

#[derive(Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct SshInfo {
    client: Box<SshEndpointInfo>,
    server: Box<SshEndpointInfo>,
}
