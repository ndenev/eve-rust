#[derive(Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct EveJsonRecord {
    #[serde(deserialize_with="deserialize_ip",serialize_with="serialize_ip")]
    dest_ip: IpAddr,
    dest_port: Option<u64>,
    event_type: EventType,
    flow_id: u64,
    /// host field is only set in redis
    host: Option<String>,
    proto: EventProtocol,
    #[serde(deserialize_with="deserialize_ip",serialize_with="serialize_ip")]
    src_ip: IpAddr,
    src_port: Option<u64>,
    icmp_type: Option<u8>,
    icmp_code: Option<u8>,
    timestamp: DateTime<UTC>,
    app_proto: Option<String>,
    in_iface: Option<String>,
    tx_id: Option<u64>,

    payload: Option<String>,
    payload_printable: Option<String>,
    stream: Option<u64>,
    packet: Option<String>,

    alert: Option<Box<AlertInfo>>,
    dns: Option<Box<DnsInfo>>,
    http: Option<Box<HttpInfo>>,
    netflow: Option<Box<NetflowInfo>>,
    flow: Option<Box<FlowInfo>>,
    tcp: Option<Box<TcpInfo>>,
    tls: Option<Box<TlsInfo>>,
    fileinfo: Option<Box<FileInfo>>,
    ssh: Option<Box<SshInfo>>,
} 

fn serialize_ip<S>(ip: &IpAddr, se: &mut S) -> Result<(), S::Error> where S: serde::Serializer {
    se.serialize_str(&format!("{}", ip))
}

fn deserialize_ip<D>(de: &mut D) -> Result<IpAddr, D::Error> where D: serde::Deserializer {
    let deser_result: serde_json::Value = serde::Deserialize::deserialize(de).unwrap();
    match deser_result {
        serde_json::Value::String(ref s) => {
            match IpAddr::from_str(s) {
                Ok(ip) => Ok(ip),
                Err(m) => Err(serde::de::Error::custom(format!("Unable to parse IP address: {}", m))),
            }
        },
        _ => Err(serde::de::Error::custom("Expected string containing ip address.")),
    }
}

#[derive(Debug,Serialize,Deserialize)]
enum EventType {
    #[serde(rename="alert")]
    Alert,
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
    rrname: String,
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
    subject: String,
    issuerdn: String,
    fingerprint: String,
    sni: Option<String>,
    version: String,
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
}

#[derive(Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct FileInfo {
    filename: String,
    magic: String,
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
