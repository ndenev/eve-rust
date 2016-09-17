#[derive(Debug,Deserialize)]
#[serde(deny_unknown_fields)]
struct EveJsonRecord {
    #[serde(deserialize_with="deserialize_ip")]
    dest_ip: IpAddr,
    dest_port: u64,
    event_type: EventType,
    flow_id: u64,
    host: String,
    proto: String,
    #[serde(deserialize_with="deserialize_ip")]
    src_ip: IpAddr,
    src_port: u64,
    icmp_type: Option<u8>,
    icmp_code: Option<u8>,
    //timestamp: String,
    timestamp: DateTime<UTC>,
    app_proto: Option<String>,
    in_iface: Option<String>,
    tx_id: Option<u64>,

    alert: Option<Box<AlertInfo>>,
    dns: Option<Box<DnsInfo>>,
    http: Option<Box<HttpInfo>>,
    netflow: Option<Box<NetflowInfo>>,
    tcp: Option<Box<TcpInfo>>,
    tls: Option<Box<TlsInfo>>,
    fileinfo: Option<Box<FileInfo>>,
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

#[derive(Debug,Deserialize)]
enum EventType {
    #[serde(rename="alert")]
    Alert,
    #[serde(rename="dns")]
    Dns,
    #[serde(rename="http")]
    Http,
    #[serde(rename="netflow")]
    Netflow,
    #[serde(rename="tcp")]
    Tcp,
    #[serde(rename="tls")]
    Tls,
    #[serde(rename="fileinfo")]
    Fileinfo,
}

#[derive(Debug,Deserialize)]
#[serde(deny_unknown_fields)]
struct NetflowInfo {
    age: u64,
    bytes: u64,
    pkts: u64,
    start: DateTime<UTC>,
    end: DateTime<UTC>,
}

#[derive(Debug,Deserialize)]
#[serde(deny_unknown_fields)]
struct TcpInfo {
    tcp_flags: String,
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

#[derive(Debug,Deserialize)]
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

#[derive(Debug,Deserialize)]
#[serde(deny_unknown_fields)]
struct TlsInfo {
    subject: String,
    issuerdn: String,
    fingerprint: String,
    sni: Option<String>,
    version: String,
}

#[derive(Debug,Deserialize)]
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


#[derive(Debug,Deserialize)]
#[serde(deny_unknown_fields)]
enum RuleAction {
    #[serde(rename = "allowed")]
    Allowed,
    #[serde(rename = "blocked")]
    Blocked,
}

#[derive(Debug,Deserialize)]
#[serde(deny_unknown_fields)]
struct AlertInfo {
    action: RuleAction,
    gid: u64,
    signature_id: u64,
    rev: u64,
    signature: String,
    category: String,
    severity: u64,
    payload: Option<String>,
    payload_printable: Option<String>,
    stream: Option<u64>,
    packet: String,
}

#[derive(Debug,Deserialize)]
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
