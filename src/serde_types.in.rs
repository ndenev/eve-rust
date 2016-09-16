#[derive(Debug,Deserialize)]
#[serde(deny_unknown_fields)]
struct EveJsonRecord {
    dest_ip: String,
    dest_port: u64,
    event_type: String,
    flow_id: u64,
    host: String,
    proto: String,
    src_ip: String,
    src_port: u64,
    timestamp: String,
    app_proto: Option<String>,
    in_iface: Option<String>,
    tx_id: Option<u64>,
    alert: Option<Box<AlertInfo>>,
    dns: Option<Box<DnsInfo>>,
    http: Option<Box<HttpInfo>>,
    netflow: Option<Box<NetflowInfo>>,
    tcp: Option<Box<TcpInfo>>,
    tls: Option<Box<TlsInfo>>,
    //#[serde(skip_deserializing)]
    //event: Event,
} 

#[derive(Debug,Deserialize)]
enum Event {
    #[serde(rename="alert")]
    Alert(Option<Box<AlertInfo>>),
    #[serde(rename="dns")]
    Dns(Option<Box<DnsInfo>>),
    #[serde(rename="http")]
    Http(Option<Box<HttpInfo>>),
    #[serde(rename="netflow")]
    Netflow(Option<Box<NetflowInfo>>),
    #[serde(rename="tcp")]
    Tcp(Option<Box<TcpInfo>>),
    #[serde(rename="tls")]
    Tls(Option<Box<TlsInfo>>),
}

#[derive(Debug,Deserialize)]
#[serde(deny_unknown_fields)]
struct NetflowInfo {
    age: u64,
    bytes: u64,
    end: String,
    pkts: u64,
    start: String,
}

#[derive(Debug,Deserialize)]
#[serde(deny_unknown_fields)]
struct TcpInfo {
    tcp_flags: String,
    ack: Option<bool>,
    cwr: Option<bool>,
    ecn: Option<bool>,
    fin: Option<bool>,
    psh: Option<bool>,
    rst: Option<bool>,
    syn: Option<bool>,
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
    protocol: String,
    status: Option<u64>,
    length: u64,
    tx_id: Option<u64>,
}

#[derive(Debug,Deserialize)]
#[serde(deny_unknown_fields)]
struct AlertInfo {
    action: String,
    gid: u64,
    signature_id: u64,
    rev: u64,
    signature: String,
    category: String,
    severity: u64,
    payload: Option<String>,
    payload_printable: String,
    stream: u64,
    packet: String,
}
