use crate::engine::dsl::TemplateDsl;
use crate::models::template::DnsBlock;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
use hickory_proto::rr::{DNSClass, Name, Record, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

/// Resolved DNS query response data for matcher & extractor evaluation.
///
/// Field semantics mirror Go nuclei's `responseToDSLMap`
/// (`pkg/protocols/dns/operators.go`): section strings are miekg/dns-style
/// record text and `rcode` is the numeric response code.
#[derive(Debug, Clone)]
pub struct DnsResponse {
    /// Domain that was queried (trailing dot stripped).
    pub host: String,
    /// Numeric DNS response code (0 = NOERROR, 3 = NXDOMAIN, ...).
    pub rcode: u16,
    /// Question section text.
    pub question: String,
    /// Answer section text.
    pub answer: String,
    /// Authority (NS) section text.
    pub ns: String,
    /// Additional (extra) section text.
    pub extra: String,
    /// Full response in dig-like text form (default match part).
    pub raw: String,
    /// Sent request message text (Go `request` variable).
    pub request_text: String,
    /// Per-answer-record (lowercase type name, rdata value) pairs in order.
    pub record_values: Vec<(String, String)>,
}

impl DnsResponse {
    /// Go nuclei `responseToDSLMap` parity: the variable map exposed to DSL
    /// matchers, extractors, and `part:` lookups. Answer record types are
    /// additionally exposed by lowercase name (`a`, `mx`, ...) with Go's
    /// `recordsKeyValue` semantics (single value plain, multiple as "[v1 v2]").
    pub fn variables(&self) -> HashMap<String, String> {
        let mut vars = HashMap::new();
        vars.insert("host".to_string(), self.host.clone());
        vars.insert("matched".to_string(), self.host.clone());
        vars.insert("request".to_string(), self.request_text.clone());
        vars.insert("rcode".to_string(), self.rcode.to_string());
        vars.insert("question".to_string(), self.question.clone());
        vars.insert("answer".to_string(), self.answer.clone());
        vars.insert("ns".to_string(), self.ns.clone());
        vars.insert("extra".to_string(), self.extra.clone());
        vars.insert("raw".to_string(), self.raw.clone());
        // Go `type` is the protocol type ("dns"), not the query record type.
        vars.insert("type".to_string(), "dns".to_string());
        // Trace is not implemented; Go exposes an empty string in that case.
        vars.insert("trace".to_string(), String::new());

        let mut by_type: Vec<(String, Vec<String>)> = Vec::new();
        for (type_name, value) in &self.record_values {
            match by_type.iter_mut().find(|(t, _)| t == type_name) {
                Some((_, values)) => values.push(value.clone()),
                None => by_type.push((type_name.clone(), vec![value.clone()])),
            }
        }
        for (type_name, values) in by_type {
            let rendered = if values.len() == 1 {
                values.into_iter().next().unwrap()
            } else {
                format!("[{}]", values.join(" "))
            };
            vars.insert(type_name, rendered);
        }
        vars
    }
}

pub struct DnsClient;

impl DnsClient {
    /// Execute a DNS block against a target domain/host using raw UDP
    /// queries, so the full response message (rcode, all sections) is
    /// available for Go-parity variable injection.
    pub async fn execute(
        dns_block: &DnsBlock,
        target: &str,
        vars: &HashMap<String, String>,
        timeout_secs: u64,
    ) -> Result<DnsResponse, String> {
        let name_source = dns_block.name.as_deref().unwrap_or(target);
        let resolved_name = TemplateDsl::interpolate(name_source, target, vars);
        let domain = clean_domain(&resolved_name);

        let query_type_str = dns_block.query_type.as_deref().unwrap_or("A").to_uppercase();
        let record_type = question_type(&query_type_str);

        let qname = Name::from_str(&domain).map_err(|e| format!("invalid dns name: {}", e))?;

        let mut msg = Message::new();
        msg.set_message_type(MessageType::Query);
        msg.set_op_code(OpCode::Query);
        // Go defaults RecursionDesired to true when the field is absent.
        msg.set_recursion_desired(dns_block.recursion.unwrap_or(true));
        let mut query = Query::new();
        query.set_name(qname);
        query.set_query_type(record_type);
        query.set_query_class(DNSClass::IN);
        msg.add_query(query);
        // Go: req.SetEdns0(4096, false).
        let mut edns = Edns::new();
        edns.set_max_payload(4096);
        msg.set_edns(edns);
        if record_type == RecordType::TXT {
            msg.set_authentic_data(true);
        }

        let request_bytes = msg
            .to_bytes()
            .map_err(|e| format!("could not encode dns request: {}", e))?;
        let request_text = msg.to_string();

        let resolvers = resolver_addresses(&dns_block.resolvers).await;
        let timeout = Duration::from_secs(if timeout_secs == 0 { 5 } else { timeout_secs });
        let retries = dns_block.retries.unwrap_or(3).max(1);

        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| format!("could not bind udp socket: {}", e))?;

        let mut last_error = "no dns resolvers available".to_string();
        'attempts: for _ in 0..retries {
            for resolver in &resolvers {
                if socket.send_to(&request_bytes, resolver).await.is_err() {
                    last_error = format!("could not send dns request to {}", resolver);
                    continue;
                }
                let mut buf = vec![0u8; 4096];
                match tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await {
                    Ok(Ok((n, _))) => match Message::from_vec(&buf[..n]) {
                        Ok(response) => {
                            return Ok(build_response(response, &domain, &request_text))
                        }
                        Err(e) => last_error = format!("invalid dns response: {}", e),
                    },
                    Ok(Err(e)) => last_error = format!("dns read error: {}", e),
                    Err(_) => last_error = format!("dns request to {} timed out", resolver),
                }
            }
            if resolvers.is_empty() {
                break 'attempts;
            }
        }
        Err(last_error)
    }
}

/// Strip scheme, path, and port from a DNS input, mirroring the previous
/// behavior for URL-style targets.
fn clean_domain(input: &str) -> String {
    input
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/')
        .split(':')
        .next()
        .unwrap_or(input)
        .trim_end_matches('.')
        .to_string()
}

/// Go `questionTypeToInt` parity: the full template type enum.
fn question_type(query_type: &str) -> RecordType {
    match query_type.trim().to_uppercase().as_str() {
        "A" => RecordType::A,
        "NS" => RecordType::NS,
        "CNAME" => RecordType::CNAME,
        "SOA" => RecordType::SOA,
        "PTR" => RecordType::PTR,
        "MX" => RecordType::MX,
        "TXT" => RecordType::TXT,
        "DS" => RecordType::DS,
        "AAAA" => RecordType::AAAA,
        "CAA" => RecordType::CAA,
        "TLSA" => RecordType::TLSA,
        "ANY" => RecordType::ANY,
        "SRV" => RecordType::SRV,
        "RRSIG" => RecordType::RRSIG,
        "NSEC" => RecordType::NSEC,
        "DNSKEY" => RecordType::DNSKEY,
        "NSEC3" => RecordType::NSEC3,
        "NSEC3PARAM" => RecordType::NSEC3PARAM,
        _ => RecordType::A,
    }
}

/// Resolve template `resolvers:` entries to socket addresses, stripping the
/// transport prefixes Go's `resolverHost` accepts (udp://, tcp:, doh: ...).
/// Falls back to /etc/resolv.conf nameservers, then public resolvers.
async fn resolver_addresses(entries: &[String]) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for entry in entries {
        let mut r = entry.trim();
        for prefix in [
            "udp://", "tcp://", "tls://", "doh://", "udp:", "tcp:", "tls:", "doh:",
        ] {
            r = r.strip_prefix(prefix).unwrap_or(r);
        }
        r = r.trim_end_matches('/');
        if r.is_empty() {
            continue;
        }

        let socket = if let Ok(addr) = SocketAddr::from_str(r) {
            Some(addr)
        } else if let Some((host, port)) = r.rsplit_once(':') {
            if let (Ok(ip), Ok(port)) = (host.parse::<IpAddr>(), port.parse::<u16>()) {
                Some(SocketAddr::new(ip, port))
            } else {
                None
            }
        } else if let Ok(ip) = r.parse::<IpAddr>() {
            Some(SocketAddr::new(ip, 53))
        } else {
            // Hostname resolver: resolve it once via the system.
            tokio::net::lookup_host((r, 53))
                .await
                .ok()
                .and_then(|mut addrs| addrs.next())
        };
        if let Some(addr) = socket {
            out.push(addr);
        }
    }
    if !out.is_empty() {
        return out;
    }

    let mut system = Vec::new();
    if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in content.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("nameserver") {
                if let Ok(ip) = rest.trim().parse::<IpAddr>() {
                    system.push(SocketAddr::new(ip, 53));
                }
            }
        }
    }
    if system.is_empty() {
        system.push(SocketAddr::new(IpAddr::from([8, 8, 8, 8]), 53));
        system.push(SocketAddr::new(IpAddr::from([1, 1, 1, 1]), 53));
    }
    system
}

/// Build the Go-parity response data from a wire message.
fn build_response(
    response: Message,
    domain: &str,
    request_text: &str,
) -> DnsResponse {
    let rcode = u16::from(response.response_code());

    let question = response
        .queries()
        .iter()
        .map(|q| format!(";{}\t{}\t {}", q.name(), q.query_class(), q.query_type()))
        .collect::<Vec<_>>()
        .join("");

    let answer = rr_section(response.answers());
    let ns = rr_section(response.name_servers());
    let extra = rr_section(response.additionals());

    let mut record_values = Vec::new();
    for record in response.answers() {
        let type_name = record.record_type().to_string().to_lowercase();
        let value = record
            .data()
            .map(|d| d.to_string())
            .unwrap_or_default()
            .trim_end_matches('.')
            .to_string();
        record_values.push((type_name, value));
    }

    let mut flags = String::from("qr");
    if response.recursion_desired() {
        flags.push_str(" rd");
    }
    if response.recursion_available() {
        flags.push_str(" ra");
    }
    let mut raw = format!(
        ";; opcode: {}, status: {}, id: {}\n;; flags:{}; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}\n",
        response.op_code(),
        rcode_name(rcode),
        response.id(),
        flags,
        response.queries().len(),
        response.answers().len(),
        response.name_servers().len(),
        response.additionals().len(),
    );
    if !question.is_empty() {
        raw.push_str(&format!("\n;; QUESTION SECTION:\n{}\n", question));
    }
    if !answer.is_empty() {
        raw.push_str(&format!("\n;; ANSWER SECTION:\n{}\n", answer));
    }
    if !ns.is_empty() {
        raw.push_str(&format!("\n;; AUTHORITY SECTION:\n{}\n", ns));
    }
    if !extra.is_empty() {
        raw.push_str(&format!("\n;; ADDITIONAL SECTION:\n{}\n", extra));
    }

    DnsResponse {
        host: domain.to_string(),
        rcode,
        question,
        answer,
        ns,
        extra,
        raw,
        request_text: request_text.to_string(),
        record_values,
    }
}

/// miekg/dns `rrToString` parity: tab-separated record text concatenated
/// without separators.
fn rr_section(records: &[Record]) -> String {
    let mut out = String::new();
    for record in records {
        let data = record
            .data()
            .map(|d| d.to_string())
            .unwrap_or_default();
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}",
            record.name(),
            record.ttl(),
            record.dns_class(),
            record.record_type(),
            data,
        ));
    }
    out
}

/// Numeric response code to its canonical name (miekg `RcodeToString`).
fn rcode_name(rcode: u16) -> &'static str {
    match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        6 => "YXDOMAIN",
        7 => "YXRRSET",
        8 => "NXRRSET",
        9 => "NOTAUTH",
        10 => "NOTZONE",
        16 => "BADSIG",
        17 => "BADKEY",
        18 => "BADTIME",
        19 => "BADMODE",
        20 => "BADNAME",
        21 => "BADALG",
        22 => "BADTRUNC",
        23 => "BADCOOKIE",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_domain() {
        assert_eq!(clean_domain("https://example.com/"), "example.com");
        assert_eq!(clean_domain("example.com:8080"), "example.com");
        assert_eq!(clean_domain("sub.example.org."), "sub.example.org");
    }

    #[test]
    fn test_question_type_mapping() {
        assert_eq!(question_type("A"), RecordType::A);
        assert_eq!(question_type("txt"), RecordType::TXT);
        assert_eq!(question_type("NSEC3PARAM"), RecordType::NSEC3PARAM);
        assert_eq!(question_type("bogus"), RecordType::A);
    }

    #[test]
    fn test_variables_single_and_multi_record() {
        let resp = DnsResponse {
            host: "example.com".to_string(),
            rcode: 0,
            question: ";example.com.\tIN\t A".to_string(),
            answer: "example.com.\t300\tIN\tA\t1.2.3.4".to_string(),
            ns: String::new(),
            extra: String::new(),
            raw: ";; opcode: QUERY, status: NOERROR".to_string(),
            request_text: ";; opcode: QUERY".to_string(),
            record_values: vec![
                ("a".to_string(), "1.2.3.4".to_string()),
                ("a".to_string(), "5.6.7.8".to_string()),
            ],
        };
        let vars = resp.variables();
        assert_eq!(vars.get("rcode").map(String::as_str), Some("0"));
        assert_eq!(vars.get("host").map(String::as_str), Some("example.com"));
        assert_eq!(vars.get("request").map(String::as_str), Some(";; opcode: QUERY"));
        // Multiple records of the same type render Go's "[v1 v2]" form.
        assert_eq!(vars.get("a").map(String::as_str), Some("[1.2.3.4 5.6.7.8]"));
        assert!(vars.contains_key("raw"));
        assert_eq!(vars.get("trace").map(String::as_str), Some(""));
        assert_eq!(vars.get("type").map(String::as_str), Some("dns"));
    }
}
