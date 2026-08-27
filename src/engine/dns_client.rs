use crate::models::template::DnsBlock;
use hickory_proto::rr::RecordType;
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use std::net::SocketAddr;
use std::str::FromStr;

/// Resolved DNS query response data for matcher & extractor evaluation.
#[derive(Debug, Clone)]
pub struct DnsResponse {
    pub host: String,
    pub query_type: String,
    pub raw: String,
    pub records: Vec<String>,
}

pub struct DnsClient;

impl DnsClient {
    /// Execute a DNS block against a target domain/host.
    pub async fn execute(dns_block: &DnsBlock, target: &str) -> Result<DnsResponse, String> {
        let domain = dns_block
            .name
            .as_deref()
            .unwrap_or(target)
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_end_matches('/')
            .split(':')
            .next()
            .unwrap_or(target);

        let query_type_str = dns_block.query_type.as_deref().unwrap_or("A").to_uppercase();
        let record_type = match query_type_str.as_str() {
            "A" => RecordType::A,
            "AAAA" => RecordType::AAAA,
            "CNAME" => RecordType::CNAME,
            "NS" => RecordType::NS,
            "TXT" => RecordType::TXT,
            "MX" => RecordType::MX,
            "PTR" => RecordType::PTR,
            "SOA" => RecordType::SOA,
            "SRV" => RecordType::SRV,
            "CAA" => RecordType::CAA,
            "AXFR" => RecordType::AXFR,
            _ => RecordType::A,
        };

        // Create resolver: custom resolvers if specified, or system default
        let resolver = if !dns_block.resolvers.is_empty() {
            let mut name_servers = Vec::new();
            for r in &dns_block.resolvers {
                let addr_str = if r.contains(':') {
                    r.clone()
                } else {
                    format!("{}:53", r)
                };
                if let Ok(socket_addr) = SocketAddr::from_str(&addr_str) {
                    name_servers.push(socket_addr);
                }
            }
            if !name_servers.is_empty() {
                let group = NameServerConfigGroup::from_ips_clear(&name_servers.iter().map(|s| s.ip()).collect::<Vec<_>>(), 53, true);
                let config = ResolverConfig::from_parts(None, vec![], group);
                TokioAsyncResolver::tokio(config, ResolverOpts::default())
            } else {
                TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
            }
        } else {
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
        };

        // Lookup records
        let mut records = Vec::new();
        let mut raw_lines = Vec::new();

        let lookup_res = resolver.lookup(domain, record_type).await;
        match lookup_res {
            Ok(response) => {
                for rdata in response.iter() {
                    let record_str = rdata.to_string();
                    records.push(record_str.clone());
                    raw_lines.push(format!("{} IN {} {}", domain, query_type_str, record_str));
                }
            }
            Err(e) => {
                raw_lines.push(format!("; DNS Lookup Error: {}", e));
            }
        }

        let raw = raw_lines.join("\n");
        Ok(DnsResponse {
            host: domain.to_string(),
            query_type: query_type_str,
            raw,
            records,
        })
    }
}
