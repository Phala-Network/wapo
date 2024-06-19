use std::{collections::BTreeSet, net::IpAddr};

use ipnet::{IpNet, Ipv4Net};
use iprange::IpRange;
use rocket::figment::{
    providers::{Format as _, Toml},
    Figment,
};
use tracing::info;

#[derive(Debug, Clone)]
pub struct HostFilter {
    ipv4_blacklist: IpRange<Ipv4Net>,
    ipv6_blacklist: IpRange<ipnet::Ipv6Net>,
    domain_blacklist: BTreeSet<String>,
}

impl HostFilter {
    #[allow(dead_code)]
    pub fn from_str(s: &str) -> Self {
        Self::from_iter(s.lines().map(|s| s.to_string()))
    }

    pub fn from_config_file(filename: &str) -> HostFilter {
        let figment = Figment::from(Toml::file(filename));
        let blacklist = figment
            .extract_inner::<Vec<String>>("default.tcp_connect_blacklist")
            .unwrap_or_default();
        let filter = HostFilter::from_iter(blacklist);
        info!("loaded TCP connect filter: {filter:#?}");
        filter
    }

    pub fn from_iter(iter: impl IntoIterator<Item = String>) -> Self {
        let mut ipv4_blacklist = IpRange::new();
        let mut ipv6_blacklist = IpRange::new();
        let mut domain_blacklist = BTreeSet::new();

        for line in iter {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Ok(net) = line.parse() {
                match net {
                    IpNet::V4(net) => {
                        ipv4_blacklist.add(net);
                    }
                    IpNet::V6(net) => {
                        ipv6_blacklist.add(net);
                    }
                }
            } else if let Ok(ip) = line.parse() {
                match ip {
                    IpAddr::V4(ip) => {
                        ipv4_blacklist.add(ip.into());
                    }
                    IpAddr::V6(ip) => {
                        ipv6_blacklist.add(ip.into());
                    }
                }
            } else {
                domain_blacklist.insert(line.to_string());
            }
        }

        Self {
            ipv4_blacklist,
            ipv6_blacklist,
            domain_blacklist,
        }
    }

    pub fn is_host_allowed(&self, host: &str) -> bool {
        if self.domain_blacklist.contains(host) {
            return false;
        }

        let Ok::<IpAddr, _>(ip) = host.parse() else {
            return true;
        };

        match ip {
            IpAddr::V4(ip) => !self.ipv4_blacklist.contains(&ip),
            IpAddr::V6(ip) => !self.ipv6_blacklist.contains(&ip),
        }
    }
}

#[test]
fn test_host_filter() {
    let filter = HostFilter::from_str(
        r#"
            192.168.0.0/16
            localhost
            127.0.0.1
            ::1
        "#,
    );
    dbg!(&filter);
    assert!(filter.is_host_allowed("google.com"));
    assert!(!filter.is_host_allowed("localhost"));
    assert!(!filter.is_host_allowed("192.168.1.195"));
    assert!(!filter.is_host_allowed("::1"));
}
