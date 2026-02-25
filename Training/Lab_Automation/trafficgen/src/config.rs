// Runtime configuration

use std::net::IpAddr;

use ipnetwork::IpNetwork;

pub struct Config {
    pub sites: Vec<url::Url>,
    pub adapter: String,
    pub cidr: IpNetwork,
    pub dns: IpAddr,
    pub gateway: IpAddr,
    pub rotation_interval_mins: u64,
    pub request_delay_mins: f64,
    pub site_switch_mins: u64,
    pub num_users: usize,
    pub max_depth: usize,
}

pub fn parse_sites(input: &str) -> Vec<url::Url> {
    input
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| {
            let trimmed = line.trim();
            match url::Url::parse(trimmed) {
                Ok(u) => Some(u),
                Err(e) => {
                    eprintln!("[warn] Skipping invalid URL '{}': {}", trimmed, e);
                    None
                }
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_config_creation() {
        let config = Config {
            sites: vec![url::Url::parse("https://example.com").unwrap()],
            adapter: "eth0".to_string(),
            cidr: IpNetwork::from_str("10.0.0.0/24").unwrap(),
            dns: IpAddr::from_str("8.8.8.8").unwrap(),
            gateway: IpAddr::from_str("10.0.0.1").unwrap(),
            rotation_interval_mins: 15,
            request_delay_mins: 2.0,
            site_switch_mins: 30,
            num_users: 3,
            max_depth: 5,
        };
        assert_eq!(config.sites.len(), 1);
        assert_eq!(config.adapter, "eth0");
        assert_eq!(config.num_users, 3);
        assert_eq!(config.max_depth, 5);
    }

    #[test]
    fn test_parse_sites_valid() {
        let input = "https://10.0.0.1/login\nhttp://10.0.0.2:8080/index\nhttps://example.com\n";
        let sites = parse_sites(input);
        assert_eq!(sites.len(), 3);
        assert_eq!(sites[0].host_str().unwrap(), "10.0.0.1");
        assert_eq!(sites[1].port().unwrap(), 8080);
    }

    #[test]
    fn test_parse_sites_skips_invalid() {
        let input = "https://valid.com\nnot-a-url\nhttps://also-valid.com\n";
        let sites = parse_sites(input);
        assert_eq!(sites.len(), 2);
    }

    #[test]
    fn test_parse_sites_skips_empty_lines() {
        let input = "https://valid.com\n\n\nhttps://also-valid.com\n";
        let sites = parse_sites(input);
        assert_eq!(sites.len(), 2);
    }
}
