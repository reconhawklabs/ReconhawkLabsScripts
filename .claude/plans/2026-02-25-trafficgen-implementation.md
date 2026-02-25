# trafficgen Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a Rust-based traffic emulation tool that generates realistic web browsing traffic on a cybersecurity training range, with IP/MAC rotation to simulate different machines.

**Architecture:** Async tokio runtime with multiple concurrent virtual user tasks. Each user browses sites from `sites.txt` using reqwest, following links up to 5 levels deep. A shared rotation timer changes the adapter's IP and MAC simultaneously, pausing all users during the switch. Network changes use the Linux `ip` command.

**Tech Stack:** Rust 1.93, tokio, reqwest, scraper, ipnetwork, dialoguer, rand

---

### Task 1: Scaffold Project

**Files:**
- Create: `Training/Lab_Automation/trafficgen/Cargo.toml`
- Create: `Training/Lab_Automation/trafficgen/src/main.rs`
- Create: `Training/Lab_Automation/trafficgen/src/config.rs`
- Create: `Training/Lab_Automation/trafficgen/src/mac.rs`
- Create: `Training/Lab_Automation/trafficgen/src/network.rs`
- Create: `Training/Lab_Automation/trafficgen/src/browser.rs`
- Create: `Training/Lab_Automation/trafficgen/src/crawler.rs`
- Create: `Training/Lab_Automation/trafficgen/src/user_sim.rs`

**Step 1: Create Cargo.toml**

```toml
[package]
name = "trafficgen"
version = "0.1.0"
edition = "2021"
description = "Cyber range traffic emulator for blue team training"

[dependencies]
tokio = { version = "1", features = ["full"] }
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "cookies", "gzip"] }
scraper = "0.22"
url = "2"
ipnetwork = "0.20"
rand = "0.8"
dialoguer = "0.11"
console = "0.15"
```

**Step 2: Create module stubs**

`src/main.rs`:
```rust
mod config;
mod mac;
mod network;
mod browser;
mod crawler;
mod user_sim;

fn main() {
    println!("trafficgen - cyber range traffic emulator");
}
```

Each other file (`config.rs`, `mac.rs`, `network.rs`, `browser.rs`, `crawler.rs`, `user_sim.rs`) starts empty.

**Step 3: Verify it compiles**

Run: `cd Training/Lab_Automation/trafficgen && cargo build`
Expected: Compiles with no errors (warnings about unused modules are OK)

**Step 4: Commit**

```bash
git add Training/Lab_Automation/trafficgen/
git commit -m "feat: scaffold trafficgen project with dependencies and module stubs"
```

---

### Task 2: Config Module

**Files:**
- Modify: `src/config.rs`

**Step 1: Write tests for Config**

```rust
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
```

**Step 2: Run tests to verify they fail**

Run: `cargo test --lib config`
Expected: FAIL — `parse_sites` not defined

**Step 3: Implement parse_sites**

```rust
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
```

**Step 4: Run tests to verify they pass**

Run: `cargo test --lib config`
Expected: All 4 tests PASS

**Step 5: Commit**

```bash
git add src/config.rs
git commit -m "feat: add Config struct and sites.txt parser with validation"
```

---

### Task 3: MAC Address Generator

**Files:**
- Modify: `src/mac.rs`

**Step 1: Write tests for MAC generation**

```rust
use rand::Rng;

pub struct MacAddress {
    pub address: String,
    pub vendor: &'static str,
}

// Real vendor OUI prefixes (first 3 bytes of MAC)
const OUI_DATABASE: &[(&str, [u8; 3])] = &[
    ("Dell", [0x00, 0x14, 0x22]),
    ("Dell", [0x24, 0xB6, 0xFD]),
    ("HP", [0x00, 0x1A, 0x4B]),
    ("HP", [0x3C, 0xD9, 0x2B]),
    ("HPE", [0x94, 0x57, 0xA5]),
    ("Intel", [0x00, 0x1B, 0x21]),
    ("Intel", [0x68, 0x05, 0xCA]),
    ("Intel", [0xA4, 0xBF, 0x01]),
    ("Lenovo", [0x00, 0x06, 0x1B]),
    ("Lenovo", [0x50, 0x7B, 0x9D]),
    ("Realtek", [0x00, 0xE0, 0x4C]),
    ("Realtek", [0x52, 0x54, 0x00]),
    ("Cisco", [0x00, 0x1A, 0xA1]),
    ("Cisco", [0x00, 0x26, 0x0B]),
    ("Cisco", [0xF4, 0xCF, 0xE2]),
    ("Apple", [0x00, 0x1F, 0xF3]),
    ("Apple", [0xA8, 0x51, 0xAB]),
    ("Apple", [0xDC, 0xA4, 0xCA]),
    ("Samsung", [0x00, 0x16, 0x32]),
    ("Samsung", [0x78, 0x47, 0x1D]),
    ("Samsung", [0xAC, 0x5A, 0x14]),
    ("TP-Link", [0x00, 0x27, 0x19]),
    ("TP-Link", [0x50, 0xC7, 0xBF]),
    ("ASUS", [0x00, 0x1A, 0x92]),
    ("ASUS", [0x2C, 0x56, 0xDC]),
    ("Netgear", [0x00, 0x1E, 0x2A]),
    ("Netgear", [0xA0, 0x04, 0x60]),
    ("D-Link", [0x00, 0x1C, 0xF0]),
    ("D-Link", [0xB8, 0xA3, 0x86]),
    ("Juniper", [0x00, 0x26, 0x88]),
    ("Juniper", [0xF0, 0x1C, 0x2D]),
    ("Aruba", [0x00, 0x0B, 0x86]),
    ("Aruba", [0x24, 0xDE, 0xC6]),
    ("Ubiquiti", [0x04, 0x18, 0xD6]),
    ("Ubiquiti", [0xFC, 0xEC, 0xDA]),
    ("Microsoft", [0x00, 0x15, 0x5D]),
    ("Microsoft", [0x00, 0x50, 0xF2]),
    ("VMware", [0x00, 0x0C, 0x29]),
    ("VMware", [0x00, 0x50, 0x56]),
    ("Broadcom", [0x00, 0x10, 0x18]),
    ("Broadcom", [0xD8, 0x38, 0xFC]),
    ("Qualcomm", [0x00, 0x03, 0x7F]),
    ("Qualcomm", [0x9C, 0xFC, 0x01]),
    ("Huawei", [0x00, 0x18, 0x82]),
    ("Huawei", [0xE0, 0x24, 0x7F]),
    ("Supermicro", [0x00, 0x25, 0x90]),
    ("Supermicro", [0xAC, 0x1F, 0x6B]),
    ("Mellanox", [0x00, 0x02, 0xC9]),
    ("Arista", [0x00, 0x1C, 0x73]),
    ("Fortinet", [0x00, 0x09, 0x0F]),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mac_format() {
        let mac = generate_mac();
        // Format: XX:XX:XX:XX:XX:XX
        assert_eq!(mac.address.len(), 17);
        let parts: Vec<&str> = mac.address.split(':').collect();
        assert_eq!(parts.len(), 6);
        for part in &parts {
            assert_eq!(part.len(), 2);
            assert!(u8::from_str_radix(part, 16).is_ok());
        }
    }

    #[test]
    fn test_generate_mac_uses_real_vendor() {
        let mac = generate_mac();
        assert!(!mac.vendor.is_empty());
        // Verify the OUI matches a known vendor
        let oui_str: String = mac.address[..8].to_uppercase();
        let found = OUI_DATABASE.iter().any(|(name, bytes)| {
            let formatted = format!("{:02X}:{:02X}:{:02X}", bytes[0], bytes[1], bytes[2]);
            formatted == oui_str && *name == mac.vendor
        });
        assert!(found, "MAC {} with vendor {} not in OUI database", mac.address, mac.vendor);
    }

    #[test]
    fn test_generate_mac_not_locally_administered() {
        // Bit 1 of first byte (the "locally administered" bit) should NOT be set
        for _ in 0..20 {
            let mac = generate_mac();
            let first_byte = u8::from_str_radix(&mac.address[..2], 16).unwrap();
            assert_eq!(first_byte & 0x02, 0, "Locally administered bit is set on {}", mac.address);
        }
    }

    #[test]
    fn test_generate_mac_randomness() {
        // Generate 10 MACs, they should not all be identical
        let macs: Vec<MacAddress> = (0..10).map(|_| generate_mac()).collect();
        let first = &macs[0].address;
        let all_same = macs.iter().all(|m| m.address == *first);
        assert!(!all_same, "All 10 generated MACs were identical");
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test --lib mac`
Expected: FAIL — `generate_mac` not defined

**Step 3: Implement generate_mac**

```rust
pub fn generate_mac() -> MacAddress {
    let mut rng = rand::thread_rng();
    let idx = rng.gen_range(0..OUI_DATABASE.len());
    let (vendor, oui) = OUI_DATABASE[idx];

    let b3: u8 = rng.gen();
    let b4: u8 = rng.gen();
    let b5: u8 = rng.gen();

    let address = format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        oui[0], oui[1], oui[2], b3, b4, b5
    );

    MacAddress { address, vendor }
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test --lib mac`
Expected: All 4 tests PASS

**Step 5: Commit**

```bash
git add src/mac.rs
git commit -m "feat: add MAC address generator with 50 real vendor OUI prefixes"
```

---

### Task 4: Network Adapter Management

**Files:**
- Modify: `src/network.rs`

**Step 1: Write tests for network utilities**

```rust
use std::net::IpAddr;
use std::process::Command;
use ipnetwork::IpNetwork;
use crate::mac;

pub struct OriginalConfig {
    pub ip: Option<String>,
    pub mac: Option<String>,
    pub adapter: String,
}

pub struct AdapterInfo {
    pub name: String,
    pub mac: String,
    pub state: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_adapter_list() {
        let ip_link_output = r#"1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000
    link/ether 52:54:00:12:34:56 brd ff:ff:ff:ff:ff:ff
3: wlan0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff
4: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN mode DEFAULT group default
    link/ether 02:42:ac:11:00:01 brd ff:ff:ff:ff:ff:ff
5: veth123@if6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP mode DEFAULT
    link/ether 7e:3a:2b:1c:0d:0e brd ff:ff:ff:ff:ff:ff link-netnsid 0"#;
        let adapters = parse_adapters(ip_link_output);
        // Should include eth0 and wlan0, exclude lo, docker0, veth*
        let names: Vec<&str> = adapters.iter().map(|a| a.name.as_str()).collect();
        assert!(names.contains(&"eth0"), "Should contain eth0, got: {:?}", names);
        assert!(names.contains(&"wlan0"), "Should contain wlan0, got: {:?}", names);
        assert!(!names.contains(&"lo"), "Should not contain lo");
        assert!(!names.contains(&"docker0"), "Should not contain docker0");
    }

    #[test]
    fn test_parse_adapter_extracts_mac() {
        let ip_link_output = r#"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000
    link/ether 52:54:00:12:34:56 brd ff:ff:ff:ff:ff:ff"#;
        let adapters = parse_adapters(ip_link_output);
        assert_eq!(adapters[0].mac, "52:54:00:12:34:56");
    }

    #[test]
    fn test_build_rotation_commands() {
        let cmds = build_rotation_commands(
            "eth0",
            "AA:BB:CC:DD:EE:FF",
            "10.0.0.50",
            24,
            "10.0.0.1",
            "8.8.8.8",
        );
        assert_eq!(cmds.len(), 7);
        assert_eq!(cmds[0], vec!["ip", "link", "set", "dev", "eth0", "down"]);
        assert_eq!(cmds[1], vec!["ip", "link", "set", "dev", "eth0", "address", "AA:BB:CC:DD:EE:FF"]);
        assert_eq!(cmds[2], vec!["ip", "link", "set", "dev", "eth0", "up"]);
        assert_eq!(cmds[3], vec!["ip", "addr", "flush", "dev", "eth0"]);
        assert_eq!(cmds[4], vec!["ip", "addr", "add", "10.0.0.50/24", "dev", "eth0"]);
        assert_eq!(cmds[5], vec!["ip", "route", "add", "default", "via", "10.0.0.1", "dev", "eth0"]);
        assert_eq!(cmds[6], vec!["bash", "-c", "echo 'nameserver 8.8.8.8' > /etc/resolv.conf"]);
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test --lib network`
Expected: FAIL — functions not defined

**Step 3: Implement network functions**

```rust
pub fn parse_adapters(output: &str) -> Vec<AdapterInfo> {
    let mut adapters = Vec::new();
    let lines: Vec<&str> = output.lines().collect();
    let skip_prefixes = ["lo", "docker", "veth", "br-", "virbr"];

    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        // Match lines like "2: eth0: <FLAGS> ..."
        if let Some(name_part) = line.split(':').nth(1) {
            let name = name_part.trim().split('@').next().unwrap_or("").trim().to_string();
            if !name.is_empty() && !skip_prefixes.iter().any(|p| name.starts_with(p)) {
                let state = if line.contains("state UP") {
                    "UP".to_string()
                } else {
                    "DOWN".to_string()
                };

                let mut mac_addr = String::new();
                if i + 1 < lines.len() {
                    let next_line = lines[i + 1].trim();
                    if next_line.starts_with("link/ether") {
                        if let Some(m) = next_line.split_whitespace().nth(1) {
                            mac_addr = m.to_string();
                        }
                    }
                }

                if !mac_addr.is_empty() {
                    adapters.push(AdapterInfo { name, mac: mac_addr, state });
                }
            }
        }
        i += 1;
    }
    adapters
}

pub fn build_rotation_commands(
    adapter: &str,
    new_mac: &str,
    new_ip: &str,
    prefix_len: u8,
    gateway: &str,
    dns: &str,
) -> Vec<Vec<String>> {
    vec![
        vec!["ip", "link", "set", "dev", adapter, "down"],
        vec!["ip", "link", "set", "dev", adapter, "address", new_mac],
        vec!["ip", "link", "set", "dev", adapter, "up"],
        vec!["ip", "addr", "flush", "dev", adapter],
        vec!["ip", "addr", "add", &format!("{}/{}", new_ip, prefix_len), "dev", adapter],
        vec!["ip", "route", "add", "default", "via", gateway, "dev", adapter],
        vec!["bash", "-c", &format!("echo 'nameserver {}' > /etc/resolv.conf", dns)],
    ]
    .into_iter()
    .map(|v| v.into_iter().map(String::from).collect())
    .collect()
}

pub fn list_adapters() -> Result<Vec<AdapterInfo>, String> {
    let output = Command::new("ip")
        .args(["link", "show"])
        .output()
        .map_err(|e| format!("Failed to run 'ip link show': {}", e))?;

    if !output.status.success() {
        return Err(format!("'ip link show' failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_adapters(&stdout))
}

pub fn save_original_config(adapter: &str) -> Result<OriginalConfig, String> {
    let output = Command::new("ip")
        .args(["addr", "show", "dev", adapter])
        .output()
        .map_err(|e| format!("Failed to query adapter {}: {}", adapter, e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let ip = stdout.lines()
        .find(|l| l.contains("inet ") && !l.contains("inet6"))
        .and_then(|l| l.split_whitespace().nth(1))
        .map(|s| s.to_string());

    let mac = stdout.lines()
        .find(|l| l.contains("link/ether"))
        .and_then(|l| l.split_whitespace().nth(1))
        .map(|s| s.to_string());

    Ok(OriginalConfig {
        ip,
        mac,
        adapter: adapter.to_string(),
    })
}

pub async fn execute_rotation(
    adapter: &str,
    new_mac: &str,
    new_ip: &str,
    prefix_len: u8,
    gateway: &str,
    dns: &str,
) -> Result<(), String> {
    let commands = build_rotation_commands(adapter, new_mac, new_ip, prefix_len, gateway, dns);
    for cmd in &commands {
        let (program, args) = cmd.split_first().ok_or("Empty command")?;
        let output = Command::new(program)
            .args(args)
            .output()
            .map_err(|e| format!("Failed to execute '{}': {}", cmd.join(" "), e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Ignore "No such process" errors from route/flush (expected on fresh setup)
            if !stderr.contains("No such process") && !stderr.contains("File exists") {
                return Err(format!("Command '{}' failed: {}", cmd.join(" "), stderr));
            }
        }
    }

    // Wait briefly for adapter to come up
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    Ok(())
}

pub async fn restore_config(original: &OriginalConfig) -> Result<(), String> {
    if let Some(ref mac) = original.mac {
        let _ = Command::new("ip")
            .args(["link", "set", "dev", &original.adapter, "down"])
            .output();
        let _ = Command::new("ip")
            .args(["link", "set", "dev", &original.adapter, "address", mac])
            .output();
        let _ = Command::new("ip")
            .args(["link", "set", "dev", &original.adapter, "up"])
            .output();
    }
    if let Some(ref ip) = original.ip {
        let _ = Command::new("ip")
            .args(["addr", "flush", "dev", &original.adapter])
            .output();
        let _ = Command::new("ip")
            .args(["addr", "add", ip, "dev", &original.adapter])
            .output();
    }
    Ok(())
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test --lib network`
Expected: All 3 tests PASS

**Step 5: Commit**

```bash
git add src/network.rs
git commit -m "feat: add network adapter listing, IP/MAC rotation, and config backup/restore"
```

---

### Task 5: Browser / HTTP Client

**Files:**
- Modify: `src/browser.rs`

**Step 1: Write tests for user agent rotation and client building**

```rust
use reqwest::Client;
use rand::seq::SliceRandom;

const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
];

const ACCEPT_HEADER: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8";
const ACCEPT_LANGUAGE: &str = "en-US,en;q=0.9";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_user_agent_returns_valid() {
        let ua = random_user_agent();
        assert!(USER_AGENTS.contains(&ua), "Unexpected user agent: {}", ua);
    }

    #[test]
    fn test_random_user_agent_varies() {
        let agents: Vec<&str> = (0..20).map(|_| random_user_agent()).collect();
        let first = agents[0];
        let all_same = agents.iter().all(|a| *a == first);
        // With 10 options and 20 tries, extremely unlikely to get all same
        assert!(!all_same, "All 20 user agents were identical");
    }

    #[test]
    fn test_build_client_succeeds() {
        let client = build_client();
        assert!(client.is_ok());
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test --lib browser`
Expected: FAIL — functions not defined

**Step 3: Implement browser functions**

```rust
pub fn random_user_agent() -> &'static str {
    let mut rng = rand::thread_rng();
    USER_AGENTS.choose(&mut rng).expect("USER_AGENTS is non-empty")
}

pub fn build_client() -> Result<Client, reqwest::Error> {
    let ua = random_user_agent();
    Client::builder()
        .user_agent(ua)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(10))
        .connect_timeout(std::time::Duration::from_secs(30))
        .timeout(std::time::Duration::from_secs(60))
        .cookie_store(true)
        .default_headers({
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(reqwest::header::ACCEPT, ACCEPT_HEADER.parse().unwrap());
            headers.insert(reqwest::header::ACCEPT_LANGUAGE, ACCEPT_LANGUAGE.parse().unwrap());
            headers.insert(
                reqwest::header::ACCEPT_ENCODING,
                "gzip, deflate, br".parse().unwrap(),
            );
            headers
        })
        .build()
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test --lib browser`
Expected: All 3 tests PASS

**Step 5: Commit**

```bash
git add src/browser.rs
git commit -m "feat: add HTTP client builder with user-agent rotation and browser-like headers"
```

---

### Task 6: Link Crawler

**Files:**
- Modify: `src/crawler.rs`

**Step 1: Write tests for link extraction**

```rust
use scraper::{Html, Selector};
use url::Url;
use rand::seq::SliceRandom;
use std::collections::HashSet;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_links_absolute() {
        let html = r#"<html><body>
            <a href="https://example.com/page1">Page 1</a>
            <a href="https://example.com/page2">Page 2</a>
        </body></html>"#;
        let base = Url::parse("https://example.com").unwrap();
        let links = extract_links(html, &base);
        assert_eq!(links.len(), 2);
        assert!(links.iter().any(|u| u.as_str() == "https://example.com/page1"));
    }

    #[test]
    fn test_extract_links_relative() {
        let html = r#"<html><body>
            <a href="/about">About</a>
            <a href="contact">Contact</a>
        </body></html>"#;
        let base = Url::parse("https://example.com/home/").unwrap();
        let links = extract_links(html, &base);
        assert!(links.iter().any(|u| u.as_str() == "https://example.com/about"));
        assert!(links.iter().any(|u| u.as_str() == "https://example.com/home/contact"));
    }

    #[test]
    fn test_extract_links_ignores_fragments_and_mailto() {
        let html = r#"<html><body>
            <a href="#section">Jump</a>
            <a href="mailto:test@example.com">Email</a>
            <a href="javascript:void(0)">JS</a>
            <a href="https://example.com/real">Real</a>
        </body></html>"#;
        let base = Url::parse("https://example.com").unwrap();
        let links = extract_links(html, &base);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].as_str(), "https://example.com/real");
    }

    #[test]
    fn test_filter_same_domain() {
        let links = vec![
            Url::parse("https://example.com/page1").unwrap(),
            Url::parse("https://other.com/page2").unwrap(),
            Url::parse("https://example.com/page3").unwrap(),
        ];
        let filtered = filter_same_domain(&links, "example.com");
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_pick_random_links_respects_limit() {
        let links: Vec<Url> = (0..20)
            .map(|i| Url::parse(&format!("https://example.com/page{}", i)).unwrap())
            .collect();
        let visited = HashSet::new();
        let picked = pick_random_links(&links, 3, &visited);
        assert!(picked.len() <= 3);
    }

    #[test]
    fn test_pick_random_links_excludes_visited() {
        let links = vec![
            Url::parse("https://example.com/a").unwrap(),
            Url::parse("https://example.com/b").unwrap(),
            Url::parse("https://example.com/c").unwrap(),
        ];
        let mut visited = HashSet::new();
        visited.insert("https://example.com/a".to_string());
        visited.insert("https://example.com/b".to_string());
        let picked = pick_random_links(&links, 5, &visited);
        assert_eq!(picked.len(), 1);
        assert_eq!(picked[0].as_str(), "https://example.com/c");
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test --lib crawler`
Expected: FAIL — functions not defined

**Step 3: Implement crawler functions**

```rust
pub fn extract_links(html: &str, base_url: &Url) -> Vec<Url> {
    let document = Html::parse_document(html);
    let selector = Selector::parse("a[href]").expect("valid selector");
    let skip_schemes = ["mailto", "javascript", "tel", "ftp"];

    document
        .select(&selector)
        .filter_map(|el| el.value().attr("href"))
        .filter(|href| !href.starts_with('#'))
        .filter_map(|href| base_url.join(href).ok())
        .filter(|url| !skip_schemes.contains(&url.scheme()))
        .collect()
}

pub fn filter_same_domain<'a>(links: &'a [Url], domain: &str) -> Vec<&'a Url> {
    links
        .iter()
        .filter(|url| url.host_str() == Some(domain))
        .collect()
}

pub fn pick_random_links(links: &[Url], max: usize, visited: &HashSet<String>) -> Vec<Url> {
    let mut unvisited: Vec<&Url> = links
        .iter()
        .filter(|u| !visited.contains(u.as_str()))
        .collect();

    let mut rng = rand::thread_rng();
    unvisited.shuffle(&mut rng);
    unvisited.into_iter().take(max).cloned().collect()
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test --lib crawler`
Expected: All 6 tests PASS

**Step 5: Commit**

```bash
git add src/crawler.rs
git commit -m "feat: add link extraction, domain filtering, and random link selection"
```

---

### Task 7: User Simulation Engine

**Files:**
- Modify: `src/user_sim.rs`

**Step 1: Write the VirtualUser struct and jitter function with tests**

```rust
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::{watch, Mutex};
use rand::Rng;
use url::Url;

use crate::browser;
use crate::crawler;
use crate::config::Config;

pub struct UserStatus {
    pub user_id: usize,
    pub current_url: String,
    pub depth: usize,
    pub state: String, // "browsing", "waiting", "paused"
}

pub struct VirtualUser {
    pub id: usize,
    pub config: Arc<Config>,
    pub pause_rx: watch::Receiver<bool>,
    pub status: Arc<Mutex<UserStatus>>,
}

fn add_jitter(base_secs: f64) -> f64 {
    let mut rng = rand::thread_rng();
    let jitter_factor = rng.gen_range(0.7..1.3);
    base_secs * jitter_factor
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_jitter_within_range() {
        for _ in 0..100 {
            let base = 60.0;
            let result = add_jitter(base);
            assert!(result >= 42.0, "Jitter too low: {}", result); // 60 * 0.7
            assert!(result <= 78.0, "Jitter too high: {}", result); // 60 * 1.3
        }
    }

    #[test]
    fn test_add_jitter_varies() {
        let results: Vec<f64> = (0..20).map(|_| add_jitter(60.0)).collect();
        let first = results[0];
        let all_same = results.iter().all(|r| (*r - first).abs() < 0.001);
        assert!(!all_same, "All jitter results identical");
    }
}
```

**Step 2: Run tests to verify they pass**

Run: `cargo test --lib user_sim`
Expected: All 2 tests PASS (these are written implementation-first since jitter is simple)

**Step 3: Implement the VirtualUser::run method**

```rust
impl VirtualUser {
    pub fn new(
        id: usize,
        config: Arc<Config>,
        pause_rx: watch::Receiver<bool>,
    ) -> Self {
        let status = Arc::new(Mutex::new(UserStatus {
            user_id: id,
            current_url: String::new(),
            depth: 0,
            state: "starting".to_string(),
        }));
        Self { id, config, pause_rx, status }
    }

    pub async fn run(&self) {
        let mut rng = rand::thread_rng();

        loop {
            // Pick a random site
            let site_idx = rng.gen_range(0..self.config.sites.len());
            let site = self.config.sites[site_idx].clone();
            let domain = site.host_str().unwrap_or("").to_string();

            // Build a fresh client (new user-agent, fresh cookies)
            let client = match browser::build_client() {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("[user {}] Failed to build HTTP client: {}", self.id, e);
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                    continue;
                }
            };

            let mut visited = HashSet::new();
            let mut current_url = site.clone();
            let site_switch_deadline = tokio::time::Instant::now()
                + std::time::Duration::from_secs(self.config.site_switch_mins * 60);

            // Browse this site until switch timer expires
            'site_loop: loop {
                if tokio::time::Instant::now() >= site_switch_deadline {
                    break 'site_loop;
                }

                // Check if paused (IP/MAC rotation in progress)
                self.wait_if_paused().await;

                let mut depth = 0;
                visited.insert(current_url.to_string());

                // Depth loop: follow links up to max_depth
                while depth < self.config.max_depth {
                    // Update status
                    {
                        let mut s = self.status.lock().await;
                        s.current_url = current_url.to_string();
                        s.depth = depth;
                        s.state = "browsing".to_string();
                    }

                    // Fetch page
                    let body = match client.get(current_url.as_str()).send().await {
                        Ok(resp) => match resp.text().await {
                            Ok(text) => text,
                            Err(e) => {
                                eprintln!("[user {}] Failed to read body from {}: {}", self.id, current_url, e);
                                break;
                            }
                        },
                        Err(e) => {
                            eprintln!("[user {}] Failed to fetch {}: {}", self.id, current_url, e);
                            break;
                        }
                    };

                    // Wait between requests
                    {
                        let mut s = self.status.lock().await;
                        s.state = "waiting".to_string();
                    }
                    let delay = add_jitter(self.config.request_delay_mins * 60.0);
                    tokio::time::sleep(std::time::Duration::from_secs_f64(delay)).await;

                    self.wait_if_paused().await;

                    // Extract and follow links
                    let all_links = crawler::extract_links(&body, &current_url);
                    let same_domain: Vec<Url> = crawler::filter_same_domain(&all_links, &domain)
                        .into_iter()
                        .cloned()
                        .collect();
                    let candidates = crawler::pick_random_links(&same_domain, 1, &visited);

                    if let Some(next_url) = candidates.into_iter().next() {
                        visited.insert(next_url.to_string());
                        current_url = next_url;
                        depth += 1;
                    } else {
                        // No unvisited links found, break out
                        break;
                    }
                }

                // Reset to original site URL for another browse cycle
                current_url = site.clone();
                visited.clear();
            }
        }
    }

    async fn wait_if_paused(&self) {
        let mut rx = self.pause_rx.clone();
        while *rx.borrow() {
            {
                let mut s = self.status.lock().await;
                s.state = "paused".to_string();
            }
            let _ = rx.changed().await;
        }
    }
}
```

**Step 4: Verify it compiles**

Run: `cargo build`
Expected: Compiles successfully

**Step 5: Commit**

```bash
git add src/user_sim.rs
git commit -m "feat: add VirtualUser with browsing loop, link following, pause support, and jitter"
```

---

### Task 8: Main Orchestration — CLI Prompts

**Files:**
- Modify: `src/main.rs`

**Step 1: Implement the interactive startup prompts and orchestration**

```rust
mod config;
mod mac;
mod network;
mod browser;
mod crawler;
mod user_sim;

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::{watch, Mutex};
use ipnetwork::IpNetwork;
use dialoguer::{Select, Input, Confirm};
use console::style;
use rand::Rng;

use config::Config;
use network::{AdapterInfo, OriginalConfig};
use user_sim::VirtualUser;

fn load_sites(path: &str) -> Vec<url::Url> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{} Failed to read {}: {}", style("[error]").red().bold(), path, e);
            std::process::exit(1);
        }
    };
    let sites = config::parse_sites(&content);
    if sites.is_empty() {
        eprintln!("{} No valid URLs found in {}", style("[error]").red().bold(), path);
        std::process::exit(1);
    }
    println!("{} Loaded {} sites from {}", style("[ok]").green().bold(), sites.len(), path);
    for s in &sites {
        println!("  - {}", s);
    }
    sites
}

fn check_root() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("{} This program must be run as root (sudo)", style("[error]").red().bold());
        eprintln!("  Network adapter changes require root privileges.");
        std::process::exit(1);
    }
}

fn prompt_config(sites: Vec<url::Url>, adapters: &[AdapterInfo]) -> Config {
    println!("\n{}", style("=== trafficgen configuration ===").cyan().bold());

    // Select adapter
    let adapter_names: Vec<String> = adapters
        .iter()
        .map(|a| format!("{} (MAC: {}, State: {})", a.name, a.mac, a.state))
        .collect();
    let adapter_idx = Select::new()
        .with_prompt("Select network adapter")
        .items(&adapter_names)
        .default(0)
        .interact()
        .expect("Failed to read selection");
    let adapter = adapters[adapter_idx].name.clone();

    // CIDR range
    let cidr_str: String = Input::new()
        .with_prompt("CIDR range for IP rotation (e.g., 10.0.0.0/24)")
        .interact_text()
        .expect("Failed to read input");
    let cidr = IpNetwork::from_str(&cidr_str).unwrap_or_else(|e| {
        eprintln!("{} Invalid CIDR: {}", style("[error]").red().bold(), e);
        std::process::exit(1);
    });

    // DNS
    let dns_str: String = Input::new()
        .with_prompt("DNS server IP")
        .interact_text()
        .expect("Failed to read input");
    let dns = IpAddr::from_str(&dns_str).unwrap_or_else(|e| {
        eprintln!("{} Invalid DNS IP: {}", style("[error]").red().bold(), e);
        std::process::exit(1);
    });

    // Gateway
    let gw_str: String = Input::new()
        .with_prompt("Gateway/router IP")
        .interact_text()
        .expect("Failed to read input");
    let gateway = IpAddr::from_str(&gw_str).unwrap_or_else(|e| {
        eprintln!("{} Invalid gateway IP: {}", style("[error]").red().bold(), e);
        std::process::exit(1);
    });

    // Rotation interval
    let rotation_interval_mins: u64 = Input::new()
        .with_prompt("IP/MAC rotation interval (minutes)")
        .default(15)
        .interact_text()
        .expect("Failed to read input");

    // Request delay
    let request_delay_mins: f64 = Input::new()
        .with_prompt("Delay between web requests (minutes)")
        .default(2.0)
        .interact_text()
        .expect("Failed to read input");

    // Site switch
    let site_switch_mins: u64 = Input::new()
        .with_prompt("Switch to a different site every (minutes)")
        .default(30)
        .interact_text()
        .expect("Failed to read input");

    // Number of users
    let num_users: usize = Input::new()
        .with_prompt("Number of concurrent virtual users")
        .default(3)
        .interact_text()
        .expect("Failed to read input");

    Config {
        sites,
        adapter,
        cidr,
        dns,
        gateway,
        rotation_interval_mins,
        request_delay_mins,
        site_switch_mins,
        num_users,
        max_depth: 5,
    }
}

fn display_summary(config: &Config) {
    println!("\n{}", style("=== Configuration Summary ===").cyan().bold());
    println!("  Adapter:          {}", config.adapter);
    println!("  CIDR range:       {}", config.cidr);
    println!("  DNS:              {}", config.dns);
    println!("  Gateway:          {}", config.gateway);
    println!("  IP/MAC rotation:  every {} min", config.rotation_interval_mins);
    println!("  Request delay:    {} min", config.request_delay_mins);
    println!("  Site switch:      every {} min", config.site_switch_mins);
    println!("  Virtual users:    {}", config.num_users);
    println!("  Max crawl depth:  {}", config.max_depth);
    println!("  Sites:            {}", config.sites.len());
}

fn random_ip_from_cidr(cidr: &IpNetwork, gateway: &IpAddr) -> IpAddr {
    let mut rng = rand::thread_rng();
    let hosts: Vec<IpAddr> = cidr
        .iter()
        .filter(|ip| ip != gateway && ip != &cidr.network() && ip != &cidr.broadcast())
        .collect();
    hosts[rng.gen_range(0..hosts.len())]
}

#[tokio::main]
async fn main() {
    println!("{}", style("trafficgen — cyber range traffic emulator").bold());
    println!();

    // Root check
    check_root();

    // Load sites
    let sites = load_sites("sites.txt");

    // List adapters
    let adapters = network::list_adapters().unwrap_or_else(|e| {
        eprintln!("{} {}", style("[error]").red().bold(), e);
        std::process::exit(1);
    });
    if adapters.is_empty() {
        eprintln!("{} No suitable network adapters found", style("[error]").red().bold());
        std::process::exit(1);
    }

    // Prompt for config
    let config = prompt_config(sites, &adapters);
    display_summary(&config);

    // Confirm
    if !Confirm::new()
        .with_prompt("Start traffic generation?")
        .default(true)
        .interact()
        .expect("Failed to read confirmation")
    {
        println!("Aborted.");
        return;
    }

    // Save original config for restore on exit
    let original = network::save_original_config(&config.adapter).unwrap_or_else(|e| {
        eprintln!("{} Failed to save original config: {}", style("[error]").red().bold(), e);
        std::process::exit(1);
    });
    let original = Arc::new(original);

    let config = Arc::new(config);

    // Pause channel: true = paused, false = running
    let (pause_tx, pause_rx) = watch::channel(false);

    // Spawn virtual users
    let mut user_handles = Vec::new();
    let mut user_statuses = Vec::new();
    for i in 0..config.num_users {
        let user = VirtualUser::new(i + 1, Arc::clone(&config), pause_rx.clone());
        user_statuses.push(Arc::clone(&user.status));
        let handle = tokio::spawn(async move {
            user.run().await;
        });
        user_handles.push(handle);
    }

    // Perform initial IP/MAC rotation
    {
        let new_mac = mac::generate_mac();
        let new_ip = random_ip_from_cidr(&config.cidr, &config.gateway);
        let prefix = config.cidr.prefix();
        println!(
            "\n{} Initial rotation: IP={}, MAC={} ({})",
            style("[rotate]").yellow().bold(),
            new_ip,
            new_mac.address,
            new_mac.vendor,
        );
        if let Err(e) = network::execute_rotation(
            &config.adapter,
            &new_mac.address,
            &new_ip.to_string(),
            prefix,
            &config.gateway.to_string(),
            &config.dns.to_string(),
        )
        .await
        {
            eprintln!("{} Initial rotation failed: {}", style("[error]").red().bold(), e);
        }
    }

    // Spawn rotation timer
    let config_rot = Arc::clone(&config);
    let pause_tx_rot = pause_tx.clone();
    let original_for_ctrlc = Arc::clone(&original);
    let config_for_ctrlc = Arc::clone(&config);

    let rotation_handle = tokio::spawn(async move {
        let interval = std::time::Duration::from_secs(config_rot.rotation_interval_mins * 60);
        loop {
            tokio::time::sleep(interval).await;

            // Pause users
            let _ = pause_tx_rot.send(true);
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;

            let new_mac = mac::generate_mac();
            let new_ip = random_ip_from_cidr(&config_rot.cidr, &config_rot.gateway);
            let prefix = config_rot.cidr.prefix();

            println!(
                "\n{} Rotating: IP={}, MAC={} ({})",
                style("[rotate]").yellow().bold(),
                new_ip,
                new_mac.address,
                new_mac.vendor,
            );

            match network::execute_rotation(
                &config_rot.adapter,
                &new_mac.address,
                &new_ip.to_string(),
                prefix,
                &config_rot.gateway.to_string(),
                &config_rot.dns.to_string(),
            )
            .await
            {
                Ok(()) => {
                    println!(
                        "{} Rotation complete",
                        style("[rotate]").yellow().bold(),
                    );
                }
                Err(e) => {
                    eprintln!(
                        "{} Rotation failed: {}",
                        style("[error]").red().bold(),
                        e,
                    );
                }
            }

            // Resume users
            let _ = pause_tx_rot.send(false);
        }
    });

    // Spawn status display
    let user_statuses_display = user_statuses.clone();
    let config_display = Arc::clone(&config);
    let status_handle = tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            println!("\n{}", style("--- Status ---").dim());
            for status_lock in &user_statuses_display {
                let s = status_lock.lock().await;
                let url_display = if s.current_url.len() > 60 {
                    format!("{}...", &s.current_url[..57])
                } else {
                    s.current_url.clone()
                };
                println!(
                    "  User {}: {} {} (depth {}/{})",
                    s.user_id,
                    s.state,
                    url_display,
                    s.depth,
                    config_display.max_depth,
                );
            }
        }
    });

    // Wait for Ctrl+C
    println!(
        "\n{} Traffic generation started. Press Ctrl+C to stop.",
        style("[running]").green().bold(),
    );

    tokio::signal::ctrl_c()
        .await
        .expect("Failed to listen for Ctrl+C");

    println!(
        "\n{} Shutting down...",
        style("[stop]").red().bold(),
    );

    // Abort all tasks
    rotation_handle.abort();
    status_handle.abort();
    for h in &user_handles {
        h.abort();
    }

    // Restore original config
    println!("Restoring original network configuration...");
    if let Err(e) = network::restore_config(&original_for_ctrlc).await {
        eprintln!(
            "{} Failed to restore config: {}",
            style("[error]").red().bold(),
            e,
        );
    } else {
        println!(
            "{} Original network configuration restored.",
            style("[ok]").green().bold(),
        );
    }
}
```

**Step 2: Add `libc` to Cargo.toml dependencies**

Add to `[dependencies]`:
```toml
libc = "0.2"
```

**Step 3: Verify it compiles**

Run: `cargo build`
Expected: Compiles successfully

**Step 4: Commit**

```bash
git add src/main.rs Cargo.toml
git commit -m "feat: add main orchestration with CLI prompts, rotation timer, status display, and graceful shutdown"
```

---

### Task 9: Full Integration Test

**Step 1: Run all unit tests**

Run: `cargo test`
Expected: All tests pass (config: 4, mac: 4, browser: 3, crawler: 6, user_sim: 2, network: 3 = ~22 tests)

**Step 2: Build release binary**

Run: `cargo build --release`
Expected: Compiles. Binary at `target/release/trafficgen`

**Step 3: Create a sample sites.txt**

Create `sites.txt` in the trafficgen directory:
```
https://www.example.com
http://httpbin.org
https://www.rust-lang.org
```

**Step 4: Commit**

```bash
git add sites.txt
git commit -m "feat: add sample sites.txt for traffic generation"
```

---

### Task 10: Final Review and Cleanup

**Step 1: Run clippy for lint checks**

Run: `cargo clippy -- -D warnings`
Expected: No warnings. Fix any that appear.

**Step 2: Run cargo fmt**

Run: `cargo fmt`
Expected: Code formatted.

**Step 3: Final commit**

```bash
git add -u
git commit -m "chore: apply clippy fixes and formatting"
```

---

## Task Dependency Graph

```
Task 1 (scaffold)
  ├── Task 2 (config)
  ├── Task 3 (mac)
  ├── Task 5 (browser)
  └── Task 6 (crawler)
       │
Task 4 (network) ← depends on Task 3 (mac)
Task 7 (user_sim) ← depends on Tasks 2, 5, 6
Task 8 (main) ← depends on all above
Task 9 (integration) ← depends on Task 8
Task 10 (cleanup) ← depends on Task 9
```

Tasks 2, 3, 5, 6 can be implemented in parallel after Task 1.
Task 4 needs Task 3 first.
Task 7 needs Tasks 2, 5, 6.
Tasks 8-10 are sequential.
