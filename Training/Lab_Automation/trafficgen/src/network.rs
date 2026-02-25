use tokio::process::Command;

pub struct OriginalConfig {
    pub ip: Option<String>,
    pub mac: Option<String>,
    pub gateway: Option<String>,
    pub resolv_conf: Option<String>,
    pub adapter: String,
}

pub struct AdapterInfo {
    pub name: String,
    pub mac: String,
    pub state: String,
}

fn is_valid_adapter_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
}

pub fn parse_adapters(output: &str) -> Vec<AdapterInfo> {
    let mut adapters = Vec::new();
    let lines: Vec<&str> = output.lines().collect();
    let skip_prefixes = ["lo", "docker", "veth", "br-", "virbr"];

    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        if let Some(name_part) = line.split(':').nth(1) {
            let name = name_part
                .trim()
                .split('@')
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            if !name.is_empty()
                && is_valid_adapter_name(&name)
                && !skip_prefixes.iter().any(|p| name.starts_with(p))
            {
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
                    adapters.push(AdapterInfo {
                        name,
                        mac: mac_addr,
                        state,
                    });
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
) -> Vec<Vec<String>> {
    vec![
        vec!["ip", "link", "set", "dev", adapter, "down"],
        vec![
            "ip", "link", "set", "dev", adapter, "address", new_mac,
        ],
        vec!["ip", "link", "set", "dev", adapter, "up"],
        vec!["ip", "addr", "flush", "dev", adapter],
        vec![
            "ip",
            "addr",
            "add",
            &format!("{}/{}", new_ip, prefix_len),
            "dev",
            adapter,
        ],
        vec![
            "ip", "route", "add", "default", "via", gateway, "dev", adapter,
        ],
    ]
    .into_iter()
    .map(|v| v.into_iter().map(String::from).collect())
    .collect()
}

pub async fn list_adapters() -> Result<Vec<AdapterInfo>, String> {
    let output = Command::new("ip")
        .args(["link", "show"])
        .output()
        .await
        .map_err(|e| format!("Failed to run 'ip link show': {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "'ip link show' failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_adapters(&stdout))
}

pub async fn save_original_config(adapter: &str) -> Result<OriginalConfig, String> {
    let output = Command::new("ip")
        .args(["addr", "show", "dev", adapter])
        .output()
        .await
        .map_err(|e| format!("Failed to query adapter {}: {}", adapter, e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let ip = stdout
        .lines()
        .find(|l| l.contains("inet ") && !l.contains("inet6"))
        .and_then(|l| l.split_whitespace().nth(1))
        .map(|s| s.to_string());

    let mac = stdout
        .lines()
        .find(|l| l.contains("link/ether"))
        .and_then(|l| l.split_whitespace().nth(1))
        .map(|s| s.to_string());

    // Save default route
    let route_output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .await
        .map_err(|e| format!("Failed to query default route: {}", e))?;
    let route_stdout = String::from_utf8_lossy(&route_output.stdout);
    let gateway = route_stdout
        .lines()
        .next()
        .and_then(|l| {
            let parts: Vec<&str> = l.split_whitespace().collect();
            parts
                .iter()
                .position(|&p| p == "via")
                .and_then(|i| parts.get(i + 1))
                .map(|s| s.to_string())
        });

    // Save resolv.conf
    let resolv_conf = tokio::fs::read_to_string("/etc/resolv.conf")
        .await
        .ok();

    Ok(OriginalConfig {
        ip,
        mac,
        gateway,
        resolv_conf,
        adapter: adapter.to_string(),
    })
}

pub async fn write_resolv_conf(dns: &str) -> Result<(), String> {
    let content = format!("nameserver {}\n", dns);
    let tmp_path = "/etc/resolv.conf.trafficgen.tmp";
    tokio::fs::write(tmp_path, &content)
        .await
        .map_err(|e| format!("Failed to write temp resolv.conf: {}", e))?;
    tokio::fs::rename(tmp_path, "/etc/resolv.conf")
        .await
        .map_err(|e| format!("Failed to rename resolv.conf: {}", e))?;
    Ok(())
}

async fn run_cmd(args: &[String]) -> Result<(), String> {
    let (program, cmd_args) = args.split_first().ok_or("Empty command")?;
    let output = Command::new(program)
        .args(cmd_args)
        .output()
        .await
        .map_err(|e| format!("Failed to execute '{}': {}", args.join(" "), e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("No such process") && !stderr.contains("File exists") {
            return Err(format!("Command '{}' failed: {}", args.join(" "), stderr));
        }
    }
    Ok(())
}

pub async fn execute_rotation(
    adapter: &str,
    new_mac: &str,
    new_ip: &str,
    prefix_len: u8,
    gateway: &str,
    dns: &str,
) -> Result<(), String> {
    let commands = build_rotation_commands(adapter, new_mac, new_ip, prefix_len, gateway);
    for cmd in &commands {
        let result = run_cmd(cmd).await;
        if let Err(ref e) = result {
            // If the route command fails (e.g. gateway outside subnet), retry with onlink
            if cmd.contains(&"route".to_string()) && e.contains("invalid gateway") {
                eprintln!("[network] Route failed, retrying with onlink flag...");
                let mut onlink_cmd = cmd.clone();
                onlink_cmd.push("onlink".to_string());
                run_cmd(&onlink_cmd).await?;
            } else {
                return result;
            }
        }
    }

    // Write DNS config directly (no shell)
    write_resolv_conf(dns).await?;

    // Wait briefly for adapter to come up
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    Ok(())
}

pub async fn restore_config(original: &OriginalConfig) -> Result<(), String> {
    if let Some(ref mac) = original.mac {
        let _ = Command::new("ip")
            .args(["link", "set", "dev", &original.adapter, "down"])
            .output()
            .await;
        let _ = Command::new("ip")
            .args(["link", "set", "dev", &original.adapter, "address", mac])
            .output()
            .await;
        let _ = Command::new("ip")
            .args(["link", "set", "dev", &original.adapter, "up"])
            .output()
            .await;
    }
    if let Some(ref ip) = original.ip {
        let _ = Command::new("ip")
            .args(["addr", "flush", "dev", &original.adapter])
            .output()
            .await;
        let _ = Command::new("ip")
            .args(["addr", "add", ip, "dev", &original.adapter])
            .output()
            .await;
    }
    // Restore default route
    if let Some(ref gw) = original.gateway {
        let _ = Command::new("ip")
            .args(["route", "add", "default", "via", gw, "dev", &original.adapter])
            .output()
            .await;
    }
    // Restore resolv.conf
    if let Some(ref content) = original.resolv_conf {
        let _ = tokio::fs::write("/etc/resolv.conf", content).await;
    }
    Ok(())
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
        let names: Vec<&str> = adapters.iter().map(|a| a.name.as_str()).collect();
        assert!(
            names.contains(&"eth0"),
            "Should contain eth0, got: {:?}",
            names
        );
        assert!(
            names.contains(&"wlan0"),
            "Should contain wlan0, got: {:?}",
            names
        );
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
        );
        assert_eq!(cmds.len(), 6);
        assert_eq!(cmds[0], vec!["ip", "link", "set", "dev", "eth0", "down"]);
        assert_eq!(
            cmds[1],
            vec!["ip", "link", "set", "dev", "eth0", "address", "AA:BB:CC:DD:EE:FF"]
        );
        assert_eq!(cmds[2], vec!["ip", "link", "set", "dev", "eth0", "up"]);
        assert_eq!(cmds[3], vec!["ip", "addr", "flush", "dev", "eth0"]);
        assert_eq!(
            cmds[4],
            vec!["ip", "addr", "add", "10.0.0.50/24", "dev", "eth0"]
        );
        assert_eq!(
            cmds[5],
            vec!["ip", "route", "add", "default", "via", "10.0.0.1", "dev", "eth0"]
        );
    }

    #[test]
    fn test_is_valid_adapter_name() {
        assert!(is_valid_adapter_name("eth0"));
        assert!(is_valid_adapter_name("wlan0"));
        assert!(is_valid_adapter_name("ens3"));
        assert!(is_valid_adapter_name("enp0s3"));
        assert!(!is_valid_adapter_name(""));
        assert!(!is_valid_adapter_name("a b"));
        assert!(!is_valid_adapter_name("eth0; rm -rf /"));
        assert!(!is_valid_adapter_name("abcdefghijklmnop")); // 16 chars
    }
}
