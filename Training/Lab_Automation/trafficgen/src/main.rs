mod browser;
mod config;
mod crawler;
mod mac;
mod network;
mod user_sim;

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use console::style;
use dialoguer::{Confirm, Input, Select};
use ipnetwork::IpNetwork;
use rand::Rng;
use tokio::sync::watch;

use config::Config;
use network::AdapterInfo;
use user_sim::VirtualUser;

fn load_sites(path: &str) -> Vec<url::Url> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{} Failed to read {}: {}",
                style("[error]").red().bold(),
                path,
                e
            );
            std::process::exit(1);
        }
    };
    let sites = config::parse_sites(&content);
    if sites.is_empty() {
        eprintln!(
            "{} No valid URLs found in {}",
            style("[error]").red().bold(),
            path
        );
        std::process::exit(1);
    }
    println!(
        "{} Loaded {} sites from {}",
        style("[ok]").green().bold(),
        sites.len(),
        path
    );
    for s in &sites {
        println!("  - {}", s);
    }
    sites
}

fn check_root() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!(
            "{} This program must be run as root (sudo)",
            style("[error]").red().bold()
        );
        eprintln!("  Network adapter changes require root privileges.");
        std::process::exit(1);
    }
}

fn prompt_config(sites: Vec<url::Url>, adapters: &[AdapterInfo]) -> Config {
    println!(
        "\n{}",
        style("=== trafficgen configuration ===").cyan().bold()
    );

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

    let cidr_str: String = Input::new()
        .with_prompt("CIDR range for IP rotation (e.g., 10.0.0.0/24)")
        .interact_text()
        .expect("Failed to read input");
    let cidr = IpNetwork::from_str(&cidr_str).unwrap_or_else(|e| {
        eprintln!("{} Invalid CIDR: {}", style("[error]").red().bold(), e);
        std::process::exit(1);
    });

    let dns_str: String = Input::new()
        .with_prompt("DNS server IP")
        .interact_text()
        .expect("Failed to read input");
    let dns = IpAddr::from_str(&dns_str).unwrap_or_else(|e| {
        eprintln!("{} Invalid DNS IP: {}", style("[error]").red().bold(), e);
        std::process::exit(1);
    });

    let gw_str: String = Input::new()
        .with_prompt("Gateway/router IP")
        .interact_text()
        .expect("Failed to read input");
    let gateway = IpAddr::from_str(&gw_str).unwrap_or_else(|e| {
        eprintln!(
            "{} Invalid gateway IP: {}",
            style("[error]").red().bold(),
            e
        );
        std::process::exit(1);
    });

    if !cidr.contains(gateway) {
        eprintln!(
            "{} Gateway {} is not within CIDR range {}",
            style("[warn]").yellow().bold(),
            gateway,
            cidr,
        );
        eprintln!("  The gateway must be reachable from the assigned subnet.");
        eprintln!("  Routes will be added with 'onlink' flag as a fallback.");
    }

    let rotation_interval_mins: u64 = Input::new()
        .with_prompt("IP/MAC rotation interval (minutes)")
        .default(15)
        .interact_text()
        .expect("Failed to read input");
    if rotation_interval_mins == 0 {
        eprintln!(
            "{} Rotation interval must be at least 1 minute",
            style("[error]").red().bold()
        );
        std::process::exit(1);
    }

    let request_delay_mins: f64 = Input::new()
        .with_prompt("Delay between web requests (minutes)")
        .default(2.0)
        .interact_text()
        .expect("Failed to read input");
    if request_delay_mins < 0.0 {
        eprintln!(
            "{} Request delay cannot be negative",
            style("[error]").red().bold()
        );
        std::process::exit(1);
    }

    let site_switch_mins: u64 = Input::new()
        .with_prompt("Switch to a different site every (minutes)")
        .default(30)
        .interact_text()
        .expect("Failed to read input");

    let num_users: usize = Input::new()
        .with_prompt("Number of concurrent virtual users")
        .default(3)
        .interact_text()
        .expect("Failed to read input");
    if num_users == 0 || num_users > 50 {
        eprintln!(
            "{} Number of virtual users must be between 1 and 50",
            style("[error]").red().bold()
        );
        std::process::exit(1);
    }

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
    println!(
        "\n{}",
        style("=== Configuration Summary ===").cyan().bold()
    );
    println!("  Adapter:          {}", config.adapter);
    println!("  CIDR range:       {}", config.cidr);
    println!("  DNS:              {}", config.dns);
    println!("  Gateway:          {}", config.gateway);
    println!(
        "  IP/MAC rotation:  every {} min",
        config.rotation_interval_mins
    );
    println!("  Request delay:    {} min", config.request_delay_mins);
    println!(
        "  Site switch:      every {} min",
        config.site_switch_mins
    );
    println!("  Virtual users:    {}", config.num_users);
    println!("  Max crawl depth:  {}", config.max_depth);
    println!("  Sites:            {}", config.sites.len());
}

fn random_ip_from_cidr(cidr: &IpNetwork, gateway: &IpAddr) -> Result<IpAddr, String> {
    let hosts: Vec<IpAddr> = cidr
        .iter()
        .filter(|ip| ip != gateway && *ip != cidr.network() && *ip != cidr.broadcast())
        .collect();
    if hosts.is_empty() {
        return Err(format!("No valid hosts in CIDR range {}", cidr));
    }
    let idx = {
        let mut rng = rand::thread_rng();
        rng.gen_range(0..hosts.len())
    };
    Ok(hosts[idx])
}

#[tokio::main]
async fn main() {
    println!(
        "{}",
        style("trafficgen - cyber range traffic emulator").bold()
    );
    println!();

    check_root();

    let sites = load_sites("sites.txt");

    let adapters = network::list_adapters().await.unwrap_or_else(|e| {
        eprintln!("{} {}", style("[error]").red().bold(), e);
        std::process::exit(1);
    });
    if adapters.is_empty() {
        eprintln!(
            "{} No suitable network adapters found",
            style("[error]").red().bold()
        );
        std::process::exit(1);
    }

    let config = prompt_config(sites, &adapters);
    display_summary(&config);

    if !Confirm::new()
        .with_prompt("Start traffic generation?")
        .default(true)
        .interact()
        .expect("Failed to read confirmation")
    {
        println!("Aborted.");
        return;
    }

    let original = network::save_original_config(&config.adapter).await.unwrap_or_else(|e| {
        eprintln!(
            "{} Failed to save original config: {}",
            style("[error]").red().bold(),
            e
        );
        std::process::exit(1);
    });
    let original = Arc::new(original);

    let config = Arc::new(config);

    let (pause_tx, pause_rx) = watch::channel(false);

    let mut user_handles = Vec::new();
    let mut user_statuses = Vec::new();
    for i in 0..config.num_users {
        let mut user = VirtualUser::new(i + 1, Arc::clone(&config), pause_rx.clone());
        user_statuses.push(Arc::clone(&user.status));
        let handle = tokio::spawn(async move {
            user.run().await;
        });
        user_handles.push(handle);
    }

    // Perform initial IP/MAC rotation
    {
        let new_mac = mac::generate_mac();
        let new_ip = match random_ip_from_cidr(&config.cidr, &config.gateway) {
            Ok(ip) => ip,
            Err(e) => {
                eprintln!("{} {}", style("[error]").red().bold(), e);
                eprintln!("Restoring original network configuration...");
                if let Err(re) = network::restore_config(&original).await {
                    eprintln!("{} Failed to restore config: {}", style("[error]").red().bold(), re);
                }
                std::process::exit(1);
            }
        };
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
            eprintln!(
                "{} Initial rotation failed: {}",
                style("[error]").red().bold(),
                e
            );
        }
    }

    // Spawn rotation timer
    let config_rot = Arc::clone(&config);
    let rotation_handle = tokio::spawn(async move {
        let interval = std::time::Duration::from_secs(config_rot.rotation_interval_mins * 60);
        loop {
            tokio::time::sleep(interval).await;

            // Signal pause and wait for in-flight requests to finish
            let _ = pause_tx.send(true);
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;

            let new_mac = mac::generate_mac();
            let new_ip = match random_ip_from_cidr(&config_rot.cidr, &config_rot.gateway) {
                Ok(ip) => ip,
                Err(e) => {
                    eprintln!(
                        "{} CIDR exhaustion: {}",
                        style("[error]").red().bold(),
                        e,
                    );
                    let _ = pause_tx.send(false);
                    continue;
                }
            };
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

            let _ = pause_tx.send(false);
        }
    });

    // Spawn status display
    let config_display = Arc::clone(&config);
    let status_handle = tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            println!("\n{}", style("--- Status ---").dim());
            for status_lock in &user_statuses {
                let s = status_lock.lock().await;
                let url_display = if s.current_url.len() > 60 {
                    format!("{}...", &s.current_url[..57])
                } else {
                    s.current_url.clone()
                };
                println!(
                    "  User {}: {} {} (depth {}/{})",
                    s.user_id, s.state, url_display, s.depth, config_display.max_depth,
                );
            }
        }
    });

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

    rotation_handle.abort();
    status_handle.abort();
    for h in &user_handles {
        h.abort();
    }

    println!("Restoring original network configuration...");
    if let Err(e) = network::restore_config(&original).await {
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
