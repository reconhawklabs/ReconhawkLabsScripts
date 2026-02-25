# trafficgen - Cyber Range Traffic Emulator Design

**Date:** 2026-02-25
**Status:** Approved

## Purpose

Generate realistic-looking web traffic on a cybersecurity training range to mask malicious traffic, making it harder for blue team operators to identify attacks by volume/pattern alone.

## Architecture

**Approach:** Async Tokio + reqwest (headless HTTP, no browser dependency)

- `tokio` async runtime with concurrent virtual user tasks
- `reqwest` for HTTP with cookies, user-agent rotation, TLS skip
- `scraper` for HTML parsing and link extraction
- Network changes via `ip` command (shell out)
- No desktop environment required

## Project Structure

```
Training/Lab_Automation/trafficgen/
├── Cargo.toml
├── sites.txt                  # User-created, one URL per line
├── src/
│   ├── main.rs                # Entry point, CLI prompts, orchestration
│   ├── config.rs              # Runtime configuration struct
│   ├── network.rs             # IP/MAC/adapter management
│   ├── mac.rs                 # Realistic MAC address generation (vendor OUIs)
│   ├── browser.rs             # HTTP client, user-agent rotation, cookie jar
│   ├── crawler.rs             # Link extraction, page navigation, depth control
│   └── user_sim.rs            # Virtual user behavior (timing, randomness)
```

## Startup Flow

1. Load `sites.txt` - parse and validate URLs
2. Interactive prompts:
   - Select network adapter (list available, pick by number)
   - CIDR range for IP rotation (e.g., `10.0.0.0/24`)
   - DNS server IP
   - Gateway/router IP
   - IP/MAC rotation interval (minutes)
   - Delay between web requests (minutes)
   - Site switch interval (minutes)
   - Number of concurrent virtual users
3. Validate all inputs
4. Display summary, confirm before starting
5. Launch virtual user tasks and rotation timer

## Network Adapter Management

### Listing Adapters
- Parse `ip link show` output
- Filter out `lo` and virtual interfaces
- Present as numbered list

### IP Rotation
- Parse CIDR to determine valid host addresses
- Exclude network address, broadcast address, gateway IP
- Pick random IP from valid set
- Execute: `ip addr flush` then `ip addr add <ip>/<prefix> dev <iface>`
- Set default route via gateway
- Write DNS to `/etc/resolv.conf`

### MAC Rotation
- ~50 hardcoded real vendor OUI prefixes (Dell, HP, Intel, Lenovo, Cisco, Apple, etc.)
- Random OUI + 3 cryptographic random bytes
- Locally-administered bit NOT set (looks like real vendor)

### Combined Rotation Sequence
1. Pause all virtual user HTTP requests
2. Bring adapter down
3. Set new MAC
4. Bring adapter up
5. Flush old IP, assign new IP with prefix length from CIDR
6. Set route + DNS
7. Poll for adapter up
8. Resume virtual user requests

## Web Traffic Generation

### HTTP Client (per virtual user)
- Cookie jar (reset on site switch)
- Random user-agent from ~10 current real browser strings
- TLS verification disabled
- Follow redirects (up to 10)
- Timeouts: 30s connect, 60s total
- Real browser Accept headers

### Link Extraction
- Parse HTML with `scraper`
- Extract `<a href="...">` links
- Resolve relative URLs
- Same-domain only (no external link following)
- Random selection (don't follow all links)
- Track visited URLs to avoid loops
- Max depth: 4-5 links

### User Simulation Loop
1. Pick random site from list
2. Visit URL
3. Wait randomized delay (configured minutes +/- 30% jitter)
4. Extract links, pick one randomly, visit it
5. Repeat 3-4 up to max depth
6. On site switch timer: pick different random site, go to 1
7. Otherwise: return to top-level and browse again
8. On IP/MAC rotation: pause, wait for completion, resume

## Dependencies

```toml
tokio = { version = "1", features = ["full"] }
reqwest = { version = "0.12", features = ["cookies"] }
scraper = "0.22"
url = "2"
ipnetwork = "0.20"
rand = "0.8"
dialoguer = "0.11"
console = "0.15"
```

## Error Handling

- **Root check**: Verify euid == 0 at startup
- **Adapter failure**: Retry 3x with 5s delays, attempt restore on failure
- **Site unreachable**: Log warning, skip to next site
- **No links found**: Wait delay, switch to different site
- **CIDR exhaustion**: Log warning, continue with potential IP reuse
- **Ctrl+C**: Graceful shutdown, attempt to restore original IP/MAC
- **Invalid sites.txt entries**: Skip with warning, require at least 1 valid URL

## Terminal Output

Compact in-place status display:
```
[trafficgen] Running | Users: 3 | IP: 10.0.0.47 | MAC: 00:1A:4B:3C:2D:1E (HP)
  User 1: browsing https://10.40.40.3/dashboard (depth 2/5)
  User 2: browsing https://10.40.40.5:8080/index (depth 1/5)
  User 3: waiting 45s before next request
  Next IP/MAC rotation in: 12m 33s
```

## Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Concurrency | Multiple virtual users | More realistic traffic volume |
| IP strategy | Shared IP + MAC, timed rotation | Each rotation looks like a different device |
| HTTP approach | reqwest (no browser) | Lightweight, no dependencies, headless |
| Crawl depth | 4-5 links | Simulates topic research browsing |
| TLS | Skip verification | Lab environment with self-signed certs |
| Run mode | Interactive foreground | Simpler operation and debugging |
| Link scope | Same domain only | Controlled, predictable traffic |
| Subnet mask | From CIDR prefix length | Single input, no redundancy |
| MAC vendors | ~50 hardcoded OUIs | Sufficient variety, no external files |
