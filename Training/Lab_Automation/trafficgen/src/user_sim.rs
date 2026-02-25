use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::{watch, Mutex};
use rand::Rng;
use url::Url;

use crate::browser;
use crate::config::Config;
use crate::crawler;

pub struct UserStatus {
    pub user_id: usize,
    pub current_url: String,
    pub depth: usize,
    pub state: String,
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

impl VirtualUser {
    pub fn new(id: usize, config: Arc<Config>, pause_rx: watch::Receiver<bool>) -> Self {
        let status = Arc::new(Mutex::new(UserStatus {
            user_id: id,
            current_url: String::new(),
            depth: 0,
            state: "starting".to_string(),
        }));
        Self {
            id,
            config,
            pause_rx,
            status,
        }
    }

    pub async fn run(&mut self) {
        loop {
            let site_idx = {
                let mut rng = rand::thread_rng();
                rng.gen_range(0..self.config.sites.len())
            };
            let site = self.config.sites[site_idx].clone();
            let domain = site.host_str().unwrap_or("").to_string();

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

            'site_loop: loop {
                if tokio::time::Instant::now() >= site_switch_deadline {
                    break 'site_loop;
                }

                self.wait_if_paused().await;

                let mut depth = 0;
                visited.insert(current_url.to_string());

                while depth < self.config.max_depth {
                    {
                        let mut s = self.status.lock().await;
                        s.current_url = current_url.to_string();
                        s.depth = depth;
                        s.state = "browsing".to_string();
                    }

                    let body = match client.get(current_url.as_str()).send().await {
                        Ok(resp) => match resp.text().await {
                            Ok(text) => text,
                            Err(e) => {
                                eprintln!(
                                    "[user {}] Failed to read body from {}: {}",
                                    self.id, current_url, e
                                );
                                break;
                            }
                        },
                        Err(e) => {
                            eprintln!(
                                "[user {}] Failed to fetch {}: {}",
                                self.id, current_url, e
                            );
                            break;
                        }
                    };

                    {
                        let mut s = self.status.lock().await;
                        s.state = "waiting".to_string();
                    }
                    let delay = add_jitter(self.config.request_delay_mins * 60.0);
                    tokio::time::sleep(std::time::Duration::from_secs_f64(delay)).await;

                    self.wait_if_paused().await;

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
                        break;
                    }
                }

                current_url = site.clone();
                visited.clear();
            }
        }
    }

    async fn wait_if_paused(&mut self) {
        while *self.pause_rx.borrow() {
            {
                let mut s = self.status.lock().await;
                s.state = "paused".to_string();
            }
            let _ = self.pause_rx.changed().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_jitter_within_range() {
        for _ in 0..100 {
            let base = 60.0;
            let result = add_jitter(base);
            assert!(result >= 42.0, "Jitter too low: {}", result);
            assert!(result <= 78.0, "Jitter too high: {}", result);
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
