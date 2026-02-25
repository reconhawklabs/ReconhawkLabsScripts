use rand::seq::SliceRandom;
use scraper::{Html, Selector};
use std::collections::HashSet;
use url::Url;

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
        assert!(links
            .iter()
            .any(|u| u.as_str() == "https://example.com/home/contact"));
    }

    #[test]
    fn test_extract_links_ignores_fragments_and_mailto() {
        let html = r##"<html><body>
            <a href="#section">Jump</a>
            <a href="mailto:test@example.com">Email</a>
            <a href="javascript:void(0)">JS</a>
            <a href="https://example.com/real">Real</a>
        </body></html>"##;
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
