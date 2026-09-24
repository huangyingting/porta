use super::session::{RequestContext, Response};
use std::fs;
use std::path::Path;
use std::sync::Arc;

pub const ROBOTS_TEXT: &str = "User-agent: *\nDisallow: /\n";
pub const ROBOTS_DIRECTIVES: &str = "noindex, nofollow, noarchive, nosnippet, noimageindex";
pub const MAX_LANDING_TEMPLATE_SIZE: u64 = 1 << 20;
pub const WEB_FONT_PATH: &str = "/assets/mona-sans.woff2";
pub const PORTA_MARK_PATH: &str = "/assets/porta-mark.svg";
pub const FAVICON_PATH: &str = "/favicon.ico";

const LANDING_HTML: &str = include_str!("../../assets/landing.html");
const LANDING_ACCESS_HTML: &str = include_str!("../../assets/landing-access.html");
const LANDING_EDITORIAL_HTML: &str = include_str!("../../assets/landing-editorial.html");
const LANDING_GRID_HTML: &str = include_str!("../../assets/landing-grid.html");
const LANDING_GALLERY_HTML: &str = include_str!("../../assets/landing-gallery.html");
const LANDING_MINIMAL_HTML: &str = include_str!("../../assets/landing-minimal.html");
const MONA_SANS: &[u8] = include_bytes!("../../assets/MonaSans.woff2");
const PORTA_MARK: &[u8] = include_bytes!("../../assets/porta-mark.svg");

type IndexSelector = Arc<dyn Fn(usize) -> usize + Send + Sync>;

#[derive(Clone)]
pub struct LandingTemplateSet {
    pages: Arc<Vec<String>>,
    selector: Option<IndexSelector>,
}

impl LandingTemplateSet {
    pub fn new(pages: Vec<String>) -> Self {
        Self {
            pages: Arc::new(pages),
            selector: None,
        }
    }

    #[cfg(test)]
    fn with_selector(pages: Vec<String>, selector: IndexSelector) -> Self {
        Self {
            pages: Arc::new(pages),
            selector: Some(selector),
        }
    }

    pub fn pages(&self) -> &[String] {
        &self.pages
    }

    pub fn select_page(&self) -> &str {
        assert!(!self.pages.is_empty(), "landing template set is empty");
        if self.pages.len() == 1 {
            return &self.pages[0];
        }
        let index = self.selector.as_ref().map_or_else(
            || rand::random_range(0..self.pages.len()),
            |select| select(self.pages.len()) % self.pages.len(),
        );
        &self.pages[index]
    }
}

pub fn bundled_landing_templates() -> LandingTemplateSet {
    LandingTemplateSet::new(vec![
        LANDING_HTML.to_owned(),
        LANDING_ACCESS_HTML.to_owned(),
        LANDING_EDITORIAL_HTML.to_owned(),
        LANDING_GRID_HTML.to_owned(),
        LANDING_GALLERY_HTML.to_owned(),
        LANDING_MINIMAL_HTML.to_owned(),
    ])
}

pub fn load_landing_template_set(
    directory: impl AsRef<Path>,
) -> Result<LandingTemplateSet, String> {
    let directory = directory.as_ref();
    if directory.as_os_str().is_empty() {
        return Ok(bundled_landing_templates());
    }
    let mut entries = fs::read_dir(directory)
        .map_err(|error| format!("read landing template directory: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("read landing template directory: {error}"))?;
    entries.sort_by_key(|entry| entry.file_name());
    let mut pages = Vec::new();
    for entry in entries {
        let file_type = entry.file_type().map_err(|error| {
            format!("inspect landing template {:?}: {error}", entry.file_name())
        })?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !file_type.is_file()
            || !name
                .rsplit_once('.')
                .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case("html"))
        {
            continue;
        }
        let metadata = entry
            .metadata()
            .map_err(|error| format!("inspect landing template \"{name}\": {error}"))?;
        if metadata.len() > MAX_LANDING_TEMPLATE_SIZE {
            return Err(format!(
                "landing template \"{name}\" exceeds the 1 MiB limit"
            ));
        }
        let content = fs::read(entry.path())
            .map_err(|error| format!("read landing template \"{name}\": {error}"))?;
        if content.len() as u64 > MAX_LANDING_TEMPLATE_SIZE {
            return Err(format!(
                "landing template \"{name}\" exceeds the 1 MiB limit"
            ));
        }
        let content = String::from_utf8(content)
            .map_err(|_| format!("landing template \"{name}\" is not valid UTF-8"))?;
        if content.trim().is_empty() {
            return Err(format!("landing template \"{name}\" is empty"));
        }
        pages.push(content);
    }
    if pages.is_empty() {
        Ok(bundled_landing_templates())
    } else {
        Ok(LandingTemplateSet::new(pages))
    }
}

pub struct LandingSite {
    pub enabled: bool,
    pub templates: LandingTemplateSet,
}

impl LandingSite {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            templates: bundled_landing_templates(),
        }
    }

    pub fn with_templates(enabled: bool, templates: LandingTemplateSet) -> Self {
        Self { enabled, templates }
    }

    pub fn handle(&self, request: &RequestContext) -> Option<Response> {
        if request.path == "/robots.txt" && request.is_get_or_head() {
            let mut response = Response::text(
                200,
                "text/plain; charset=utf-8",
                ROBOTS_TEXT.as_bytes().to_vec(),
            );
            set_crawler_policy(&mut response);
            response.set_header("Cache-Control", "public, max-age=300");
            return Some(response.without_body_for_head(request));
        }
        if let Some(response) = serve_asset(request) {
            return Some(response);
        }
        if is_operational_path(&request.path) {
            if self.enabled && request.is_get_or_head() {
                return Some(landing_response(request, self.templates.select_page()));
            }
            return Some(Response::not_found());
        }
        if !self.enabled || !request.is_get_or_head() {
            return None;
        }
        Some(landing_response(request, self.templates.select_page()))
    }
}

pub fn is_operational_path(path: &str) -> bool {
    matches!(path, "/healthz" | "/readyz" | "/metrics")
}

pub fn serve_asset(request: &RequestContext) -> Option<Response> {
    let (content_type, content) = match request.path.as_str() {
        WEB_FONT_PATH => ("font/woff2", MONA_SANS),
        PORTA_MARK_PATH | FAVICON_PATH => ("image/svg+xml", PORTA_MARK),
        _ => return None,
    };
    if !request.is_get_or_head() {
        return Some(Response::not_found());
    }
    let mut response = Response::text(200, content_type, content.to_vec());
    response.set_header("Cache-Control", "public, max-age=31536000, immutable");
    response.set_header("X-Content-Type-Options", "nosniff");
    response.set_header("Content-Length", content.len().to_string());
    Some(response.without_body_for_head(request))
}

pub fn set_crawler_policy(response: &mut Response) {
    response.set_header("X-Robots-Tag", ROBOTS_DIRECTIVES);
}

fn landing_response(request: &RequestContext, content: &str) -> Response {
    let mut response = Response::html(200, content.as_bytes().to_vec());
    set_crawler_policy(&mut response);
    response.set_header(
        "Content-Security-Policy",
        "default-src 'none'; style-src 'unsafe-inline'; font-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    );
    response.set_header("Referrer-Policy", "no-referrer");
    response.set_header("X-Content-Type-Options", "nosniff");
    response.set_header("Cache-Control", "no-store");
    response.without_body_for_head(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn bundled_pool_has_six_distinct_responsive_pages() {
        let templates = bundled_landing_templates();
        assert_eq!(templates.pages().len(), 6);
        let mut seen = std::collections::HashSet::new();
        for page in templates.pages() {
            for required in [
                "<title>Porta",
                "<h1>",
                "src=\"/assets/porta-mark.svg\"",
                "href=\"/access\"",
                "font-family:\"Mona Sans\"",
                "@media",
                ROBOTS_DIRECTIVES,
            ] {
                assert!(page.contains(required), "missing {required}");
            }
            for forbidden in [
                "network",
                "vpn",
                "gateway",
                "tunnel",
                "http/3",
                "self-hosted",
            ] {
                assert!(!page.to_ascii_lowercase().contains(forbidden));
            }
            assert!(seen.insert(page));
        }
    }

    #[test]
    fn selection_and_public_headers_match_go_behavior() {
        let call = Arc::new(AtomicUsize::new(0));
        let selection = Arc::clone(&call);
        let templates = LandingTemplateSet::with_selector(
            vec!["first".into(), "second".into()],
            Arc::new(move |limit| selection.fetch_add(1, Ordering::Relaxed) % limit),
        );
        let site = LandingSite::with_templates(true, templates);
        for expected in ["first", "second", "first"] {
            let response = site.handle(&RequestContext::new("GET", "/")).unwrap();
            assert_eq!(response.status, 200);
            assert_eq!(response.body, expected.as_bytes());
            assert_eq!(response.header("Cache-Control"), Some("no-store"));
            assert_eq!(response.header("X-Robots-Tag"), Some(ROBOTS_DIRECTIVES));
        }
    }

    #[test]
    fn custom_templates_are_sorted_limited_and_validated() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("b.html"), "<h1>second</h1>").unwrap();
        fs::write(directory.path().join("a.HTML"), "<h1>first</h1>").unwrap();
        fs::write(directory.path().join("notes.txt"), "ignored").unwrap();
        let templates = load_landing_template_set(directory.path()).unwrap();
        assert!(templates.pages()[0].contains("first"));
        assert!(templates.pages()[1].contains("second"));

        let empty = tempfile::tempdir().unwrap();
        fs::write(empty.path().join("empty.html"), " \n").unwrap();
        assert!(load_landing_template_set(empty.path())
            .err()
            .unwrap()
            .contains("is empty"));

        let oversized = tempfile::tempdir().unwrap();
        fs::write(
            oversized.path().join("large.html"),
            vec![0_u8; MAX_LANDING_TEMPLATE_SIZE as usize + 1],
        )
        .unwrap();
        assert!(load_landing_template_set(oversized.path())
            .err()
            .unwrap()
            .contains("exceeds the 1 MiB limit"));
    }

    #[test]
    fn robots_assets_and_operational_concealment_are_always_handled() {
        let disabled = LandingSite::new(false);
        assert_eq!(
            disabled
                .handle(&RequestContext::new("GET", "/robots.txt"))
                .unwrap()
                .body,
            ROBOTS_TEXT.as_bytes()
        );
        assert_eq!(
            disabled
                .handle(&RequestContext::new("GET", "/healthz"))
                .unwrap()
                .status,
            404
        );
        assert!(disabled.handle(&RequestContext::new("GET", "/")).is_none());
        let font = disabled
            .handle(&RequestContext::new("HEAD", WEB_FONT_PATH))
            .unwrap();
        assert_eq!(font.status, 200);
        assert!(font.body.is_empty());
        let expected_length = MONA_SANS.len().to_string();
        assert_eq!(
            font.header("Content-Length"),
            Some(expected_length.as_str())
        );
    }
}
