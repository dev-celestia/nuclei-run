use std::path::Path;

/// Locate a Chrome/Chromium executable across standard paths and environment variables.
pub fn locate_chrome() -> Option<String> {
    for env in ["CHROME_PATH", "CHROMIUM_PATH"] {
        if let Ok(p) = std::env::var(env) {
            if !p.is_empty() && Path::new(&p).exists() {
                return Some(p);
            }
        }
    }

    const CANDIDATES: &[&str] = &[
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/snap/bin/chromium",
    ];
    CANDIDATES
        .iter()
        .map(|p| p.to_string())
        .find(|p| Path::new(p).exists())
}
