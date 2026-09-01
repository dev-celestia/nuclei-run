use crate::parser::template_resolver::github::GitHubUrl;
use std::path::{Path, PathBuf};

/// Default cache TTL: 24 hours in seconds.
pub const CACHE_TTL_SECS: u64 = 86400;

/// Cache metadata stored as JSON.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct CacheMetadata {
    pub owner: String,
    pub repo: String,
    pub branch: String,
    pub subpath: String,
    pub downloaded_at: u64,
    pub url: String,
}

/// Get the cache directory path for a GitHub URL.
/// Structure: ~/.nuclei-run/templates/<owner>/<repo>/<branch>/
pub fn get_cache_dir(github: &GitHubUrl) -> PathBuf {
    let home = dirs_path();
    home.join(".nuclei-run")
        .join("templates")
        .join(&github.owner)
        .join(&github.repo)
        .join(&github.branch)
}

/// Get the user's home directory.
pub fn dirs_path() -> PathBuf {
    // Try HOME env var first, then fallback.
    if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home)
    } else if let Ok(home) = std::env::var("USERPROFILE") {
        PathBuf::from(home)
    } else {
        PathBuf::from(".")
    }
}

/// Check if cached templates are still valid (within TTL).
/// Returns the path to use if cache is valid, None otherwise.
pub fn check_cache(cache_dir: &Path, meta_path: &Path, github: &GitHubUrl) -> Option<PathBuf> {
    let content = std::fs::read_to_string(meta_path).ok()?;
    let meta: CacheMetadata = serde_json::from_str(&content).ok()?;

    // Verify the cache matches the requested URL components.
    if meta.owner != github.owner
        || meta.repo != github.repo
        || meta.branch != github.branch
        || meta.subpath != github.subpath
    {
        return None;
    }

    // Check TTL.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();

    if now - meta.downloaded_at > CACHE_TTL_SECS {
        eprintln!("[INF] Template cache expired, re-downloading...");
        return None;
    }

    let elapsed_mins = (now - meta.downloaded_at) / 60;
    eprintln!("[INF] Cache age: {} minutes (TTL: 24h)", elapsed_mins);

    // Return the path to the subpath within the cache.
    let result_path = if github.subpath.is_empty() {
        cache_dir.to_path_buf()
    } else {
        cache_dir.join(&github.subpath)
    };

    if result_path.exists() {
        Some(result_path)
    } else {
        None
    }
}

/// Write cache metadata file.
pub fn write_cache_metadata(meta_path: &Path, github: &GitHubUrl) -> Result<(), String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("Failed to get system time: {}", e))?
        .as_secs();

    let meta = CacheMetadata {
        owner: github.owner.clone(),
        repo: github.repo.clone(),
        branch: github.branch.clone(),
        subpath: github.subpath.clone(),
        downloaded_at: now,
        url: format!(
            "https://github.com/{}/{}/tree/{}/{}",
            github.owner, github.repo, github.branch, github.subpath
        ),
    };

    let json = serde_json::to_string_pretty(&meta)
        .map_err(|e| format!("Failed to serialize cache metadata: {}", e))?;

    std::fs::write(meta_path, json)
        .map_err(|e| format!("Failed to write cache metadata: {}", e))?;

    Ok(())
}
