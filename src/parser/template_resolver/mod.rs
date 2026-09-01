pub mod archive;
pub mod cache;
pub mod github;

#[allow(unused_imports)]
pub use archive::extract_zip;
#[allow(unused_imports)]
pub use cache::{
    check_cache, dirs_path, get_cache_dir, write_cache_metadata, CacheMetadata, CACHE_TTL_SECS,
};
#[allow(unused_imports)]
pub use github::{download_github_archive, is_remote_url, parse_github_url, GitHubUrl};

use std::path::PathBuf;

/// Resolved template source: either a local path (as-is) or a cached/downloaded remote path.
pub struct ResolvedTemplates {
    /// Local path to use for template loading.
    pub local_path: PathBuf,
    /// Temp directory handle — kept alive so it won't be deleted until dropped.
    /// Only used when cache is not available (fallback).
    pub _temp_dir: Option<tempfile::TempDir>,
}

/// Resolve a template path. If it's a local path, return it directly.
/// If it's a GitHub URL, check cache first, then download and extract if needed.
pub async fn resolve_template_path(
    path: &str,
    force_update: bool,
) -> Result<ResolvedTemplates, String> {
    if !is_remote_url(path) {
        return Ok(ResolvedTemplates {
            local_path: PathBuf::from(path),
            _temp_dir: None,
        });
    }

    // Parse GitHub URL to extract owner, repo, branch, and subpath.
    let github =
        parse_github_url(path).ok_or_else(|| format!("Unsupported remote URL format: {}", path))?;

    // Check cache first (unless force update).
    let cache_dir = get_cache_dir(&github);
    let cache_meta = cache_dir.join(".nuclei-run-cache.json");

    if !force_update && cache_dir.exists() && cache_meta.exists() {
        if let Some(cached_path) = check_cache(&cache_dir, &cache_meta, &github) {
            eprintln!("[INF] Using cached templates from {}", cache_dir.display());
            return Ok(ResolvedTemplates {
                local_path: cached_path,
                _temp_dir: None,
            });
        }
    }

    eprintln!(
        "[INF] Downloading templates from {}/{} (branch: {}, path: {})",
        github.owner, github.repo, github.branch, github.subpath
    );

    // Download the repo archive.
    let zip_bytes = download_github_archive(&github).await?;

    // Extract to cache directory.
    // Clear old cache if it exists.
    if cache_dir.exists() {
        let _ = std::fs::remove_dir_all(&cache_dir);
    }
    std::fs::create_dir_all(&cache_dir)
        .map_err(|e| format!("Failed to create cache directory: {}", e))?;

    let extracted_path = extract_zip(&zip_bytes, &cache_dir, &github)?;

    // Write cache metadata.
    write_cache_metadata(&cache_meta, &github)?;

    eprintln!("[INF] Templates cached to {}", cache_dir.display());

    Ok(ResolvedTemplates {
        local_path: extracted_path,
        _temp_dir: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_github_url_full() {
        let url = "https://github.com/projectdiscovery/nuclei-templates/tree/main/http/cves";
        let parsed = parse_github_url(url).unwrap();
        assert_eq!(parsed.owner, "projectdiscovery");
        assert_eq!(parsed.repo, "nuclei-templates");
        assert_eq!(parsed.branch, "main");
        assert_eq!(parsed.subpath, "http/cves");
    }

    #[test]
    fn test_parse_github_url_repo_only() {
        let url = "https://github.com/projectdiscovery/nuclei-templates";
        let parsed = parse_github_url(url).unwrap();
        assert_eq!(parsed.owner, "projectdiscovery");
        assert_eq!(parsed.repo, "nuclei-templates");
        assert_eq!(parsed.branch, "main");
        assert_eq!(parsed.subpath, "");
    }

    #[test]
    fn test_parse_github_url_with_branch() {
        let url = "https://github.com/projectdiscovery/nuclei-templates/tree/develop";
        let parsed = parse_github_url(url).unwrap();
        assert_eq!(parsed.branch, "develop");
        assert_eq!(parsed.subpath, "");
    }

    #[test]
    fn test_is_remote_url() {
        assert!(is_remote_url("https://github.com/owner/repo"));
        assert!(is_remote_url("http://github.com/owner/repo"));
        assert!(!is_remote_url("./templates/"));
        assert!(!is_remote_url("/home/user/templates"));
    }

    #[test]
    fn test_cache_dir_structure() {
        let github = GitHubUrl {
            owner: "projectdiscovery".to_string(),
            repo: "nuclei-templates".to_string(),
            branch: "main".to_string(),
            subpath: "http/cves".to_string(),
        };
        let cache_dir = get_cache_dir(&github);
        assert!(cache_dir.ends_with("projectdiscovery/nuclei-templates/main"));
    }
}
