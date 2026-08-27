use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

/// Default cache TTL: 24 hours in seconds.
const CACHE_TTL_SECS: u64 = 86400;

/// Resolved template source: either a local path (as-is) or a cached/downloaded remote path.
pub struct ResolvedTemplates {
    /// Local path to use for template loading.
    pub local_path: PathBuf,
    /// Temp directory handle — kept alive so it won't be deleted until dropped.
    /// Only used when cache is not available (fallback).
    pub _temp_dir: Option<tempfile::TempDir>,
}

/// Check if a template path looks like a remote GitHub URL.
pub fn is_remote_url(path: &str) -> bool {
    path.starts_with("http://") || path.starts_with("https://")
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
    let github = parse_github_url(path)
        .ok_or_else(|| format!("Unsupported remote URL format: {}", path))?;

    // Check cache first (unless force update).
    let cache_dir = get_cache_dir(&github);
    let cache_meta = cache_dir.join(".nuclei-run-cache.json");

    if !force_update && cache_dir.exists() && cache_meta.exists() {
        if let Some(cached_path) = check_cache(&cache_dir, &cache_meta, &github) {
            eprintln!(
                "[INF] Using cached templates from {}",
                cache_dir.display()
            );
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

    eprintln!(
        "[INF] Templates cached to {}",
        cache_dir.display()
    );

    Ok(ResolvedTemplates {
        local_path: extracted_path,
        _temp_dir: None,
    })
}

/// Get the cache directory path for a GitHub URL.
/// Structure: ~/.nuclei-run/templates/<owner>/<repo>/<branch>/
fn get_cache_dir(github: &GitHubUrl) -> PathBuf {
    let home = dirs_path();
    home.join(".nuclei-run")
        .join("templates")
        .join(&github.owner)
        .join(&github.repo)
        .join(&github.branch)
}

/// Get the user's home directory.
fn dirs_path() -> PathBuf {
    // Try HOME env var first, then fallback.
    if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home)
    } else if let Ok(home) = std::env::var("USERPROFILE") {
        PathBuf::from(home)
    } else {
        PathBuf::from(".")
    }
}

/// Cache metadata stored as JSON.
#[derive(serde::Serialize, serde::Deserialize)]
struct CacheMetadata {
    owner: String,
    repo: String,
    branch: String,
    subpath: String,
    downloaded_at: u64,
    url: String,
}

/// Check if cached templates are still valid (within TTL).
/// Returns the path to use if cache is valid, None otherwise.
fn check_cache(cache_dir: &Path, meta_path: &Path, github: &GitHubUrl) -> Option<PathBuf> {
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
fn write_cache_metadata(meta_path: &Path, github: &GitHubUrl) -> Result<(), String> {
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

/// Parsed GitHub URL components.
struct GitHubUrl {
    owner: String,
    repo: String,
    branch: String,
    subpath: String,
}

/// Parse a GitHub URL into its components.
///
/// Supported formats:
/// - `https://github.com/owner/repo`
/// - `https://github.com/owner/repo/tree/branch`
/// - `https://github.com/owner/repo/tree/branch/path/to/dir`
fn parse_github_url(url: &str) -> Option<GitHubUrl> {
    let url = url.trim().trim_end_matches('/');

    // Strip the github.com prefix.
    let path = url
        .strip_prefix("https://github.com/")
        .or_else(|| url.strip_prefix("http://github.com/"))?;

    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() < 2 {
        return None;
    }

    let owner = parts[0].to_string();
    let repo = parts[1].to_string();

    // Default branch and subpath.
    let (branch, subpath) = if parts.len() >= 4 && parts[2] == "tree" {
        let branch = parts[3].to_string();
        let subpath = if parts.len() > 4 {
            parts[4..].join("/")
        } else {
            String::new()
        };
        (branch, subpath)
    } else {
        ("main".to_string(), String::new())
    };

    Some(GitHubUrl {
        owner,
        repo,
        branch,
        subpath,
    })
}

/// Download a GitHub repo archive as a zip file.
async fn download_github_archive(github: &GitHubUrl) -> Result<Vec<u8>, String> {
    let url = format!(
        "https://github.com/{}/{}/archive/refs/heads/{}.zip",
        github.owner, github.repo, github.branch
    );

    let client = reqwest::Client::builder()
        .user_agent("nuclei-run/0.1")
        .redirect(reqwest::redirect::Policy::limited(10))
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Failed to download {}: {}", url, e))?;

    if !response.status().is_success() {
        return Err(format!(
            "Failed to download templates: HTTP {} from {}",
            response.status(),
            url
        ));
    }

    let bytes = response
        .bytes()
        .await
        .map_err(|e| format!("Failed to read response body: {}", e))?;

    eprintln!("[INF] Downloaded {:.1} MB", bytes.len() as f64 / 1_048_576.0);

    Ok(bytes.to_vec())
}

/// Extract zip archive and return the path to the relevant subdirectory.
fn extract_zip(
    zip_bytes: &[u8],
    dest: &Path,
    github: &GitHubUrl,
) -> Result<PathBuf, String> {
    let cursor = Cursor::new(zip_bytes);
    let mut archive =
        zip::ZipArchive::new(cursor).map_err(|e| format!("Failed to open zip archive: {}", e))?;

    // GitHub archives are prefixed with `repo-branch/`.
    let archive_prefix = format!("{}-{}/", github.repo, github.branch);
    let subpath_prefix = if github.subpath.is_empty() {
        archive_prefix.clone()
    } else {
        format!("{}{}/", archive_prefix, github.subpath)
    };

    let mut extracted_count = 0;

    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .map_err(|e| format!("Failed to read zip entry: {}", e))?;

        let raw_name = file.name().to_string();

        // Only extract files within the target subpath.
        if !raw_name.starts_with(&subpath_prefix) && !raw_name.eq(&subpath_prefix.trim_end_matches('/')) {
            continue;
        }

        // Strip the archive prefix to get a clean relative path.
        let relative = raw_name
            .strip_prefix(&archive_prefix)
            .unwrap_or(&raw_name);

        let out_path = dest.join(relative);

        if file.is_dir() {
            std::fs::create_dir_all(&out_path)
                .map_err(|e| format!("Failed to create directory {}: {}", out_path.display(), e))?;
        } else {
            // Ensure parent directory exists.
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    format!("Failed to create directory {}: {}", parent.display(), e)
                })?;
            }

            let mut buf = Vec::new();
            file.read_to_end(&mut buf)
                .map_err(|e| format!("Failed to read zip entry {}: {}", raw_name, e))?;

            std::fs::write(&out_path, &buf)
                .map_err(|e| format!("Failed to write {}: {}", out_path.display(), e))?;

            extracted_count += 1;
        }
    }

    eprintln!("[INF] Extracted {} template files", extracted_count);

    // Return the path to the subpath directory within the cache dir.
    let result_path = if github.subpath.is_empty() {
        dest.to_path_buf()
    } else {
        dest.join(&github.subpath)
    };

    if !result_path.exists() {
        return Err(format!(
            "Subpath '{}' not found in repository {}/{}",
            github.subpath, github.owner, github.repo
        ));
    }

    Ok(result_path)
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
