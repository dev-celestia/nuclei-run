/// Parsed GitHub URL components.
#[derive(Debug, Clone)]
pub struct GitHubUrl {
    pub owner: String,
    pub repo: String,
    pub branch: String,
    pub subpath: String,
}

/// Check if a template path looks like a remote GitHub URL.
pub fn is_remote_url(path: &str) -> bool {
    path.starts_with("http://") || path.starts_with("https://")
}

/// Parse a GitHub URL into its components.
///
/// Supported formats:
/// - `https://github.com/owner/repo`
/// - `https://github.com/owner/repo/tree/branch`
/// - `https://github.com/owner/repo/tree/branch/path/to/dir`
pub fn parse_github_url(url: &str) -> Option<GitHubUrl> {
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
pub async fn download_github_archive(github: &GitHubUrl) -> Result<Vec<u8>, String> {
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

    eprintln!(
        "[INF] Downloaded {:.1} MB",
        bytes.len() as f64 / 1_048_576.0
    );

    Ok(bytes.to_vec())
}
