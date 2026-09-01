use crate::parser::template_resolver::github::GitHubUrl;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

/// Extract zip archive and return the path to the relevant subdirectory.
pub fn extract_zip(zip_bytes: &[u8], dest: &Path, github: &GitHubUrl) -> Result<PathBuf, String> {
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
        if !raw_name.starts_with(&subpath_prefix)
            && !raw_name.eq(&subpath_prefix.trim_end_matches('/'))
        {
            continue;
        }

        // Strip the archive prefix to get a clean relative path.
        let relative = raw_name.strip_prefix(&archive_prefix).unwrap_or(&raw_name);

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
