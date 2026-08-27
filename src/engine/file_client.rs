use crate::models::template::FileBlock;
use std::path::Path;
use walkdir::WalkDir;

#[derive(Debug, Clone)]
pub struct FileResponse {
    pub file_path: String,
    pub content: String,
    pub extension: String,
}

pub struct FileClient;

impl FileClient {
    pub fn scan_path(block: &FileBlock, target_dir: &str) -> Vec<FileResponse> {
        let mut results = Vec::new();
        let path = Path::new(target_dir);

        if !path.exists() {
            return results;
        }

        let exts: Vec<String> = block.extensions.iter().map(|e| e.trim_start_matches('.').to_lowercase()).collect();

        if path.is_file() {
            if let Ok(content) = std::fs::read_to_string(path) {
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
                if exts.is_empty() || exts.contains(&ext) {
                    results.push(FileResponse {
                        file_path: path.to_string_lossy().to_string(),
                        content,
                        extension: ext,
                    });
                }
            }
        } else if path.is_dir() {
            for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
                let p = entry.path();
                if p.is_file() {
                    let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
                    if exts.is_empty() || exts.contains(&ext) {
                        if let Ok(content) = std::fs::read_to_string(p) {
                            results.push(FileResponse {
                                file_path: p.to_string_lossy().to_string(),
                                content,
                                extension: ext,
                            });
                        }
                    }
                }
            }
        }

        results
    }
}
