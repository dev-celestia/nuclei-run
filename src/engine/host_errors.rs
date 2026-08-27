use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Circuit breaker tracking consecutive failure counts per target host.
#[derive(Clone)]
pub struct HostErrorsCache {
    max_errors: usize,
    error_counts: Arc<RwLock<HashMap<String, usize>>>,
    dropped_hosts: Arc<RwLock<HashMap<String, bool>>>,
}

impl HostErrorsCache {
    pub fn new(max_errors: usize) -> Self {
        Self {
            max_errors,
            error_counts: Arc::new(RwLock::new(HashMap::new())),
            dropped_hosts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check if target host has exceeded max error threshold.
    pub async fn is_dropped(&self, target: &str) -> bool {
        if self.max_errors == 0 {
            return false;
        }
        let dropped = self.dropped_hosts.read().await;
        *dropped.get(target).unwrap_or(&false)
    }

    /// Record a connection or request error for target host.
    pub async fn record_error(&self, target: &str) -> bool {
        if self.max_errors == 0 {
            return false;
        }

        let mut counts = self.error_counts.write().await;
        let count = counts.entry(target.to_string()).or_insert(0);
        *count += 1;

        if *count >= self.max_errors {
            let mut dropped = self.dropped_hosts.write().await;
            dropped.insert(target.to_string(), true);
            return true; // Host just got tripped
        }

        false
    }

    /// Reset consecutive error count on successful response.
    pub async fn record_success(&self, target: &str) {
        if self.max_errors == 0 {
            return;
        }
        let mut counts = self.error_counts.write().await;
        counts.insert(target.to_string(), 0);
    }
}

/// Detects honeypot responses (e.g. servers returning the same 200 OK body for all non-existent paths).
pub struct HoneypotDetector;

impl HoneypotDetector {
    pub fn is_honeypot(responses: &[String]) -> bool {
        if responses.len() < 3 {
            return false;
        }
        let first = &responses[0];
        responses.iter().all(|r| r == first && !r.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_circuit_breaker() {
        let cache = HostErrorsCache::new(3);
        assert!(!cache.is_dropped("http://dead-host.com").await);

        cache.record_error("http://dead-host.com").await;
        cache.record_error("http://dead-host.com").await;
        assert!(!cache.is_dropped("http://dead-host.com").await);

        cache.record_error("http://dead-host.com").await;
        assert!(cache.is_dropped("http://dead-host.com").await);
    }

    #[test]
    fn test_honeypot_detection() {
        let same = vec!["<html>ok</html>".to_string(), "<html>ok</html>".to_string(), "<html>ok</html>".to_string()];
        assert!(HoneypotDetector::is_honeypot(&same));

        let diff = vec!["<html>404</html>".to_string(), "<html>200</html>".to_string(), "<html>500</html>".to_string()];
        assert!(!HoneypotDetector::is_honeypot(&diff));
    }
}
