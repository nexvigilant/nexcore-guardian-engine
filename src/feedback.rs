#![allow(dead_code)]

//! # Feedback Persistence
//!
//! Records decision outcomes from the homeostasis loop for offline analysis
//! and adaptive learning. Each tick appends feedback records to a JSONL file.
//!
//! ## T1 Primitive Grounding
//!
//! | Concept | Primitive | Symbol |
//! |---------|-----------|--------|
//! | Record structure | Product | x |
//! | Append to file | Sequence | s |
//! | File path | Location | l |
//! | Write to disk | Persistence | p |
//! | Success/failure | Sum | S |

use nexcore_chrono::DateTime;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::config::FeedbackConfig;

/// A single feedback record from a homeostasis loop iteration.
///
/// Captures the signal→decision→outcome triple for offline analysis.
///
/// Tier: T2-C (composed product of T1 types)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackRecord {
    /// Timestamp of the feedback
    pub timestamp: DateTime,
    /// The signal pattern that triggered the decision
    pub signal_pattern: String,
    /// Signal severity level
    pub severity: String,
    /// The decision/action taken
    pub decision: String,
    /// Whether the actuator execution succeeded
    pub outcome_success: bool,
    /// Name of the actuator that executed
    pub actuator: String,
    /// Iteration ID from the homeostasis loop
    pub iteration_id: String,
}

/// Persistent feedback store backed by a JSONL file.
///
/// Appends one JSON line per record. Creates parent directories on first write.
/// Errors are logged (not propagated) to avoid feedback failures disrupting
/// the main control loop.
///
/// Tier: T2-C (persistence + sequence)
#[derive(Debug, Clone)]
pub struct FeedbackStore {
    /// Path to the JSONL file
    path: PathBuf,
    /// Whether feedback persistence is enabled
    enabled: bool,
}

impl FeedbackStore {
    /// Create a new feedback store at the given path.
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            enabled: true,
        }
    }

    /// Create from a `FeedbackConfig`.
    ///
    /// Resolves the path relative to `~/nexcore/` unless absolute.
    #[must_use]
    pub fn from_config(config: &FeedbackConfig) -> Self {
        let path = if std::path::Path::new(&config.path).is_absolute() {
            PathBuf::from(&config.path)
        } else {
            let mut base = if let Some(home) = std::env::var_os("HOME") {
                let mut p = PathBuf::from(home);
                p.push("nexcore");
                p
            } else {
                PathBuf::from("nexcore")
            };
            base.push(&config.path);
            base
        };

        Self {
            path,
            enabled: config.enabled,
        }
    }

    /// Check if the store is enabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get the file path.
    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Append a feedback record to the JSONL file.
    ///
    /// Creates parent directories if needed. Errors are logged, not propagated,
    /// because feedback must never disrupt the main control loop.
    pub fn append(&self, record: &FeedbackRecord) {
        if !self.enabled {
            return;
        }

        if let Err(e) = self.append_inner(record) {
            tracing::warn!(
                path = %self.path.display(),
                error = %e,
                "Failed to write feedback record"
            );
        }
    }

    /// Inner append implementation that can return errors.
    fn append_inner(&self, record: &FeedbackRecord) -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Write;

        // Ensure parent directory exists
        if let Some(parent) = self.path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let line = serde_json::to_string(record)?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(file, "{line}")?;
        Ok(())
    }

    /// Load all feedback records from the JSONL file.
    ///
    /// Returns an empty vec if the file doesn't exist or can't be read.
    #[must_use]
    pub fn load_all(&self) -> Vec<FeedbackRecord> {
        let content = match std::fs::read_to_string(&self.path) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(pattern: &str, success: bool) -> FeedbackRecord {
        FeedbackRecord {
            timestamp: DateTime::now(),
            signal_pattern: pattern.to_string(),
            severity: "High".to_string(),
            decision: "Alert".to_string(),
            outcome_success: success,
            actuator: "alert-actuator".to_string(),
            iteration_id: "iter-1".to_string(),
        }
    }

    #[test]
    fn test_feedback_roundtrip() {
        let dir = tempfile::tempdir().ok().expect("tempdir");
        let path = dir.path().join("feedback.jsonl");
        let store = FeedbackStore::new(path);

        let record = make_record("sql_injection:test", true);
        store.append(&record);

        let loaded = store.load_all();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].signal_pattern, "sql_injection:test");
        assert!(loaded[0].outcome_success);
    }

    #[test]
    fn test_feedback_multiple_records() {
        let dir = tempfile::tempdir().ok().expect("tempdir");
        let path = dir.path().join("feedback.jsonl");
        let store = FeedbackStore::new(path);

        store.append(&make_record("pattern-1", true));
        store.append(&make_record("pattern-2", false));
        store.append(&make_record("pattern-3", true));

        let loaded = store.load_all();
        assert_eq!(loaded.len(), 3);
        assert!(!loaded[1].outcome_success);
    }

    #[test]
    fn test_feedback_disabled() {
        let dir = tempfile::tempdir().ok().expect("tempdir");
        let path = dir.path().join("feedback.jsonl");
        let store = FeedbackStore {
            path,
            enabled: false,
        };

        store.append(&make_record("should-not-write", true));

        let loaded = store.load_all();
        assert!(loaded.is_empty());
    }

    #[test]
    fn test_feedback_missing_file_returns_empty() {
        let store = FeedbackStore::new(PathBuf::from("/tmp/nonexistent-guardian-feedback.jsonl"));
        let loaded = store.load_all();
        assert!(loaded.is_empty());
    }

    #[test]
    fn test_feedback_auto_creates_parent_dirs() {
        let dir = tempfile::tempdir().ok().expect("tempdir");
        let path = dir
            .path()
            .join("deep")
            .join("nested")
            .join("feedback.jsonl");
        let store = FeedbackStore::new(path.clone());

        store.append(&make_record("test", true));

        assert!(path.exists());
        let loaded = store.load_all();
        assert_eq!(loaded.len(), 1);
    }

    #[test]
    fn test_from_config() {
        let config = FeedbackConfig {
            path: "custom_feedback.jsonl".to_string(),
            enabled: true,
        };
        let store = FeedbackStore::from_config(&config);
        assert!(store.is_enabled());
        assert!(store.path().to_string_lossy().contains("custom_feedback"));
    }

    #[test]
    fn test_feedback_record_serialization() {
        let record = make_record("test_pattern", true);
        let json = serde_json::to_string(&record);
        assert!(json.is_ok());
        let parsed: Result<FeedbackRecord, _> =
            serde_json::from_str(&json.ok().expect("serialized"));
        assert!(parsed.is_ok());
    }
}
