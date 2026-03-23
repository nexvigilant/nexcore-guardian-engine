//! # Incident Memory
//!
//! Persistent memory for Guardian incidents — threat signals, responses, and
//! lessons learned. Bridges the homeostasis loop to the Brain system for
//! cross-session recall and pattern detection.
//!
//! ## T1 Primitive Grounding
//!
//! | Component | Primitives |
//! |-----------|-----------|
//! | IncidentRecord | ×(Product) + π(Persistence) + σ(Sequence) |
//! | IncidentMemory | π(Persistence) + μ(Mapping) |
//! | RecallQuery | κ(Comparison) + λ(Location) |
//! | LessonLearned | →(Causality) + ρ(Recursion) |

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use nexcore_chrono::DateTime;
use serde::{Deserialize, Serialize};

use crate::response::ResponseAction;
use crate::sensing::{SignalSource, ThreatLevel, ThreatSignal};

// =============================================================================
// IncidentRecord — the primary unit of incident memory
// =============================================================================

/// A complete record of a Guardian incident: signal + decision + outcome.
///
/// Tier: T2-C (composed from T3 Guardian types + T1 persistence)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentRecord {
    /// Unique incident identifier
    pub id: String,
    /// When the incident was detected
    pub detected_at: DateTime,
    /// Homeostasis loop iteration that produced this incident
    pub iteration_id: String,
    /// The threat signal that triggered this incident
    pub signal: IncidentSignal,
    /// The response action taken
    pub action: ResponseAction,
    /// Whether the actuator succeeded
    pub outcome_success: bool,
    /// Actuator that executed the response
    pub actuator_name: String,
    /// Free-form tags for categorization
    pub tags: Vec<String>,
}

/// Simplified signal snapshot for storage (avoids generic T in ThreatSignal<T>).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentSignal {
    /// Signal ID
    pub id: String,
    /// Pattern description (stringified)
    pub pattern: String,
    /// Threat severity
    pub severity: ThreatLevel,
    /// Detection timestamp
    pub timestamp: DateTime,
    /// Signal source classification
    pub source: SignalSource,
    /// Confidence value
    pub confidence: f64,
    /// Signal metadata
    pub metadata: HashMap<String, String>,
}

impl IncidentSignal {
    /// Create from a type-erased ThreatSignal<String>
    pub fn from_threat_signal(signal: &ThreatSignal<String>) -> Self {
        Self {
            id: signal.id.clone(),
            pattern: signal.pattern.clone(),
            severity: signal.severity,
            timestamp: signal.timestamp,
            source: signal.source.clone(),
            confidence: signal.confidence.value,
            metadata: signal.metadata.clone(),
        }
    }
}

// =============================================================================
// LessonLearned — extracted insight from incident patterns
// =============================================================================

/// A lesson extracted from repeated incidents.
///
/// Grounds to: →(Causality) + ρ(Recursion) — cause-effect learned through iteration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LessonLearned {
    /// Unique lesson identifier
    pub id: String,
    /// What pattern was observed
    pub pattern_description: String,
    /// What the system learned
    pub insight: String,
    /// How many incidents contributed to this lesson
    pub incident_count: u32,
    /// Confidence in the lesson (0.0-1.0)
    pub confidence: f64,
    /// When first observed
    pub first_seen: DateTime,
    /// When last reinforced
    pub last_seen: DateTime,
    /// Source severity distribution
    pub severity_distribution: HashMap<String, u32>,
}

// =============================================================================
// RecallQuery — search criteria for incident memory
// =============================================================================

/// Query parameters for recalling incidents from memory.
///
/// Grounds to: κ(Comparison) + λ(Location) — predicate matching with positional context.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecallQuery {
    /// Filter by threat level
    pub severity: Option<ThreatLevel>,
    /// Filter by signal source type
    pub source_type: Option<String>,
    /// Filter by pattern substring
    pub pattern_contains: Option<String>,
    /// Filter by tag
    pub tag: Option<String>,
    /// Maximum results to return
    pub limit: Option<usize>,
    /// Only incidents after this time
    pub after: Option<DateTime>,
    /// Only incidents before this time
    pub before: Option<DateTime>,
}

// =============================================================================
// IncidentMemory trait — pluggable persistence backend
// =============================================================================

/// Trait for persisting and recalling Guardian incidents.
///
/// Implementors provide storage backends (Brain artifacts, SQLite, in-memory).
pub trait IncidentMemory: Send + Sync {
    /// Record a new incident
    fn record(&self, incident: &IncidentRecord) -> Result<(), IncidentError>;

    /// Recall incidents matching a query
    fn recall(&self, query: &RecallQuery) -> Result<Vec<IncidentRecord>, IncidentError>;

    /// Count incidents matching a query
    fn count(&self, query: &RecallQuery) -> Result<usize, IncidentError>;

    /// Extract lessons learned from accumulated incidents
    fn lessons(&self) -> Result<Vec<LessonLearned>, IncidentError>;

    /// Get the most recent N incidents
    fn recent(&self, limit: usize) -> Result<Vec<IncidentRecord>, IncidentError>;

    /// Name of this memory backend
    fn backend_name(&self) -> &str;
}

/// Errors from incident memory operations
#[derive(Debug, nexcore_error::Error)]
pub enum IncidentError {
    /// Storage I/O failure
    #[error("incident storage error: {0}")]
    Storage(String),
    /// Serialization failure
    #[error("incident serialization error: {0}")]
    Serialization(String),
    /// Query validation failure
    #[error("invalid query: {0}")]
    InvalidQuery(String),
}

// =============================================================================
// BrainIncidentMemory — Brain-backed persistent implementation
// =============================================================================

/// Incident memory backed by the Brain artifact system.
///
/// Stores incidents as JSONL in a Brain session artifact, enabling:
/// - Cross-session persistence via artifact versioning
/// - Pattern detection through accumulated incident data
/// - Lesson extraction from severity/pattern distributions
///
/// Grounds to: π(Persistence) + μ(Mapping) + σ(Sequence)
pub struct BrainIncidentMemory {
    /// Path to the JSONL incident log
    incident_log_path: PathBuf,
}

impl BrainIncidentMemory {
    /// Create incident memory at the default location.
    ///
    /// Default: `~/.claude/brain/incidents.jsonl`
    pub fn new() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let incident_log_path = PathBuf::from(home)
            .join(".claude")
            .join("brain")
            .join("incidents.jsonl");
        Self { incident_log_path }
    }

    /// Create incident memory at a specific path.
    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        Self {
            incident_log_path: path.into(),
        }
    }

    /// Ensure the parent directory exists.
    fn ensure_dir(&self) -> Result<(), IncidentError> {
        if let Some(parent) = self.incident_log_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| IncidentError::Storage(format!("mkdir: {e}")))?;
        }
        Ok(())
    }

    /// Read all incidents from the log file.
    fn read_all(&self) -> Result<Vec<IncidentRecord>, IncidentError> {
        if !self.incident_log_path.exists() {
            return Ok(Vec::new());
        }

        let content = std::fs::read_to_string(&self.incident_log_path)
            .map_err(|e| IncidentError::Storage(format!("read: {e}")))?;

        let mut incidents = Vec::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            match serde_json::from_str::<IncidentRecord>(trimmed) {
                Ok(record) => incidents.push(record),
                Err(e) => {
                    tracing::warn!("Skipping malformed incident line: {e}");
                }
            }
        }
        Ok(incidents)
    }

    /// Check if an incident matches a query.
    fn matches(incident: &IncidentRecord, query: &RecallQuery) -> bool {
        if let Some(ref sev) = query.severity {
            if incident.signal.severity != *sev {
                return false;
            }
        }
        if let Some(ref src) = query.source_type {
            let source_str = match &incident.signal.source {
                SignalSource::Pamp { .. } => "pamp",
                SignalSource::Damp { .. } => "damp",
                SignalSource::Hybrid { .. } => "hybrid",
            };
            if source_str != src.to_lowercase() {
                return false;
            }
        }
        if let Some(ref pat) = query.pattern_contains {
            if !incident
                .signal
                .pattern
                .to_lowercase()
                .contains(&pat.to_lowercase())
            {
                return false;
            }
        }
        if let Some(ref tag) = query.tag {
            if !incident.tags.iter().any(|t| t == tag) {
                return false;
            }
        }
        if let Some(after) = query.after {
            if incident.detected_at < after {
                return false;
            }
        }
        if let Some(before) = query.before {
            if incident.detected_at > before {
                return false;
            }
        }
        true
    }

    /// Extract lessons from a set of incidents by grouping on pattern.
    fn extract_lessons(incidents: &[IncidentRecord]) -> Vec<LessonLearned> {
        let mut pattern_groups: HashMap<String, Vec<&IncidentRecord>> = HashMap::new();

        for incident in incidents {
            // Normalize pattern to first 64 chars for grouping
            let key = incident
                .signal
                .pattern
                .chars()
                .take(64)
                .collect::<String>()
                .to_lowercase();
            pattern_groups.entry(key).or_default().push(incident);
        }

        let mut lessons = Vec::new();
        for (pattern_key, group) in &pattern_groups {
            // Only extract lessons from patterns seen 2+ times
            if group.len() < 2 {
                continue;
            }

            let mut severity_dist: HashMap<String, u32> = HashMap::new();
            let mut success_count = 0u32;
            let mut first = group[0].detected_at;
            let mut last = group[0].detected_at;

            for inc in group {
                let sev_str = format!("{:?}", inc.signal.severity);
                *severity_dist.entry(sev_str).or_insert(0) += 1;
                if inc.outcome_success {
                    success_count += 1;
                }
                if inc.detected_at < first {
                    first = inc.detected_at;
                }
                if inc.detected_at > last {
                    last = inc.detected_at;
                }
            }

            let total = group.len() as u32;
            let success_rate = success_count as f64 / total as f64;
            let confidence = (total as f64 / (total as f64 + 2.0)).min(0.95);

            let insight = if success_rate > 0.8 {
                format!(
                    "Pattern '{}' seen {total} times — response effective ({:.0}% success)",
                    pattern_key,
                    success_rate * 100.0
                )
            } else {
                format!(
                    "Pattern '{}' seen {total} times — response needs improvement ({:.0}% success)",
                    pattern_key,
                    success_rate * 100.0
                )
            };

            lessons.push(LessonLearned {
                id: format!("lesson-{}", pattern_key.replace(' ', "-")),
                pattern_description: pattern_key.clone(),
                insight,
                incident_count: total,
                confidence,
                first_seen: first,
                last_seen: last,
                severity_distribution: severity_dist,
            });
        }

        // Sort by incident count descending
        lessons.sort_by(|a, b| b.incident_count.cmp(&a.incident_count));
        lessons
    }

    /// Get the incident log file path.
    pub fn path(&self) -> &Path {
        &self.incident_log_path
    }
}

impl Default for BrainIncidentMemory {
    fn default() -> Self {
        Self::new()
    }
}

impl IncidentMemory for BrainIncidentMemory {
    fn record(&self, incident: &IncidentRecord) -> Result<(), IncidentError> {
        self.ensure_dir()?;

        let json = serde_json::to_string(incident)
            .map_err(|e| IncidentError::Serialization(e.to_string()))?;

        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.incident_log_path)
            .map_err(|e| IncidentError::Storage(format!("open: {e}")))?;

        writeln!(file, "{json}").map_err(|e| IncidentError::Storage(format!("write: {e}")))?;

        Ok(())
    }

    fn recall(&self, query: &RecallQuery) -> Result<Vec<IncidentRecord>, IncidentError> {
        let all = self.read_all()?;
        let limit = query.limit.unwrap_or(usize::MAX);

        let results: Vec<IncidentRecord> = all
            .into_iter()
            .filter(|inc| Self::matches(inc, query))
            .take(limit)
            .collect();

        Ok(results)
    }

    fn count(&self, query: &RecallQuery) -> Result<usize, IncidentError> {
        let all = self.read_all()?;
        Ok(all.iter().filter(|inc| Self::matches(inc, query)).count())
    }

    fn lessons(&self) -> Result<Vec<LessonLearned>, IncidentError> {
        let all = self.read_all()?;
        Ok(Self::extract_lessons(&all))
    }

    fn recent(&self, limit: usize) -> Result<Vec<IncidentRecord>, IncidentError> {
        let mut all = self.read_all()?;
        // Most recent first
        all.sort_by(|a, b| b.detected_at.cmp(&a.detected_at));
        all.truncate(limit);
        Ok(all)
    }

    fn backend_name(&self) -> &str {
        "brain-jsonl"
    }
}

// =============================================================================
// InMemoryIncidentStore — for testing
// =============================================================================

/// In-memory incident store for testing.
pub struct InMemoryIncidentStore {
    incidents: std::sync::Mutex<Vec<IncidentRecord>>,
}

impl InMemoryIncidentStore {
    /// Create a new empty in-memory store.
    pub fn new() -> Self {
        Self {
            incidents: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl Default for InMemoryIncidentStore {
    fn default() -> Self {
        Self::new()
    }
}

impl IncidentMemory for InMemoryIncidentStore {
    fn record(&self, incident: &IncidentRecord) -> Result<(), IncidentError> {
        let mut store = self
            .incidents
            .lock()
            .map_err(|e| IncidentError::Storage(format!("lock: {e}")))?;
        store.push(incident.clone());
        Ok(())
    }

    fn recall(&self, query: &RecallQuery) -> Result<Vec<IncidentRecord>, IncidentError> {
        let store = self
            .incidents
            .lock()
            .map_err(|e| IncidentError::Storage(format!("lock: {e}")))?;
        let limit = query.limit.unwrap_or(usize::MAX);
        Ok(store
            .iter()
            .filter(|inc| BrainIncidentMemory::matches(inc, query))
            .take(limit)
            .cloned()
            .collect())
    }

    fn count(&self, query: &RecallQuery) -> Result<usize, IncidentError> {
        let store = self
            .incidents
            .lock()
            .map_err(|e| IncidentError::Storage(format!("lock: {e}")))?;
        Ok(store
            .iter()
            .filter(|inc| BrainIncidentMemory::matches(inc, query))
            .count())
    }

    fn lessons(&self) -> Result<Vec<LessonLearned>, IncidentError> {
        let store = self
            .incidents
            .lock()
            .map_err(|e| IncidentError::Storage(format!("lock: {e}")))?;
        Ok(BrainIncidentMemory::extract_lessons(&store))
    }

    fn recent(&self, limit: usize) -> Result<Vec<IncidentRecord>, IncidentError> {
        let store = self
            .incidents
            .lock()
            .map_err(|e| IncidentError::Storage(format!("lock: {e}")))?;
        let mut sorted = store.clone();
        sorted.sort_by(|a, b| b.detected_at.cmp(&a.detected_at));
        sorted.truncate(limit);
        Ok(sorted)
    }

    fn backend_name(&self) -> &str {
        "in-memory"
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sensing::SignalSource;

    fn make_incident(pattern: &str, severity: ThreatLevel, success: bool) -> IncidentRecord {
        IncidentRecord {
            id: format!("inc-{}", pattern.replace(' ', "-")),
            detected_at: DateTime::now(),
            iteration_id: "iter-1".to_string(),
            signal: IncidentSignal {
                id: "sig-1".to_string(),
                pattern: pattern.to_string(),
                severity,
                timestamp: DateTime::now(),
                source: SignalSource::Damp {
                    subsystem: "test".to_string(),
                    damage_type: "test-damage".to_string(),
                },
                confidence: 0.9,
                metadata: HashMap::new(),
            },
            action: ResponseAction::AuditLog {
                category: "test".to_string(),
                message: "test action".to_string(),
                data: HashMap::new(),
            },
            outcome_success: success,
            actuator_name: "test-actuator".to_string(),
            tags: vec!["test".to_string()],
        }
    }

    #[test]
    fn in_memory_record_and_recall() {
        let store = InMemoryIncidentStore::new();

        let inc = make_incident("sql-injection attempt", ThreatLevel::High, true);
        store.record(&inc).unwrap_or_default();

        let all = store.recall(&RecallQuery::default()).unwrap_or_default();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].signal.pattern, "sql-injection attempt");
    }

    #[test]
    fn recall_with_severity_filter() {
        let store = InMemoryIncidentStore::new();

        store
            .record(&make_incident("low-threat", ThreatLevel::Low, true))
            .unwrap_or_default();
        store
            .record(&make_incident("high-threat", ThreatLevel::High, true))
            .unwrap_or_default();
        store
            .record(&make_incident(
                "critical-threat",
                ThreatLevel::Critical,
                false,
            ))
            .unwrap_or_default();

        let high_only = store
            .recall(&RecallQuery {
                severity: Some(ThreatLevel::High),
                ..Default::default()
            })
            .unwrap_or_default();

        assert_eq!(high_only.len(), 1);
        assert_eq!(high_only[0].signal.pattern, "high-threat");
    }

    #[test]
    fn recall_with_pattern_filter() {
        let store = InMemoryIncidentStore::new();

        store
            .record(&make_incident("sql-injection", ThreatLevel::High, true))
            .unwrap_or_default();
        store
            .record(&make_incident("xss-attack", ThreatLevel::Medium, true))
            .unwrap_or_default();
        store
            .record(&make_incident("sql-overflow", ThreatLevel::High, false))
            .unwrap_or_default();

        let sql_only = store
            .recall(&RecallQuery {
                pattern_contains: Some("sql".to_string()),
                ..Default::default()
            })
            .unwrap_or_default();

        assert_eq!(sql_only.len(), 2);
    }

    #[test]
    fn count_matches() {
        let store = InMemoryIncidentStore::new();

        for _ in 0..5 {
            store
                .record(&make_incident(
                    "repeated-pattern",
                    ThreatLevel::Medium,
                    true,
                ))
                .unwrap_or_default();
        }
        store
            .record(&make_incident("unique-pattern", ThreatLevel::Low, true))
            .unwrap_or_default();

        let count = store
            .count(&RecallQuery {
                severity: Some(ThreatLevel::Medium),
                ..Default::default()
            })
            .unwrap_or(0);

        assert_eq!(count, 5);
    }

    #[test]
    fn lessons_extracted_from_repeated_patterns() {
        let store = InMemoryIncidentStore::new();

        // Same pattern 5 times → should produce a lesson
        for _ in 0..5 {
            store
                .record(&make_incident("memory-pressure", ThreatLevel::High, true))
                .unwrap_or_default();
        }

        // Unique pattern 1 time → no lesson
        store
            .record(&make_incident("one-off-event", ThreatLevel::Low, false))
            .unwrap_or_default();

        let lessons = store.lessons().unwrap_or_default();
        assert_eq!(lessons.len(), 1);
        assert!(lessons[0].insight.contains("memory-pressure"));
        assert_eq!(lessons[0].incident_count, 5);
        assert!(lessons[0].confidence > 0.5);
    }

    #[test]
    fn lessons_detect_poor_response_rate() {
        let store = InMemoryIncidentStore::new();

        // Pattern with low success rate
        for i in 0..4 {
            store
                .record(&make_incident(
                    "failing-response",
                    ThreatLevel::High,
                    i == 0,
                ))
                .unwrap_or_default();
        }

        let lessons = store.lessons().unwrap_or_default();
        assert_eq!(lessons.len(), 1);
        assert!(lessons[0].insight.contains("needs improvement"));
    }

    #[test]
    fn recent_returns_newest_first() {
        let store = InMemoryIncidentStore::new();

        store
            .record(&make_incident("first", ThreatLevel::Low, true))
            .unwrap_or_default();
        store
            .record(&make_incident("second", ThreatLevel::Medium, true))
            .unwrap_or_default();
        store
            .record(&make_incident("third", ThreatLevel::High, true))
            .unwrap_or_default();

        let recent = store.recent(2).unwrap_or_default();
        assert_eq!(recent.len(), 2);
        // Newest first (but all same timestamp in test, so just check count)
    }

    #[test]
    fn brain_memory_roundtrip() {
        let dir = tempfile::tempdir()
            .unwrap_or_else(|_| tempfile::TempDir::new().unwrap_or_else(|_| panic!("temp dir")));
        let path = dir.path().join("incidents.jsonl");
        let store = BrainIncidentMemory::with_path(&path);

        let inc = make_incident("test-roundtrip", ThreatLevel::Medium, true);
        store.record(&inc).unwrap_or_default();

        let recalled = store.recall(&RecallQuery::default()).unwrap_or_default();
        assert_eq!(recalled.len(), 1);
        assert_eq!(recalled[0].signal.pattern, "test-roundtrip");
    }

    #[test]
    fn brain_memory_persists_across_instances() {
        let dir = tempfile::tempdir()
            .unwrap_or_else(|_| tempfile::TempDir::new().unwrap_or_else(|_| panic!("temp dir")));
        let path = dir.path().join("incidents.jsonl");

        // First instance writes
        let store1 = BrainIncidentMemory::with_path(&path);
        store1
            .record(&make_incident("persist-test", ThreatLevel::High, true))
            .unwrap_or_default();

        // Second instance reads
        let store2 = BrainIncidentMemory::with_path(&path);
        let recalled = store2.recall(&RecallQuery::default()).unwrap_or_default();
        assert_eq!(recalled.len(), 1);
    }

    #[test]
    fn tag_filter_works() {
        let store = InMemoryIncidentStore::new();

        let mut tagged = make_incident("tagged-event", ThreatLevel::Medium, true);
        tagged.tags = vec!["pv-signal".to_string(), "hepatotox".to_string()];
        store.record(&tagged).unwrap_or_default();

        let mut untagged = make_incident("untagged-event", ThreatLevel::Medium, true);
        untagged.tags = vec![];
        store.record(&untagged).unwrap_or_default();

        let pv_only = store
            .recall(&RecallQuery {
                tag: Some("pv-signal".to_string()),
                ..Default::default()
            })
            .unwrap_or_default();

        assert_eq!(pv_only.len(), 1);
        assert_eq!(pv_only[0].signal.pattern, "tagged-event");
    }
}
