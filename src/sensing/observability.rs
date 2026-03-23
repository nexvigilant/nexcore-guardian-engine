//! Observability Sensor
//!
//! DAMP sensor that monitors system health via the observability snapshot file.
//! The guardian-observer cron daemon computes vitals and writes them to
//! `~/.claude/hooks/state/observability-vitals.json`. This sensor reads
//! that file and fires DAMP signals when vitals degrade or the snapshot
//! goes stale.
//!
//! # Tier: T3 (Domain-Specific Sensor)
//! # Grounding: ν (Frequency) + κ (Comparison) + ∂ (Boundary)

use crate::confidence::ConfidenceSource;
use crate::sensing::{Sensor, SignalSource, ThreatLevel, ThreatSignal};
use serde::Deserialize;
use std::path::PathBuf;

/// Maximum age of snapshot before staleness alert (seconds).
const STALENESS_THRESHOLD_SECS: u64 = 600; // 10 minutes (2x the 5-min cron interval)

/// Composite health score below which we alert.
const COMPOSITE_WARN: f64 = 0.7;
/// Composite health score below which we escalate.
const COMPOSITE_CRITICAL: f64 = 0.4;

/// Individual vital thresholds.
const SESSION_VELOCITY_MIN: f64 = 0.5; // At least 0.5 sessions/day
const MICROGRAM_INTEGRITY_MIN: f64 = 0.99; // >99% pass rate
const HOOK_ERROR_RATE_MAX: f64 = 0.05; // <5% error rate
const ARTIFACT_FRESHNESS_MIN: f64 = 0.5; // Freshness score

/// Snapshot of system health vitals, written by the observer cron daemon.
#[derive(Debug, Clone, Deserialize)]
struct VitalsSnapshot {
    captured_at: String,
    session_velocity: f64,
    mcp_backend_health: f64,
    microgram_integrity: f64,
    station_activity: f64,
    guardian_threat: String,
    artifact_freshness: f64,
    hook_error_rate: f64,
    composite_score: f64,
    #[serde(default)]
    alerts: Vec<String>,
}

/// Observability Sensor — detects system health degradation from snapshot file.
///
/// # Tier: T3
/// Grounds to: ν (Frequency) via snapshot recency check,
///             κ (Comparison) via vital-to-threshold comparison,
///             ∂ (Boundary) via threshold enforcement.
#[derive(Debug, Clone)]
pub struct ObservabilitySensor {
    sensitivity: f64,
    snapshot_path: PathBuf,
}

impl Default for ObservabilitySensor {
    fn default() -> Self {
        Self::new()
    }
}

impl ObservabilitySensor {
    /// Create with default snapshot path.
    #[must_use]
    pub fn new() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        Self {
            sensitivity: 0.90,
            snapshot_path: PathBuf::from(home)
                .join(".claude")
                .join("hooks")
                .join("state")
                .join("observability-vitals.json"),
        }
    }

    /// Create with custom path (for testing).
    #[must_use]
    pub fn with_path(path: PathBuf) -> Self {
        Self {
            sensitivity: 0.90,
            snapshot_path: path,
        }
    }

    /// Read the latest snapshot from disk.
    fn read_snapshot(&self) -> Option<VitalsSnapshot> {
        let content = std::fs::read_to_string(&self.snapshot_path).ok()?;
        serde_json::from_str(&content).ok()
    }

    /// Check if the snapshot is stale (older than threshold).
    fn is_stale(&self) -> bool {
        let metadata = match std::fs::metadata(&self.snapshot_path) {
            Ok(m) => m,
            Err(_) => return true, // File doesn't exist = stale
        };
        let modified = match metadata.modified() {
            Ok(t) => t,
            Err(_) => return true,
        };
        let age = std::time::SystemTime::now()
            .duration_since(modified)
            .unwrap_or_default();
        age.as_secs() > STALENESS_THRESHOLD_SECS
    }

    /// Detect vital sign degradation.
    fn detect_vital_degradation(&self, snapshot: &VitalsSnapshot) -> Vec<ThreatSignal<String>> {
        let mut signals = Vec::new();

        // Composite score check
        if snapshot.composite_score < COMPOSITE_CRITICAL {
            signals.push(self.make_signal(
                format!(
                    "composite_health_critical:{:.0}%",
                    snapshot.composite_score * 100.0
                ),
                ThreatLevel::High,
                "observability",
                "system_health_degradation",
            ));
        } else if snapshot.composite_score < COMPOSITE_WARN {
            signals.push(self.make_signal(
                format!(
                    "composite_health_warn:{:.0}%",
                    snapshot.composite_score * 100.0
                ),
                ThreatLevel::Medium,
                "observability",
                "system_health_degradation",
            ));
        }

        // Individual vital checks
        if snapshot.session_velocity < SESSION_VELOCITY_MIN {
            signals.push(self.make_signal(
                format!("low_session_velocity:{:.1}/day", snapshot.session_velocity),
                ThreatLevel::Low,
                "observability",
                "session_stagnation",
            ));
        }

        if snapshot.microgram_integrity < MICROGRAM_INTEGRITY_MIN {
            signals.push(self.make_signal(
                format!(
                    "microgram_integrity_degraded:{:.1}%",
                    snapshot.microgram_integrity * 100.0
                ),
                ThreatLevel::High,
                "observability",
                "logic_corruption",
            ));
        }

        if snapshot.hook_error_rate > HOOK_ERROR_RATE_MAX {
            signals.push(self.make_signal(
                format!(
                    "hook_error_rate_high:{:.1}%",
                    snapshot.hook_error_rate * 100.0
                ),
                ThreatLevel::Medium,
                "observability",
                "reflex_failure",
            ));
        }

        if snapshot.artifact_freshness < ARTIFACT_FRESHNESS_MIN {
            signals.push(self.make_signal(
                format!(
                    "artifact_freshness_low:{:.1}%",
                    snapshot.artifact_freshness * 100.0
                ),
                ThreatLevel::Low,
                "observability",
                "knowledge_decay",
            ));
        }

        if snapshot.guardian_threat != "Low" && snapshot.guardian_threat != "Info" {
            signals.push(self.make_signal(
                format!("guardian_elevated_threat:{}", snapshot.guardian_threat),
                ThreatLevel::Medium,
                "observability",
                "active_threats",
            ));
        }

        signals
    }

    /// Helper to construct a DAMP signal.
    fn make_signal(
        &self,
        pattern: String,
        severity: ThreatLevel,
        subsystem: &str,
        damage_type: &str,
    ) -> ThreatSignal<String> {
        ThreatSignal::new(
            pattern,
            severity,
            SignalSource::Damp {
                subsystem: subsystem.to_string(),
                damage_type: damage_type.to_string(),
            },
        )
        .with_confidence(
            ConfidenceSource::Calibrated {
                value: self.sensitivity,
                rationale: "observability: pre-computed snapshot vitals",
            }
            .derive(),
        )
    }
}

impl Sensor for ObservabilitySensor {
    type Pattern = String;

    fn detect(&self) -> Vec<ThreatSignal<Self::Pattern>> {
        // Check staleness first
        if self.is_stale() {
            return vec![self.make_signal(
                "observability_snapshot_stale".to_string(),
                ThreatLevel::Medium,
                "observability",
                "snapshot_staleness",
            )];
        }

        // Read and evaluate
        match self.read_snapshot() {
            Some(snapshot) => self.detect_vital_degradation(&snapshot),
            None => vec![self.make_signal(
                "observability_snapshot_unreadable".to_string(),
                ThreatLevel::Low,
                "observability",
                "snapshot_parse_failure",
            )],
        }
    }

    fn sensitivity(&self) -> f64 {
        self.sensitivity
    }

    fn name(&self) -> &str {
        "observability-sensor"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_snapshot(vitals: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("create temp file");
        f.write_all(vitals.as_bytes()).expect("write snapshot");
        f
    }

    #[test]
    fn test_healthy_system_no_signals() {
        let f = write_snapshot(
            r#"{
                "captured_at": "2026-03-08T12:00:00Z",
                "session_velocity": 3.0,
                "mcp_backend_health": 1.0,
                "microgram_integrity": 1.0,
                "station_activity": 10.0,
                "guardian_threat": "Low",
                "artifact_freshness": 0.9,
                "hook_error_rate": 0.01,
                "composite_score": 0.95,
                "alerts": []
            }"#,
        );
        let sensor = ObservabilitySensor::with_path(f.path().to_path_buf());
        let signals = sensor.detect();
        assert!(
            signals.is_empty(),
            "Healthy system should produce no signals"
        );
    }

    #[test]
    fn test_degraded_composite_fires_warn() {
        let f = write_snapshot(
            r#"{
                "captured_at": "2026-03-08T12:00:00Z",
                "session_velocity": 3.0,
                "mcp_backend_health": 1.0,
                "microgram_integrity": 1.0,
                "station_activity": 10.0,
                "guardian_threat": "Low",
                "artifact_freshness": 0.9,
                "hook_error_rate": 0.01,
                "composite_score": 0.55,
                "alerts": []
            }"#,
        );
        let sensor = ObservabilitySensor::with_path(f.path().to_path_buf());
        let signals = sensor.detect();
        assert_eq!(signals.len(), 1);
        assert!(signals[0].pattern.contains("composite_health_warn"));
        assert_eq!(signals[0].severity, ThreatLevel::Medium);
    }

    #[test]
    fn test_critical_composite_fires_high() {
        let f = write_snapshot(
            r#"{
                "captured_at": "2026-03-08T12:00:00Z",
                "session_velocity": 3.0,
                "mcp_backend_health": 1.0,
                "microgram_integrity": 1.0,
                "station_activity": 10.0,
                "guardian_threat": "Low",
                "artifact_freshness": 0.9,
                "hook_error_rate": 0.01,
                "composite_score": 0.3,
                "alerts": []
            }"#,
        );
        let sensor = ObservabilitySensor::with_path(f.path().to_path_buf());
        let signals = sensor.detect();
        assert!(signals.iter().any(|s| s.pattern.contains("critical")));
        assert!(signals.iter().any(|s| s.severity == ThreatLevel::High));
    }

    #[test]
    fn test_microgram_integrity_failure() {
        let f = write_snapshot(
            r#"{
                "captured_at": "2026-03-08T12:00:00Z",
                "session_velocity": 3.0,
                "mcp_backend_health": 1.0,
                "microgram_integrity": 0.95,
                "station_activity": 10.0,
                "guardian_threat": "Low",
                "artifact_freshness": 0.9,
                "hook_error_rate": 0.01,
                "composite_score": 0.85,
                "alerts": []
            }"#,
        );
        let sensor = ObservabilitySensor::with_path(f.path().to_path_buf());
        let signals = sensor.detect();
        assert!(signals.iter().any(|s| s.pattern.contains("microgram")));
    }

    #[test]
    fn test_missing_file_fires_stale() {
        let sensor = ObservabilitySensor::with_path(PathBuf::from("/nonexistent/vitals.json"));
        let signals = sensor.detect();
        assert_eq!(signals.len(), 1);
        assert!(signals[0].pattern.contains("stale"));
    }

    #[test]
    fn test_elevated_guardian_threat() {
        let f = write_snapshot(
            r#"{
                "captured_at": "2026-03-08T12:00:00Z",
                "session_velocity": 3.0,
                "mcp_backend_health": 1.0,
                "microgram_integrity": 1.0,
                "station_activity": 10.0,
                "guardian_threat": "High",
                "artifact_freshness": 0.9,
                "hook_error_rate": 0.01,
                "composite_score": 0.85,
                "alerts": []
            }"#,
        );
        let sensor = ObservabilitySensor::with_path(f.path().to_path_buf());
        let signals = sensor.detect();
        assert!(
            signals
                .iter()
                .any(|s| s.pattern.contains("elevated_threat"))
        );
    }
}
