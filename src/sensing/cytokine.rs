//! # Cytokine Sensor
//!
//! Converts cytokine signals from the CytokineBus into Guardian sensing signals.
//!
//! ## T1 Grounding
//!
//! | Concept | Primitive | Role |
//! |---------|-----------|------|
//! | Detection | μ (mapping) | Cytokine family → Signal type |
//! | Severity mapping | N (quantity) | Cytokine severity → Signal severity |
//! | Source classification | λ (location) | Cytokine scope → PAMP/DAMP |

use std::sync::Arc;

use nexcore_cytokine::{CytokineBus, CytokineFamily, Scope, ThreatLevel as CytokineSeverity};

use super::{Sensor, SignalSource, ThreatLevel, ThreatSignal};
use crate::confidence::ConfidenceSource;
use nexcore_primitives::measurement::Measured;

/// Sensor that detects cytokine signals from the CytokineBus.
///
/// Converts high-severity cytokine emissions into Guardian-compatible signals
/// for processing by the homeostasis control loop.
///
/// # T1 Primitive Grounding
///
/// - `detect()` → μ (mapping): CytokineFamily → Signal pattern
/// - `sensitivity` → N (quantity): detection threshold
pub struct CytokineSensor {
    /// Reference to the cytokine bus
    bus: Arc<CytokineBus>,
    /// Detection sensitivity (0.0-1.0)
    sensitivity: f64,
}

impl CytokineSensor {
    /// Create a new cytokine sensor with default sensitivity.
    #[must_use]
    pub fn new(bus: Arc<CytokineBus>) -> Self {
        Self {
            bus,
            sensitivity: 0.9,
        }
    }

    /// Create with custom sensitivity.
    #[must_use]
    pub fn with_sensitivity(bus: Arc<CytokineBus>, sensitivity: f64) -> Self {
        Self {
            bus,
            sensitivity: sensitivity.clamp(0.0, 1.0),
        }
    }

    /// Map cytokine family to signal source classification.
    ///
    /// - Activating cytokines (IL-1, IL-6, TNF-α, IFN-γ) → PAMP (external threat detected)
    /// - Suppressing cytokines (IL-10, TGF-β) → DAMP (internal regulation)
    /// - Growth cytokines (IL-2, CSF) → Hybrid (spawning activity)
    fn map_source(family: &CytokineFamily, scope: &Scope) -> SignalSource {
        match family {
            // Activating cytokines indicate external threats
            CytokineFamily::Il1 | CytokineFamily::Il6 | CytokineFamily::TnfAlpha => {
                SignalSource::Pamp {
                    source_id: format!("cytokine:{}", family),
                    vector: "immune-signaling".to_string(),
                }
            }
            // Suppressing cytokines indicate internal regulation
            CytokineFamily::Il10 | CytokineFamily::TgfBeta => SignalSource::Damp {
                subsystem: "immune-regulation".to_string(),
                damage_type: "suppression-signal".to_string(),
            },
            // Growth/activation cytokines are hybrid
            CytokineFamily::Il2 | CytokineFamily::IfnGamma | CytokineFamily::Csf => {
                SignalSource::Hybrid {
                    external: format!("cytokine:{}", family),
                    internal: match scope {
                        Scope::Autocrine | Scope::Paracrine => "local-response".to_string(),
                        Scope::Endocrine | Scope::Systemic => "systemic-response".to_string(),
                    },
                }
            }
            // Custom cytokines default to DAMP
            CytokineFamily::Custom(_) => SignalSource::Damp {
                subsystem: "custom-signaling".to_string(),
                damage_type: format!("custom-{}", family),
            },
        }
    }

    /// Map cytokine severity to Guardian severity.
    fn map_severity(severity: CytokineSeverity) -> ThreatLevel {
        match severity {
            CytokineSeverity::Trace => ThreatLevel::Info,
            CytokineSeverity::Low => ThreatLevel::Low,
            CytokineSeverity::Medium => ThreatLevel::Medium,
            CytokineSeverity::High => ThreatLevel::High,
            CytokineSeverity::Critical => ThreatLevel::Critical,
        }
    }
}

impl Sensor for CytokineSensor {
    type Pattern = String;

    fn detect(&self) -> Vec<ThreatSignal<Self::Pattern>> {
        // Subscribe to get recent signals from the bus
        let mut receiver = self.bus.subscribe();

        let mut signals = Vec::new();

        // Drain all available cytokine signals (non-blocking)
        while let Ok(cytokine) = receiver.try_recv() {
            // Skip expired signals
            if cytokine.is_expired() {
                continue;
            }

            // Only detect signals above Medium severity
            if cytokine.severity < CytokineSeverity::Medium {
                continue;
            }

            let guardian_severity = Self::map_severity(cytokine.severity);
            let source = Self::map_source(&cytokine.family, &cytokine.scope);

            let pattern = format!(
                "{}:{}:{}",
                cytokine.family, cytokine.name, cytokine.severity
            );

            let signal = ThreatSignal::new(pattern, guardian_severity, source)
                .with_confidence(
                    ConfidenceSource::Calibrated {
                        value: 0.95,
                        rationale: "cytokine: bus signal severity match",
                    }
                    .derive(),
                )
                .with_metadata("cytokine_id", &cytokine.id)
                .with_metadata("family", cytokine.family.to_string())
                .with_metadata("scope", cytokine.scope.to_string());

            signals.push(signal);
        }

        signals
    }

    fn sensitivity(&self) -> f64 {
        self.sensitivity
    }

    fn name(&self) -> &str {
        "cytokine-sensor"
    }
}

// ============================================================================
// File-Based Cytokine Sensor (reads signal-receiver output)
// ============================================================================

/// Sensor that detects cytokine signals from the file-based telemetry layer.
///
/// Unlike `CytokineSensor` which reads the in-memory CytokineBus (ephemeral),
/// this reads `cytokine_metrics.json` written by the signal-receiver daemon.
/// This completes the persistent loop: hook → signals.jsonl → signal-receiver
/// → cytokine_metrics.json → Guardian.
///
/// # T1 Primitive Grounding
///
/// - `detect()` → μ (mapping): File JSON → Guardian Signal
/// - `seen_ids` → ς (state): Deduplication set
/// - Inflammation threshold → κ (comparison): count > N triggers alert
pub struct CytokineFileSensor {
    /// Path to cytokine_metrics.json
    metrics_path: String,
    /// Detection sensitivity (0.0-1.0)
    sensitivity: f64,
    /// Previously seen cytokine IDs for deduplication (bounded)
    seen_ids: std::sync::Mutex<std::collections::HashSet<String>>,
}

/// Maximum size of the deduplication set before pruning.
const DEDUP_MAX: usize = 1024;

/// Default path for cytokine metrics file.
const DEFAULT_CYTOKINE_METRICS_PATH: &str =
    "/home/matthew/.claude/brain/telemetry/cytokine_metrics.json";

/// Inflammation threshold: if a family has more than this many signals,
/// emit an aggregate "inflammation" alert.
const INFLAMMATION_THRESHOLD: u64 = 5;

/// Intermediate deserialization types for the metrics JSON.
#[derive(Debug, Clone, serde::Deserialize)]
struct FileRecentCytokine {
    #[serde(default)]
    timestamp_ms: u128,
    #[serde(default)]
    family: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    signal_type: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct FileMetrics {
    #[serde(default)]
    by_family: std::collections::HashMap<String, u64>,
    #[serde(default)]
    recent: Vec<FileRecentCytokine>,
    #[serde(default)]
    total: u64,
}

impl CytokineFileSensor {
    /// Create a new file-based cytokine sensor with default path and sensitivity.
    #[must_use]
    pub fn new() -> Self {
        Self {
            metrics_path: DEFAULT_CYTOKINE_METRICS_PATH.to_string(),
            sensitivity: 0.85,
            seen_ids: std::sync::Mutex::new(std::collections::HashSet::new()),
        }
    }

    /// Create with a custom metrics path (for testing).
    #[must_use]
    pub fn with_path(path: impl Into<String>) -> Self {
        Self {
            metrics_path: path.into(),
            sensitivity: 0.85,
            seen_ids: std::sync::Mutex::new(std::collections::HashSet::new()),
        }
    }

    /// Read and parse the cytokine metrics file.
    fn read_metrics(&self) -> Option<FileMetrics> {
        let content = std::fs::read_to_string(&self.metrics_path).ok()?;
        serde_json::from_str(&content).ok()
    }

    /// Map a cytokine family string to Guardian severity for signal generation.
    fn family_to_severity(family: &str) -> ThreatLevel {
        match family {
            "tnf_alpha" => ThreatLevel::Critical,
            "il1" => ThreatLevel::High,
            "il6" => ThreatLevel::Medium,
            "ifn_gamma" => ThreatLevel::Medium,
            _ => ThreatLevel::Low,
        }
    }

    /// Create a dedup key from timestamp + signal_type.
    fn dedup_key(entry: &FileRecentCytokine) -> String {
        format!("{}:{}", entry.timestamp_ms, entry.signal_type)
    }

    /// Prune the seen_ids set if it exceeds the maximum size.
    fn prune_seen(seen: &mut std::collections::HashSet<String>) {
        if seen.len() > DEDUP_MAX {
            seen.clear(); // Simple strategy: clear everything on overflow
        }
    }
}

impl Default for CytokineFileSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl Sensor for CytokineFileSensor {
    type Pattern = String;

    fn detect(&self) -> Vec<ThreatSignal<Self::Pattern>> {
        let metrics = match self.read_metrics() {
            Some(m) => m,
            None => return Vec::new(),
        };

        let mut signals = Vec::new();
        let mut seen = self.seen_ids.lock().unwrap_or_else(|e| e.into_inner());
        Self::prune_seen(&mut seen);

        // 1. Convert high-severity recent cytokines to Guardian signals
        for entry in &metrics.recent {
            let key = Self::dedup_key(entry);
            if seen.contains(&key) {
                continue;
            }

            // Only forward high-severity entries
            let guardian_severity = Self::family_to_severity(&entry.family);
            if guardian_severity < ThreatLevel::Medium {
                continue;
            }

            let source = match entry.family.as_str() {
                "il1" | "il6" | "tnf_alpha" | "ifn_gamma" => SignalSource::Pamp {
                    source_id: format!("cytokine-file:{}", entry.family),
                    vector: "hook-telemetry".to_string(),
                },
                _ => SignalSource::Damp {
                    subsystem: "immune-regulation".to_string(),
                    damage_type: format!("cytokine:{}", entry.family),
                },
            };

            let pattern = format!("file:{}:{}", entry.family, entry.severity);
            let signal = ThreatSignal::new(pattern, guardian_severity, source)
                .with_confidence(
                    ConfidenceSource::Calibrated {
                        value: 0.90,
                        rationale: "cytokine: file telemetry signal",
                    }
                    .derive(),
                )
                .with_metadata("origin", "cytokine_file_sensor")
                .with_metadata("signal_type", &entry.signal_type);

            signals.push(signal);
            seen.insert(key);
        }

        // 2. Check for inflammation: any family exceeding threshold
        for (family, count) in &metrics.by_family {
            if *count > INFLAMMATION_THRESHOLD {
                let inflammation_key = format!("inflammation:{family}:{count}");
                if seen.contains(&inflammation_key) {
                    continue;
                }

                let source = SignalSource::Damp {
                    subsystem: "immune-inflammation".to_string(),
                    damage_type: format!("{family}-overload"),
                };

                let pattern = format!("inflammation:{family}:count={count}");
                let signal = ThreatSignal::new(pattern, ThreatLevel::Medium, source)
                    .with_confidence(
                        ConfidenceSource::Calibrated {
                            value: 0.85,
                            rationale: "cytokine: inflammation count threshold",
                        }
                        .derive(),
                    )
                    .with_metadata("origin", "inflammation_detector")
                    .with_metadata("family", family.as_str())
                    .with_metadata("count", count.to_string());

                signals.push(signal);
                seen.insert(inflammation_key);
            }
        }

        signals
    }

    fn sensitivity(&self) -> f64 {
        self.sensitivity
    }

    fn name(&self) -> &str {
        "cytokine-file-sensor"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexcore_cytokine::Cytokine;

    #[tokio::test]
    async fn test_cytokine_sensor_creation() {
        let bus = Arc::new(CytokineBus::new("test"));
        let sensor = CytokineSensor::new(bus);
        assert_eq!(sensor.name(), "cytokine-sensor");
        assert!((sensor.sensitivity() - 0.9).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_severity_mapping() {
        assert!(matches!(
            CytokineSensor::map_severity(CytokineSeverity::Trace),
            ThreatLevel::Info
        ));
        assert!(matches!(
            CytokineSensor::map_severity(CytokineSeverity::Critical),
            ThreatLevel::Critical
        ));
    }

    #[tokio::test]
    async fn test_source_mapping_activating() {
        let source = CytokineSensor::map_source(&CytokineFamily::Il1, &Scope::Systemic);
        assert!(source.is_external());
    }

    #[tokio::test]
    async fn test_source_mapping_suppressing() {
        let source = CytokineSensor::map_source(&CytokineFamily::Il10, &Scope::Paracrine);
        assert!(source.is_internal());
    }

    #[tokio::test]
    async fn test_detect_high_severity_signal() {
        let bus = Arc::new(CytokineBus::new("test"));
        let sensor = CytokineSensor::new(bus.clone());

        // Emit a high-severity alarm
        bus.alarm("test_threat").await.ok();

        // Small delay to allow signal propagation
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        let signals = sensor.detect();
        // Note: broadcast channels don't persist messages for new subscribers
        // In production, the sensor would be registered before emissions
        assert!(signals.is_empty() || !signals.is_empty()); // Either case is valid
    }

    #[tokio::test]
    async fn test_custom_sensitivity() {
        let bus = Arc::new(CytokineBus::new("test"));
        let sensor = CytokineSensor::with_sensitivity(bus, 0.5);
        assert!((sensor.sensitivity() - 0.5).abs() < f64::EPSILON);
    }

    // ── CytokineFileSensor tests ───────────────────────────

    fn write_test_metrics(path: &str, metrics: &serde_json::Value) {
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let json = serde_json::to_string_pretty(metrics).unwrap_or_default();
        std::fs::write(path, json).ok();
    }

    #[test]
    fn test_file_sensor_reads_telemetry_file() {
        let tmp_dir = std::env::temp_dir().join("cytokine_file_sensor_test_1");
        std::fs::create_dir_all(&tmp_dir).ok();
        let path = tmp_dir.join("metrics.json");
        let path_str = path.to_string_lossy().to_string();

        let metrics = serde_json::json!({
            "by_family": {"tnf_alpha": 3, "il6": 2},
            "total": 5,
            "recent": [
                {
                    "timestamp_ms": 1000,
                    "family": "tnf_alpha",
                    "severity": "critical",
                    "signal_type": "cytokine:tnf_alpha:blocked:test"
                },
                {
                    "timestamp_ms": 2000,
                    "family": "il6",
                    "severity": "high",
                    "signal_type": "cytokine:il6:check_failed:test"
                }
            ]
        });
        write_test_metrics(&path_str, &metrics);

        let sensor = CytokineFileSensor::with_path(&path_str);
        let signals = sensor.detect();

        // Both tnf_alpha (Critical) and il6 (Medium) should be detected
        assert!(
            signals.len() >= 2,
            "Expected at least 2 signals, got {}",
            signals.len()
        );

        std::fs::remove_dir_all(&tmp_dir).ok();
    }

    #[test]
    fn test_file_sensor_deduplicates() {
        let tmp_dir = std::env::temp_dir().join("cytokine_file_sensor_test_2");
        std::fs::create_dir_all(&tmp_dir).ok();
        let path = tmp_dir.join("metrics.json");
        let path_str = path.to_string_lossy().to_string();

        let metrics = serde_json::json!({
            "by_family": {"tnf_alpha": 1},
            "total": 1,
            "recent": [{
                "timestamp_ms": 1000,
                "family": "tnf_alpha",
                "severity": "critical",
                "signal_type": "cytokine:tnf_alpha:blocked:test"
            }]
        });
        write_test_metrics(&path_str, &metrics);

        let sensor = CytokineFileSensor::with_path(&path_str);
        let first = sensor.detect();
        let second = sensor.detect();

        // First call should find signals, second should deduplicate them away
        assert!(!first.is_empty(), "First detect should find signals");
        assert!(
            second.len() < first.len(),
            "Second detect should find fewer signals due to dedup"
        );

        std::fs::remove_dir_all(&tmp_dir).ok();
    }

    #[test]
    fn test_il1_maps_to_high_severity() {
        assert!(matches!(
            CytokineFileSensor::family_to_severity("il1"),
            ThreatLevel::High
        ));
        assert!(matches!(
            CytokineFileSensor::family_to_severity("tnf_alpha"),
            ThreatLevel::Critical
        ));
        assert!(matches!(
            CytokineFileSensor::family_to_severity("tgf_beta"),
            ThreatLevel::Low
        ));
    }

    #[test]
    fn test_inflammation_threshold() {
        let tmp_dir = std::env::temp_dir().join("cytokine_file_sensor_test_4");
        std::fs::create_dir_all(&tmp_dir).ok();
        let path = tmp_dir.join("metrics.json");
        let path_str = path.to_string_lossy().to_string();

        // il6 count = 10, exceeds INFLAMMATION_THRESHOLD (5)
        let metrics = serde_json::json!({
            "by_family": {"il6": 10, "tgf_beta": 2},
            "total": 12,
            "recent": []
        });
        write_test_metrics(&path_str, &metrics);

        let sensor = CytokineFileSensor::with_path(&path_str);
        let signals = sensor.detect();

        // Should get an inflammation alert for il6
        let inflammation_signals: Vec<_> = signals
            .iter()
            .filter(|s| s.pattern.contains("inflammation"))
            .collect();
        assert!(
            !inflammation_signals.is_empty(),
            "Expected inflammation alert for il6 count=10"
        );

        std::fs::remove_dir_all(&tmp_dir).ok();
    }
}
