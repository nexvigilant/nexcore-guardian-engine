//! Signal Health Sensor
//!
//! DAMP sensor that monitors the biological signal system health.
//! Reads `signals.jsonl` and detects:
//! - Cytokine burst (>10 pro-inflammatory in 5 minutes)
//! - File size >10MB (unbounded growth)
//! - Circuit breaker open signals
//!
//! # Tier: T3 (Domain-Specific Sensor)
//! # Grounding: ν (Frequency) + Σ (Sum) + ∂ (Boundary)

use crate::confidence::ConfidenceSource;
use crate::sensing::{Measured, Sensor, SignalSource, ThreatLevel, ThreatSignal};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Maximum file size before alerting (10 MB).
const MAX_FILE_SIZE_BYTES: u64 = 10 * 1024 * 1024;
/// Pro-inflammatory burst threshold (count in window).
const CYTOKINE_BURST_THRESHOLD: usize = 10;
/// Burst detection window in milliseconds (5 minutes).
const BURST_WINDOW_MS: u128 = 5 * 60 * 1000;
/// Maximum lines to read from tail.
const TAIL_LINES: usize = 500;

/// Minimal signal record for parsing.
///
/// # Tier: T2-C
#[derive(Debug, Clone, Deserialize)]
struct SignalRecord {
    #[serde(default)]
    signal_type: String,
    #[serde(default)]
    timestamp_ms: u128,
    #[serde(default)]
    data: std::collections::HashMap<String, String>,
}

/// Pro-inflammatory cytokine families.
const PRO_INFLAMMATORY: &[&str] = &["il1", "il6", "tnf_alpha", "ifn_gamma"];

/// Signal Health Sensor — monitors biological signal system integrity.
///
/// # Tier: T3
/// Grounds to: ν (Frequency) via burst detection,
///             Σ (Sum) via file size accumulation,
///             ∂ (Boundary) via threshold enforcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalHealthSensor {
    sensitivity: f64,
    signals_path: PathBuf,
}

impl Default for SignalHealthSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl SignalHealthSensor {
    /// Create with default signals path.
    #[must_use]
    pub fn new() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        Self {
            sensitivity: 0.85,
            signals_path: PathBuf::from(home)
                .join(".claude")
                .join("brain")
                .join("telemetry")
                .join("signals.jsonl"),
        }
    }

    /// Create with custom path (for testing).
    #[must_use]
    pub fn with_path(path: PathBuf) -> Self {
        Self {
            sensitivity: 0.85,
            signals_path: path,
        }
    }

    /// Read the last N records from the signals file.
    fn read_recent_records(&self) -> Vec<SignalRecord> {
        let content = match std::fs::read_to_string(&self.signals_path) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        let lines: Vec<&str> = content.lines().collect();
        let start = lines.len().saturating_sub(TAIL_LINES);
        lines[start..]
            .iter()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    }

    /// Detect pro-inflammatory cytokine burst.
    fn detect_cytokine_burst(&self, records: &[SignalRecord]) -> Option<ThreatSignal<String>> {
        // Filter to pro-inflammatory cytokines
        let pro_inflam: Vec<&SignalRecord> = records
            .iter()
            .filter(|r| {
                r.signal_type.starts_with("cytokine:")
                    && PRO_INFLAMMATORY.iter().any(|f| r.signal_type.contains(f))
            })
            .collect();

        if pro_inflam.len() < CYTOKINE_BURST_THRESHOLD {
            return None;
        }

        // Check if there's a burst within the window
        // Look at the most recent ones
        let recent = &pro_inflam[pro_inflam.len().saturating_sub(CYTOKINE_BURST_THRESHOLD)..];
        if recent.len() < CYTOKINE_BURST_THRESHOLD {
            return None;
        }

        let first_ts = recent.first().map(|r| r.timestamp_ms).unwrap_or(0);
        let last_ts = recent.last().map(|r| r.timestamp_ms).unwrap_or(0);
        let window = last_ts.saturating_sub(first_ts);

        if window <= BURST_WINDOW_MS {
            return Some(
                ThreatSignal::new(
                    format!("cytokine_burst:{}_in_{}min", recent.len(), window / 60_000),
                    ThreatLevel::High,
                    SignalSource::Damp {
                        subsystem: "signal-health".to_string(),
                        damage_type: "cytokine-burst".to_string(),
                    },
                )
                .with_confidence(
                    ConfidenceSource::Calibrated {
                        value: 0.9,
                        rationale: "signal health: cytokine burst window",
                    }
                    .derive(),
                )
                .with_metadata("count", recent.len().to_string())
                .with_metadata("window_ms", window.to_string()),
            );
        }
        None
    }

    /// Detect if signal file is too large.
    fn detect_file_size(&self) -> Option<ThreatSignal<String>> {
        let metadata = std::fs::metadata(&self.signals_path).ok()?;
        let size = metadata.len();

        if size > MAX_FILE_SIZE_BYTES {
            let size_mb = size as f64 / (1024.0 * 1024.0);
            return Some(
                ThreatSignal::new(
                    format!("signal_file_oversized:{:.1}MB", size_mb),
                    ThreatLevel::Medium,
                    SignalSource::Damp {
                        subsystem: "signal-health".to_string(),
                        damage_type: "unbounded-growth".to_string(),
                    },
                )
                .with_confidence(
                    ConfidenceSource::Calibrated {
                        value: 0.95,
                        rationale: "signal health: file size threshold",
                    }
                    .derive(),
                )
                .with_metadata("size_bytes", size.to_string())
                .with_metadata("size_mb", format!("{:.1}", size_mb)),
            );
        }
        None
    }

    /// Detect circuit breaker open signals in recent records.
    fn detect_circuit_breaker_open(&self, records: &[SignalRecord]) -> Vec<ThreatSignal<String>> {
        let mut signals = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for record in records {
            if record.signal_type.contains("circuit_breaker")
                && record.data.get("state").map_or(false, |s| s == "open")
            {
                let subsystem = record
                    .data
                    .get("subsystem")
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string());
                if seen.insert(subsystem.clone()) {
                    signals.push(
                        ThreatSignal::new(
                            format!("circuit_breaker_open:{}", subsystem),
                            ThreatLevel::High,
                            SignalSource::Damp {
                                subsystem: "signal-health".to_string(),
                                damage_type: "circuit-breaker-open".to_string(),
                            },
                        )
                        .with_confidence(
                            ConfidenceSource::Calibrated {
                                value: 0.95,
                                rationale: "signal health: circuit breaker state",
                            }
                            .derive(),
                        )
                        .with_metadata("affected_subsystem", subsystem),
                    );
                }
            }
        }
        signals
    }
}

impl Sensor for SignalHealthSensor {
    type Pattern = String;

    fn detect(&self) -> Vec<ThreatSignal<Self::Pattern>> {
        let mut signals = Vec::new();

        // Check file size
        if let Some(signal) = self.detect_file_size() {
            signals.push(signal);
        }

        // Read records for content-based checks
        let records = self.read_recent_records();
        if !records.is_empty() {
            if let Some(signal) = self.detect_cytokine_burst(&records) {
                signals.push(signal);
            }
            signals.extend(self.detect_circuit_breaker_open(&records));
        }

        signals
            .into_iter()
            .filter(|s| s.confidence.value >= (1.0 - self.sensitivity))
            .collect()
    }

    fn sensitivity(&self) -> f64 {
        self.sensitivity
    }

    fn name(&self) -> &str {
        "signal-health-sensor"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_test_signals(path: &std::path::Path, records: &[&str]) {
        let mut file = std::fs::File::create(path).expect("create test file");
        for record in records {
            writeln!(file, "{record}").expect("write record");
        }
    }

    #[test]
    fn test_sensor_creation() {
        let sensor = SignalHealthSensor::new();
        assert_eq!(sensor.name(), "signal-health-sensor");
    }

    #[test]
    fn test_detect_oversized_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("signals.jsonl");

        // Create a file larger than 10MB
        let mut file = std::fs::File::create(&path).expect("create");
        let line = "x".repeat(1024); // 1KB line
        for _ in 0..11_000 {
            writeln!(file, "{line}").expect("write");
        }
        drop(file);

        let sensor = SignalHealthSensor::with_path(path);
        let signals = sensor.detect();
        assert!(
            signals
                .iter()
                .any(|s| s.pattern.contains("signal_file_oversized"))
        );
    }

    #[test]
    fn test_detect_cytokine_burst() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("signals.jsonl");

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);

        // 12 pro-inflammatory signals within 1 minute
        let mut records = Vec::new();
        for i in 0..12 {
            let ts = now_ms - (60_000 - i * 1000); // spread over 12 seconds
            records.push(format!(
                r#"{{"signal_type":"cytokine:tnf_alpha:blocked:{i}","timestamp_ms":{ts},"data":{{}}}}"#
            ));
        }
        let refs: Vec<&str> = records.iter().map(|s| s.as_str()).collect();
        write_test_signals(&path, &refs);

        let sensor = SignalHealthSensor::with_path(path);
        let signals = sensor.detect();
        assert!(signals.iter().any(|s| s.pattern.contains("cytokine_burst")));
    }

    #[test]
    fn test_healthy_signals() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("signals.jsonl");

        // Small file with benign signals
        let records = vec![
            r#"{"signal_type":"skill_invoked","timestamp_ms":1000,"data":{"skill":"forge"}}"#,
            r#"{"signal_type":"hook_completed","timestamp_ms":2000,"data":{"hook":"schema-gate"}}"#,
        ];
        write_test_signals(&path, &records);

        let sensor = SignalHealthSensor::with_path(path);
        let signals = sensor.detect();
        assert!(signals.is_empty());
    }

    #[test]
    fn test_detect_circuit_breaker() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("signals.jsonl");

        let records = vec![
            r#"{"signal_type":"circuit_breaker","timestamp_ms":1000,"data":{"state":"open","subsystem":"auth"}}"#,
        ];
        write_test_signals(&path, &records);

        let sensor = SignalHealthSensor::with_path(path);
        let signals = sensor.detect();
        assert!(
            signals
                .iter()
                .any(|s| s.pattern.contains("circuit_breaker_open"))
        );
    }
}
