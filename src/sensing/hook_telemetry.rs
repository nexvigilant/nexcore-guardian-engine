//! Hook Telemetry Sensor
//!
//! DAMP sensor that monitors hook execution telemetry for anomalies.
//! Reads `hook_executions.jsonl` and detects:
//! - Block rate >50% (high false-positive rate or systematic issue)
//! - Execution time >5000ms (hook performance degradation)
//! - Missing hooks >24h (hook infrastructure failure)
//!
//! # Tier: T3 (Domain-Specific Sensor)
//! # Grounding: ς (State) + ν (Frequency) + ∂ (Boundary)

use crate::confidence::ConfidenceSource;
use crate::sensing::{Measured, Sensor, SignalSource, ThreatLevel, ThreatSignal};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Block rate threshold above which we alert.
const BLOCK_RATE_WARN: f64 = 0.50;
/// Execution time threshold in milliseconds.
const SLOW_HOOK_MS: u64 = 5000;
/// Maximum age of last execution before "missing" alert (seconds).
const MISSING_THRESHOLD_SECS: u64 = 86400; // 24 hours
/// Maximum lines to read from tail of telemetry file.
const TAIL_LINES: usize = 200;

/// Minimal hook execution record for parsing.
///
/// # Tier: T2-C
#[derive(Debug, Clone, Deserialize)]
struct HookRecord {
    timestamp: String,
    hook: HookName,
    #[allow(dead_code)]
    event: String,
    duration_ms: DurationMs,
    exit_code: u8,
    blocked: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(transparent)]
struct HookName(String);

#[derive(Debug, Clone, Deserialize)]
#[serde(transparent)]
struct DurationMs(u64);

/// Hook Telemetry Sensor — detects anomalies in hook execution patterns.
///
/// # Tier: T3
/// Grounds to: ς (State) via telemetry state tracking,
///             ν (Frequency) via block rate computation,
///             ∂ (Boundary) via threshold enforcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookTelemetrySensor {
    sensitivity: f64,
    telemetry_path: PathBuf,
}

impl Default for HookTelemetrySensor {
    fn default() -> Self {
        Self::new()
    }
}

impl HookTelemetrySensor {
    /// Create with default telemetry path.
    #[must_use]
    pub fn new() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        Self {
            sensitivity: 0.85,
            telemetry_path: PathBuf::from(home)
                .join(".claude")
                .join("brain")
                .join("telemetry")
                .join("hook_executions.jsonl"),
        }
    }

    /// Create with custom path (for testing).
    #[must_use]
    pub fn with_path(path: PathBuf) -> Self {
        Self {
            sensitivity: 0.85,
            telemetry_path: path,
        }
    }

    /// Read the last N records from the telemetry file.
    fn read_recent_records(&self) -> Vec<HookRecord> {
        let content = match std::fs::read_to_string(&self.telemetry_path) {
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

    /// Compute per-hook block rates.
    fn compute_block_rates(records: &[HookRecord]) -> HashMap<String, (usize, usize)> {
        let mut stats: HashMap<String, (usize, usize)> = HashMap::new(); // (total, blocked)
        for record in records {
            let entry = stats.entry(record.hook.0.clone()).or_insert((0, 0));
            entry.0 += 1;
            if record.blocked {
                entry.1 += 1;
            }
        }
        stats
    }

    /// Detect hooks with high block rates.
    fn detect_high_block_rate(&self, records: &[HookRecord]) -> Vec<ThreatSignal<String>> {
        let stats = Self::compute_block_rates(records);
        let mut signals = Vec::new();

        for (hook, (total, blocked)) in &stats {
            if *total < 5 {
                continue; // Not enough data
            }
            let rate = *blocked as f64 / *total as f64;
            if rate > BLOCK_RATE_WARN {
                let severity = if rate > 0.75 {
                    ThreatLevel::High
                } else {
                    ThreatLevel::Medium
                };
                signals.push(
                    ThreatSignal::new(
                        format!("hook_high_block_rate:{}:{:.0}%", hook, rate * 100.0),
                        severity,
                        SignalSource::Damp {
                            subsystem: "hook-telemetry".to_string(),
                            damage_type: "high-block-rate".to_string(),
                        },
                    )
                    .with_confidence(
                        ConfidenceSource::Calibrated {
                            value: 0.9,
                            rationale: "hook telemetry: block rate frequency",
                        }
                        .derive(),
                    )
                    .with_metadata("hook", hook.clone())
                    .with_metadata("block_rate", format!("{:.2}", rate))
                    .with_metadata("total", total.to_string())
                    .with_metadata("blocked", blocked.to_string()),
                );
            }
        }
        signals
    }

    /// Detect hooks with slow execution times.
    fn detect_slow_hooks(&self, records: &[HookRecord]) -> Vec<ThreatSignal<String>> {
        let mut signals = Vec::new();
        let mut seen: HashMap<String, u64> = HashMap::new();

        for record in records {
            if record.duration_ms.0 > SLOW_HOOK_MS {
                let max = seen.entry(record.hook.0.clone()).or_insert(0);
                if record.duration_ms.0 > *max {
                    *max = record.duration_ms.0;
                }
            }
        }

        for (hook, max_ms) in &seen {
            signals.push(
                ThreatSignal::new(
                    format!("hook_slow_execution:{}:{}ms", hook, max_ms),
                    ThreatLevel::Medium,
                    SignalSource::Damp {
                        subsystem: "hook-telemetry".to_string(),
                        damage_type: "performance-degradation".to_string(),
                    },
                )
                .with_confidence(
                    ConfidenceSource::Calibrated {
                        value: 0.85,
                        rationale: "hook telemetry: execution time anomaly",
                    }
                    .derive(),
                )
                .with_metadata("hook", hook.clone())
                .with_metadata("max_duration_ms", max_ms.to_string()),
            );
        }
        signals
    }

    /// Detect if telemetry file is missing or empty (infrastructure failure).
    fn detect_missing_telemetry(&self) -> Option<ThreatSignal<String>> {
        if !self.telemetry_path.exists() {
            return Some(
                ThreatSignal::new(
                    "hook_telemetry_missing:no_file".to_string(),
                    ThreatLevel::Medium,
                    SignalSource::Damp {
                        subsystem: "hook-telemetry".to_string(),
                        damage_type: "infrastructure-failure".to_string(),
                    },
                )
                .with_confidence(
                    ConfidenceSource::Calibrated {
                        value: 0.95,
                        rationale: "hook telemetry: file absence check",
                    }
                    .derive(),
                ),
            );
        }

        // Check file modification time
        let metadata = std::fs::metadata(&self.telemetry_path).ok()?;
        let modified = metadata.modified().ok()?;
        let age = std::time::SystemTime::now().duration_since(modified).ok()?;

        if age.as_secs() > MISSING_THRESHOLD_SECS {
            return Some(
                ThreatSignal::new(
                    format!("hook_telemetry_stale:{}h", age.as_secs() / 3600),
                    ThreatLevel::Medium,
                    SignalSource::Damp {
                        subsystem: "hook-telemetry".to_string(),
                        damage_type: "stale-data".to_string(),
                    },
                )
                .with_confidence(
                    ConfidenceSource::Calibrated {
                        value: 0.8,
                        rationale: "hook telemetry: stale data age",
                    }
                    .derive(),
                )
                .with_metadata("age_hours", (age.as_secs() / 3600).to_string()),
            );
        }
        None
    }
}

impl Sensor for HookTelemetrySensor {
    type Pattern = String;

    fn detect(&self) -> Vec<ThreatSignal<Self::Pattern>> {
        let mut signals = Vec::new();

        // Check infrastructure health first
        if let Some(signal) = self.detect_missing_telemetry() {
            signals.push(signal);
            return signals; // No point checking records if file is missing/stale
        }

        let records = self.read_recent_records();
        if records.is_empty() {
            return signals;
        }

        signals.extend(self.detect_high_block_rate(&records));
        signals.extend(self.detect_slow_hooks(&records));

        // Apply sensitivity filter
        signals
            .into_iter()
            .filter(|s| s.confidence.value >= (1.0 - self.sensitivity))
            .collect()
    }

    fn sensitivity(&self) -> f64 {
        self.sensitivity
    }

    fn name(&self) -> &str {
        "hook-telemetry-sensor"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_test_records(path: &std::path::Path, records: &[&str]) {
        let mut file = std::fs::File::create(path).expect("create test file");
        for record in records {
            writeln!(file, "{record}").expect("write record");
        }
    }

    #[test]
    fn test_sensor_creation() {
        let sensor = HookTelemetrySensor::new();
        assert_eq!(sensor.name(), "hook-telemetry-sensor");
        assert!((sensor.sensitivity() - 0.85).abs() < f64::EPSILON);
    }

    #[test]
    fn test_detect_high_block_rate() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("hook_executions.jsonl");

        // 10 records: 7 blocked, 3 passed → 70% block rate
        let mut records = Vec::new();
        for i in 0..10 {
            let blocked = i < 7;
            records.push(format!(
                r#"{{"timestamp":"2026-02-06T00:00:00Z","hook":"test-hook","event":"PreToolUse","duration_ms":10,"exit_code":{},"blocked":{}}}"#,
                if blocked { 2 } else { 0 },
                blocked
            ));
        }
        let refs: Vec<&str> = records.iter().map(|s| s.as_str()).collect();
        write_test_records(&path, &refs);

        let sensor = HookTelemetrySensor::with_path(path);
        let signals = sensor.detect();
        assert!(!signals.is_empty());
        assert!(signals[0].pattern.contains("hook_high_block_rate"));
    }

    #[test]
    fn test_detect_slow_hook() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("hook_executions.jsonl");

        let records = vec![
            r#"{"timestamp":"2026-02-06T00:00:00Z","hook":"slow-hook","event":"PreToolUse","duration_ms":8000,"exit_code":0,"blocked":false}"#,
        ];
        write_test_records(&path, &records);

        let sensor = HookTelemetrySensor::with_path(path);
        let signals = sensor.detect();
        assert!(!signals.is_empty());
        assert!(signals[0].pattern.contains("hook_slow_execution"));
    }

    #[test]
    fn test_detect_missing_file() {
        let sensor = HookTelemetrySensor::with_path(PathBuf::from("/nonexistent/path.jsonl"));
        let signals = sensor.detect();
        assert!(!signals.is_empty());
        assert!(signals[0].pattern.contains("hook_telemetry_missing"));
    }

    #[test]
    fn test_healthy_hooks_no_signals() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("hook_executions.jsonl");

        // All passing, fast hooks
        let mut records = Vec::new();
        for _ in 0..10 {
            records.push(
                r#"{"timestamp":"2026-02-06T00:00:00Z","hook":"good-hook","event":"PreToolUse","duration_ms":5,"exit_code":0,"blocked":false}"#.to_string()
            );
        }
        let refs: Vec<&str> = records.iter().map(|s| s.as_str()).collect();
        write_test_records(&path, &refs);

        let sensor = HookTelemetrySensor::with_path(path);
        let signals = sensor.detect();
        assert!(signals.is_empty());
    }
}
