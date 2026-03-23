//! Code Health Sensor
//!
//! DAMP sensor that monitors development system health metrics.
//! Reads `~/.claude/metrics/capabilities.json` and detects:
//! - Score degradation >20%
//! - Test count regression
//! - Missing metrics file
//!
//! # Tier: T3 (Domain-Specific Sensor)
//! # Grounding: κ (Comparison) + ∂ (Boundary) + N (Quantity)

use crate::confidence::ConfidenceSource;
use crate::sensing::{Measured, Sensor, SignalSource, ThreatLevel, ThreatSignal};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Score degradation threshold (fraction).
const DEGRADATION_THRESHOLD: f64 = 0.20;

/// Minimal capabilities structure for parsing.
///
/// # Tier: T2-C
#[derive(Debug, Clone, Deserialize)]
struct Capabilities {
    #[serde(default)]
    overall_score: Option<f64>,
    #[serde(default)]
    test_count: Option<u64>,
    #[serde(default)]
    previous_score: Option<f64>,
    #[serde(default)]
    previous_test_count: Option<u64>,
    #[serde(default)]
    crate_count: Option<u64>,
}

/// Code Health Sensor — detects degradation in development system metrics.
///
/// # Tier: T3
/// Grounds to: κ (Comparison) via score delta computation,
///             ∂ (Boundary) via threshold enforcement,
///             N (Quantity) via test count tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeHealthSensor {
    sensitivity: f64,
    capabilities_path: PathBuf,
}

impl Default for CodeHealthSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl CodeHealthSensor {
    /// Create with default capabilities path.
    #[must_use]
    pub fn new() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        Self {
            sensitivity: 0.85,
            capabilities_path: PathBuf::from(home)
                .join(".claude")
                .join("metrics")
                .join("capabilities.json"),
        }
    }

    /// Create with custom path (for testing).
    #[must_use]
    pub fn with_path(path: PathBuf) -> Self {
        Self {
            sensitivity: 0.85,
            capabilities_path: path,
        }
    }

    /// Load capabilities from disk.
    fn load_capabilities(&self) -> Option<Capabilities> {
        let content = std::fs::read_to_string(&self.capabilities_path).ok()?;
        serde_json::from_str(&content).ok()
    }

    /// Detect score degradation.
    fn detect_score_degradation(&self, caps: &Capabilities) -> Option<ThreatSignal<String>> {
        let current = caps.overall_score?;
        let previous = caps.previous_score?;

        if previous <= 0.0 {
            return None;
        }

        let delta = (previous - current) / previous;
        if delta > DEGRADATION_THRESHOLD {
            let severity = if delta > 0.40 {
                ThreatLevel::High
            } else {
                ThreatLevel::Medium
            };
            return Some(
                ThreatSignal::new(
                    format!("code_health_degradation:{:.1}%", delta * 100.0),
                    severity,
                    SignalSource::Damp {
                        subsystem: "code-health".to_string(),
                        damage_type: "score-degradation".to_string(),
                    },
                )
                .with_confidence(
                    ConfidenceSource::Calibrated {
                        value: 0.85,
                        rationale: "code health: score degradation delta",
                    }
                    .derive(),
                )
                .with_metadata("current_score", format!("{:.2}", current))
                .with_metadata("previous_score", format!("{:.2}", previous))
                .with_metadata("degradation_pct", format!("{:.1}", delta * 100.0)),
            );
        }
        None
    }

    /// Detect test count regression.
    fn detect_test_regression(&self, caps: &Capabilities) -> Option<ThreatSignal<String>> {
        let current = caps.test_count?;
        let previous = caps.previous_test_count?;

        if current < previous {
            let lost = previous - current;
            let severity = if lost > 100 {
                ThreatLevel::High
            } else if lost > 20 {
                ThreatLevel::Medium
            } else {
                ThreatLevel::Low
            };
            return Some(
                ThreatSignal::new(
                    format!("test_count_regression:{}_lost", lost),
                    severity,
                    SignalSource::Damp {
                        subsystem: "code-health".to_string(),
                        damage_type: "test-regression".to_string(),
                    },
                )
                .with_confidence(
                    ConfidenceSource::Calibrated {
                        value: 0.9,
                        rationale: "code health: test count regression",
                    }
                    .derive(),
                )
                .with_metadata("current_tests", current.to_string())
                .with_metadata("previous_tests", previous.to_string())
                .with_metadata("tests_lost", lost.to_string()),
            );
        }
        None
    }

    /// Detect missing metrics file.
    fn detect_missing_metrics(&self) -> Option<ThreatSignal<String>> {
        if !self.capabilities_path.exists() {
            return Some(
                ThreatSignal::new(
                    "code_health_metrics_missing".to_string(),
                    ThreatLevel::Low,
                    SignalSource::Damp {
                        subsystem: "code-health".to_string(),
                        damage_type: "missing-metrics".to_string(),
                    },
                )
                .with_confidence(
                    ConfidenceSource::Calibrated {
                        value: 0.7,
                        rationale: "code health: metrics file absence",
                    }
                    .derive(),
                ),
            );
        }
        None
    }
}

impl Sensor for CodeHealthSensor {
    type Pattern = String;

    fn detect(&self) -> Vec<ThreatSignal<Self::Pattern>> {
        let mut signals = Vec::new();

        if let Some(signal) = self.detect_missing_metrics() {
            signals.push(signal);
            return signals;
        }

        if let Some(caps) = self.load_capabilities() {
            if let Some(signal) = self.detect_score_degradation(&caps) {
                signals.push(signal);
            }
            if let Some(signal) = self.detect_test_regression(&caps) {
                signals.push(signal);
            }
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
        "code-health-sensor"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sensor_creation() {
        let sensor = CodeHealthSensor::new();
        assert_eq!(sensor.name(), "code-health-sensor");
    }

    #[test]
    fn test_detect_missing_file() {
        let sensor = CodeHealthSensor::with_path(PathBuf::from("/nonexistent/caps.json"));
        let signals = sensor.detect();
        assert!(!signals.is_empty());
        assert!(signals[0].pattern.contains("metrics_missing"));
    }

    #[test]
    fn test_detect_score_degradation() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("capabilities.json");
        std::fs::write(
            &path,
            r#"{"overall_score": 6.0, "previous_score": 8.0, "test_count": 100, "previous_test_count": 100}"#,
        ).expect("write");

        let sensor = CodeHealthSensor::with_path(path);
        let signals = sensor.detect();
        assert!(!signals.is_empty());
        assert!(signals[0].pattern.contains("code_health_degradation"));
    }

    #[test]
    fn test_detect_test_regression() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("capabilities.json");
        std::fs::write(
            &path,
            r#"{"overall_score": 8.0, "previous_score": 8.0, "test_count": 80, "previous_test_count": 130}"#,
        ).expect("write");

        let sensor = CodeHealthSensor::with_path(path);
        let signals = sensor.detect();
        assert!(!signals.is_empty());
        assert!(signals[0].pattern.contains("test_count_regression"));
    }

    #[test]
    fn test_healthy_metrics() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("capabilities.json");
        std::fs::write(
            &path,
            r#"{"overall_score": 8.5, "previous_score": 8.0, "test_count": 4500, "previous_test_count": 4400}"#,
        ).expect("write");

        let sensor = CodeHealthSensor::with_path(path);
        let signals = sensor.detect();
        assert!(signals.is_empty());
    }
}
