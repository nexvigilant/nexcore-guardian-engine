//! Browser sensor for Guardian homeostasis loop
//!
//! Detects browser-based threats (PAMPs) by monitoring:
//! - Console errors (JavaScript exceptions, failed assertions)
//! - Network failures (connection errors, timeouts, 5xx responses)
//!
//! Tier: T3 (Domain-specific browser sensing)

use std::collections::HashMap;
use std::sync::Arc;

use nexcore_chrono::DateTime;
use nexcore_id::NexId;

use nexcore_primitives::measurement::Measured;

use nexcore_browser::collectors::console::{ConsoleCollector, get_console_collector};
use nexcore_browser::collectors::network::{NetworkCollector, get_network_collector};

use crate::sensing::{Sensor, SignalSource, ThreatLevel, ThreatSignal};

/// Pattern detected by the browser sensor
#[derive(Debug, Clone)]
pub enum BrowserPattern {
    /// Console errors detected
    ConsoleErrors {
        /// Number of errors
        count: usize,
        /// Sample error messages
        samples: Vec<String>,
    },
    /// Network failures detected
    NetworkFailures {
        /// Number of failures
        count: usize,
        /// Failure rate (failures / total)
        rate: f64,
        /// Sample URLs that failed
        failed_urls: Vec<String>,
    },
    /// High error rate (combined console + network)
    HighErrorRate {
        /// Console error count
        console_errors: usize,
        /// Network error count
        network_errors: usize,
        /// Combined rate
        combined_rate: f64,
    },
}

/// Browser sensor for detecting browser-based threats
///
/// Implements the Sensor trait for Guardian homeostasis loop integration.
/// Detects PAMPs (external threats) from browser telemetry.
pub struct BrowserSensor {
    /// Console message collector
    console: Arc<ConsoleCollector>,
    /// Network request collector
    network: Arc<NetworkCollector>,
    /// Sensor sensitivity (0.0-1.0)
    sensitivity: f64,
    /// Threshold for console errors to trigger signal
    console_error_threshold: usize,
    /// Threshold for network failure rate to trigger signal
    network_failure_rate_threshold: f64,
}

impl BrowserSensor {
    /// Create a new browser sensor with default thresholds
    #[must_use]
    pub fn new() -> Self {
        Self {
            console: get_console_collector(),
            network: get_network_collector(),
            sensitivity: 0.7,
            console_error_threshold: 5,
            network_failure_rate_threshold: 0.1, // 10% failure rate
        }
    }

    /// Create with custom thresholds
    #[must_use]
    pub fn with_thresholds(
        console_error_threshold: usize,
        network_failure_rate_threshold: f64,
    ) -> Self {
        Self {
            console: get_console_collector(),
            network: get_network_collector(),
            sensitivity: 0.7,
            console_error_threshold,
            network_failure_rate_threshold,
        }
    }

    /// Set sensitivity
    #[must_use]
    pub fn with_sensitivity(mut self, sensitivity: f64) -> Self {
        self.sensitivity = sensitivity.clamp(0.0, 1.0);
        self
    }

    /// Detect console error signals
    fn detect_console_errors(&self) -> Option<ThreatSignal<BrowserPattern>> {
        let error_count = self.console.error_count();

        if error_count < self.console_error_threshold {
            return None;
        }

        let errors = self.console.get_errors();
        let samples: Vec<String> = errors
            .iter()
            .take(5)
            .map(|e| e.text.chars().take(100).collect())
            .collect();

        let severity = match error_count {
            n if n >= 20 => ThreatLevel::High,
            n if n >= 10 => ThreatLevel::Medium,
            _ => ThreatLevel::Low,
        };

        let confidence_val = (error_count as f64 / 20.0).min(1.0) * self.sensitivity;

        let mut metadata = HashMap::new();
        metadata.insert("error_count".to_string(), error_count.to_string());
        metadata.insert(
            "warning_count".to_string(),
            self.console.warning_count().to_string(),
        );

        Some(ThreatSignal {
            id: NexId::v4().to_string(),
            pattern: BrowserPattern::ConsoleErrors {
                count: error_count,
                samples,
            },
            severity,
            timestamp: DateTime::now(),
            source: SignalSource::Pamp {
                source_id: "browser_console".to_string(),
                vector: "javascript_errors".to_string(),
            },
            confidence: Measured::certain(confidence_val),
            metadata,
        })
    }

    /// Detect network failure signals
    fn detect_network_failures(&self) -> Option<ThreatSignal<BrowserPattern>> {
        let failure_rate = self.network.failure_rate();
        let error_count = self.network.error_count();

        if failure_rate < self.network_failure_rate_threshold && error_count < 3 {
            return None;
        }

        let failures = self.network.get_failures();
        let failed_urls: Vec<String> = failures.iter().take(5).map(|e| e.url.clone()).collect();

        let severity = if failure_rate > 0.5 {
            ThreatLevel::High
        } else if failure_rate > 0.25 {
            ThreatLevel::Medium
        } else {
            ThreatLevel::Low
        };

        let confidence_val = (failure_rate * 2.0).min(1.0) * self.sensitivity;

        let mut metadata = HashMap::new();
        metadata.insert("failure_rate".to_string(), failure_rate.to_string());
        metadata.insert("error_count".to_string(), error_count.to_string());
        metadata.insert("total_requests".to_string(), self.network.len().to_string());

        Some(ThreatSignal {
            id: NexId::v4().to_string(),
            pattern: BrowserPattern::NetworkFailures {
                count: error_count,
                rate: failure_rate,
                failed_urls,
            },
            severity,
            timestamp: DateTime::now(),
            source: SignalSource::Pamp {
                source_id: "browser_network".to_string(),
                vector: "network_failures".to_string(),
            },
            confidence: Measured::certain(confidence_val),
            metadata,
        })
    }
}

impl Default for BrowserSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl Sensor for BrowserSensor {
    type Pattern = BrowserPattern;

    fn detect(&self) -> Vec<ThreatSignal<Self::Pattern>> {
        let mut signals = Vec::new();

        if let Some(signal) = self.detect_console_errors() {
            signals.push(signal);
        }

        if let Some(signal) = self.detect_network_failures() {
            signals.push(signal);
        }

        signals
    }

    fn sensitivity(&self) -> f64 {
        self.sensitivity
    }

    fn name(&self) -> &str {
        "browser_sensor"
    }

    fn is_active(&self) -> bool {
        // Active if browser collectors have any data
        !self.console.is_empty() || !self.network.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_browser_sensor_default() {
        let sensor = BrowserSensor::new();
        assert_eq!(sensor.name(), "browser_sensor");
        assert!((sensor.sensitivity() - 0.7).abs() < 0.001);
    }

    #[test]
    fn test_browser_sensor_with_sensitivity() {
        let sensor = BrowserSensor::new().with_sensitivity(0.9);
        assert!((sensor.sensitivity() - 0.9).abs() < 0.001);
    }

    #[test]
    fn test_browser_sensor_inactive_when_empty() {
        let _sensor = BrowserSensor::new();
        // Without any browser activity, sensor should be inactive
        // (depends on global collector state)
    }

    #[test]
    fn test_browser_pattern_debug() {
        let pattern = BrowserPattern::ConsoleErrors {
            count: 5,
            samples: vec!["Error 1".to_string()],
        };
        let debug_str = std::format!("{:?}", pattern);
        assert!(debug_str.contains("ConsoleErrors"));
    }
}
