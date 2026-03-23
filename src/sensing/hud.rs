//! # HUD Governance Sensor
//!
//! Sensor implementation for monitoring HUD (Head-Up Display) governance
//! Acts and emitting signals when governance thresholds are exceeded.
//!
//! Maps to US federal agency domains (CAP-014 through CAP-037).

use super::{Sensor, SignalSource, ThreatLevel, ThreatSignal};
use std::collections::HashMap;

/// HUD signal pattern - what the sensor detected
#[derive(Debug, Clone)]
pub struct HudPattern {
    /// Act identifier (e.g., "SSA" for Social Security Act)
    pub act_id: String,
    /// Capability that triggered the signal
    pub capability: String,
    /// Current value that exceeded threshold
    pub current_value: f64,
    /// Threshold that was exceeded
    pub threshold: f64,
    /// Pattern type
    pub pattern_type: HudPatternType,
}

/// Types of HUD governance patterns
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HudPatternType {
    /// State storage capacity exceeded
    StorageCapacity,
    /// Integrity hash verification failed
    IntegrityFailure,
    /// Backup frequency too low
    BackupFrequency,
    /// Audit trail gap detected
    AuditGap,
    /// Authority delegation exceeded
    AuthorityExceeded,
    /// Rate limit approaching
    RateLimitApproaching,
}

impl std::fmt::Display for HudPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{:?}({}={:.2},threshold={:.2})",
            self.act_id, self.pattern_type, self.capability, self.current_value, self.threshold
        )
    }
}

impl HudPatternType {
    /// Get severity for this pattern type
    #[must_use]
    pub const fn default_severity(&self) -> ThreatLevel {
        match self {
            Self::IntegrityFailure => ThreatLevel::Critical,
            Self::AuthorityExceeded => ThreatLevel::High,
            Self::AuditGap => ThreatLevel::High,
            Self::StorageCapacity => ThreatLevel::Medium,
            Self::BackupFrequency => ThreatLevel::Medium,
            Self::RateLimitApproaching => ThreatLevel::Low,
        }
    }
}

/// HUD Governance Sensor
///
/// Monitors HUD Act states and emits signals when governance
/// thresholds are exceeded. This sensor checks:
///
/// - State storage capacity (SSA, FERPA, etc.)
/// - Integrity verification status (Federal Reserve Act)
/// - Audit trail completeness (EPA, SEC)
/// - Authority delegation limits (all Acts)
pub struct HudSensor {
    /// Sensor sensitivity (0.0-1.0)
    sensitivity: f64,
    /// Thresholds per Act
    thresholds: HashMap<String, HudThresholds>,
    /// Whether sensor is active
    active: bool,
}

/// Thresholds for HUD governance monitoring
#[derive(Debug, Clone)]
pub struct HudThresholds {
    /// Maximum state entries before warning
    pub max_state_entries: usize,
    /// Maximum time since last backup (seconds)
    pub max_backup_age_seconds: u64,
    /// Maximum failed integrity checks before alert
    pub max_integrity_failures: u32,
    /// Percentage of rate limit that triggers warning
    pub rate_limit_warning_percent: f64,
}

impl Default for HudThresholds {
    fn default() -> Self {
        Self {
            max_state_entries: 10_000,
            max_backup_age_seconds: 3600, // 1 hour
            max_integrity_failures: 3,
            rate_limit_warning_percent: 0.8, // 80%
        }
    }
}

impl HudSensor {
    /// Create a new HUD sensor with default settings
    #[must_use]
    pub fn new() -> Self {
        Self {
            sensitivity: 0.8,
            thresholds: HashMap::new(),
            active: true,
        }
    }

    /// Set sensitivity
    #[must_use]
    pub fn with_sensitivity(mut self, sensitivity: f64) -> Self {
        self.sensitivity = sensitivity.clamp(0.0, 1.0);
        self
    }

    /// Set thresholds for a specific Act
    pub fn set_thresholds(&mut self, act_id: impl Into<String>, thresholds: HudThresholds) {
        self.thresholds.insert(act_id.into(), thresholds);
    }

    /// Get thresholds for an Act (returns defaults if not set)
    #[must_use]
    pub fn get_thresholds(&self, act_id: &str) -> HudThresholds {
        self.thresholds.get(act_id).cloned().unwrap_or_default()
    }

    /// Set active state
    pub fn set_active(&mut self, active: bool) {
        self.active = active;
    }

    /// Check state storage capacity for an Act
    #[must_use]
    pub fn check_storage_capacity(
        &self,
        act_id: &str,
        current_entries: usize,
    ) -> Option<ThreatSignal<HudPattern>> {
        let thresholds = self.get_thresholds(act_id);

        if current_entries >= thresholds.max_state_entries {
            let pattern = HudPattern {
                act_id: act_id.to_string(),
                capability: "state_storage".to_string(),
                current_value: current_entries as f64,
                threshold: thresholds.max_state_entries as f64,
                pattern_type: HudPatternType::StorageCapacity,
            };

            let severity = if current_entries >= thresholds.max_state_entries * 2 {
                ThreatLevel::High
            } else {
                ThreatLevel::Medium
            };

            Some(
                ThreatSignal::new(
                    pattern,
                    severity,
                    SignalSource::Damp {
                        subsystem: format!("hud.{}", act_id),
                        damage_type: "storage_capacity_exceeded".to_string(),
                    },
                )
                .with_metadata("act_id", act_id)
                .with_metadata("current_entries", current_entries.to_string())
                .with_metadata("threshold", thresholds.max_state_entries.to_string()),
            )
        } else {
            None
        }
    }

    /// Check integrity verification status
    #[must_use]
    pub fn check_integrity(
        &self,
        act_id: &str,
        failed_checks: u32,
    ) -> Option<ThreatSignal<HudPattern>> {
        let thresholds = self.get_thresholds(act_id);

        if failed_checks >= thresholds.max_integrity_failures {
            let pattern = HudPattern {
                act_id: act_id.to_string(),
                capability: "integrity_verification".to_string(),
                current_value: failed_checks as f64,
                threshold: thresholds.max_integrity_failures as f64,
                pattern_type: HudPatternType::IntegrityFailure,
            };

            Some(
                ThreatSignal::new(
                    pattern,
                    ThreatLevel::Critical,
                    SignalSource::Damp {
                        subsystem: format!("hud.{}", act_id),
                        damage_type: "integrity_verification_failed".to_string(),
                    },
                )
                .with_metadata("act_id", act_id)
                .with_metadata("failed_checks", failed_checks.to_string()),
            )
        } else {
            None
        }
    }

    /// Check backup freshness
    #[must_use]
    pub fn check_backup_age(
        &self,
        act_id: &str,
        seconds_since_backup: u64,
    ) -> Option<ThreatSignal<HudPattern>> {
        let thresholds = self.get_thresholds(act_id);

        if seconds_since_backup >= thresholds.max_backup_age_seconds {
            let pattern = HudPattern {
                act_id: act_id.to_string(),
                capability: "backup_freshness".to_string(),
                current_value: seconds_since_backup as f64,
                threshold: thresholds.max_backup_age_seconds as f64,
                pattern_type: HudPatternType::BackupFrequency,
            };

            let severity = if seconds_since_backup >= thresholds.max_backup_age_seconds * 2 {
                ThreatLevel::High
            } else {
                ThreatLevel::Medium
            };

            Some(
                ThreatSignal::new(
                    pattern,
                    severity,
                    SignalSource::Damp {
                        subsystem: format!("hud.{}", act_id),
                        damage_type: "backup_stale".to_string(),
                    },
                )
                .with_metadata("act_id", act_id)
                .with_metadata("seconds_since_backup", seconds_since_backup.to_string()),
            )
        } else {
            None
        }
    }

    /// Check rate limit status
    #[must_use]
    pub fn check_rate_limit(
        &self,
        act_id: &str,
        current_usage: f64,
        max_limit: f64,
    ) -> Option<ThreatSignal<HudPattern>> {
        let thresholds = self.get_thresholds(act_id);
        let usage_percent = current_usage / max_limit;

        if usage_percent >= thresholds.rate_limit_warning_percent {
            let pattern = HudPattern {
                act_id: act_id.to_string(),
                capability: "rate_limit".to_string(),
                current_value: usage_percent,
                threshold: thresholds.rate_limit_warning_percent,
                pattern_type: HudPatternType::RateLimitApproaching,
            };

            let severity = if usage_percent >= 0.95 {
                ThreatLevel::High
            } else if usage_percent >= 0.9 {
                ThreatLevel::Medium
            } else {
                ThreatLevel::Low
            };

            Some(
                ThreatSignal::new(
                    pattern,
                    severity,
                    SignalSource::Damp {
                        subsystem: format!("hud.{}", act_id),
                        damage_type: "rate_limit_approaching".to_string(),
                    },
                )
                .with_metadata("act_id", act_id)
                .with_metadata("usage_percent", format!("{:.1}%", usage_percent * 100.0)),
            )
        } else {
            None
        }
    }
}

impl Default for HudSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl Sensor for HudSensor {
    type Pattern = HudPattern;

    fn detect(&self) -> Vec<ThreatSignal<Self::Pattern>> {
        // In a real implementation, this would query the HUD Act singletons
        // and check each one for threshold violations.
        //
        // For now, returns empty - actual detection happens via the
        // check_* methods called by the HUD MCP tools.
        Vec::new()
    }

    fn sensitivity(&self) -> f64 {
        self.sensitivity
    }

    fn name(&self) -> &str {
        "hud-governance-sensor"
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_capacity_below_threshold() {
        let sensor = HudSensor::new();
        let result = sensor.check_storage_capacity("SSA", 1000);
        assert!(result.is_none());
    }

    #[test]
    fn test_storage_capacity_exceeded() {
        let sensor = HudSensor::new();
        let result = sensor.check_storage_capacity("SSA", 15000);
        assert!(result.is_some());
        let signal = result.unwrap();
        assert_eq!(signal.pattern.act_id, "SSA");
        assert_eq!(signal.pattern.pattern_type, HudPatternType::StorageCapacity);
    }

    #[test]
    fn test_integrity_failure_detected() {
        let sensor = HudSensor::new();
        let result = sensor.check_integrity("FRA", 5);
        assert!(result.is_some());
        let signal = result.unwrap();
        assert_eq!(signal.severity, ThreatLevel::Critical);
    }

    #[test]
    fn test_rate_limit_approaching() {
        let sensor = HudSensor::new();
        let result = sensor.check_rate_limit("EPA", 85.0, 100.0);
        assert!(result.is_some());
        let signal = result.unwrap();
        assert_eq!(
            signal.pattern.pattern_type,
            HudPatternType::RateLimitApproaching
        );
    }

    #[test]
    fn test_custom_thresholds() {
        let mut sensor = HudSensor::new();
        sensor.set_thresholds(
            "TEST",
            HudThresholds {
                max_state_entries: 100,
                ..Default::default()
            },
        );

        let result = sensor.check_storage_capacity("TEST", 150);
        assert!(result.is_some());
    }
}
