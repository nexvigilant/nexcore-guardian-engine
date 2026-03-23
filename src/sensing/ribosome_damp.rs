// Copyright © 2026 NexVigilant LLC. All Rights Reserved.
// Intellectual Property of Matthew Alexander Campion, PharmD

//! # Ribosome DAMP Sensor
//!
//! Converts schema drift signals from `nexcore-ribosome` into Guardian-compatible
//! DAMP (Damage-Associated Molecular Pattern) signals for the homeostasis loop.
//!
//! ## Biology
//!
//! In immunology, DAMPs are endogenous danger signals released by damaged cells.
//! Schema drift is internal data corruption — a DAMP, not a PAMP.
//!
//! ## Pipeline
//!
//! ```text
//! Ribosome::validate() → DriftSignal → RibosomeDampSensor → Signal<String> → Guardian
//! ```
//!
//! ## T1 Grounding
//!
//! | Concept | Primitive | Role |
//! |---------|-----------|------|
//! | Severity mapping | μ (mapping) | DriftSeverity → Guardian Severity |
//! | Signal buffer | σ (sequence) | Pending drift signals |
//! | Drain + convert | ρ (recursion) | Consume all pending, emit signals |
//! | Deduplication | ς (state) | Track seen contract_id:score pairs |

use std::collections::HashSet;
use std::sync::Mutex;

use nexcore_ribosome::{DriftSeverity, DriftSignal};

use super::{Sensor, SignalSource, ThreatLevel, ThreatSignal};
use nexcore_primitives::measurement::Measured;

/// Maximum dedup set size before pruning.
const DEDUP_MAX: usize = 512;

/// Sensor that detects schema drift from the Ribosome contract registry.
///
/// External code pushes `DriftSignal`s via [`push_signal()`](Self::push_signal).
/// The Guardian homeostasis loop calls [`detect()`](Self::detect) to drain
/// all pending signals, converting them to Guardian-compatible DAMP signals.
///
/// # Example
///
/// ```ignore
/// use nexcore_vigilance::guardian::sensing::ribosome_damp::RibosomeDampSensor;
/// use nexcore_vigilance::guardian::sensing::Sensor;
/// use nexcore_ribosome::DriftSignal;
///
/// let sensor = RibosomeDampSensor::new();
///
/// // External code pushes a drift signal
/// sensor.push_signal(DriftSignal {
///     contract_id: "user-api-v1".into(),
///     drift_score: 0.42,
///     violations: vec![],
///     confidence: 0.916,
/// });
///
/// // Guardian polls the sensor
/// let signals = sensor.detect();
/// assert_eq!(signals.len(), 1);
/// assert!(signals[0].pattern.contains("schema_drift"));
/// ```
pub struct RibosomeDampSensor {
    /// Pending drift signals (pushed externally, drained on detect).
    pending: Mutex<Vec<DriftSignal>>,
    /// Detection sensitivity (0.0-1.0).
    sensitivity: f64,
    /// Previously seen drift keys for deduplication.
    seen: Mutex<HashSet<String>>,
}

impl Default for RibosomeDampSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl RibosomeDampSensor {
    /// Create a new ribosome DAMP sensor with default sensitivity (0.9).
    #[must_use]
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(Vec::new()),
            sensitivity: 0.9,
            seen: Mutex::new(HashSet::new()),
        }
    }

    /// Create with custom sensitivity.
    #[must_use]
    pub fn with_sensitivity(sensitivity: f64) -> Self {
        Self {
            pending: Mutex::new(Vec::new()),
            sensitivity: sensitivity.clamp(0.0, 1.0),
            seen: Mutex::new(HashSet::new()),
        }
    }

    /// Push a drift signal into the pending buffer.
    ///
    /// Called by external code (e.g., MCP tool handlers) when drift is detected.
    pub fn push_signal(&self, signal: DriftSignal) {
        if let Ok(mut pending) = self.pending.lock() {
            pending.push(signal);
        }
    }

    /// Push multiple drift signals at once.
    pub fn push_signals(&self, signals: Vec<DriftSignal>) {
        if let Ok(mut pending) = self.pending.lock() {
            pending.extend(signals);
        }
    }

    /// Get the number of pending (unprocessed) drift signals.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.lock().map(|p| p.len()).unwrap_or(0)
    }

    /// Map `DriftSeverity` → Guardian `Severity`.
    ///
    /// Drift is internal damage, so we map conservatively:
    /// - Info → Low (monitor)
    /// - Warning → Medium (investigate)
    /// - Critical → High (respond)
    fn map_severity(drift_sev: DriftSeverity) -> ThreatLevel {
        match drift_sev {
            DriftSeverity::Info => ThreatLevel::Low,
            DriftSeverity::Warning => ThreatLevel::Medium,
            DriftSeverity::Critical => ThreatLevel::High,
        }
    }

    /// Determine the highest severity from drift violations, defaulting
    /// to a score-based severity if no violations exist.
    fn effective_severity(signal: &DriftSignal) -> ThreatLevel {
        // If violations exist, use the highest violation severity
        let max_violation_sev = signal.violations.iter().map(|v| v.severity).max();

        if let Some(sev) = max_violation_sev {
            return Self::map_severity(sev);
        }

        // Fallback: derive from drift score
        if signal.drift_score >= 0.75 {
            ThreatLevel::High
        } else if signal.drift_score >= 0.40 {
            ThreatLevel::Medium
        } else {
            ThreatLevel::Low
        }
    }

    /// Create a dedup key from contract_id + quantized drift score.
    /// We quantize to 2 decimal places to avoid floating-point noise.
    fn dedup_key(signal: &DriftSignal) -> String {
        format!("{}:{:.2}", signal.contract_id, signal.drift_score)
    }

    /// Prune the seen set if it exceeds the maximum size.
    fn prune_seen(seen: &mut HashSet<String>) {
        if seen.len() > DEDUP_MAX {
            seen.clear();
        }
    }
}

impl Sensor for RibosomeDampSensor {
    type Pattern = String;

    fn detect(&self) -> Vec<ThreatSignal<Self::Pattern>> {
        // Drain all pending drift signals
        let drift_signals = {
            let mut pending = match self.pending.lock() {
                Ok(p) => p,
                Err(e) => e.into_inner(),
            };
            std::mem::take(&mut *pending)
        };

        if drift_signals.is_empty() {
            return Vec::new();
        }

        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        Self::prune_seen(&mut seen);

        let mut signals = Vec::new();

        for drift in &drift_signals {
            let key = Self::dedup_key(drift);
            if seen.contains(&key) {
                continue;
            }

            let severity = Self::effective_severity(drift);
            let confidence = Measured::certain(drift.confidence.clamp(0.0, 1.0));

            let pattern = format!(
                "schema_drift:{}:score={:.2}:violations={}",
                drift.contract_id,
                drift.drift_score,
                drift.violations.len(),
            );

            let source = SignalSource::Damp {
                subsystem: "schema-registry".to_string(),
                damage_type: "schema-drift".to_string(),
            };

            let signal = ThreatSignal::new(pattern, severity, source)
                .with_confidence(confidence)
                .with_metadata("contract_id", &drift.contract_id)
                .with_metadata("drift_score", format!("{:.4}", drift.drift_score))
                .with_metadata("violation_count", drift.violations.len().to_string());

            signals.push(signal);
            seen.insert(key);
        }

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
        "ribosome-damp-sensor"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexcore_ribosome::SchemaDrift;

    fn make_drift_signal(
        contract_id: &str,
        score: f64,
        violations: Vec<SchemaDrift>,
    ) -> DriftSignal {
        DriftSignal {
            contract_id: contract_id.to_string(),
            drift_score: score,
            violations,
            confidence: 1.0 - (score * 0.2),
        }
    }

    fn make_violation(
        field: &str,
        drift_type: nexcore_ribosome::DriftType,
        severity: DriftSeverity,
    ) -> SchemaDrift {
        SchemaDrift {
            field: field.to_string(),
            drift_type,
            expected: "expected".to_string(),
            observed: "observed".to_string(),
            severity,
        }
    }

    // ── Sensor basics ──────────────────────────────────────────────────────

    #[test]
    fn test_sensor_name() {
        let sensor = RibosomeDampSensor::new();
        assert_eq!(sensor.name(), "ribosome-damp-sensor");
    }

    #[test]
    fn test_default_sensitivity() {
        let sensor = RibosomeDampSensor::new();
        assert!((sensor.sensitivity() - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn test_custom_sensitivity() {
        let sensor = RibosomeDampSensor::with_sensitivity(0.75);
        assert!((sensor.sensitivity() - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn test_sensitivity_clamped() {
        let sensor = RibosomeDampSensor::with_sensitivity(1.5);
        assert!((sensor.sensitivity() - 1.0).abs() < f64::EPSILON);
    }

    // ── Push and detect ────────────────────────────────────────────────────

    #[test]
    fn test_empty_detect() {
        let sensor = RibosomeDampSensor::new();
        let signals = sensor.detect();
        assert!(signals.is_empty());
    }

    #[test]
    fn test_push_and_detect_single() {
        let sensor = RibosomeDampSensor::new();
        sensor.push_signal(make_drift_signal("api-v1", 0.45, vec![]));

        assert_eq!(sensor.pending_count(), 1);

        let signals = sensor.detect();
        assert_eq!(signals.len(), 1);
        assert!(signals[0].pattern.contains("schema_drift:api-v1"));
        assert!(signals[0].pattern.contains("score=0.45"));

        // Pending should be drained
        assert_eq!(sensor.pending_count(), 0);
    }

    #[test]
    fn test_push_multiple_and_detect() {
        let sensor = RibosomeDampSensor::new();
        sensor.push_signals(vec![
            make_drift_signal("api-v1", 0.30, vec![]),
            make_drift_signal("api-v2", 0.60, vec![]),
        ]);

        let signals = sensor.detect();
        assert_eq!(signals.len(), 2);
    }

    // ── Severity mapping ───────────────────────────────────────────────────

    #[test]
    fn test_severity_from_violations() {
        let sensor = RibosomeDampSensor::new();
        let violation = make_violation(
            "status",
            nexcore_ribosome::DriftType::TypeMismatch,
            DriftSeverity::Critical,
        );
        sensor.push_signal(make_drift_signal(
            "critical-contract",
            0.80,
            vec![violation],
        ));

        let signals = sensor.detect();
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].severity, ThreatLevel::High); // Critical → High
    }

    #[test]
    fn test_severity_from_score_high() {
        let sensor = RibosomeDampSensor::new();
        sensor.push_signal(make_drift_signal("high-drift", 0.80, vec![]));

        let signals = sensor.detect();
        assert_eq!(signals[0].severity, ThreatLevel::High);
    }

    #[test]
    fn test_severity_from_score_medium() {
        let sensor = RibosomeDampSensor::new();
        sensor.push_signal(make_drift_signal("med-drift", 0.50, vec![]));

        let signals = sensor.detect();
        assert_eq!(signals[0].severity, ThreatLevel::Medium);
    }

    #[test]
    fn test_severity_from_score_low() {
        let sensor = RibosomeDampSensor::new();
        sensor.push_signal(make_drift_signal("low-drift", 0.10, vec![]));

        let signals = sensor.detect();
        assert_eq!(signals[0].severity, ThreatLevel::Low);
    }

    // ── DAMP source ────────────────────────────────────────────────────────

    #[test]
    fn test_source_is_damp() {
        let sensor = RibosomeDampSensor::new();
        sensor.push_signal(make_drift_signal("test", 0.30, vec![]));

        let signals = sensor.detect();
        assert!(signals[0].source.is_internal());
        assert!(!signals[0].source.is_external());
    }

    // ── Deduplication ──────────────────────────────────────────────────────

    #[test]
    fn test_deduplication() {
        let sensor = RibosomeDampSensor::new();

        // Push same signal twice
        sensor.push_signal(make_drift_signal("api-v1", 0.45, vec![]));
        let first = sensor.detect();
        assert_eq!(first.len(), 1);

        // Push identical signal again
        sensor.push_signal(make_drift_signal("api-v1", 0.45, vec![]));
        let second = sensor.detect();
        assert!(second.is_empty(), "Duplicate should be deduplicated");
    }

    #[test]
    fn test_different_scores_not_deduplicated() {
        let sensor = RibosomeDampSensor::new();

        sensor.push_signal(make_drift_signal("api-v1", 0.45, vec![]));
        let first = sensor.detect();
        assert_eq!(first.len(), 1);

        // Different score → different dedup key
        sensor.push_signal(make_drift_signal("api-v1", 0.60, vec![]));
        let second = sensor.detect();
        assert_eq!(second.len(), 1, "Different score should not be deduped");
    }

    // ── Confidence ─────────────────────────────────────────────────────────

    #[test]
    fn test_confidence_from_drift() {
        let sensor = RibosomeDampSensor::new();
        // drift_score=0.50, confidence = 1.0 - (0.50 * 0.2) = 0.90
        sensor.push_signal(make_drift_signal("test", 0.50, vec![]));

        let signals = sensor.detect();
        assert!((signals[0].confidence.value - 0.90).abs() < f64::EPSILON);
    }

    // ── Metadata ───────────────────────────────────────────────────────────

    #[test]
    fn test_metadata_populated() {
        let sensor = RibosomeDampSensor::new();
        let violation = make_violation(
            "name",
            nexcore_ribosome::DriftType::MissingField,
            DriftSeverity::Warning,
        );
        sensor.push_signal(make_drift_signal("user-api", 0.35, vec![violation]));

        let signals = sensor.detect();
        assert_eq!(
            signals[0].metadata.get("contract_id").map(String::as_str),
            Some("user-api")
        );
        assert_eq!(
            signals[0]
                .metadata
                .get("violation_count")
                .map(String::as_str),
            Some("1")
        );
    }

    // ── Default trait ──────────────────────────────────────────────────────

    #[test]
    fn test_default_creates_sensor() {
        let sensor = RibosomeDampSensor::default();
        assert_eq!(sensor.name(), "ribosome-damp-sensor");
    }

    // ── DriftSeverity mapping coverage ─────────────────────────────────────

    #[test]
    fn test_map_severity_all_variants() {
        assert_eq!(
            RibosomeDampSensor::map_severity(DriftSeverity::Info),
            ThreatLevel::Low
        );
        assert_eq!(
            RibosomeDampSensor::map_severity(DriftSeverity::Warning),
            ThreatLevel::Medium
        );
        assert_eq!(
            RibosomeDampSensor::map_severity(DriftSeverity::Critical),
            ThreatLevel::High
        );
    }
}
