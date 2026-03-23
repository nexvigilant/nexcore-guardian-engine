//! Sensor confidence derivation.
//!
//! Replaces hardcoded `Measured::certain(0.x)` with typed derivation
//! that documents WHY a confidence value was chosen.
//!
//! # Usage
//!
//! ```rust,ignore
//! // BEFORE — opaque magic number:
//! .with_confidence(Measured::certain(0.85))
//!
//! // AFTER — self-documenting derivation:
//! .with_confidence(ConfidenceSource::Calibrated {
//!     value: 0.85,
//!     rationale: "code health: clippy warning count severity",
//! }.derive())
//! ```

use nexcore_primitives::measurement::Measured;

/// Source of a sensor's confidence value.
///
/// Every `Measured::certain(literal)` in sensor code should be replaced
/// with a derivation source. Each variant documents the calibration
/// basis for the confidence value it produces.
#[derive(Debug, Clone)]
pub enum ConfidenceSource {
    /// Confidence scales with observation count.
    ///
    /// CALIBRATION: 0–2 → 0.3 (low), 3–5 → 0.6, 6–10 → 0.8, 11+ → 1.0.
    /// Matches `space3d::sample_confidence`.
    SampleSize(u64),

    /// Confidence derived from observable signal strength × sensitivity.
    ///
    /// CALIBRATION: `(signal * sensitivity).clamp(0.0, 1.0)`.
    /// Use when the sensor has a measurable signal-to-noise ratio
    /// (e.g., error rate × detection sensitivity).
    SignalStrength {
        /// Raw signal magnitude (e.g., failure rate, match score).
        signal: f64,
        /// Sensor sensitivity factor (typically 1.0 unless tuned).
        sensitivity: f64,
    },

    /// Confidence forwarded from an upstream analysis engine.
    ///
    /// Use when an analysis (adversarial detector, fingerprint matcher,
    /// drift analyzer) already computed a confidence value.
    Analysis(f64),

    /// Deterministic algorithmic match (CVE lookup, exact pattern).
    ///
    /// CALIBRATION: Returns 0.99 — near-certain, with 1% reserved
    /// for data-quality uncertainty.
    Deterministic,

    /// Sensor-type calibrated constant with documented rationale.
    ///
    /// Use when the sensor type inherently determines confidence
    /// and no per-signal observable data refines it. The rationale
    /// string prevents opaque magic numbers.
    Calibrated {
        /// The confidence value in [0.0, 1.0].
        value: f64,
        /// Why this value was chosen (e.g., "hook telemetry: binary pass/fail").
        rationale: &'static str,
    },
}

impl ConfidenceSource {
    /// Derive the confidence `Measured<f64>` from this source.
    ///
    /// The returned value is suitable for `ThreatSignal::with_confidence()`.
    // CALIBRATION: each variant's doc string states its derivation basis.
    #[must_use]
    pub fn derive(&self) -> Measured<f64> {
        let value = match self {
            Self::SampleSize(n) => match n {
                0..=2 => 0.3,
                3..=5 => 0.6,
                6..=10 => 0.8,
                _ => 1.0,
            },
            Self::SignalStrength {
                signal,
                sensitivity,
            } => (signal * sensitivity).clamp(0.0, 1.0),
            Self::Analysis(c) => c.clamp(0.0, 1.0),
            Self::Deterministic => 0.99,
            Self::Calibrated { value, .. } => value.clamp(0.0, 1.0),
        };
        Measured::certain(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_size_scales_with_observations() {
        assert!((ConfidenceSource::SampleSize(1).derive().value - 0.3).abs() < f64::EPSILON);
        assert!((ConfidenceSource::SampleSize(4).derive().value - 0.6).abs() < f64::EPSILON);
        assert!((ConfidenceSource::SampleSize(8).derive().value - 0.8).abs() < f64::EPSILON);
        assert!((ConfidenceSource::SampleSize(50).derive().value - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn signal_strength_clamps_to_unit() {
        let s = ConfidenceSource::SignalStrength {
            signal: 0.6,
            sensitivity: 1.0,
        };
        assert!((s.derive().value - 0.6).abs() < f64::EPSILON);

        // Overdriven signal clamps to 1.0
        let loud = ConfidenceSource::SignalStrength {
            signal: 2.0,
            sensitivity: 1.0,
        };
        assert!((loud.derive().value - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn analysis_passthrough_clamps() {
        assert!((ConfidenceSource::Analysis(0.87).derive().value - 0.87).abs() < f64::EPSILON);
        assert!((ConfidenceSource::Analysis(1.5).derive().value - 1.0).abs() < f64::EPSILON);
        assert!((ConfidenceSource::Analysis(-0.1).derive().value - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn deterministic_is_near_certain() {
        assert!((ConfidenceSource::Deterministic.derive().value - 0.99).abs() < f64::EPSILON);
    }

    #[test]
    fn calibrated_requires_rationale() {
        let c = ConfidenceSource::Calibrated {
            value: 0.85,
            rationale: "code health: clippy warning severity",
        };
        assert!((c.derive().value - 0.85).abs() < f64::EPSILON);
        // Rationale is preserved for debugging
        if let ConfidenceSource::Calibrated { rationale, .. } = &c {
            assert!(!rationale.is_empty());
        }
    }
}
