//! # Spatial Bridge: nexcore-guardian-engine → stem-math
//!
//! Formalizes the Guardian immune system as a spatial structure:
//! - `SeverityMetric` measures distance between severity levels
//! - `RiskScoreMetric` measures distance between risk scores
//! - `signal_source_orientation` maps PAMP/DAMP to spatial orientation
//! - Severity bands expressed as `Neighborhood` containment
//!
//! ## Primitive Foundation
//!
//! The Guardian control loop is inherently spatial:
//! - Severity is an ordered distance from "no threat" (Info=0) to "emergency" (Critical=100)
//! - PAMPs push inward (Positive orientation), DAMPs radiate outward (Negative)
//! - Risk thresholds are neighborhoods: a score "inside" the threshold = safe
//! - The homeostasis loop seeks to keep system state within the safe neighborhood
//!
//! ## Architecture Decision
//!
//! `SeverityMetric` wraps the existing `ThreatLevel::score()` method as a formal `Metric`.
//! `signal_source_orientation` classifies threat directionality.
//! Severity bands become nested `Neighborhood` regions.

use nexcore_lex_primitiva::grounding::GroundsTo;
use nexcore_lex_primitiva::primitiva::{LexPrimitiva, PrimitiveComposition};
use stem_math::spatial::{Distance, Metric, Neighborhood, Orientation};

use crate::sensing::{SignalSource, ThreatLevel};

// ============================================================================
// SeverityMetric: Distance between severity levels
// ============================================================================

/// Metric over `Severity` levels.
///
/// Distance = |score(a) - score(b)| where scores are 0, 25, 50, 75, 100.
/// This is a valid metric on the ordered set {Info, Low, Medium, High, Critical}.
///
/// Use case: Measuring how much a signal escalated — going from Low→Critical
/// is distance 75, while Low→Medium is distance 25.
///
/// Tier: T2-P (κ Comparison + N Quantity)
pub struct SeverityMetric;

impl Metric for SeverityMetric {
    type Element = ThreatLevel;

    fn distance(&self, a: &ThreatLevel, b: &ThreatLevel) -> Distance {
        let sa = f64::from(a.score());
        let sb = f64::from(b.score());
        Distance::new((sa - sb).abs())
    }
}

/// GroundsTo: T2-P (κ Comparison + N Quantity), dominant κ
///
/// A severity metric IS a comparison — it measures distance between two
/// severity levels. Comparison-dominant: the metric's purpose is to quantify
/// how much severity has changed (escalation/de-escalation).
impl GroundsTo for SeverityMetric {
    fn primitive_composition() -> PrimitiveComposition {
        PrimitiveComposition::new(vec![
            LexPrimitiva::Comparison, // κ — metric IS a comparison
            LexPrimitiva::Quantity,   // N — produces numeric distance (0-100)
        ])
        .with_dominant(LexPrimitiva::Comparison, 0.90)
    }
}

// ============================================================================
// RiskScoreMetric: Distance between risk scores
// ============================================================================

/// Metric over risk score values (0-100).
///
/// Distance = |score_a - score_b|. Measures how far apart two risk
/// assessments are on the 0-100 scale.
///
/// Use case: Comparing consecutive risk evaluations to detect risk drift.
///
/// Tier: T2-P (N Quantity + κ Comparison)
pub struct RiskScoreMetric;

impl RiskScoreMetric {
    /// Compute distance between two raw risk score values.
    pub fn score_distance(a: f64, b: f64) -> Distance {
        Distance::new((a - b).abs())
    }
}

/// GroundsTo: T2-P (κ Comparison + N Quantity), dominant κ
///
/// Risk score metric compares two risk assessments on the 0-100 scale.
/// Comparison-dominant: the purpose is to detect risk drift between evaluations.
impl GroundsTo for RiskScoreMetric {
    fn primitive_composition() -> PrimitiveComposition {
        PrimitiveComposition::new(vec![
            LexPrimitiva::Comparison, // κ — metric IS a comparison
            LexPrimitiva::Quantity,   // N — produces numeric distance (0-100)
        ])
        .with_dominant(LexPrimitiva::Comparison, 0.90)
    }
}

// ============================================================================
// SignalSource → Orientation mapping
// ============================================================================

/// Map a Guardian signal source to spatial orientation.
///
/// - **PAMP** (external threat) → `Positive` (threat pushing inward toward the system)
/// - **DAMP** (internal damage) → `Negative` (damage radiating outward from within)
/// - **Hybrid** (both) → `Unoriented` (bidirectional threat)
///
/// This models the biological immune system's directional threat model:
/// PAMPs are foreign pathogens entering the body (inward direction),
/// DAMPs are damage signals from within (outward distress signal).
///
/// Tier: T2-P (→ Causality — directional threat classification)
pub fn signal_source_orientation(source: &SignalSource) -> Orientation {
    match source {
        SignalSource::Pamp { .. } => Orientation::Positive,
        SignalSource::Damp { .. } => Orientation::Negative,
        SignalSource::Hybrid { .. } => Orientation::Unoriented,
    }
}

// ============================================================================
// Severity band Neighborhoods
// ============================================================================

/// Neighborhood for the "safe" severity region (Info + Low ≤ 25).
///
/// A signal is in the safe neighborhood when its severity score is ≤ 25.
/// This corresponds to Info (0) and Low (25) severity levels.
pub fn safe_neighborhood() -> Neighborhood {
    Neighborhood::closed(Distance::new(25.0))
}

/// Neighborhood for the "concern" region (severity ≤ 50).
///
/// A signal is in the concern neighborhood when severity ≤ 50.
/// This covers Info, Low, and Medium severity levels.
pub fn concern_neighborhood() -> Neighborhood {
    Neighborhood::closed(Distance::new(50.0))
}

/// Neighborhood for the "action required" region (severity ≤ 75).
///
/// Signals beyond this neighborhood (High and Critical) require immediate response.
pub fn action_neighborhood() -> Neighborhood {
    Neighborhood::closed(Distance::new(75.0))
}

/// Check if a severity is within the safe band.
///
/// Safe = severity score ≤ 25 (Info or Low).
pub fn severity_is_safe(severity: &ThreatLevel) -> bool {
    safe_neighborhood().contains(Distance::new(f64::from(severity.score())))
}

/// Check if a severity requires immediate action.
///
/// Action required = severity score > 50 (High or Critical).
pub fn severity_requires_action(severity: &ThreatLevel) -> bool {
    !concern_neighborhood().contains(Distance::new(f64::from(severity.score())))
}

// ============================================================================
// Risk threshold as Neighborhood
// ============================================================================

/// Express a risk threshold as a Neighborhood.
///
/// The default Guardian threshold is 50.0. Scores within this neighborhood
/// are below the response threshold; scores outside trigger response actions.
///
/// This wraps `DecisionEngine::risk_threshold` as a formal spatial concept.
pub fn risk_threshold_neighborhood(threshold: f64) -> Neighborhood {
    Neighborhood::closed(Distance::new(threshold))
}

/// Check if a risk score exceeds the given threshold.
///
/// Equivalent to: score NOT in risk_threshold_neighborhood.
pub fn risk_exceeds_threshold(score: f64, threshold: f64) -> bool {
    score > threshold
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ===== SeverityMetric axiom tests =====

    #[test]
    fn severity_metric_identity() {
        let m = SeverityMetric;
        assert!(
            m.distance(&ThreatLevel::High, &ThreatLevel::High)
                .approx_eq(&Distance::ZERO, 1e-10)
        );
    }

    #[test]
    fn severity_metric_symmetry() {
        let m = SeverityMetric;
        assert!(m.is_symmetric(&ThreatLevel::Low, &ThreatLevel::Critical, 1e-10));
    }

    #[test]
    fn severity_metric_triangle() {
        let m = SeverityMetric;
        let d_ab = m.distance(&ThreatLevel::Info, &ThreatLevel::Medium);
        let d_bc = m.distance(&ThreatLevel::Medium, &ThreatLevel::Critical);
        let d_ac = m.distance(&ThreatLevel::Info, &ThreatLevel::Critical);
        assert!(Distance::triangle_valid(d_ab, d_bc, d_ac));
    }

    #[test]
    fn severity_metric_values() {
        let m = SeverityMetric;
        // Info(0) to Critical(100) = 100
        assert!(
            m.distance(&ThreatLevel::Info, &ThreatLevel::Critical)
                .approx_eq(&Distance::new(100.0), 1e-10)
        );
        // Low(25) to High(75) = 50
        assert!(
            m.distance(&ThreatLevel::Low, &ThreatLevel::High)
                .approx_eq(&Distance::new(50.0), 1e-10)
        );
        // Adjacent levels = 25
        assert!(
            m.distance(&ThreatLevel::Low, &ThreatLevel::Medium)
                .approx_eq(&Distance::new(25.0), 1e-10)
        );
    }

    // ===== RiskScoreMetric =====

    #[test]
    fn risk_score_distance_symmetric() {
        let d1 = RiskScoreMetric::score_distance(30.0, 70.0);
        let d2 = RiskScoreMetric::score_distance(70.0, 30.0);
        assert!(d1.approx_eq(&d2, 1e-10));
    }

    #[test]
    fn risk_score_distance_identity() {
        let d = RiskScoreMetric::score_distance(50.0, 50.0);
        assert!(d.approx_eq(&Distance::ZERO, 1e-10));
    }

    // ===== SignalSource → Orientation =====

    #[test]
    fn pamp_is_positive() {
        let source = SignalSource::Pamp {
            source_id: "attacker".to_string(),
            vector: "sql-injection".to_string(),
        };
        assert_eq!(signal_source_orientation(&source), Orientation::Positive);
    }

    #[test]
    fn damp_is_negative() {
        let source = SignalSource::Damp {
            subsystem: "memory".to_string(),
            damage_type: "exhaustion".to_string(),
        };
        assert_eq!(signal_source_orientation(&source), Orientation::Negative);
    }

    #[test]
    fn hybrid_is_unoriented() {
        let source = SignalSource::Hybrid {
            external: "api".to_string(),
            internal: "cache".to_string(),
        };
        assert_eq!(signal_source_orientation(&source), Orientation::Unoriented);
    }

    // ===== Severity band Neighborhoods =====

    #[test]
    fn info_is_safe() {
        assert!(severity_is_safe(&ThreatLevel::Info));
    }

    #[test]
    fn low_is_safe() {
        assert!(severity_is_safe(&ThreatLevel::Low));
    }

    #[test]
    fn medium_is_not_safe() {
        assert!(!severity_is_safe(&ThreatLevel::Medium));
    }

    #[test]
    fn high_requires_action() {
        assert!(severity_requires_action(&ThreatLevel::High));
    }

    #[test]
    fn critical_requires_action() {
        assert!(severity_requires_action(&ThreatLevel::Critical));
    }

    #[test]
    fn medium_does_not_require_action() {
        assert!(!severity_requires_action(&ThreatLevel::Medium));
    }

    // ===== Risk threshold =====

    #[test]
    fn risk_within_threshold() {
        assert!(!risk_exceeds_threshold(40.0, 50.0));
    }

    #[test]
    fn risk_exceeds() {
        assert!(risk_exceeds_threshold(60.0, 50.0));
    }

    #[test]
    fn risk_at_threshold() {
        // At exactly the threshold, does not exceed
        assert!(!risk_exceeds_threshold(50.0, 50.0));
    }

    #[test]
    fn risk_neighborhood_containment() {
        let n = risk_threshold_neighborhood(50.0);
        assert!(n.contains(Distance::new(40.0))); // 40 ≤ 50
        assert!(n.contains(Distance::new(50.0))); // boundary, closed
        assert!(!n.contains(Distance::new(60.0))); // 60 > 50
    }
}
