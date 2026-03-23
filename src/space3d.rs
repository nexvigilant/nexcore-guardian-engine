//! # 3D Safety Space Visualization
//!
//! Three-dimensional parametric space for safety visualization, integrating
//! ToV axioms, GVR framework, and PV signal metrics.
//!
//! ## The Three Dimensions
//!
//! | Dimension | Range | Source | Interpretation |
//! |-----------|-------|--------|----------------|
//! | X: Severity | 0.0-1.0 | Harm hierarchy + type | Magnitude if boundary crossed |
//! | Y: Likelihood | 0.0-1.0 | Safety margin d(s) | Probability of boundary crossing |
//! | Z: Detectability | 0.0-1.0 | GVR + signal metrics | How early harm can be detected |
//!
//! ## Risk Priority Number (RPN)
//!
//! `RPN = Severity × Likelihood × (1 - Detectability)`

use crate::tov_types::{HarmType, SafetyMargin};
use crate::{OriginatorType, RiskContext, RiskScore};
use nexcore_primitives::measurement::{Confidence, Measured};
use serde::{Deserialize, Serialize};

// =============================================================================
// Core 3D Space Types
// =============================================================================

/// A point in 3D safety space with coordinates and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyPoint3D {
    pub severity: Measured<f64>,
    pub likelihood: Measured<f64>,
    pub detectability: Measured<f64>,
    pub rpn: Measured<f64>,
    pub zone: RiskZone,
    pub factors: SafetyFactors,
}

/// Factors contributing to each dimension.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SafetyFactors {
    pub severity_factors: Vec<String>,
    pub likelihood_factors: Vec<String>,
    pub detectability_factors: Vec<String>,
}

/// Risk zone in 3D space, derived from RPN thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RiskZone {
    Green,  // RPN < 0.1
    Yellow, // RPN 0.1-0.3
    Orange, // RPN 0.3-0.6
    Red,    // RPN > 0.6
}

impl RiskZone {
    #[must_use]
    pub fn from_rpn(rpn: f64) -> Self {
        match rpn {
            x if x < 0.1 => Self::Green,
            x if x < 0.3 => Self::Yellow,
            x if x < 0.6 => Self::Orange,
            _ => Self::Red,
        }
    }

    #[must_use]
    pub const fn hex_color(&self) -> &'static str {
        match self {
            Self::Green => "#22c55e",
            Self::Yellow => "#eab308",
            Self::Orange => "#f97316",
            Self::Red => "#ef4444",
        }
    }

    #[must_use]
    pub const fn rgb(&self) -> (u8, u8, u8) {
        match self {
            Self::Green => (34, 197, 94),
            Self::Yellow => (234, 179, 8),
            Self::Orange => (249, 115, 22),
            Self::Red => (239, 68, 68),
        }
    }

    #[must_use]
    pub const fn action(&self) -> &'static str {
        match self {
            Self::Green => "Routine surveillance",
            Self::Yellow => "Enhanced monitoring",
            Self::Orange => "Intervention required",
            Self::Red => "Immediate escalation",
        }
    }
}

// =============================================================================
// Dimension Primitive Helpers (σ: scoring primitives)
// =============================================================================

/// σ: Harm type to severity score (0.0-0.2)
#[must_use]
pub fn harm_severity_score(harm: HarmType) -> f64 {
    match harm {
        HarmType::Acute => 0.20,
        HarmType::Cascade => 0.18,
        HarmType::Population => 0.16,
        HarmType::Cumulative => 0.14,
        HarmType::OffTarget => 0.12,
        HarmType::Interaction => 0.10,
        HarmType::Saturation => 0.08,
        HarmType::Idiosyncratic => 0.06,
    }
}

/// σ: Harm type to detectability score (0.0-0.2)
#[must_use]
pub fn harm_detectability_score(harm: HarmType) -> f64 {
    match harm {
        HarmType::Acute => 0.20,
        HarmType::Saturation => 0.18,
        HarmType::OffTarget => 0.15,
        HarmType::Interaction => 0.12,
        HarmType::Cascade => 0.10,
        HarmType::Cumulative => 0.08,
        HarmType::Population => 0.06,
        HarmType::Idiosyncratic => 0.04,
    }
}

/// σ: GVR originator to detectability score (0.0-0.5)
#[must_use]
pub fn gvr_detectability_score(originator: OriginatorType) -> f64 {
    match originator {
        OriginatorType::Tool => 0.1,
        OriginatorType::AgentWithR => 0.2,
        OriginatorType::AgentWithGR => 0.3,
        OriginatorType::AgentWithVR => 0.4,
        OriginatorType::AgentWithGVR => 0.5,
    }
}

/// σ: Sample size to confidence factor (0.3-1.0)
#[must_use]
pub fn sample_confidence(n: u64) -> f64 {
    match n {
        0..=2 => 0.3,
        3..=5 => 0.6,
        6..=10 => 0.8,
        _ => 1.0,
    }
}

// =============================================================================
// Dimension Calculations (ρ: composition primitives)
// =============================================================================

/// ρ: Calculate severity dimension (X-axis).
#[must_use]
pub fn calculate_severity(
    harm_type: Option<HarmType>,
    risk_score: &RiskScore,
    hierarchy_level: u8,
) -> (Measured<f64>, Vec<String>) {
    let mut factors = Vec::new();

    let h_factor = (hierarchy_level as f64 / 8.0) * 0.4;
    factors.push(format!("Hierarchy {}/8 → {:.2}", hierarchy_level, h_factor));

    let r_factor = (risk_score.score.value / 100.0) * 0.4;
    factors.push(format!(
        "Risk {:.0}/100 → {:.2}",
        risk_score.score.value, r_factor
    ));

    let harm_factor = harm_type
        .map(|h| {
            let s = harm_severity_score(h);
            factors.push(format!("Harm {} → {:.2}", h.letter(), s));
            s
        })
        .unwrap_or(0.0);

    let score = (h_factor + r_factor + harm_factor).clamp(0.0, 1.0);
    (Measured::certain(score), factors)
}

/// ρ: Calculate likelihood dimension (Y-axis).
#[must_use]
pub fn calculate_likelihood(
    safety_margin: &SafetyMargin,
    prr: f64,
    ror_lower: f64,
    n: u64,
) -> (Measured<f64>, Vec<String>) {
    let mut factors = Vec::new();
    let mut score = 0.0;

    let m_factor = ((1.0 - safety_margin.distance) / 2.0).clamp(0.0, 0.5);
    score += m_factor;
    factors.push(format!(
        "d(s)={:.2} → {:.2}",
        safety_margin.distance, m_factor
    ));

    if prr >= 2.0 {
        let p = ((prr - 2.0) / 8.0).clamp(0.0, 0.2);
        score += p;
        factors.push(format!("PRR {:.1} → {:.2}", prr, p));
    }

    if ror_lower > 1.0 {
        let r = ((ror_lower - 1.0) / 4.0).clamp(0.0, 0.15);
        score += r;
        factors.push(format!("ROR {:.2} → {:.2}", ror_lower, r));
    }

    let conf = sample_confidence(n);
    factors.push(format!("n={} → conf {:.1}", n, conf));

    let weighted = (score * conf).clamp(0.0, 1.0);
    (Measured::new(weighted, Confidence::new(conf)), factors)
}

/// ρ: Calculate detectability dimension (Z-axis).
#[must_use]
pub fn calculate_detectability(
    originator: OriginatorType,
    harm_type: Option<HarmType>,
    metrics_present: usize,
    total_metrics: usize,
) -> (Measured<f64>, Vec<String>) {
    let mut factors = Vec::new();
    let mut score = 0.0;

    let g = gvr_detectability_score(originator);
    score += g;
    factors.push(format!("GVR {:?} → {:.2}", originator, g));

    if total_metrics > 0 {
        let cov = metrics_present as f64 / total_metrics as f64;
        let c = cov * 0.3;
        score += c;
        factors.push(format!(
            "Metrics {}/{} → {:.2}",
            metrics_present, total_metrics, c
        ));
    }

    if let Some(h) = harm_type {
        let d = harm_detectability_score(h);
        score += d;
        factors.push(format!("Harm {} detect → {:.2}", h.letter(), d));
    }

    (Measured::certain(score.clamp(0.0, 1.0)), factors)
}

// =============================================================================
// Input/Output Types
// =============================================================================

/// Parameters for computing a 3D safety point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetySpace3DInput {
    pub prr: f64,
    pub ror_lower: f64,
    pub ic025: f64,
    pub eb05: f64,
    pub n: u64,
    #[serde(default)]
    pub originator: OriginatorType,
    pub harm_type: Option<HarmType>,
    pub hierarchy_level: u8,
    #[serde(default = "default_metrics")]
    pub signal_metrics_present: usize,
}

fn default_metrics() -> usize {
    4
}

impl Default for SafetySpace3DInput {
    fn default() -> Self {
        Self {
            prr: 1.0,
            ror_lower: 0.5,
            ic025: -0.5,
            eb05: 1.0,
            n: 5,
            originator: OriginatorType::default(),
            harm_type: None,
            hierarchy_level: 4,
            signal_metrics_present: 4,
        }
    }
}

// =============================================================================
// Main API (ρ: composition of primitives)
// =============================================================================

/// Build RiskContext from input (helper).
fn build_risk_context(input: &SafetySpace3DInput) -> RiskContext {
    RiskContext {
        drug: String::new(),
        event: String::new(),
        prr: input.prr,
        ror_lower: input.ror_lower,
        ic025: input.ic025,
        eb05: input.eb05,
        n: input.n,
        originator: input.originator,
    }
}

/// Compute RPN from three dimensions.
fn compute_rpn(s: &Measured<f64>, l: &Measured<f64>, d: &Measured<f64>) -> Measured<f64> {
    let val = s.value * l.value * (1.0 - d.value);
    // Take minimum confidence using total ordering (Codex V compliant)
    let conf = [s.confidence, l.confidence, d.confidence]
        .into_iter()
        .min_by(|a, b| a.cmp_total(*b))
        .unwrap_or(Confidence::UNCERTAIN);
    Measured::new(val, conf)
}

/// Compute a 3D safety point from input parameters.
#[must_use]
pub fn compute_safety_point(input: &SafetySpace3DInput) -> SafetyPoint3D {
    let risk_score = crate::calculate_risk_score(&build_risk_context(input));
    let safety_margin =
        SafetyMargin::calculate(input.prr, input.ror_lower, input.ic025, input.eb05, input.n);

    let (severity, sf) = calculate_severity(input.harm_type, &risk_score, input.hierarchy_level);
    let (likelihood, lf) =
        calculate_likelihood(&safety_margin, input.prr, input.ror_lower, input.n);
    let (detectability, df) = calculate_detectability(
        input.originator,
        input.harm_type,
        input.signal_metrics_present,
        4,
    );

    let rpn = compute_rpn(&severity, &likelihood, &detectability);

    SafetyPoint3D {
        severity,
        likelihood,
        detectability,
        rpn,
        zone: RiskZone::from_rpn(rpn.value),
        factors: SafetyFactors {
            severity_factors: sf,
            likelihood_factors: lf,
            detectability_factors: df,
        },
    }
}

/// Batch compute multiple safety points.
#[must_use]
pub fn compute_safety_space(inputs: &[SafetySpace3DInput]) -> Vec<SafetyPoint3D> {
    inputs.iter().map(compute_safety_point).collect()
}

/// Generate grid for surface visualization.
#[must_use]
pub fn generate_surface_grid(detectability: f64, res: usize) -> Vec<(f64, f64, f64, RiskZone)> {
    (0..res)
        .flat_map(|i| {
            (0..res).map(move |j| {
                let s = i as f64 / (res - 1) as f64;
                let l = j as f64 / (res - 1) as f64;
                let rpn = s * l * (1.0 - detectability);
                (s, l, detectability, RiskZone::from_rpn(rpn))
            })
        })
        .collect()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_low_risk() {
        let input = SafetySpace3DInput {
            prr: 1.0,
            ror_lower: 0.5,
            ic025: -1.0,
            eb05: 0.5,
            n: 10,
            ..Default::default()
        };
        let pt = compute_safety_point(&input);
        assert!(pt.severity.value < 0.5);
        assert_eq!(pt.zone, RiskZone::Green);
    }

    #[test]
    fn test_high_risk() {
        let input = SafetySpace3DInput {
            prr: 5.0,
            ror_lower: 2.5,
            ic025: 1.5,
            eb05: 4.0,
            n: 20,
            harm_type: Some(HarmType::Acute),
            hierarchy_level: 7,
            ..Default::default()
        };
        let pt = compute_safety_point(&input);
        assert!(pt.severity.value > 0.5);
        assert!(matches!(pt.zone, RiskZone::Orange | RiskZone::Red));
    }

    #[test]
    fn test_gvr_detectability() {
        let tool = compute_safety_point(&SafetySpace3DInput {
            originator: OriginatorType::Tool,
            ..Default::default()
        });
        let gvr = compute_safety_point(&SafetySpace3DInput {
            originator: OriginatorType::AgentWithGVR,
            ..Default::default()
        });
        assert!(gvr.detectability.value > tool.detectability.value);
    }

    #[test]
    fn test_zone_colors() {
        assert_eq!(RiskZone::Green.hex_color(), "#22c55e");
        assert_eq!(RiskZone::Red.rgb(), (239, 68, 68));
    }

    #[test]
    fn test_surface_grid() {
        let grid = generate_surface_grid(0.5, 5);
        assert_eq!(grid.len(), 25);
    }
}
