//! # Theory of Vigilance (ToV)
//!
//! Formal axiom system for safety-critical signal detection.
//!
//! ## The 8 Harm Types (§9 ToV v8.0.0)
//!
//! | Type | Name | Conservation Law | Mechanism |
//! |------|------|------------------|-----------|
//! | A | Acute | Law 1 (Mass) | Rapid accumulation |
//! | B | Cumulative | Law 1 (Mass) | Accumulated exposure |
//! | C | Off-Target | Law 2 (Energy) | Favorable off-target binding |
//! | D | Cascade | Law 4 (Flux) | Imbalance propagation |
//! | E | Idiosyncratic | θ-space | Unusual susceptibility |
//! | F | Saturation | Law 8 (Capacity) | Capacity exceeded |
//! | G | Interaction | Law 5 (Catalyst) | Competitive inhibition |
//! | H | Population | θ-distribution | Demographic heterogeneity |
//!
//! ## Safety Manifold
//!
//! Safe states form the interior of a stratified manifold M.
//! Harm = boundary crossing: τ_∂M < ∞ (first-passage time is finite).
//! Safety margin d(s) = signed distance to harm boundary.

use serde::{Deserialize, Serialize};

/// The 8 harm types from ToV §9 (A-H).
///
/// Derived combinatorially from 3 binary attributes (2³ = 8):
/// - Temporal: Immediate vs Delayed
/// - Scope: Local vs Systemic
/// - Mechanism: Conservation violation vs θ-space phenomenon
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HarmType {
    /// Type A: Acute Harm - Immediate, severe harm with clear temporal relationship.
    /// Conservation Law: Law 1 (Mass) - rapid accumulation.
    /// Hierarchy levels: 1-3 primarily.
    Acute,

    /// Type B: Cumulative Harm - Gradual harm from repeated/prolonged exposure.
    /// Conservation Law: Law 1 (Mass) - accumulated exposure over time.
    /// Hierarchy levels: 2-5 primarily.
    Cumulative,

    /// Type C: Off-Target Harm - Unintended effects on non-target components.
    /// Conservation Law: Law 2 (Energy) - favorable off-target interactions.
    /// Hierarchy levels: 1-4 primarily.
    OffTarget,

    /// Type D: Cascade Harm - Propagating failure through interconnected components.
    /// Conservation Law: Law 4 (Flux) - imbalance propagation.
    /// Hierarchy levels: 3-6 primarily.
    Cascade,

    /// Type E: Idiosyncratic Harm - Rare harm in individuals with unusual susceptibility.
    /// Mechanism: θ ∈ Θ_susceptible (parameter-space, not conservation law).
    /// Hierarchy levels: 1-3 primarily.
    Idiosyncratic,

    /// Type F: Saturation Harm - Harm from exceeding processing capacity.
    /// Conservation Law: Law 8 (Capacity/Saturation) - rate-limiting exceeded.
    /// Hierarchy levels: 2-4 primarily.
    Saturation,

    /// Type G: Interaction Harm - Harm from combining multiple perturbations.
    /// Conservation Law: Law 5 (Catalyst) - competitive inhibition.
    /// Hierarchy levels: 2-5 primarily.
    Interaction,

    /// Type H: Population Harm - Disparate impact across subgroups.
    /// Mechanism: θ-distribution heterogeneity (not conservation law).
    /// Hierarchy levels: 6-8 primarily.
    Population,
}

impl HarmType {
    /// Returns the primary conservation law violated (if any).
    ///
    /// Types E and H are θ-space phenomena, not conservation law violations.
    pub fn conservation_law(&self) -> Option<u8> {
        match self {
            Self::Acute => Some(1),       // Law 1: Mass
            Self::Cumulative => Some(1),  // Law 1: Mass (accumulated)
            Self::OffTarget => Some(2),   // Law 2: Energy/Thermodynamic
            Self::Cascade => Some(4),     // Law 4: Flux
            Self::Idiosyncratic => None,  // θ-space phenomenon
            Self::Saturation => Some(8),  // Law 8: Saturation
            Self::Interaction => Some(5), // Law 5: Catalyst
            Self::Population => None,     // θ-distribution phenomenon
        }
    }

    /// Returns the type letter (A-H).
    pub fn letter(&self) -> char {
        match self {
            Self::Acute => 'A',
            Self::Cumulative => 'B',
            Self::OffTarget => 'C',
            Self::Cascade => 'D',
            Self::Idiosyncratic => 'E',
            Self::Saturation => 'F',
            Self::Interaction => 'G',
            Self::Population => 'H',
        }
    }

    /// Returns the primary hierarchy levels affected (ToV §9.1.1).
    ///
    /// Per ToV §9.1.1 Manifestation Level Summary Table:
    /// | Type | Levels | Derivation Basis |
    /// |------|--------|------------------|
    /// | A | 4-6 | High m ⟹ fast propagation |
    /// | B | 5-7 | Accumulation requires time |
    /// | C | 3-5 | Local off-target detection |
    /// | D | 4-7 | Network-dependent |
    /// | E | 3-6 | θ-dependent variance |
    /// | F | 3-5 | Local capacity phenomenon |
    /// | G | 4-6 | Multi-input convergence |
    /// | H | 6-8 | Population-level definition |
    pub fn hierarchy_levels(&self) -> &'static [u8] {
        match self {
            Self::Acute => &[4, 5, 6],            // High m ⟹ fast propagation
            Self::Cumulative => &[5, 6, 7],       // Accumulation requires time
            Self::OffTarget => &[3, 4, 5],        // Local off-target detection
            Self::Cascade => &[4, 5, 6, 7],       // Network-dependent
            Self::Idiosyncratic => &[3, 4, 5, 6], // θ-dependent variance
            Self::Saturation => &[3, 4, 5],       // Local capacity phenomenon
            Self::Interaction => &[4, 5, 6],      // Multi-input convergence
            Self::Population => &[6, 7, 8],       // Population-level definition
        }
    }

    /// Returns all 8 harm types in order.
    pub fn all() -> &'static [HarmType] {
        &[
            Self::Acute,
            Self::Cumulative,
            Self::OffTarget,
            Self::Cascade,
            Self::Idiosyncratic,
            Self::Saturation,
            Self::Interaction,
            Self::Population,
        ]
    }
}

/// Safety margin d(s) calculation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyMargin {
    /// Signed distance to harm boundary
    pub distance: f64,
    /// Interpretation of the distance
    pub interpretation: String,
    /// Recommended action
    pub action: String,
}

impl SafetyMargin {
    /// Calculate safety margin d(s) calculation result based on formal ToV axioms.
    ///
    /// d(s) = min(metrics - thresholds)
    #[must_use]
    pub fn calculate(prr: f64, ror_lower: f64, ic025: f64, eb05: f64, n: u64) -> Self {
        // Formal ToV thresholds
        let prr_t = 2.0;
        let ror_t = 1.0;
        let ic_t = 0.0;
        let eb_t = 2.0;

        // Distance from each threshold (positive = safe, negative = violation)
        // Lower values are safer, so invert: (threshold - value)
        let d_prr = (prr_t - prr) / prr_t;
        let d_ror = (ror_t - ror_lower) / ror_t;
        let d_ic = ic_t - ic025;
        let d_eb = (eb_t - eb05) / eb_t;

        // ToV §9.2: The safety margin is the distance to the nearest boundary
        let distance = d_prr.min(d_ror).min(d_ic).min(d_eb);

        // Epistemic penalty for low sample size
        let epistemic_factor = if n < 3 {
            0.1
        } else if n < 5 {
            0.5
        } else {
            1.0
        };
        let weighted_distance = distance * epistemic_factor;

        let (interpretation, action) = if weighted_distance > 0.5 {
            ("Robustly Safe", "Routine surveillance")
        } else if weighted_distance > 0.0 {
            ("Safe (Low Margin)", "Enhanced monitoring")
        } else if weighted_distance > -0.5 {
            ("Potential Signal", "Signal validation required")
        } else {
            (
                "Confirmed Axiomatic Violation",
                "Immediate regulatory action",
            )
        };

        Self {
            distance: (weighted_distance * 100.0).round() / 100.0,
            interpretation: interpretation.to_string(),
            action: action.to_string(),
        }
    }

    /// Scores the epistemic trust of a result based on ToV hierarchy completeness.
    #[must_use]
    pub fn score_epistemic_trust(levels_covered: &[u8], sources: usize) -> f64 {
        let coverage = levels_covered.len() as f64 / 8.0;
        let source_factor = (sources as f64).ln_1p() / 5.0f64.ln_1p();
        (coverage * 0.7 + source_factor * 0.3).clamp(0.0, 1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_harm_type_letters() {
        assert_eq!(HarmType::Acute.letter(), 'A');
        assert_eq!(HarmType::Cumulative.letter(), 'B');
        assert_eq!(HarmType::OffTarget.letter(), 'C');
        assert_eq!(HarmType::Cascade.letter(), 'D');
        assert_eq!(HarmType::Idiosyncratic.letter(), 'E');
        assert_eq!(HarmType::Saturation.letter(), 'F');
        assert_eq!(HarmType::Interaction.letter(), 'G');
        assert_eq!(HarmType::Population.letter(), 'H');
    }

    #[test]
    fn test_harm_type_conservation_laws() {
        // Types with conservation law violations
        assert_eq!(HarmType::Acute.conservation_law(), Some(1));
        assert_eq!(HarmType::Cumulative.conservation_law(), Some(1));
        assert_eq!(HarmType::OffTarget.conservation_law(), Some(2));
        assert_eq!(HarmType::Cascade.conservation_law(), Some(4));
        assert_eq!(HarmType::Saturation.conservation_law(), Some(8));
        assert_eq!(HarmType::Interaction.conservation_law(), Some(5));

        // Types that are θ-space phenomena (not conservation law violations)
        assert_eq!(HarmType::Idiosyncratic.conservation_law(), None);
        assert_eq!(HarmType::Population.conservation_law(), None);
    }

    #[test]
    fn test_harm_type_all() {
        let all = HarmType::all();
        assert_eq!(all.len(), 8);
        assert_eq!(all[0], HarmType::Acute);
        assert_eq!(all[7], HarmType::Population);
    }

    #[test]
    fn test_safety_margin_safe() {
        // Low signal values = safe
        let margin = SafetyMargin::calculate(1.0, 0.5, -1.0, 1.0, 5);
        assert!(margin.distance > 0.0);
        assert!(margin.interpretation.contains("Safe"));
    }

    #[test]
    fn test_safety_margin_signal() {
        // High signal values = axiomatic violation detected
        let margin = SafetyMargin::calculate(5.0, 2.0, 1.0, 3.0, 10);
        assert!(margin.distance < 0.0);
        assert!(margin.interpretation.contains("Violation"));
    }

    #[test]
    fn test_population_harm_high_hierarchy() {
        // Population harm affects hierarchy levels 6-8
        let levels = HarmType::Population.hierarchy_levels();
        assert!(levels.contains(&6));
        assert!(levels.contains(&7));
        assert!(levels.contains(&8));
        assert!(!levels.contains(&1));
    }

    #[test]
    fn test_hierarchy_levels_per_tov_9_1_1() {
        // Verify levels match ToV §9.1.1 exactly
        assert_eq!(HarmType::Acute.hierarchy_levels(), &[4, 5, 6]);
        assert_eq!(HarmType::Cumulative.hierarchy_levels(), &[5, 6, 7]);
        assert_eq!(HarmType::OffTarget.hierarchy_levels(), &[3, 4, 5]);
        assert_eq!(HarmType::Cascade.hierarchy_levels(), &[4, 5, 6, 7]);
        assert_eq!(HarmType::Idiosyncratic.hierarchy_levels(), &[3, 4, 5, 6]);
        assert_eq!(HarmType::Saturation.hierarchy_levels(), &[3, 4, 5]);
        assert_eq!(HarmType::Interaction.hierarchy_levels(), &[4, 5, 6]);
        assert_eq!(HarmType::Population.hierarchy_levels(), &[6, 7, 8]);
    }
}
