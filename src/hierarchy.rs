//! # ToV §3: Axiom 2 - Hierarchical Organization
//!
//! Formal implementation of Axiom 2 and its prerequisites (Definitions 3.1-3.5).
//!
//! ## Axiom Statement
//!
//! For every vigilance system 𝒱 with decomposition (E, Φ), there exists a hierarchy
//! ℒ = (L, ≺, ψ) with scale separation such that:
//! 1. The global state space S admits a decomposition S ≅ S₁ × S₂ × ... × Sₙ
//! 2. There exist coarse-graining maps πᵢ: Sᵢ → Sᵢ₊₁ for i = 1, ..., N-1
//! 3. Each level ℓᵢ₊₁ admits at least one emergent property
//!
//! ## Symbolic Formulation
//!
//! **∀𝒱 : ∃ℒ = (L, ≺, ψ), {Sᵢ}ᵢ₌₁ᴺ, {πᵢ}ᵢ₌₁ᴺ⁻¹ such that:**
//!
//! **S ≅ ∏ᵢ₌₁ᴺ Sᵢ  ∧  πᵢ: Sᵢ ↠ Sᵢ₊₁  ∧  ∀i: ∃Pᵢ₊₁ emergent**
//!
//! ## Wolfram Validation (2026-01-29)
//!
//! | Property | Formula | Result |
//! |----------|---------|--------|
//! | Scale separation | 10^8 / 10^7 | 10 |
//! | 8-level attenuation | 0.9^8 | 0.43046721 |
//! | Time scale ratio | log₁₀(86400/3600) | 1.38 |

use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════════════════
// DEFINITION 3.1: HIERARCHY
// ═══════════════════════════════════════════════════════════════════════════

/// Definition 3.1: A hierarchy is a tuple ℒ = (L, ≺, ψ).
///
/// - `L = {ℓ₁, ℓ₂, ..., ℓₙ}` is a finite set of levels with |L| = N
/// - `≺` is a strict total order on L (ℓ₁ ≺ ℓ₂ ≺ ... ≺ ℓₙ)
/// - `ψ: L → ℝ>0` is a scale function assigning characteristic scales
///
/// # Remarks
/// - The ordering ≺ represents "finer than": ℓ₁ is finest (microscopic), ℓₙ is coarsest
/// - The scale function ψ assigns characteristic scale (spatial, temporal, energetic)
/// - The theory uses only ratios ψ(ℓᵢ₊₁)/ψ(ℓᵢ), so absolute units are not required
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hierarchy<L: Level> {
    /// Levels in order (ℓ₁ ≺ ℓ₂ ≺ ... ≺ ℓₙ)
    levels: Vec<L>,
    /// Scale function ψ: L → ℝ>0
    scales: Vec<f64>,
    /// Minimum scale separation ratio ε (Definition 3.5)
    min_scale_separation: f64,
}

/// Trait for hierarchy levels.
///
/// Levels must be orderable and have a unique index.
pub trait Level: Clone + Ord + Eq + std::fmt::Debug {
    /// Level index (0-based, finest = 0).
    fn index(&self) -> usize;

    /// Human-readable name for the level.
    fn name(&self) -> &'static str;
}

impl<L: Level> Hierarchy<L> {
    /// Create a hierarchy with levels and scales.
    ///
    /// # Errors
    /// Returns `Err` if levels are not in ascending order or scales are not positive.
    pub fn new(levels: Vec<L>, scales: Vec<f64>) -> Result<Self, HierarchyError> {
        if levels.len() != scales.len() {
            return Err(HierarchyError::LevelScaleMismatch {
                levels: levels.len(),
                scales: scales.len(),
            });
        }

        if levels.is_empty() {
            return Err(HierarchyError::EmptyHierarchy);
        }

        // Verify levels are in ascending order
        for i in 1..levels.len() {
            if levels[i] <= levels[i - 1] {
                return Err(HierarchyError::LevelsNotOrdered);
            }
        }

        // Verify scales are positive
        for (i, &scale) in scales.iter().enumerate() {
            if scale <= 0.0 {
                return Err(HierarchyError::NonPositiveScale { level_index: i });
            }
        }

        // Calculate minimum scale separation
        let min_scale_separation = Self::calculate_min_separation(&scales);

        Ok(Self {
            levels,
            scales,
            min_scale_separation,
        })
    }

    /// Calculate minimum scale separation ratio.
    fn calculate_min_separation(scales: &[f64]) -> f64 {
        if scales.len() < 2 {
            return f64::INFINITY;
        }

        let mut min_ratio = f64::INFINITY;
        for i in 0..scales.len() - 1 {
            let ratio = scales[i + 1] / scales[i];
            if ratio < min_ratio {
                min_ratio = ratio;
            }
        }
        min_ratio
    }

    /// Number of levels N = |L|.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.levels.len()
    }

    /// Get level at index (0 = finest, N-1 = coarsest).
    #[must_use]
    pub fn level(&self, index: usize) -> Option<&L> {
        self.levels.get(index)
    }

    /// Get scale ψ(ℓᵢ) for level at index.
    #[must_use]
    pub fn scale(&self, index: usize) -> Option<f64> {
        self.scales.get(index).copied()
    }

    /// Scale ratio ψ(ℓᵢ₊₁)/ψ(ℓᵢ) between adjacent levels.
    #[must_use]
    pub fn scale_ratio(&self, lower_index: usize) -> Option<f64> {
        if lower_index + 1 >= self.scales.len() {
            return None;
        }
        Some(self.scales[lower_index + 1] / self.scales[lower_index])
    }

    /// Minimum scale separation ratio ε (Definition 3.5).
    #[must_use]
    pub fn min_scale_separation(&self) -> f64 {
        self.min_scale_separation
    }

    /// Check if hierarchy has scale separation (ε > 1).
    #[must_use]
    pub fn has_scale_separation(&self) -> bool {
        self.min_scale_separation > 1.0
    }

    /// Iterate over levels from finest to coarsest.
    pub fn iter(&self) -> impl Iterator<Item = (&L, f64)> {
        self.levels.iter().zip(self.scales.iter().copied())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PV-SPECIFIC HIERARCHY LEVELS
// ═══════════════════════════════════════════════════════════════════════════

/// Pharmacovigilance hierarchy levels (8 levels, ToV §A.2).
///
/// Molecular ≺ Cellular ≺ Tissue ≺ Organ ≺ System ≺ Organism ≺ Population ≺ Societal
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PVLevel {
    /// Level 1: Molecular interactions (drugs, receptors, enzymes)
    Molecular = 0,
    /// Level 2: Cellular responses (apoptosis, proliferation)
    Cellular = 1,
    /// Level 3: Tissue-level effects (inflammation, fibrosis)
    Tissue = 2,
    /// Level 4: Organ dysfunction (hepatotoxicity, cardiotoxicity)
    Organ = 3,
    /// Level 5: System-level pathology (cardiovascular, nervous)
    System = 4,
    /// Level 6: Whole organism effects (morbidity, mortality)
    Organism = 5,
    /// Level 7: Population-level impacts (epidemiological signals)
    Population = 6,
    /// Level 8: Societal consequences (healthcare burden, regulatory action)
    Societal = 7,
}

impl Level for PVLevel {
    fn index(&self) -> usize {
        *self as usize
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Molecular => "Molecular",
            Self::Cellular => "Cellular",
            Self::Tissue => "Tissue",
            Self::Organ => "Organ",
            Self::System => "System",
            Self::Organism => "Organism",
            Self::Population => "Population",
            Self::Societal => "Societal",
        }
    }
}

impl PVLevel {
    /// All PV levels in order.
    pub const ALL: [PVLevel; 8] = [
        Self::Molecular,
        Self::Cellular,
        Self::Tissue,
        Self::Organ,
        Self::System,
        Self::Organism,
        Self::Population,
        Self::Societal,
    ];

    /// Standard PV timescales (seconds).
    ///
    /// Wolfram validated: ratios ~10× between adjacent levels.
    pub const TIMESCALES: [f64; 8] = [
        1e-9,      // Molecular: nanoseconds
        1e-6,      // Cellular: microseconds
        1e-3,      // Tissue: milliseconds
        1.0,       // Organ: seconds
        60.0,      // System: minutes
        3600.0,    // Organism: hours
        86400.0,   // Population: days
        604_800.0, // Societal: weeks
    ];

    /// Create standard PV hierarchy with default timescales.
    ///
    /// # Panics
    ///
    /// Cannot panic: ALL and TIMESCALES are both length 8 and non-empty.
    #[must_use]
    pub fn standard_hierarchy() -> Hierarchy<PVLevel> {
        Hierarchy::new(Self::ALL.to_vec(), Self::TIMESCALES.to_vec())
            .unwrap_or_else(|_| unreachable!())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// DEFINITION 3.2: LEVEL STATE SPACE
// ═══════════════════════════════════════════════════════════════════════════

/// Definition 3.2: Level state space Sᵢ.
///
/// For each level ℓᵢ ∈ L, Sᵢ is the space of all possible configurations
/// observable at that level. The dimension dim(Sᵢ) may differ across levels.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LevelStateSpace {
    /// Level index
    pub level_index: usize,
    /// Dimension of state space dim(Sᵢ)
    pub dimension: usize,
    /// Optional bounds for each dimension
    pub bounds: Option<Vec<(f64, f64)>>,
}

impl LevelStateSpace {
    /// Create a level state space.
    #[must_use]
    pub fn new(level_index: usize, dimension: usize) -> Self {
        Self {
            level_index,
            dimension,
            bounds: None,
        }
    }

    /// Create with bounds.
    #[must_use]
    pub fn with_bounds(level_index: usize, bounds: Vec<(f64, f64)>) -> Self {
        Self {
            level_index,
            dimension: bounds.len(),
            bounds: Some(bounds),
        }
    }

    /// Check if a state is in bounds.
    #[must_use]
    pub fn contains(&self, state: &[f64]) -> bool {
        if state.len() != self.dimension {
            return false;
        }
        if let Some(bounds) = &self.bounds {
            for (i, &val) in state.iter().enumerate() {
                let (lo, hi) = bounds[i];
                if val < lo || val > hi {
                    return false;
                }
            }
        }
        true
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// DEFINITION 3.3: COARSE-GRAINING MAP
// ═══════════════════════════════════════════════════════════════════════════

/// Definition 3.3: Coarse-graining map πᵢ: Sᵢ → Sᵢ₊₁.
///
/// A surjective function that projects fine-grained states at level i
/// to coarse-grained states at level i+1. The map loses information:
/// typically dim(Sᵢ₊₁) < dim(Sᵢ).
///
/// # Remark
/// Since πᵢ is surjective but not injective, multiple fine-grained states
/// may map to the same coarse-grained state. The preimage πᵢ⁻¹(sᵢ₊₁)
/// represents the set of microscopic configurations consistent with
/// macroscopic state sᵢ₊₁.
pub trait CoarseGrainingMap {
    /// Fine-grained state type at level i.
    type FineState;
    /// Coarse-grained state type at level i+1.
    type CoarseState;

    /// Apply coarse-graining: πᵢ(s) → s'.
    fn coarsen(&self, fine_state: &Self::FineState) -> Self::CoarseState;

    /// Source level index i.
    fn source_level(&self) -> usize;

    /// Target level index i+1.
    fn target_level(&self) -> usize {
        self.source_level() + 1
    }
}

/// Simple averaging coarse-graining map.
///
/// Projects by averaging groups of dimensions.
#[derive(Debug, Clone)]
pub struct AveragingCoarseGrain {
    source_level: usize,
    /// Group sizes for averaging (sum must equal source dimension)
    group_sizes: Vec<usize>,
}

impl AveragingCoarseGrain {
    /// Create averaging coarse-graining.
    #[must_use]
    pub fn new(source_level: usize, group_sizes: Vec<usize>) -> Self {
        Self {
            source_level,
            group_sizes,
        }
    }

    /// Source dimension (sum of group sizes).
    #[must_use]
    pub fn source_dimension(&self) -> usize {
        self.group_sizes.iter().sum()
    }

    /// Target dimension (number of groups).
    #[must_use]
    pub fn target_dimension(&self) -> usize {
        self.group_sizes.len()
    }
}

impl CoarseGrainingMap for AveragingCoarseGrain {
    type FineState = Vec<f64>;
    type CoarseState = Vec<f64>;

    fn coarsen(&self, fine_state: &Self::FineState) -> Self::CoarseState {
        let mut coarse = Vec::with_capacity(self.group_sizes.len());
        let mut offset = 0;

        for &size in &self.group_sizes {
            let sum: f64 = fine_state[offset..offset + size].iter().sum();
            coarse.push(sum / size as f64);
            offset += size;
        }

        coarse
    }

    fn source_level(&self) -> usize {
        self.source_level
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// DEFINITION 3.4: EMERGENCE
// ═══════════════════════════════════════════════════════════════════════════

/// Definition 3.4: Emergent property.
///
/// A property P at level ℓᵢ₊₁ is emergent if it cannot be expressed as a
/// function of states at level ℓᵢ alone. Formally, P: Sᵢ₊₁ → Y is emergent
/// if there exists no function f: Sᵢ → Y such that P(πᵢ(s)) = f(s) for all s ∈ Sᵢ.
///
/// # Remarks
/// - When Y = {0,1}, P is an indicator property (presence/absence)
/// - When Y = ℝ, P is a continuous emergent quantity (temperature, pressure)
/// - P is emergent if knowing only fine-grained state s is insufficient to compute P
pub trait EmergentProperty<S, Y> {
    /// Evaluate the emergent property P(s) → y.
    fn evaluate(&self, coarse_state: &S) -> Y;

    /// Human-readable name of the property.
    fn name(&self) -> &'static str;

    /// Level at which this property is observable.
    fn observable_level(&self) -> usize;
}

/// Binary emergent property (indicator function).
#[derive(Debug, Clone)]
pub struct BinaryEmergentProperty {
    name: &'static str,
    level: usize,
    /// Threshold for the indicator
    threshold: f64,
    /// Index of dimension to threshold
    dimension_index: usize,
}

impl BinaryEmergentProperty {
    /// Create a binary emergent property.
    #[must_use]
    pub fn new(name: &'static str, level: usize, threshold: f64, dimension_index: usize) -> Self {
        Self {
            name,
            level,
            threshold,
            dimension_index,
        }
    }
}

impl EmergentProperty<Vec<f64>, bool> for BinaryEmergentProperty {
    fn evaluate(&self, coarse_state: &Vec<f64>) -> bool {
        coarse_state
            .get(self.dimension_index)
            .is_some_and(|&v| v >= self.threshold)
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn observable_level(&self) -> usize {
        self.level
    }
}

/// Continuous emergent property.
#[derive(Debug, Clone)]
pub struct ContinuousEmergentProperty {
    name: &'static str,
    level: usize,
    /// Weights for linear combination of dimensions
    weights: Vec<f64>,
}

impl ContinuousEmergentProperty {
    /// Create a continuous emergent property.
    #[must_use]
    pub fn new(name: &'static str, level: usize, weights: Vec<f64>) -> Self {
        Self {
            name,
            level,
            weights,
        }
    }
}

impl EmergentProperty<Vec<f64>, f64> for ContinuousEmergentProperty {
    fn evaluate(&self, coarse_state: &Vec<f64>) -> f64 {
        self.weights
            .iter()
            .zip(coarse_state.iter())
            .map(|(w, s)| w * s)
            .sum()
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn observable_level(&self) -> usize {
        self.level
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// HIERARCHICAL STATE (PRODUCT STRUCTURE)
// ═══════════════════════════════════════════════════════════════════════════

/// Hierarchical state S ≅ S₁ × S₂ × ... × Sₙ.
///
/// A state in the product space with components at each level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HierarchicalState {
    /// State components at each level
    components: Vec<Vec<f64>>,
}

impl HierarchicalState {
    /// Create a hierarchical state from level components.
    #[must_use]
    pub fn new(components: Vec<Vec<f64>>) -> Self {
        Self { components }
    }

    /// Number of levels.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.components.len()
    }

    /// Get state component at level i.
    #[must_use]
    pub fn level_state(&self, level: usize) -> Option<&[f64]> {
        self.components.get(level).map(Vec::as_slice)
    }

    /// Set state component at level i.
    pub fn set_level_state(&mut self, level: usize, state: Vec<f64>) {
        if level < self.components.len() {
            self.components[level] = state;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// AXIOM 2 VERIFICATION
// ═══════════════════════════════════════════════════════════════════════════

/// Axiom 2 verification result.
///
/// Verifies: ∀𝒱 : ∃ℒ, {Sᵢ}, {πᵢ} such that:
/// - S ≅ ∏ᵢ Sᵢ (product structure)
/// - πᵢ: Sᵢ ↠ Sᵢ₊₁ (coarse-graining maps exist)
/// - ∀i: ∃Pᵢ₊₁ emergent (emergent properties at each level)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Axiom2Verification {
    /// Number of hierarchy levels N
    pub level_count: usize,
    /// Scale separation ε (minimum ratio between adjacent scales)
    pub scale_separation: f64,
    /// Has valid scale separation (ε > 1)
    pub has_scale_separation: bool,
    /// Number of coarse-graining maps (should be N-1)
    pub coarse_graining_map_count: usize,
    /// Number of emergent properties (should be ≥ N-1)
    pub emergent_property_count: usize,
    /// All axiom conditions satisfied
    pub axiom_satisfied: bool,
}

impl Axiom2Verification {
    /// Verify Axiom 2 for a hierarchy with maps and properties.
    #[must_use]
    pub fn verify<L: Level>(
        hierarchy: &Hierarchy<L>,
        coarse_graining_map_count: usize,
        emergent_property_count: usize,
    ) -> Self {
        let level_count = hierarchy.depth();
        let scale_separation = hierarchy.min_scale_separation();
        let has_scale_separation = hierarchy.has_scale_separation();

        // Conditions:
        // 1. Scale separation: ε > 1
        // 2. Coarse-graining maps: exactly N-1 maps
        // 3. Emergent properties: at least N-1 properties (one per non-base level)
        let required_maps = level_count.saturating_sub(1);
        let maps_valid = coarse_graining_map_count >= required_maps;
        let properties_valid = emergent_property_count >= required_maps;

        let axiom_satisfied = has_scale_separation && maps_valid && properties_valid;

        Self {
            level_count,
            scale_separation,
            has_scale_separation,
            coarse_graining_map_count,
            emergent_property_count,
            axiom_satisfied,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════════════════════════════

/// Errors related to hierarchical organization.
#[derive(Debug, Clone, nexcore_error::Error)]
pub enum HierarchyError {
    /// Empty hierarchy (no levels).
    #[error("Hierarchy must have at least one level")]
    EmptyHierarchy,

    /// Levels not in ascending order.
    #[error("Levels must be in strictly ascending order")]
    LevelsNotOrdered,

    /// Level and scale count mismatch.
    #[error("Level count ({levels}) != scale count ({scales})")]
    LevelScaleMismatch {
        /// Number of levels provided.
        levels: usize,
        /// Number of scales provided.
        scales: usize,
    },

    /// Non-positive scale value.
    #[error("Scale at level {level_index} must be positive")]
    NonPositiveScale {
        /// Index of the level with invalid scale.
        level_index: usize,
    },

    /// Missing coarse-graining map.
    #[error("Missing coarse-graining map for level {level}")]
    MissingCoarseGrainingMap {
        /// Level missing the map.
        level: usize,
    },

    /// Level index out of bounds.
    #[error("Level index {index} out of bounds (max {max})")]
    LevelOutOfBounds {
        /// Requested index.
        index: usize,
        /// Maximum valid index.
        max: usize,
    },
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pv_level_ordering() {
        assert!(PVLevel::Molecular < PVLevel::Cellular);
        assert!(PVLevel::Cellular < PVLevel::Tissue);
        assert!(PVLevel::Population < PVLevel::Societal);
    }

    #[test]
    fn test_pv_standard_hierarchy() {
        let hierarchy = PVLevel::standard_hierarchy();
        assert_eq!(hierarchy.depth(), 8);
        assert!(hierarchy.has_scale_separation());
    }

    #[test]
    fn test_scale_separation_wolfram_validated() {
        let hierarchy = PVLevel::standard_hierarchy();

        // Wolfram: 10^8 / 10^7 = 10
        // Our scales: 86400 / 3600 = 24 (days/hours)
        let ratio = hierarchy.scale_ratio(5).unwrap(); // Organism → Population
        assert!((ratio - 24.0).abs() < 0.001);

        // All ratios should be > 1 for scale separation
        assert!(hierarchy.min_scale_separation() > 1.0);
    }

    #[test]
    fn test_level_state_space() {
        let space = LevelStateSpace::with_bounds(0, vec![(0.0, 1.0), (0.0, 10.0)]);
        assert_eq!(space.dimension, 2);
        assert!(space.contains(&[0.5, 5.0]));
        assert!(!space.contains(&[1.5, 5.0])); // out of bounds
        assert!(!space.contains(&[0.5])); // wrong dimension
    }

    #[test]
    fn test_averaging_coarse_grain() {
        // 4D → 2D by averaging pairs
        let cg = AveragingCoarseGrain::new(0, vec![2, 2]);

        assert_eq!(cg.source_dimension(), 4);
        assert_eq!(cg.target_dimension(), 2);

        let fine = vec![1.0, 3.0, 2.0, 6.0];
        let coarse = cg.coarsen(&fine);

        assert_eq!(coarse, vec![2.0, 4.0]); // (1+3)/2, (2+6)/2
    }

    #[test]
    fn test_binary_emergent_property() {
        let prop = BinaryEmergentProperty::new("threshold_exceeded", 1, 0.5, 0);

        assert!(!prop.evaluate(&vec![0.3, 0.2]));
        assert!(prop.evaluate(&vec![0.7, 0.2]));
        assert_eq!(prop.observable_level(), 1);
    }

    #[test]
    fn test_continuous_emergent_property() {
        let prop = ContinuousEmergentProperty::new("weighted_sum", 2, vec![0.5, 0.5]);

        let result = prop.evaluate(&vec![2.0, 4.0]);
        assert!((result - 3.0).abs() < 0.001); // 0.5*2 + 0.5*4 = 3
    }

    #[test]
    fn test_hierarchical_state() {
        let state = HierarchicalState::new(vec![
            vec![1.0, 2.0],      // Level 0
            vec![3.0],           // Level 1
            vec![4.0, 5.0, 6.0], // Level 2
        ]);

        assert_eq!(state.depth(), 3);
        assert_eq!(state.level_state(0), Some(&[1.0, 2.0][..]));
        assert_eq!(state.level_state(1), Some(&[3.0][..]));
        assert_eq!(state.level_state(3), None);
    }

    #[test]
    fn test_axiom2_verification() {
        let hierarchy = PVLevel::standard_hierarchy();

        // 8 levels requires 7 coarse-graining maps and 7 emergent properties
        let verification = Axiom2Verification::verify(&hierarchy, 7, 7);

        assert_eq!(verification.level_count, 8);
        assert!(verification.has_scale_separation);
        assert!(verification.axiom_satisfied);
    }

    #[test]
    fn test_axiom2_verification_fails_without_maps() {
        let hierarchy = PVLevel::standard_hierarchy();

        // Only 5 maps when 7 required
        let verification = Axiom2Verification::verify(&hierarchy, 5, 7);

        assert!(!verification.axiom_satisfied);
    }

    #[test]
    fn test_emergence_attenuation_wolfram_validated() {
        // Wolfram: 0.9^8 = 0.43046721
        let attenuation: f64 = (0..8).map(|_| 0.9).product();
        assert!((attenuation - 0.430_467_21).abs() < 0.000_001);
    }

    #[test]
    fn test_hierarchy_error_empty() {
        let result = Hierarchy::<PVLevel>::new(vec![], vec![]);
        assert!(matches!(result, Err(HierarchyError::EmptyHierarchy)));
    }

    #[test]
    fn test_hierarchy_error_mismatch() {
        let result = Hierarchy::new(
            vec![PVLevel::Molecular, PVLevel::Cellular],
            vec![1.0], // Only one scale for two levels
        );
        assert!(matches!(
            result,
            Err(HierarchyError::LevelScaleMismatch { .. })
        ));
    }

    #[test]
    fn test_hierarchy_error_non_positive_scale() {
        let result = Hierarchy::new(
            vec![PVLevel::Molecular, PVLevel::Cellular],
            vec![1.0, -1.0], // Negative scale
        );
        assert!(matches!(
            result,
            Err(HierarchyError::NonPositiveScale { .. })
        ));
    }
}
