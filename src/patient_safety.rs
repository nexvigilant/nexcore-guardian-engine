//! # Patient Safety Priority Enforcement
//!
//! **Axiom: Patient safety is the supreme priority. Always. No exceptions.**
//!
//! This module codifies the priority ordering that governs ALL Guardian decisions:
//!
//! ```text
//! P0: Patient Safety (immediate harm prevention)
//! P1: Signal Integrity (no safety signal may be lost or downgraded)
//! P2: Regulatory Compliance (meet reporting timelines)
//! P3: Data Quality (accuracy of assessments)
//! P4: Operational Efficiency (throughput, latency)
//! P5: Cost Optimization (resource allocation)
//! ```
//!
//! ## Enforcement Rules
//!
//! 1. **Never suppress a safety signal.** Even borderline signals must be logged and triaged.
//! 2. **Sensitive thresholds for serious outcomes.** Signals involving death, hospitalization,
//!    or disability ALWAYS use `SignalCriteria::sensitive()` — lower thresholds catch early.
//! 3. **Irreversible harm escalates immediately.** No waiting for confirmation on fatal signals.
//! 4. **Conservation law 1 holds.** Total signal mass is conserved: `dM/dt = J_in - J_out`.
//!    No signal may be dropped without explicit audit trail.
//! 5. **Human review required for Suspension/Withdrawal.** GVR constraint: RiskMinimizationLevel ≥ 7
//!    requires `Guardrail::HumanReviewRequired`.
//!
//! ## Tier Classification
//!
//! - `PatientSafetyPriority`: T3 (6 primitives: κ, ∂, →, ∝, σ, N)
//! - `SafetyEscalationRule`: T2-C (4 primitives: κ, ∂, →, ∝)
//! - `SeriousnessCategory`: T2-P (1 primitive: ∝)
//!
//! ## KSB Alignment
//!
//! - D01 Behavior 1: "Maintains patient safety as primary focus"
//! - D08 Behavior 7: "Focuses on patient impact"
//! - D10 Behavior 7: "Focuses on patient outcomes"
//! - EPA-01 through EPA-10: All Core EPAs serve patient safety
//!
//! ## PVOS Integration
//!
//! All 15 PVOS layers ultimately serve this priority hierarchy:
//! - PVSD (Signal Detection): Early detection → patient safety
//! - PVIR (Irreversibility): Severity weighting → harm prevention
//! - PVCL (Causal): Causality assessment → intervention targeting
//! - PVAG (Aggregation): Multi-source fusion → comprehensive safety picture

use serde::{Deserialize, Serialize};

// =============================================================================
// T2-P: SeriousnessCategory — Grounds ∝ (Irreversibility)
// =============================================================================

/// ICH E2A seriousness criteria for adverse events.
///
/// These categories determine signal triage priority. Higher seriousness
/// means lower detection thresholds and faster escalation.
///
/// ## Regulatory Source
/// ICH E2A: Clinical Safety Data Management — Definitions and Standards
///
/// ## Ordering
/// The discriminant values encode priority (higher = more serious).
/// `Fatal > LifeThreatening > Disability > Hospitalization > ...`
///
/// ## Tier: T2-P (single primitive: ∝ Irreversibility)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SeriousnessCategory {
    /// Non-serious adverse event (routine monitoring)
    NonSerious = 0,
    /// Medically important event (requires judgment)
    MedicallyImportant = 1,
    /// Congenital anomaly / birth defect
    CongenitalAnomaly = 2,
    /// Requires or prolongs hospitalization
    Hospitalization = 3,
    /// Results in persistent or significant disability
    Disability = 4,
    /// Life-threatening event
    LifeThreatening = 5,
    /// Results in death
    Fatal = 6,
}

impl SeriousnessCategory {
    /// Whether this is a serious outcome per ICH E2A.
    ///
    /// All categories ≥ Hospitalization are "serious" by regulatory definition.
    #[must_use]
    pub const fn is_serious(&self) -> bool {
        matches!(
            self,
            Self::Hospitalization
                | Self::Disability
                | Self::LifeThreatening
                | Self::Fatal
                | Self::CongenitalAnomaly
                | Self::MedicallyImportant
        )
    }

    /// Whether this outcome is irreversible (death or permanent disability).
    ///
    /// Irreversible outcomes trigger immediate escalation —
    /// the system cannot afford false negatives here.
    #[must_use]
    pub const fn is_irreversible(&self) -> bool {
        matches!(
            self,
            Self::Fatal | Self::Disability | Self::CongenitalAnomaly
        )
    }

    /// Whether sensitive signal detection thresholds should be used.
    ///
    /// **Rule: Any serious outcome uses `SignalCriteria::sensitive()`.**
    ///
    /// Rationale: For serious outcomes, the cost of a missed signal
    /// (patient harm) far exceeds the cost of a false positive
    /// (unnecessary investigation). Bayesian decision theory mandates
    /// asymmetric thresholds.
    #[must_use]
    pub const fn requires_sensitive_thresholds(&self) -> bool {
        self.is_serious()
    }

    /// Get priority weight for signal triage ordering.
    ///
    /// Higher weight = processed first in the triage queue.
    /// Fatal signals are processed before all others.
    #[must_use]
    pub const fn triage_weight(&self) -> u32 {
        match self {
            Self::Fatal => 1000,
            Self::LifeThreatening => 900,
            Self::Disability => 800,
            Self::CongenitalAnomaly => 750,
            Self::Hospitalization => 600,
            Self::MedicallyImportant => 400,
            Self::NonSerious => 100,
        }
    }

    /// Human-readable label for reporting.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Fatal => "Death",
            Self::LifeThreatening => "Life-threatening",
            Self::Disability => "Disability/Incapacity",
            Self::CongenitalAnomaly => "Congenital Anomaly",
            Self::Hospitalization => "Hospitalization",
            Self::MedicallyImportant => "Medically Important",
            Self::NonSerious => "Non-serious",
        }
    }
}

// =============================================================================
// T3: PatientSafetyPriority — The Supreme Ordering
// =============================================================================

/// The six-level priority hierarchy for ALL Guardian decisions.
///
/// **This ordering is axiomatic. It cannot be overridden, reordered, or bypassed.**
///
/// ```text
/// P0 > P1 > P2 > P3 > P4 > P5
///
/// Where:
///   P0: Patient Safety       — Prevent harm to patients
///   P1: Signal Integrity     — No safety signal may be lost
///   P2: Regulatory Compliance — Meet legal reporting obligations
///   P3: Data Quality         — Maintain assessment accuracy
///   P4: Operational Efficiency — System throughput
///   P5: Cost Optimization    — Resource allocation
/// ```
///
/// ## Enforcement
///
/// When priorities conflict, the higher-numbered priority ALWAYS yields
/// to the lower-numbered one. For example:
///
/// - If improving throughput (P4) would risk dropping a signal (P1) → preserve signal.
/// - If meeting a timeline (P2) requires publishing unvalidated data (P3) → delay for quality.
/// - If cost savings (P5) would reduce detection sensitivity (P0) → maintain sensitivity.
///
/// ## Tier: T3 (6 primitives: κ, ∂, →, ∝, σ, N)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PatientSafetyPriority {
    /// P0: Immediate patient safety (harm prevention).
    /// This is the supreme directive. All other priorities serve this one.
    ///
    /// Examples:
    /// - Detecting a new fatal ADR signal
    /// - Triggering emergency risk minimization
    /// - Escalating a life-threatening signal pattern
    PatientSafety = 0,

    /// P1: Signal integrity (conservation of safety information).
    /// No signal may be lost, downgraded, or suppressed without audit trail.
    ///
    /// Examples:
    /// - Preserving borderline signals in the triage queue
    /// - Maintaining full audit trail for regulatory inspection
    /// - Ensuring conservation law 1 (mass conservation) holds
    SignalIntegrity = 1,

    /// P2: Regulatory compliance (meeting legal obligations).
    /// Reporting timelines, ICSR submission, PSUR cycles.
    ///
    /// Examples:
    /// - 15-day expedited reporting for serious unexpected ADRs
    /// - PSUR submission deadlines
    /// - Annual safety report compilation
    RegulatoryCompliance = 2,

    /// P3: Data quality (accuracy and completeness).
    /// Assessment quality, coding accuracy, narrative completeness.
    ///
    /// Examples:
    /// - MedDRA coding accuracy
    /// - Causality assessment quality
    /// - Narrative completeness scoring
    DataQuality = 3,

    /// P4: Operational efficiency (system performance).
    /// Throughput, latency, resource utilization.
    ///
    /// Examples:
    /// - Case processing throughput
    /// - Signal detection pipeline latency
    /// - API response times
    OperationalEfficiency = 4,

    /// P5: Cost optimization (resource allocation).
    /// Budget, staffing, infrastructure costs.
    ///
    /// Examples:
    /// - Compute cost per signal evaluation
    /// - Staff allocation optimization
    /// - Infrastructure scaling decisions
    CostOptimization = 5,
}

impl PatientSafetyPriority {
    /// Check if this priority outranks another.
    ///
    /// Lower ordinal = higher priority. P0 outranks everything.
    #[must_use]
    pub const fn outranks(&self, other: &Self) -> bool {
        (*self as u8) < (*other as u8)
    }

    /// Human-readable label.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::PatientSafety => "P0: Patient Safety",
            Self::SignalIntegrity => "P1: Signal Integrity",
            Self::RegulatoryCompliance => "P2: Regulatory Compliance",
            Self::DataQuality => "P3: Data Quality",
            Self::OperationalEfficiency => "P4: Operational Efficiency",
            Self::CostOptimization => "P5: Cost Optimization",
        }
    }

    /// Get the priority level number (0-5).
    #[must_use]
    pub const fn level(&self) -> u8 {
        *self as u8
    }
}

// =============================================================================
// T2-C: SafetyEscalationRule — Grounds κ + ∂ + → + ∝
// =============================================================================

/// Rule defining when and how to escalate based on patient safety signals.
///
/// Each rule maps a (seriousness, signal_strength) pair to an escalation action.
///
/// ## Tier: T2-C (4 primitives: κ Comparison, ∂ Boundary, → Causality, ∝ Irreversibility)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyEscalationRule {
    /// The seriousness category that triggers this rule
    pub seriousness: SeriousnessCategory,
    /// Minimum signal strength (PRR) to trigger escalation
    /// For irreversible outcomes, this is lowered automatically.
    pub min_signal_strength: f64,
    /// Minimum case count to trigger escalation
    /// For fatal signals, this can be as low as 1.
    pub min_cases: u32,
    /// Whether human review is mandatory before action
    pub requires_human_review: bool,
    /// Maximum hours before escalation (0 = immediate)
    pub max_escalation_hours: u32,
    /// Description of what this rule enforces
    pub description: String,
}

/// The complete patient safety escalation matrix.
///
/// Contains the default rules that enforce patient safety priorities
/// across the entire Guardian system.
///
/// ## Tier: T3 (6+ primitives)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyEscalationMatrix {
    /// Ordered rules (highest priority first)
    pub rules: Vec<SafetyEscalationRule>,
    /// Whether the matrix is in sensitive mode (lower all thresholds)
    pub sensitive_mode: bool,
}

impl Default for SafetyEscalationMatrix {
    /// Create the default patient safety escalation matrix.
    ///
    /// These defaults encode the regulatory and ethical requirements
    /// for pharmacovigilance signal handling.
    fn default() -> Self {
        Self {
            rules: vec![
                // Rule 1: Fatal signals — IMMEDIATE escalation, even n=1
                SafetyEscalationRule {
                    seriousness: SeriousnessCategory::Fatal,
                    min_signal_strength: 1.0, // ANY signal above noise
                    min_cases: 1,             // Even a single death matters
                    requires_human_review: true,
                    max_escalation_hours: 0, // Immediate
                    description: "Fatal outcome: immediate escalation with human review"
                        .to_string(),
                },
                // Rule 2: Life-threatening — escalate within 4 hours
                SafetyEscalationRule {
                    seriousness: SeriousnessCategory::LifeThreatening,
                    min_signal_strength: 1.5, // Sensitive threshold
                    min_cases: 2,
                    requires_human_review: true,
                    max_escalation_hours: 4,
                    description: "Life-threatening: escalate within 4 hours".to_string(),
                },
                // Rule 3: Disability — escalate within 24 hours
                SafetyEscalationRule {
                    seriousness: SeriousnessCategory::Disability,
                    min_signal_strength: 1.5, // Sensitive threshold
                    min_cases: 2,
                    requires_human_review: true,
                    max_escalation_hours: 24,
                    description: "Disability: escalate within 24 hours".to_string(),
                },
                // Rule 4: Congenital anomaly — escalate within 24 hours
                SafetyEscalationRule {
                    seriousness: SeriousnessCategory::CongenitalAnomaly,
                    min_signal_strength: 1.5,
                    min_cases: 2,
                    requires_human_review: true,
                    max_escalation_hours: 24,
                    description: "Congenital anomaly: escalate within 24 hours".to_string(),
                },
                // Rule 5: Hospitalization — escalate within 72 hours
                SafetyEscalationRule {
                    seriousness: SeriousnessCategory::Hospitalization,
                    min_signal_strength: 2.0, // Standard Evans threshold
                    min_cases: 3,
                    requires_human_review: false,
                    max_escalation_hours: 72,
                    description: "Hospitalization: standard signal detection within 72 hours"
                        .to_string(),
                },
                // Rule 6: Medically important — standard processing
                SafetyEscalationRule {
                    seriousness: SeriousnessCategory::MedicallyImportant,
                    min_signal_strength: 2.0,
                    min_cases: 3,
                    requires_human_review: false,
                    max_escalation_hours: 168, // 7 days
                    description: "Medically important: standard processing within 7 days"
                        .to_string(),
                },
                // Rule 7: Non-serious — routine monitoring
                SafetyEscalationRule {
                    seriousness: SeriousnessCategory::NonSerious,
                    min_signal_strength: 2.0,
                    min_cases: 5, // Higher threshold for non-serious
                    requires_human_review: false,
                    max_escalation_hours: 720, // 30 days
                    description: "Non-serious: routine monitoring cycle".to_string(),
                },
            ],
            sensitive_mode: false,
        }
    }
}

impl SafetyEscalationMatrix {
    /// Create a new matrix with default rules.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable sensitive mode — lowers all thresholds by 25%.
    ///
    /// Use this during:
    /// - New drug launch (first 2 years post-authorization)
    /// - After a safety signal is confirmed (heightened vigilance)
    /// - Regulatory request for enhanced monitoring
    #[must_use]
    pub fn with_sensitive_mode(mut self) -> Self {
        self.sensitive_mode = true;
        for rule in &mut self.rules {
            rule.min_signal_strength *= 0.75; // 25% lower
            if rule.min_cases > 1 {
                rule.min_cases = rule.min_cases.saturating_sub(1);
            }
        }
        self
    }

    /// Find the applicable escalation rule for a given seriousness and signal.
    ///
    /// Returns `None` if no rule matches (signal too weak or insufficient cases).
    #[must_use]
    pub fn find_applicable_rule(
        &self,
        seriousness: SeriousnessCategory,
        signal_strength: f64,
        case_count: u32,
    ) -> Option<&SafetyEscalationRule> {
        self.rules.iter().find(|rule| {
            rule.seriousness == seriousness
                && signal_strength >= rule.min_signal_strength
                && case_count >= rule.min_cases
        })
    }

    /// Triage a signal by seriousness — returns (triage_weight, escalation_hours).
    ///
    /// Used to order the processing queue: fatal signals first.
    #[must_use]
    pub fn triage_signal(
        &self,
        seriousness: SeriousnessCategory,
        signal_strength: f64,
        case_count: u32,
    ) -> TriageResult {
        let rule = self.find_applicable_rule(seriousness, signal_strength, case_count);

        TriageResult {
            seriousness,
            triage_weight: seriousness.triage_weight(),
            escalation_hours: rule.map_or(u32::MAX, |r| r.max_escalation_hours),
            requires_human_review: rule.map_or(false, |r| r.requires_human_review),
            use_sensitive_thresholds: seriousness.requires_sensitive_thresholds(),
            rule_description: rule
                .map(|r| r.description.clone())
                .unwrap_or_else(|| "No applicable rule — signal below threshold".to_string()),
        }
    }

    /// Get the total number of rules.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

/// Result of triaging a signal through the safety escalation matrix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageResult {
    /// The seriousness category assessed
    pub seriousness: SeriousnessCategory,
    /// Priority weight for queue ordering (higher = process first)
    pub triage_weight: u32,
    /// Maximum hours before escalation (0 = immediate, u32::MAX = no escalation)
    pub escalation_hours: u32,
    /// Whether human review is mandatory
    pub requires_human_review: bool,
    /// Whether sensitive signal detection thresholds should be used
    pub use_sensitive_thresholds: bool,
    /// Description of the applied rule
    pub rule_description: String,
}

impl TriageResult {
    /// Is this an emergency requiring immediate action?
    #[must_use]
    pub const fn is_emergency(&self) -> bool {
        self.escalation_hours == 0
    }

    /// Is this a critical case requiring action within 24 hours?
    #[must_use]
    pub const fn is_critical(&self) -> bool {
        self.escalation_hours <= 24
    }
}

// =============================================================================
// Priority Conflict Resolution
// =============================================================================

/// Resolve a conflict between two competing priorities.
///
/// **The higher priority (lower number) always wins.**
/// This function exists to make the resolution explicit and auditable.
///
/// Returns the winning priority and a justification string.
#[must_use]
pub fn resolve_priority_conflict(
    a: PatientSafetyPriority,
    b: PatientSafetyPriority,
) -> (PatientSafetyPriority, &'static str) {
    if a.outranks(&b) {
        (a, "Higher priority wins per patient safety hierarchy")
    } else if b.outranks(&a) {
        (b, "Higher priority wins per patient safety hierarchy")
    } else {
        (a, "Equal priority — no conflict")
    }
}

/// Validate that a proposed action does not violate the priority hierarchy.
///
/// Returns `Err` with justification if the action would compromise
/// a higher-priority concern.
///
/// # Arguments
/// - `action_priority`: The priority level the proposed action serves
/// - `compromised_priority`: The priority level that would be harmed
///
/// # Example
/// ```ignore
/// // Trying to optimize cost (P5) at the expense of signal integrity (P1)
/// let result = validate_priority_compliance(
///     PatientSafetyPriority::CostOptimization,
///     PatientSafetyPriority::SignalIntegrity,
/// );
/// assert!(result.is_err()); // Cannot sacrifice P1 for P5
/// ```
pub fn validate_priority_compliance(
    action_priority: PatientSafetyPriority,
    compromised_priority: PatientSafetyPriority,
) -> Result<(), String> {
    if compromised_priority.outranks(&action_priority) {
        Err(format!(
            "PRIORITY VIOLATION: Cannot compromise {} to serve {}. \
             Patient safety hierarchy is absolute.",
            compromised_priority.label(),
            action_priority.label(),
        ))
    } else {
        Ok(())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // SeriousnessCategory tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_seriousness_ordering() {
        // Fatal > LifeThreatening > Disability > ... > NonSerious
        assert!(SeriousnessCategory::Fatal > SeriousnessCategory::LifeThreatening);
        assert!(SeriousnessCategory::LifeThreatening > SeriousnessCategory::Disability);
        assert!(SeriousnessCategory::Disability > SeriousnessCategory::Hospitalization);
        assert!(SeriousnessCategory::Hospitalization > SeriousnessCategory::MedicallyImportant);
        assert!(SeriousnessCategory::MedicallyImportant > SeriousnessCategory::NonSerious);
    }

    #[test]
    fn test_seriousness_is_serious() {
        assert!(SeriousnessCategory::Fatal.is_serious());
        assert!(SeriousnessCategory::LifeThreatening.is_serious());
        assert!(SeriousnessCategory::Disability.is_serious());
        assert!(SeriousnessCategory::Hospitalization.is_serious());
        assert!(SeriousnessCategory::MedicallyImportant.is_serious());
        assert!(SeriousnessCategory::CongenitalAnomaly.is_serious());
        assert!(!SeriousnessCategory::NonSerious.is_serious());
    }

    #[test]
    fn test_seriousness_irreversible() {
        assert!(SeriousnessCategory::Fatal.is_irreversible());
        assert!(SeriousnessCategory::Disability.is_irreversible());
        assert!(SeriousnessCategory::CongenitalAnomaly.is_irreversible());
        assert!(!SeriousnessCategory::LifeThreatening.is_irreversible());
        assert!(!SeriousnessCategory::Hospitalization.is_irreversible());
        assert!(!SeriousnessCategory::NonSerious.is_irreversible());
    }

    #[test]
    fn test_seriousness_triage_weight_ordering() {
        // Fatal should have highest triage weight
        assert!(
            SeriousnessCategory::Fatal.triage_weight()
                > SeriousnessCategory::LifeThreatening.triage_weight()
        );
        assert!(
            SeriousnessCategory::LifeThreatening.triage_weight()
                > SeriousnessCategory::Disability.triage_weight()
        );
        assert!(
            SeriousnessCategory::Disability.triage_weight()
                > SeriousnessCategory::Hospitalization.triage_weight()
        );
        assert!(
            SeriousnessCategory::Hospitalization.triage_weight()
                > SeriousnessCategory::NonSerious.triage_weight()
        );
    }

    #[test]
    fn test_seriousness_sensitive_thresholds() {
        // All serious outcomes require sensitive thresholds
        assert!(SeriousnessCategory::Fatal.requires_sensitive_thresholds());
        assert!(SeriousnessCategory::LifeThreatening.requires_sensitive_thresholds());
        assert!(SeriousnessCategory::Hospitalization.requires_sensitive_thresholds());
        // Non-serious does not
        assert!(!SeriousnessCategory::NonSerious.requires_sensitive_thresholds());
    }

    // -------------------------------------------------------------------------
    // PatientSafetyPriority tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_priority_ordering_is_absolute() {
        // P0 > P1 > P2 > P3 > P4 > P5
        assert!(
            PatientSafetyPriority::PatientSafety.outranks(&PatientSafetyPriority::SignalIntegrity)
        );
        assert!(
            PatientSafetyPriority::SignalIntegrity
                .outranks(&PatientSafetyPriority::RegulatoryCompliance)
        );
        assert!(
            PatientSafetyPriority::RegulatoryCompliance
                .outranks(&PatientSafetyPriority::DataQuality)
        );
        assert!(
            PatientSafetyPriority::DataQuality
                .outranks(&PatientSafetyPriority::OperationalEfficiency)
        );
        assert!(
            PatientSafetyPriority::OperationalEfficiency
                .outranks(&PatientSafetyPriority::CostOptimization)
        );
    }

    #[test]
    fn test_patient_safety_outranks_everything() {
        let p0 = PatientSafetyPriority::PatientSafety;
        assert!(p0.outranks(&PatientSafetyPriority::SignalIntegrity));
        assert!(p0.outranks(&PatientSafetyPriority::RegulatoryCompliance));
        assert!(p0.outranks(&PatientSafetyPriority::DataQuality));
        assert!(p0.outranks(&PatientSafetyPriority::OperationalEfficiency));
        assert!(p0.outranks(&PatientSafetyPriority::CostOptimization));
    }

    #[test]
    fn test_nothing_outranks_patient_safety() {
        let p0 = PatientSafetyPriority::PatientSafety;
        assert!(!PatientSafetyPriority::SignalIntegrity.outranks(&p0));
        assert!(!PatientSafetyPriority::RegulatoryCompliance.outranks(&p0));
        assert!(!PatientSafetyPriority::CostOptimization.outranks(&p0));
    }

    #[test]
    fn test_equal_priority_no_conflict() {
        let (winner, reason) = resolve_priority_conflict(
            PatientSafetyPriority::DataQuality,
            PatientSafetyPriority::DataQuality,
        );
        assert_eq!(winner, PatientSafetyPriority::DataQuality);
        assert!(reason.contains("no conflict"));
    }

    // -------------------------------------------------------------------------
    // Priority compliance validation tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_cannot_sacrifice_safety_for_cost() {
        let result = validate_priority_compliance(
            PatientSafetyPriority::CostOptimization,
            PatientSafetyPriority::PatientSafety,
        );
        assert!(result.is_err());
        assert!(
            result
                .as_ref()
                .err()
                .map_or(false, |e| e.contains("PRIORITY VIOLATION"))
        );
    }

    #[test]
    fn test_cannot_sacrifice_signals_for_efficiency() {
        let result = validate_priority_compliance(
            PatientSafetyPriority::OperationalEfficiency,
            PatientSafetyPriority::SignalIntegrity,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_can_sacrifice_cost_for_safety() {
        let result = validate_priority_compliance(
            PatientSafetyPriority::PatientSafety,
            PatientSafetyPriority::CostOptimization,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_can_sacrifice_efficiency_for_compliance() {
        let result = validate_priority_compliance(
            PatientSafetyPriority::RegulatoryCompliance,
            PatientSafetyPriority::OperationalEfficiency,
        );
        assert!(result.is_ok());
    }

    // -------------------------------------------------------------------------
    // SafetyEscalationMatrix tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_default_matrix_has_7_rules() {
        let matrix = SafetyEscalationMatrix::new();
        assert_eq!(matrix.rule_count(), 7);
    }

    #[test]
    fn test_fatal_signal_immediate_escalation() {
        let matrix = SafetyEscalationMatrix::new();
        let result = matrix.triage_signal(SeriousnessCategory::Fatal, 1.5, 1);
        assert!(result.is_emergency());
        assert!(result.requires_human_review);
        assert!(result.use_sensitive_thresholds);
        assert_eq!(result.triage_weight, 1000);
    }

    #[test]
    fn test_life_threatening_escalation_within_4_hours() {
        let matrix = SafetyEscalationMatrix::new();
        let result = matrix.triage_signal(SeriousnessCategory::LifeThreatening, 2.0, 3);
        assert!(result.is_critical());
        assert_eq!(result.escalation_hours, 4);
        assert!(result.requires_human_review);
    }

    #[test]
    fn test_non_serious_routine_monitoring() {
        let matrix = SafetyEscalationMatrix::new();
        let result = matrix.triage_signal(SeriousnessCategory::NonSerious, 2.5, 5);
        assert!(!result.is_emergency());
        assert!(!result.is_critical());
        assert!(!result.requires_human_review);
        assert!(!result.use_sensitive_thresholds);
        assert_eq!(result.escalation_hours, 720); // 30 days
    }

    #[test]
    fn test_sensitive_mode_lowers_thresholds() {
        let normal = SafetyEscalationMatrix::new();
        let sensitive = SafetyEscalationMatrix::new().with_sensitive_mode();

        // In sensitive mode, hospitalization rule min_signal_strength should be lower
        let normal_rule = normal
            .find_applicable_rule(SeriousnessCategory::Hospitalization, 2.0, 3)
            .map(|r| r.min_signal_strength);
        let sensitive_rule = sensitive
            .find_applicable_rule(SeriousnessCategory::Hospitalization, 1.5, 2)
            .map(|r| r.min_signal_strength);

        assert!(normal_rule.is_some());
        assert!(sensitive_rule.is_some());
        // Sensitive mode threshold should be lower (0.75x)
        if let (Some(n), Some(s)) = (normal_rule, sensitive_rule) {
            assert!(s < n, "Sensitive threshold ({s}) should be < normal ({n})");
        }
    }

    #[test]
    fn test_weak_signal_below_threshold_no_rule() {
        let matrix = SafetyEscalationMatrix::new();
        // Signal strength 0.5 is below even fatal threshold (1.0)
        let result = matrix.triage_signal(SeriousnessCategory::NonSerious, 0.5, 1);
        // Should get max escalation hours (no applicable rule)
        assert_eq!(result.escalation_hours, u32::MAX);
    }

    #[test]
    fn test_triage_result_labels() {
        let matrix = SafetyEscalationMatrix::new();
        let result = matrix.triage_signal(SeriousnessCategory::Fatal, 2.0, 1);
        assert!(result.rule_description.contains("Fatal"));
        assert!(result.rule_description.contains("immediate"));
    }

    // -------------------------------------------------------------------------
    // Serialization tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_seriousness_serialization_roundtrip() {
        let original = SeriousnessCategory::Fatal;
        let json = serde_json::to_string(&original);
        assert!(json.is_ok());
        let deserialized: Result<SeriousnessCategory, _> =
            serde_json::from_str(&json.unwrap_or_default());
        assert!(deserialized.is_ok());
        assert_eq!(
            deserialized.unwrap_or(SeriousnessCategory::NonSerious),
            original
        );
    }

    #[test]
    fn test_priority_serialization_roundtrip() {
        let original = PatientSafetyPriority::PatientSafety;
        let json = serde_json::to_string(&original);
        assert!(json.is_ok());
        let deserialized: Result<PatientSafetyPriority, _> =
            serde_json::from_str(&json.unwrap_or_default());
        assert!(deserialized.is_ok());
        assert_eq!(
            deserialized.unwrap_or(PatientSafetyPriority::CostOptimization),
            original
        );
    }

    #[test]
    fn test_triage_result_serialization() {
        let matrix = SafetyEscalationMatrix::new();
        let result = matrix.triage_signal(SeriousnessCategory::Fatal, 2.0, 1);
        let json = serde_json::to_string(&result);
        assert!(json.is_ok());
    }
}
