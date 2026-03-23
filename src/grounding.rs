//! # GroundsTo implementations for Guardian engine types
//!
//! Connects Guardian types to the Lex Primitiva type system.
//!
//! ## Product (×) Focus
//!
//! `OriginatorType` is the canonical Product grounding in the autonomy domain:
//! - **G × V × R** — three independent capabilities evaluated conjunctively
//! - The product of capabilities determines autonomy level
//! - Missing any factor fundamentally changes the classification

use nexcore_lex_primitiva::grounding::GroundsTo;
use nexcore_lex_primitiva::primitiva::{LexPrimitiva, PrimitiveComposition};
use nexcore_lex_primitiva::state_mode::StateMode;

use crate::governance::{
    ActionJournal, AuthorityDelegation, ConsentRecord, ConsentStatus, EvidenceBasis,
    EvidencedAction, GovernanceScope, LegitimacyChecker, LegitimacyVerdict,
};
use crate::homeostasis::HomeostasisLoop;
use crate::response::{Amplifier, ResponseAction, ResponseCeiling};
use crate::sensing::{ThreatLevel, ThreatSignal};
use crate::{OriginatorType, RiskContext, RiskScore};

/// OriginatorType: T2-C (κ · × · ∂), dominant ×
///
/// GVR capability product: Goal-selection × Value-evaluation × Refusal-capacity.
/// Each capability is binary (present/absent). The PRODUCT of all three determines
/// the autonomy classification. Missing G breaks goal-setting, missing V breaks
/// ethical evaluation, missing R breaks halt capability.
///
/// Product is dominant because the entity IS the conjunction of its capabilities.
impl GroundsTo for OriginatorType {
    fn primitive_composition() -> PrimitiveComposition {
        PrimitiveComposition::new(vec![
            LexPrimitiva::Comparison, // κ — binary capability check (has/lacks)
            LexPrimitiva::Product,    // × — G × V × R conjunctive combination
            LexPrimitiva::Boundary,   // ∂ — Tool vs Agent boundary classification
        ])
        .with_dominant(LexPrimitiva::Product, 0.90)
    }
}

/// RiskContext: T2-C (× · κ · N · ∂ · →), dominant ×
///
/// Risk evaluation context combining independent factors:
/// entity_id × originator × threat_level × action.
/// Product-dominant: all factors must be present for valid assessment.
impl GroundsTo for RiskContext {
    fn primitive_composition() -> PrimitiveComposition {
        PrimitiveComposition::new(vec![
            LexPrimitiva::Product,    // × — independent factors composed
            LexPrimitiva::Comparison, // κ — threat level comparison
            LexPrimitiva::Quantity,   // N — numeric risk scores
            LexPrimitiva::Boundary,   // ∂ — safety thresholds
            LexPrimitiva::Causality,  // → — context → risk assessment
        ])
        .with_dominant(LexPrimitiva::Product, 0.85)
    }
}

/// RiskScore: T2-P (N · κ), dominant N
///
/// Numeric risk score with threshold comparison.
/// Quantity-dominant: the score IS a numeric measurement.
impl GroundsTo for RiskScore {
    fn primitive_composition() -> PrimitiveComposition {
        PrimitiveComposition::new(vec![
            LexPrimitiva::Quantity,   // N — numeric score value
            LexPrimitiva::Comparison, // κ — threshold comparison
        ])
        .with_dominant(LexPrimitiva::Quantity, 0.90)
    }
}

/// ThreatSignal<T>: T2-C (→ · N · κ · ∂), dominant →
///
/// Detected threat pattern with severity and confidence.
/// Causality-dominant: signal source → detection.
impl<T> GroundsTo for ThreatSignal<T> {
    fn primitive_composition() -> PrimitiveComposition {
        PrimitiveComposition::new(vec![
            LexPrimitiva::Causality,  // → — signal source → detection
            LexPrimitiva::Quantity,   // N — signal strength/count
            LexPrimitiva::Comparison, // κ — severity comparison
            LexPrimitiva::Boundary,   // ∂ — severity thresholds
        ])
        .with_dominant(LexPrimitiva::Causality, 0.85)
    }
}

/// ThreatLevel: T2-P (∂ · κ), dominant ∂
impl GroundsTo for ThreatLevel {
    fn primitive_composition() -> PrimitiveComposition {
        PrimitiveComposition::new(vec![
            LexPrimitiva::Boundary,   // ∂ — severity categories as boundaries
            LexPrimitiva::Comparison, // κ — ordered comparison between levels
        ])
        .with_dominant(LexPrimitiva::Boundary, 0.90)
    }
}

/// ResponseAction: T2-C (→ · ∂ · κ · ς), dominant →
///
/// Action taken in response to threat signal.
/// Causality-dominant: the response IS a cause-effect action.
impl GroundsTo for ResponseAction {
    fn primitive_composition() -> PrimitiveComposition {
        PrimitiveComposition::new(vec![
            LexPrimitiva::Causality,  // → — threat → response action
            LexPrimitiva::Boundary,   // ∂ — action severity boundaries
            LexPrimitiva::Comparison, // κ — escalation level comparison
            LexPrimitiva::State,      // ς — system state change
        ])
        .with_dominant(LexPrimitiva::Causality, 0.85)
        .with_state_mode(StateMode::Modal)
    }

    fn state_mode() -> Option<StateMode> {
        Some(StateMode::Modal)
    }
}

/// ResponseCeiling: T2-C (∂ · × · κ), dominant ∂
///
/// Maximum response level based on originator capabilities.
/// Boundary-dominant: ceiling IS an upper bound.
/// Includes Product because ceiling depends on G × V × R.
impl GroundsTo for ResponseCeiling {
    fn primitive_composition() -> PrimitiveComposition {
        PrimitiveComposition::new(vec![
            LexPrimitiva::Boundary,   // ∂ — upper limit on response
            LexPrimitiva::Product,    // × — depends on GVR capability product
            LexPrimitiva::Comparison, // κ — ceiling comparison
        ])
        .with_dominant(LexPrimitiva::Boundary, 0.85)
    }
}

/// Amplifier: T2-P (N · ρ), dominant N
///
/// Response amplification factor (multiplier on response severity).
/// Quantity-dominant: amplification IS a numeric multiplier.
impl GroundsTo for Amplifier {
    fn primitive_composition() -> PrimitiveComposition {
        PrimitiveComposition::new(vec![
            LexPrimitiva::Quantity,  // N — amplification factor
            LexPrimitiva::Recursion, // ρ — cumulative amplification over iterations
        ])
        .with_dominant(LexPrimitiva::Quantity, 0.90)
    }
}

// =============================================================================
// Governance Types — Derived from Declaration of Independence primitives
// =============================================================================

/// ConsentStatus: T1 (ς), dominant ς (State)
///
/// Pure state machine: Pending → Granted → Active → Revoked.
/// Each transition changes the fundamental nature of the consent relationship.
impl GroundsTo for ConsentStatus {
    fn primitive_composition() -> PrimitiveComposition {
        PrimitiveComposition::new(vec![
            LexPrimitiva::State, // ς — consent lifecycle state machine
        ])
        .with_dominant(LexPrimitiva::State, 0.95)
        .with_state_mode(StateMode::Modal)
    }

    fn state_mode() -> Option<StateMode> {
        Some(StateMode::Modal)
    }
}

/// ConsentRecord: T2-C (μ · ς · π), dominant μ (Mapping)
///
/// "Governments deriving their just powers from the consent of the governed."
/// Mapping-dominant: consent IS the binding function between governed (grantor)
/// and governor (grantee). State (ς) tracks lifecycle. Persistence (π) because
/// consent records must survive across sessions.
impl GroundsTo for ConsentRecord {
    fn primitive_composition() -> PrimitiveComposition {
        PrimitiveComposition::new(vec![
            LexPrimitiva::Mapping,     // μ — governed → governor binding
            LexPrimitiva::State,       // ς — Pending/Granted/Active/Revoked lifecycle
            LexPrimitiva::Persistence, // π — consent records persist across sessions
        ])
        .with_dominant(LexPrimitiva::Mapping, 0.85)
        .with_state_mode(StateMode::Accumulated)
    }

    fn state_mode() -> Option<StateMode> {
        Some(StateMode::Accumulated)
    }
}

/// AuthorityDelegation: T2-C (μ · → · ∂), dominant μ (Mapping)
///
/// Authority flows through delegation chains. Each delegation maps source
/// authority to delegated authority within bounded scope.
/// Mapping-dominant: delegation IS a mapping from source to target.
/// Causality (→): delegation causes authorized capability.
/// Boundary (∂): each delegation has scope limits.
impl GroundsTo for AuthorityDelegation {
    fn primitive_composition() -> PrimitiveComposition {
        PrimitiveComposition::new(vec![
            LexPrimitiva::Mapping,   // μ — delegator → delegate mapping
            LexPrimitiva::Causality, // → — delegation causes authority
            LexPrimitiva::Boundary,  // ∂ — scope boundaries on delegation
        ])
        .with_dominant(LexPrimitiva::Mapping, 0.85)
    }
}

/// GovernanceScope: T2-P (∂ · μ), dominant ∂ (Boundary)
///
/// "Free and Independent States... have full Power..."
/// Boundary-dominant: scope IS a demarcation between inside and outside.
/// Mapping secondary: scope maps an authority to its domain.
impl GroundsTo for GovernanceScope {
    fn primitive_composition() -> PrimitiveComposition {
        PrimitiveComposition::new(vec![
            LexPrimitiva::Boundary, // ∂ — scope boundary demarcation
            LexPrimitiva::Mapping,  // μ — maps authority to domain
        ])
        .with_dominant(LexPrimitiva::Boundary, 0.90)
    }
}

/// EvidenceBasis: T2-C (∃ · κ · σ · N), dominant ∃ (Existence)
///
/// "Let Facts be submitted to a candid world."
/// Existence-dominant: evidence MUST EXIST before action is taken.
/// Comparison (κ): evidence compares claim against reality.
/// Sequence (σ): evidence items are temporally ordered.
/// Quantity (N): evidence items are enumerable.
impl GroundsTo for EvidenceBasis {
    fn primitive_composition() -> PrimitiveComposition {
        PrimitiveComposition::new(vec![
            LexPrimitiva::Existence,  // ∃ — evidence must exist
            LexPrimitiva::Comparison, // κ — comparison of claim vs. reality
            LexPrimitiva::Sequence,   // σ — temporal ordering of evidence
            LexPrimitiva::Quantity,   // N — enumerable evidence count
        ])
        .with_dominant(LexPrimitiva::Existence, 0.85)
    }
}

/// LegitimacyVerdict: T2-P (κ · ∃), dominant κ (Comparison)
///
/// The verdict of a legitimacy check. Comparison-dominant because
/// legitimacy IS the comparison of actual authority against normative standard.
impl GroundsTo for LegitimacyVerdict {
    fn primitive_composition() -> PrimitiveComposition {
        PrimitiveComposition::new(vec![
            LexPrimitiva::Comparison, // κ — is vs. ought comparison
            LexPrimitiva::Existence,  // ∃ — does legitimate authority exist?
        ])
        .with_dominant(LexPrimitiva::Comparison, 0.90)
    }
}

/// LegitimacyChecker: T2-C (κ · ∂ · μ · ς), dominant κ (Comparison)
///
/// The governance engine itself. Comparison-dominant because every
/// legitimacy check IS a comparison of actual state against requirements.
/// Includes Boundary (∂) for scope validation, Mapping (μ) for consent/delegation
/// lookup, and State (ς) for tracking check metrics.
impl GroundsTo for LegitimacyChecker {
    fn primitive_composition() -> PrimitiveComposition {
        PrimitiveComposition::new(vec![
            LexPrimitiva::Comparison, // κ — actual vs. normative comparison
            LexPrimitiva::Boundary,   // ∂ — scope boundary validation
            LexPrimitiva::Mapping,    // μ — consent/delegation lookup
            LexPrimitiva::State,      // ς — check metrics state
        ])
        .with_dominant(LexPrimitiva::Comparison, 0.85)
        .with_state_mode(StateMode::Mutable)
    }

    fn state_mode() -> Option<StateMode> {
        Some(StateMode::Mutable)
    }
}

// =============================================================================
// Evidenced Action & Journal — "Let Facts be submitted"
// =============================================================================

/// EvidencedAction: T2-C (→ · ∃ · κ), dominant → (Causality)
///
/// An action paired with its justifying evidence. The cause-effect chain
/// evidence → decision → action is Causality-dominant.
/// Existence (∃) validates evidence was present at decision time.
/// Comparison (κ) evaluates evidence against thresholds.
impl GroundsTo for EvidencedAction {
    fn primitive_composition() -> PrimitiveComposition {
        PrimitiveComposition::new(vec![
            LexPrimitiva::Causality,  // → — evidence causes action
            LexPrimitiva::Existence,  // ∃ — evidence must exist
            LexPrimitiva::Comparison, // κ — evidence vs threshold
        ])
        .with_dominant(LexPrimitiva::Causality, 0.85)
    }
}

/// ActionJournal: T2-C (σ · π · ∃ · N), dominant σ (Sequence)
///
/// Temporal ordering of all actions taken. Sequence-dominant because
/// the journal IS a temporal record. Persistence because it survives
/// across sessions. Existence because each entry validates evidence
/// was present. Quantity because entries are enumerable.
impl GroundsTo for ActionJournal {
    fn primitive_composition() -> PrimitiveComposition {
        PrimitiveComposition::new(vec![
            LexPrimitiva::Sequence,    // σ — temporal ordering
            LexPrimitiva::Persistence, // π — survives across sessions
            LexPrimitiva::Existence,   // ∃ — evidence existence validation
            LexPrimitiva::Quantity,    // N — enumerable entries
        ])
        .with_dominant(LexPrimitiva::Sequence, 0.85)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexcore_lex_primitiva::tier::Tier;

    #[test]
    fn originator_type_grounds_to_product() {
        let comp = OriginatorType::primitive_composition();
        assert!(comp.primitives.contains(&LexPrimitiva::Product));
        assert_eq!(comp.dominant, Some(LexPrimitiva::Product));
    }

    #[test]
    fn originator_type_is_t2c() {
        // 3 primitives = T2-P actually (2-3 = T2-P)
        assert_eq!(OriginatorType::tier(), Tier::T2Primitive);
    }

    #[test]
    fn risk_context_includes_product() {
        let comp = RiskContext::primitive_composition();
        assert!(comp.primitives.contains(&LexPrimitiva::Product));
        assert_eq!(comp.dominant, Some(LexPrimitiva::Product));
    }

    #[test]
    fn risk_score_is_quantity_dominant() {
        let comp = RiskScore::primitive_composition();
        assert_eq!(comp.dominant, Some(LexPrimitiva::Quantity));
        assert_eq!(RiskScore::tier(), Tier::T2Primitive);
    }

    #[test]
    fn response_action_is_causality_dominant() {
        let comp = ResponseAction::primitive_composition();
        assert_eq!(comp.dominant, Some(LexPrimitiva::Causality));
    }

    #[test]
    fn response_ceiling_includes_product() {
        let comp = ResponseCeiling::primitive_composition();
        assert!(comp.primitives.contains(&LexPrimitiva::Product));
        assert_eq!(comp.dominant, Some(LexPrimitiva::Boundary));
    }

    #[test]
    fn severity_is_boundary_dominant() {
        let comp = ThreatLevel::primitive_composition();
        assert_eq!(comp.dominant, Some(LexPrimitiva::Boundary));
    }

    // ── Governance grounding (Declaration-derived) ────────────────────

    #[test]
    fn consent_status_is_state_dominant() {
        let comp = ConsentStatus::primitive_composition();
        assert_eq!(comp.dominant, Some(LexPrimitiva::State));
        assert_eq!(ConsentStatus::tier(), Tier::T1Universal);
    }

    #[test]
    fn consent_record_is_mapping_dominant() {
        let comp = ConsentRecord::primitive_composition();
        assert_eq!(comp.dominant, Some(LexPrimitiva::Mapping));
        assert!(comp.primitives.contains(&LexPrimitiva::State));
        assert!(comp.primitives.contains(&LexPrimitiva::Persistence));
        assert_eq!(ConsentRecord::tier(), Tier::T2Primitive);
    }

    #[test]
    fn authority_delegation_is_mapping_dominant() {
        let comp = AuthorityDelegation::primitive_composition();
        assert_eq!(comp.dominant, Some(LexPrimitiva::Mapping));
        assert!(comp.primitives.contains(&LexPrimitiva::Causality));
        assert!(comp.primitives.contains(&LexPrimitiva::Boundary));
        assert_eq!(AuthorityDelegation::tier(), Tier::T2Primitive);
    }

    #[test]
    fn governance_scope_is_boundary_dominant() {
        let comp = GovernanceScope::primitive_composition();
        assert_eq!(comp.dominant, Some(LexPrimitiva::Boundary));
        assert_eq!(GovernanceScope::tier(), Tier::T2Primitive);
    }

    #[test]
    fn evidence_basis_is_existence_dominant() {
        let comp = EvidenceBasis::primitive_composition();
        assert_eq!(comp.dominant, Some(LexPrimitiva::Existence));
        assert!(comp.primitives.contains(&LexPrimitiva::Comparison));
        assert!(comp.primitives.contains(&LexPrimitiva::Sequence));
        assert!(comp.primitives.contains(&LexPrimitiva::Quantity));
        assert_eq!(EvidenceBasis::tier(), Tier::T2Composite);
    }

    #[test]
    fn legitimacy_verdict_is_comparison_dominant() {
        let comp = LegitimacyVerdict::primitive_composition();
        assert_eq!(comp.dominant, Some(LexPrimitiva::Comparison));
        assert_eq!(LegitimacyVerdict::tier(), Tier::T2Primitive);
    }

    #[test]
    fn legitimacy_checker_is_comparison_dominant() {
        let comp = LegitimacyChecker::primitive_composition();
        assert_eq!(comp.dominant, Some(LexPrimitiva::Comparison));
        assert!(comp.primitives.contains(&LexPrimitiva::Boundary));
        assert!(comp.primitives.contains(&LexPrimitiva::Mapping));
        assert!(comp.primitives.contains(&LexPrimitiva::State));
        assert_eq!(LegitimacyChecker::tier(), Tier::T2Composite);
    }

    // ── Evidenced Action & Journal grounding ────────────────────────

    #[test]
    fn evidenced_action_is_causality_dominant() {
        let comp = EvidencedAction::primitive_composition();
        assert_eq!(comp.dominant, Some(LexPrimitiva::Causality));
        assert!(comp.primitives.contains(&LexPrimitiva::Existence));
        assert!(comp.primitives.contains(&LexPrimitiva::Comparison));
        assert_eq!(EvidencedAction::tier(), Tier::T2Primitive);
    }

    #[test]
    fn action_journal_is_sequence_dominant() {
        let comp = ActionJournal::primitive_composition();
        assert_eq!(comp.dominant, Some(LexPrimitiva::Sequence));
        assert!(comp.primitives.contains(&LexPrimitiva::Persistence));
        assert!(comp.primitives.contains(&LexPrimitiva::Existence));
        assert!(comp.primitives.contains(&LexPrimitiva::Quantity));
        assert_eq!(ActionJournal::tier(), Tier::T2Composite);
    }
}
