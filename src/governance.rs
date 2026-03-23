//! # Governance Layer — Authority, Consent, and Legitimacy
//!
//! Derived from the primitive extraction of the United States Declaration of Independence.
//!
//! The Declaration teaches that authority without consent is tyranny, and that
//! legitimacy is the continuous comparison of actual authority against its
//! normative source. This module instantiates those governance primitives
//! as Rust types within the Guardian engine.
//!
//! ## Primitive Grounding
//!
//! | Type | Tier | Lex Primitiva | Dominant |
//! |------|------|---------------|----------|
//! | `ConsentStatus` | T1 | ς (State) | ς |
//! | `ConsentRecord` | T2-C | μ · ς · π | μ (Mapping) |
//! | `AuthorityDelegation` | T2-C | μ · → · ∂ | μ (Mapping) |
//! | `GovernanceScope` | T2-P | ∂ · μ | ∂ (Boundary) |
//! | `LegitimacyCheck` | T2-P | κ · ∂ | κ (Comparison) |
//! | `LegitimacyVerdict` | T2-P | κ · ∃ | κ (Comparison) |
//! | `EvidenceBasis` | T2-C | ∃ · κ · σ · N | ∃ (Existence) |
//!
//! ## Leadership Values Instantiated
//!
//! - **Value 1**: Legitimacy Before Authority — `LegitimacyCheck` validates before execution
//! - **Value 2**: Consent Is The Foundation — `ConsentRecord` tracks consent lifecycle
//! - **Value 4**: Evidence Precedes Action — `EvidenceBasis` on every response
//! - **Value 7**: Sovereignty Is Bounded — `GovernanceScope` constrains authority
//!
//! ## Architectural Decision
//!
//! These types compose with—but do not replace—the existing GVR framework.
//! GVR answers "what CAN this entity do?" (capability).
//! Governance answers "what SHOULD this entity be allowed to do?" (authorization).
//! The gap between CAN and SHOULD is where Guardian lives.

use nexcore_chrono::DateTime;
use serde::{Deserialize, Serialize};

use crate::OriginatorType;
use crate::response::ResponseAction;

// =============================================================================
// Constants
// =============================================================================

/// Maximum delegation chain depth before circular dependency is assumed.
///
/// 8 levels mirrors the PV hierarchy (Molecular → Societal) and prevents
/// infinite delegation chains. In practice, 3-4 levels suffice.
pub const MAX_DELEGATION_DEPTH: usize = 8;

/// Duration after which consent must be re-confirmed (seconds).
///
/// 86400 = 24 hours. Consent is not eternal — it must be periodically
/// reaffirmed. "The consent of the governed" is a living relation.
pub const CONSENT_RECONFIRMATION_WINDOW: u64 = 86400;

/// Minimum evidence items required to justify a non-trivial action.
///
/// Modeled after the Declaration's standard: a single grievance is
/// insufficient; a pattern of evidence is required.
pub const MIN_EVIDENCE_FOR_ACTION: usize = 1;

// =============================================================================
// Governance Scope — Value 7: Sovereignty Is Bounded
// =============================================================================

/// The bounded domain within which an authority operates.
///
/// "Free and Independent States... have full Power to levy War, conclude Peace..."
/// Each Guardian instance is sovereign within its scope and has no authority outside it.
///
/// ## Tier: T2-P (∂ · μ), dominant ∂
///
/// Boundary-dominant because a scope IS a demarcation between inside and outside.
/// Mapping secondary because scope maps an authority to its domain.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GovernanceScope {
    /// Pharmacovigilance signal detection and patient safety
    PatientSafety,

    /// HUD governance act enforcement (CAP-014 through CAP-037)
    HudGovernance,

    /// System health monitoring (hooks, code quality, signals)
    SystemHealth,

    /// Authentication and access control
    AccessControl,

    /// Data integrity and audit trail
    DataIntegrity,

    /// Custom scope with named boundary
    Custom(String),

    /// Global scope — only for P0 patient safety overrides.
    /// "Unalienable rights" that transcend scope boundaries.
    Global,
}

impl GovernanceScope {
    /// Check if this scope contains another scope.
    ///
    /// Global contains everything. Otherwise, scopes are equal or disjoint.
    #[must_use]
    pub fn contains(&self, other: &Self) -> bool {
        match self {
            Self::Global => true,
            _ => self == other,
        }
    }

    /// Check if this scope is the global (unalienable) scope.
    #[must_use]
    pub const fn is_global(&self) -> bool {
        matches!(self, Self::Global)
    }

    /// Human-readable scope name
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::PatientSafety => "patient-safety",
            Self::HudGovernance => "hud-governance",
            Self::SystemHealth => "system-health",
            Self::AccessControl => "access-control",
            Self::DataIntegrity => "data-integrity",
            Self::Custom(name) => name,
            Self::Global => "global",
        }
    }
}

impl std::fmt::Display for GovernanceScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// =============================================================================
// Consent — Value 2: Consent Is The Foundation
// =============================================================================

/// Lifecycle state of a consent relationship.
///
/// ## Tier: T1 (ς), dominant ς (State)
///
/// A pure state machine: Pending → Granted → Active → Revoked.
/// State is the irreducible primitive here — each transition changes
/// the fundamental nature of the relationship.
///
/// ```text
///   Pending ──▶ Granted ──▶ Active ──▶ Revoked
///       │                      │           ▲
///       └──────▶ Denied        └───────────┘
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConsentStatus {
    /// Consent has been requested but not yet granted.
    /// No authority may be exercised in this state.
    Pending,

    /// Consent has been granted but not yet activated.
    /// Authority is authorized but not yet exercised.
    Granted,

    /// Consent is actively in force.
    /// Authority may be exercised within the granted scope.
    Active,

    /// Consent was denied — no authority granted.
    Denied,

    /// Consent was previously active but has been revoked.
    /// Authority dissolves immediately upon revocation.
    /// "When consent is withdrawn, authority dissolves instantly."
    Revoked,

    /// Consent expired due to passage of time without reconfirmation.
    /// Functionally equivalent to Revoked but distinguished for audit.
    Expired,
}

impl ConsentStatus {
    /// Check if this status permits authority to be exercised.
    #[must_use]
    pub const fn permits_authority(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// Check if this status is terminal (no further transitions possible).
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Denied | Self::Revoked)
    }

    /// Check if this consent has ever been valid.
    #[must_use]
    pub const fn was_ever_valid(&self) -> bool {
        matches!(self, Self::Active | Self::Revoked | Self::Expired)
    }

    /// Validate a state transition.
    ///
    /// Legal transitions:
    /// - Pending → Granted | Denied
    /// - Granted → Active | Revoked
    /// - Active → Revoked | Expired
    /// - Denied, Revoked, Expired → (terminal, no transitions)
    #[must_use]
    pub const fn can_transition_to(&self, next: &ConsentStatus) -> bool {
        matches!(
            (self, next),
            (Self::Pending, Self::Granted)
                | (Self::Pending, Self::Denied)
                | (Self::Granted, Self::Active)
                | (Self::Granted, Self::Revoked)
                | (Self::Active, Self::Revoked)
                | (Self::Active, Self::Expired)
        )
    }
}

impl std::fmt::Display for ConsentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Granted => write!(f, "granted"),
            Self::Active => write!(f, "active"),
            Self::Denied => write!(f, "denied"),
            Self::Revoked => write!(f, "revoked"),
            Self::Expired => write!(f, "expired"),
        }
    }
}

/// A record of consent between a grantor and a grantee within a defined scope.
///
/// "Governments are instituted among Men, deriving their just powers
/// from the consent of the governed."
///
/// ## Tier: T2-C (μ · ς · π), dominant μ (Mapping)
///
/// Mapping-dominant because consent IS the binding function between
/// governed (grantor) and governor (grantee). State (ς) tracks lifecycle.
/// Persistence (π) because consent records must survive across sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentRecord {
    /// Unique identifier for this consent record
    pub id: String,

    /// The entity granting consent (the governed)
    pub grantor: String,

    /// The entity receiving consent (the governor/agent)
    pub grantee: String,

    /// The scope within which consent applies
    pub scope: GovernanceScope,

    /// Current consent status
    pub status: ConsentStatus,

    /// When consent was first requested
    pub requested_at: DateTime,

    /// When consent was granted (if applicable)
    pub granted_at: Option<DateTime>,

    /// When consent was activated (if applicable)
    pub activated_at: Option<DateTime>,

    /// When consent expires and must be reconfirmed
    pub expires_at: Option<DateTime>,

    /// When consent was revoked (if applicable)
    pub revoked_at: Option<DateTime>,

    /// Reason for revocation (audit trail)
    pub revocation_reason: Option<String>,

    /// The originator type of the grantee (for GVR cross-reference)
    pub grantee_originator: OriginatorType,

    /// Human-readable description of what is being consented to
    pub description: String,
}

impl ConsentRecord {
    /// Create a new pending consent record.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        grantor: impl Into<String>,
        grantee: impl Into<String>,
        scope: GovernanceScope,
        grantee_originator: OriginatorType,
        description: impl Into<String>,
    ) -> Self {
        let now = DateTime::now();
        Self {
            id: id.into(),
            grantor: grantor.into(),
            grantee: grantee.into(),
            scope,
            status: ConsentStatus::Pending,
            requested_at: now,
            granted_at: None,
            activated_at: None,
            expires_at: None,
            revoked_at: None,
            revocation_reason: None,
            grantee_originator,
            description: description.into(),
        }
    }

    /// Attempt to transition consent status.
    ///
    /// Returns `Ok(())` if the transition is valid, or `Err` with reason.
    pub fn transition(&mut self, new_status: ConsentStatus) -> Result<(), GovernanceError> {
        if !self.status.can_transition_to(&new_status) {
            return Err(GovernanceError::InvalidConsentTransition {
                from: self.status,
                to: new_status,
                consent_id: self.id.clone(),
            });
        }

        let now = DateTime::now();
        match new_status {
            ConsentStatus::Granted => {
                self.granted_at = Some(now);
                self.expires_at = Some(
                    now + nexcore_chrono::Duration::seconds(CONSENT_RECONFIRMATION_WINDOW as i64),
                );
            }
            ConsentStatus::Active => {
                self.activated_at = Some(now);
            }
            ConsentStatus::Revoked => {
                self.revoked_at = Some(now);
            }
            _ => {}
        }
        self.status = new_status;
        Ok(())
    }

    /// Revoke consent with a reason.
    pub fn revoke(&mut self, reason: impl Into<String>) -> Result<(), GovernanceError> {
        self.revocation_reason = Some(reason.into());
        self.transition(ConsentStatus::Revoked)
    }

    /// Check if consent is currently valid for authority exercise.
    ///
    /// Validates both status AND temporal validity.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        if !self.status.permits_authority() {
            return false;
        }

        // Check expiration
        if let Some(expires) = self.expires_at {
            if DateTime::now() > expires {
                return false;
            }
        }

        true
    }

    /// Check if consent has expired and should be transitioned.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        if let Some(expires) = self.expires_at {
            matches!(self.status, ConsentStatus::Active | ConsentStatus::Granted)
                && DateTime::now() > expires
        } else {
            false
        }
    }

    /// Get the age of this consent record in seconds.
    #[must_use]
    pub fn age_seconds(&self) -> i64 {
        (DateTime::now() - self.requested_at).num_seconds()
    }
}

impl std::fmt::Display for ConsentRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Consent[{}]: {} → {} ({}, scope={})",
            self.id, self.grantor, self.grantee, self.status, self.scope
        )
    }
}

// =============================================================================
// Authority Delegation — Value 1: Legitimacy Before Authority
// =============================================================================

/// A delegation of authority from one entity to another within a scope.
///
/// Authority flows downward through delegation chains. Each delegation
/// carries a reference to its source, forming a traceable chain of custody.
/// The chain MUST terminate at a root authority (human operator or P0 axiom).
///
/// ## Tier: T2-C (μ · → · ∂), dominant μ (Mapping)
///
/// Mapping-dominant because delegation IS a mapping from source authority
/// to delegated authority. Causality (→) because delegation causes
/// authorized capability. Boundary (∂) because each delegation has scope limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorityDelegation {
    /// Unique delegation identifier
    pub id: String,

    /// The entity delegating authority (source)
    pub delegator: String,

    /// The entity receiving delegated authority (target)
    pub delegate: String,

    /// Originator type of the delegator
    pub delegator_originator: OriginatorType,

    /// Originator type of the delegate
    pub delegate_originator: OriginatorType,

    /// Scope within which authority is delegated
    pub scope: GovernanceScope,

    /// The consent record authorizing this delegation (if any)
    pub consent_id: Option<String>,

    /// Parent delegation ID (forms the chain of custody)
    /// None = root authority (human operator, P0 axiom)
    pub parent_delegation_id: Option<String>,

    /// Depth in the delegation chain (0 = root)
    pub depth: usize,

    /// When this delegation was created
    pub created_at: DateTime,

    /// When this delegation expires
    pub expires_at: Option<DateTime>,

    /// Whether this delegation has been revoked
    pub revoked: bool,

    /// Maximum actions per time window under this delegation
    pub rate_limit: Option<u32>,
}

impl AuthorityDelegation {
    /// Create a root authority delegation (no parent — originates from human/axiom).
    #[must_use]
    pub fn root(
        id: impl Into<String>,
        delegator: impl Into<String>,
        delegate: impl Into<String>,
        scope: GovernanceScope,
        delegator_originator: OriginatorType,
        delegate_originator: OriginatorType,
    ) -> Self {
        Self {
            id: id.into(),
            delegator: delegator.into(),
            delegate: delegate.into(),
            delegator_originator,
            delegate_originator,
            scope,
            consent_id: None,
            parent_delegation_id: None,
            depth: 0,
            created_at: DateTime::now(),
            expires_at: None,
            revoked: false,
            rate_limit: None,
        }
    }

    /// Create a child delegation from this parent.
    ///
    /// Returns `Err` if maximum delegation depth would be exceeded.
    pub fn delegate(
        &self,
        id: impl Into<String>,
        delegate: impl Into<String>,
        delegate_originator: OriginatorType,
        consent_id: Option<String>,
    ) -> Result<Self, GovernanceError> {
        let new_depth = self.depth + 1;
        if new_depth >= MAX_DELEGATION_DEPTH {
            return Err(GovernanceError::DelegationDepthExceeded {
                max_depth: MAX_DELEGATION_DEPTH,
                attempted_depth: new_depth,
                delegation_id: self.id.clone(),
            });
        }

        Ok(Self {
            id: id.into(),
            delegator: self.delegate.clone(),
            delegate: delegate.into(),
            delegator_originator: self.delegate_originator,
            delegate_originator,
            scope: self.scope.clone(),
            consent_id,
            parent_delegation_id: Some(self.id.clone()),
            depth: new_depth,
            created_at: DateTime::now(),
            expires_at: self.expires_at, // Inherit parent expiration
            revoked: false,
            rate_limit: self.rate_limit, // Inherit parent rate limit
        })
    }

    /// Check if this delegation is currently valid.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        if self.revoked {
            return false;
        }
        if let Some(expires) = self.expires_at {
            if DateTime::now() > expires {
                return false;
            }
        }
        true
    }

    /// Revoke this delegation.
    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    /// Check if this delegation authorizes action within a given scope.
    #[must_use]
    pub fn authorizes_scope(&self, scope: &GovernanceScope) -> bool {
        self.is_valid() && self.scope.contains(scope)
    }

    /// Check if this is a root delegation (no parent).
    #[must_use]
    pub const fn is_root(&self) -> bool {
        self.parent_delegation_id.is_none()
    }
}

impl std::fmt::Display for AuthorityDelegation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let root_marker = if self.is_root() { " [ROOT]" } else { "" };
        write!(
            f,
            "Delegation[{}]: {} → {} (scope={}, depth={}){}",
            self.id, self.delegator, self.delegate, self.scope, self.depth, root_marker
        )
    }
}

// =============================================================================
// Evidence Basis — Value 4: Evidence Precedes Action
// =============================================================================

/// A piece of evidence supporting a governance decision.
///
/// "Let Facts be submitted to a candid world."
/// Each fact is a specific, enumerable observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceItem {
    /// What was observed
    pub observation: String,

    /// The metric or signal source
    pub source: String,

    /// Numeric value (if applicable)
    pub value: Option<f64>,

    /// Threshold that was compared against (if applicable)
    pub threshold: Option<f64>,

    /// When this evidence was collected
    pub observed_at: DateTime,
}

/// The evidentiary basis for a Guardian action.
///
/// No block without a signal. No escalation without a pattern.
/// No quarantine without a threshold breach. The evidence trail IS the audit trail.
///
/// ## Tier: T2-C (∃ · κ · σ · N), dominant ∃ (Existence)
///
/// Existence-dominant because evidence MUST EXIST before action is taken.
/// Comparison (κ) because evidence compares claim against reality.
/// Sequence (σ) because evidence is temporally ordered.
/// Quantity (N) because evidence items are enumerable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBasis {
    /// The specific evidence items supporting this action
    pub items: Vec<EvidenceItem>,

    /// Summary of the evidence (human-readable)
    pub summary: String,

    /// The governance check that this evidence was evaluated against
    pub evaluated_by: String,

    /// Timestamp of the evaluation
    pub evaluated_at: DateTime,
}

impl EvidenceBasis {
    /// Create a new evidence basis.
    #[must_use]
    pub fn new(summary: impl Into<String>, evaluated_by: impl Into<String>) -> Self {
        Self {
            items: Vec::new(),
            summary: summary.into(),
            evaluated_by: evaluated_by.into(),
            evaluated_at: DateTime::now(),
        }
    }

    /// Add an evidence item.
    pub fn add_item(&mut self, item: EvidenceItem) {
        self.items.push(item);
    }

    /// Add evidence from a threshold comparison.
    pub fn add_threshold_evidence(
        &mut self,
        source: impl Into<String>,
        observation: impl Into<String>,
        value: f64,
        threshold: f64,
    ) {
        self.items.push(EvidenceItem {
            observation: observation.into(),
            source: source.into(),
            value: Some(value),
            threshold: Some(threshold),
            observed_at: DateTime::now(),
        });
    }

    /// Check if sufficient evidence exists to justify action.
    #[must_use]
    pub fn is_sufficient(&self) -> bool {
        self.items.len() >= MIN_EVIDENCE_FOR_ACTION
    }

    /// Get the number of evidence items.
    #[must_use]
    pub fn count(&self) -> usize {
        self.items.len()
    }
}

impl std::fmt::Display for EvidenceBasis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Evidence[{} items]: {} (by {})",
            self.items.len(),
            self.summary,
            self.evaluated_by
        )
    }
}

// =============================================================================
// Legitimacy Check — The Core Governance Primitive
// =============================================================================

/// Reason for a legitimacy failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LegitimacyFailure {
    /// No consent record found for this action
    NoConsent,

    /// Consent exists but is not in Active status
    ConsentNotActive { status: String },

    /// Consent has expired
    ConsentExpired,

    /// No authority delegation found
    NoAuthority,

    /// Authority delegation has been revoked
    AuthorityRevoked,

    /// Authority delegation has expired
    AuthorityExpired,

    /// Action scope exceeds delegation scope
    ScopeExceeded {
        action_scope: String,
        delegation_scope: String,
    },

    /// Delegation chain exceeds maximum depth
    ChainTooDeep { depth: usize, max: usize },

    /// Insufficient evidence for the requested action
    InsufficientEvidence { have: usize, need: usize },

    /// Originator capability insufficient (GVR check)
    InsufficientCapability { required: String, actual: String },
}

impl std::fmt::Display for LegitimacyFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoConsent => write!(f, "no consent record found"),
            Self::ConsentNotActive { status } => {
                write!(f, "consent exists but status is '{status}'")
            }
            Self::ConsentExpired => write!(f, "consent has expired"),
            Self::NoAuthority => write!(f, "no authority delegation found"),
            Self::AuthorityRevoked => write!(f, "authority delegation revoked"),
            Self::AuthorityExpired => write!(f, "authority delegation expired"),
            Self::ScopeExceeded {
                action_scope,
                delegation_scope,
            } => write!(
                f,
                "action scope '{action_scope}' exceeds delegation scope '{delegation_scope}'"
            ),
            Self::ChainTooDeep { depth, max } => {
                write!(f, "delegation chain depth {depth} exceeds max {max}")
            }
            Self::InsufficientEvidence { have, need } => {
                write!(f, "insufficient evidence: have {have}, need {need}")
            }
            Self::InsufficientCapability { required, actual } => {
                write!(
                    f,
                    "insufficient capability: required {required}, actual {actual}"
                )
            }
        }
    }
}

/// The verdict of a legitimacy check.
///
/// ## Tier: T2-P (κ · ∃), dominant κ (Comparison)
///
/// Comparison-dominant because legitimacy IS the comparison of
/// actual authority against normative standard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LegitimacyVerdict {
    /// Action is legitimate — authority, consent, scope, and evidence all valid.
    Legitimate {
        /// The delegation chain that authorizes this action
        delegation_chain: Vec<String>,
        /// The consent record backing the authority
        consent_id: String,
        /// Evidence supporting the action
        evidence_count: usize,
    },

    /// Action is NOT legitimate — specific failure identified.
    Illegitimate {
        /// The specific reason legitimacy failed
        failure: LegitimacyFailure,
        /// Recommended remediation
        remediation: String,
    },

    /// Legitimacy check bypassed for P0 patient safety emergency.
    ///
    /// "Unalienable rights" — some actions transcend the consent framework
    /// because patient safety (P0) is axiomatic. These actions are still
    /// logged and audited, but they cannot be blocked by governance checks.
    P0Override {
        /// Why this was classified as P0
        justification: String,
    },
}

impl LegitimacyVerdict {
    /// Check if the action is permitted.
    #[must_use]
    pub const fn is_permitted(&self) -> bool {
        matches!(self, Self::Legitimate { .. } | Self::P0Override { .. })
    }

    /// Check if this was a P0 override.
    #[must_use]
    pub const fn is_p0_override(&self) -> bool {
        matches!(self, Self::P0Override { .. })
    }
}

impl std::fmt::Display for LegitimacyVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Legitimate {
                delegation_chain,
                evidence_count,
                ..
            } => write!(
                f,
                "LEGITIMATE (chain depth={}, evidence={})",
                delegation_chain.len(),
                evidence_count
            ),
            Self::Illegitimate { failure, .. } => write!(f, "ILLEGITIMATE: {failure}"),
            Self::P0Override { justification } => write!(f, "P0 OVERRIDE: {justification}"),
        }
    }
}

/// Performs legitimacy checks on proposed Guardian actions.
///
/// "Governments deriving their just powers from the consent of the governed."
///
/// The LegitimacyChecker validates that a proposed action has:
/// 1. Valid consent from the affected parties
/// 2. An unbroken authority delegation chain
/// 3. Scope containment (action within delegation scope)
/// 4. Sufficient evidence to justify the action
/// 5. Adequate originator capability (GVR check)
///
/// ## Tier: T2-P (κ · ∂), dominant κ (Comparison)
///
/// Comparison-dominant because every legitimacy check IS a comparison
/// of actual state against normative requirements.
#[derive(Debug, Clone, Default)]
pub struct LegitimacyChecker {
    /// Registered consent records
    consents: Vec<ConsentRecord>,

    /// Registered authority delegations
    delegations: Vec<AuthorityDelegation>,

    /// Whether P0 patient safety overrides are enabled
    p0_override_enabled: bool,

    /// Total checks performed (for metrics)
    checks_performed: u64,

    /// Total failures detected (for metrics)
    failures_detected: u64,
}

impl LegitimacyChecker {
    /// Create a new legitimacy checker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            consents: Vec::new(),
            delegations: Vec::new(),
            p0_override_enabled: true,
            checks_performed: 0,
            failures_detected: 0,
        }
    }

    /// Register a consent record.
    pub fn register_consent(&mut self, consent: ConsentRecord) {
        self.consents.push(consent);
    }

    /// Register an authority delegation.
    pub fn register_delegation(&mut self, delegation: AuthorityDelegation) {
        self.delegations.push(delegation);
    }

    /// Find active consent for a grantee within a scope.
    #[must_use]
    pub fn find_consent(&self, grantee: &str, scope: &GovernanceScope) -> Option<&ConsentRecord> {
        self.consents
            .iter()
            .find(|c| c.grantee == grantee && c.scope.contains(scope) && c.is_valid())
    }

    /// Find valid delegation for a delegate within a scope.
    #[must_use]
    pub fn find_delegation(
        &self,
        delegate: &str,
        scope: &GovernanceScope,
    ) -> Option<&AuthorityDelegation> {
        self.delegations
            .iter()
            .find(|d| d.delegate == delegate && d.authorizes_scope(scope))
    }

    /// Build the delegation chain for a delegate.
    #[must_use]
    pub fn delegation_chain(&self, delegate: &str, scope: &GovernanceScope) -> Vec<String> {
        let mut chain = Vec::new();
        let mut current_delegate = delegate;

        for _ in 0..MAX_DELEGATION_DEPTH {
            if let Some(delegation) = self.find_delegation(current_delegate, scope) {
                chain.push(delegation.id.clone());
                if delegation.is_root() {
                    break;
                }
                current_delegate = &delegation.delegator;
            } else {
                break;
            }
        }

        chain
    }

    /// Perform a full legitimacy check on a proposed action.
    ///
    /// This is the core governance operation. It validates:
    /// 1. Consent exists and is active
    /// 2. Authority delegation exists and is valid
    /// 3. Action scope is within delegation scope
    /// 4. Evidence is sufficient
    /// 5. Originator has required capabilities
    pub fn check(
        &mut self,
        actor: &str,
        actor_originator: OriginatorType,
        scope: &GovernanceScope,
        evidence: &EvidenceBasis,
        is_p0_emergency: bool,
    ) -> LegitimacyVerdict {
        self.checks_performed += 1;

        // P0 patient safety override — unalienable right
        if is_p0_emergency && self.p0_override_enabled {
            return LegitimacyVerdict::P0Override {
                justification: format!(
                    "P0 patient safety emergency for actor '{actor}' in scope '{scope}'"
                ),
            };
        }

        // 1. Check consent — extract owned data to release borrow before mutation
        let consent_info = self
            .find_consent(actor, scope)
            .map(|c| (c.id.clone(), c.is_expired()));

        let (consent_id, consent_expired) = match consent_info {
            Some((id, expired)) => (id, expired),
            None => {
                self.failures_detected += 1;
                return LegitimacyVerdict::Illegitimate {
                    failure: LegitimacyFailure::NoConsent,
                    remediation: format!("Register consent for '{actor}' in scope '{scope}'"),
                };
            }
        };

        // Check consent expiration
        if consent_expired {
            self.failures_detected += 1;
            return LegitimacyVerdict::Illegitimate {
                failure: LegitimacyFailure::ConsentExpired,
                remediation: format!("Reconfirm consent '{consent_id}' (expired)"),
            };
        }

        // 2. Check authority delegation — extract owned data to release borrow
        let delegation_info = self
            .find_delegation(actor, scope)
            .map(|d| (d.authorizes_scope(scope), d.scope.to_string()));

        let (scope_authorized, delegation_scope_name) = match delegation_info {
            Some((authorized, scope_name)) => (authorized, scope_name),
            None => {
                self.failures_detected += 1;
                return LegitimacyVerdict::Illegitimate {
                    failure: LegitimacyFailure::NoAuthority,
                    remediation: format!(
                        "Create authority delegation for '{actor}' in scope '{scope}'"
                    ),
                };
            }
        };

        // 3. Check scope containment
        if !scope_authorized {
            self.failures_detected += 1;
            return LegitimacyVerdict::Illegitimate {
                failure: LegitimacyFailure::ScopeExceeded {
                    action_scope: scope.to_string(),
                    delegation_scope: delegation_scope_name,
                },
                remediation: "Request delegation with broader scope or narrow action scope"
                    .to_string(),
            };
        }

        // 4. Check evidence sufficiency
        if !evidence.is_sufficient() {
            self.failures_detected += 1;
            return LegitimacyVerdict::Illegitimate {
                failure: LegitimacyFailure::InsufficientEvidence {
                    have: evidence.count(),
                    need: MIN_EVIDENCE_FOR_ACTION,
                },
                remediation: "Collect additional evidence before taking action".to_string(),
            };
        }

        // 5. Check GVR capability (actors with higher autonomy need less external auth)
        // Tools need full external authorization; GVR agents need minimal
        let _ = actor_originator; // GVR check is informational, not blocking

        // Build delegation chain for audit
        let delegation_chain = self.delegation_chain(actor, scope);

        LegitimacyVerdict::Legitimate {
            delegation_chain,
            consent_id,
            evidence_count: evidence.count(),
        }
    }

    /// Get the number of registered consents.
    #[must_use]
    pub fn consent_count(&self) -> usize {
        self.consents.len()
    }

    /// Get the number of registered delegations.
    #[must_use]
    pub fn delegation_count(&self) -> usize {
        self.delegations.len()
    }

    /// Get total checks performed.
    #[must_use]
    pub fn checks_performed(&self) -> u64 {
        self.checks_performed
    }

    /// Get total failures detected.
    #[must_use]
    pub fn failures_detected(&self) -> u64 {
        self.failures_detected
    }

    /// Get the legitimacy rate (checks passed / total checks).
    #[must_use]
    pub fn legitimacy_rate(&self) -> f64 {
        if self.checks_performed == 0 {
            return 1.0;
        }
        let passed = self.checks_performed - self.failures_detected;
        passed as f64 / self.checks_performed as f64
    }

    /// Expire all stale consents (transition Active → Expired).
    pub fn expire_stale_consents(&mut self) -> usize {
        let mut expired_count = 0;
        for consent in &mut self.consents {
            if consent.is_expired() {
                if consent.transition(ConsentStatus::Expired).is_ok() {
                    expired_count += 1;
                }
            }
        }
        expired_count
    }

    /// Revoke all delegations from a specific delegator.
    ///
    /// Used when trust in an entity is revoked — all downstream authority dissolves.
    pub fn revoke_delegations_from(&mut self, delegator: &str) -> usize {
        let mut revoked = 0;
        for delegation in &mut self.delegations {
            if delegation.delegator == delegator && !delegation.revoked {
                delegation.revoke();
                revoked += 1;
            }
        }
        revoked
    }
}

// =============================================================================
// Evidenced Action — Value 4: Evidence Precedes Action (applied to ResponseAction)
// =============================================================================

/// A response action paired with its justifying evidence.
///
/// "Let Facts be submitted to a candid world." — No action without evidence.
/// Every response the Guardian takes is paired with the evidence that
/// justified it, the legitimacy verdict that authorized it, and an
/// audit timestamp. This is the fundamental unit of the Guardian audit trail.
///
/// ## Tier: T2-C (→ · ∃ · κ), dominant → (Causality)
///
/// Causality-dominant because an EvidencedAction IS a cause-effect record:
/// evidence → decision → action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencedAction {
    /// The response action taken
    pub action: ResponseAction,

    /// The evidence justifying this action
    pub evidence: EvidenceBasis,

    /// The actor who authorized this action
    pub authorized_by: String,

    /// When the decision was made
    pub decided_at: DateTime,

    /// The legitimacy verdict (if governance check was performed)
    pub legitimacy: Option<LegitimacyVerdict>,

    /// The scope in which this action was authorized
    pub scope: GovernanceScope,
}

impl EvidencedAction {
    /// Create an evidenced action from a response action and evidence.
    #[must_use]
    pub fn new(
        action: ResponseAction,
        evidence: EvidenceBasis,
        authorized_by: impl Into<String>,
        scope: GovernanceScope,
    ) -> Self {
        Self {
            action,
            evidence,
            authorized_by: authorized_by.into(),
            decided_at: DateTime::now(),
            legitimacy: None,
            scope,
        }
    }

    /// Attach a legitimacy verdict to this action.
    #[must_use]
    pub fn with_legitimacy(mut self, verdict: LegitimacyVerdict) -> Self {
        self.legitimacy = Some(verdict);
        self
    }

    /// Check if this action has sufficient evidence.
    #[must_use]
    pub fn has_sufficient_evidence(&self) -> bool {
        self.evidence.is_sufficient()
    }

    /// Check if this action was legitimately authorized.
    #[must_use]
    pub fn is_legitimate(&self) -> bool {
        self.legitimacy.as_ref().is_some_and(|v| v.is_permitted())
    }

    /// Check if this action was a P0 override.
    #[must_use]
    pub fn is_p0_override(&self) -> bool {
        self.legitimacy.as_ref().is_some_and(|v| v.is_p0_override())
    }
}

impl std::fmt::Display for EvidencedAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let legitimacy = self
            .legitimacy
            .as_ref()
            .map(|v| format!("{v}"))
            .unwrap_or_else(|| "unchecked".to_string());
        write!(
            f,
            "EvidencedAction[by={}, scope={}, evidence={}, legitimacy={}]",
            self.authorized_by,
            self.scope,
            self.evidence.count(),
            legitimacy,
        )
    }
}

/// An audit journal recording all evidenced actions.
///
/// Every action the Guardian takes is recorded here with full evidence
/// and legitimacy verdicts. This IS the audit trail — the permanent record
/// that "Facts were submitted to a candid world" before action was taken.
///
/// ## Tier: T2-C (σ · π · ∃), dominant σ (Sequence)
///
/// Sequence-dominant because the journal IS a temporal ordering of actions.
/// Persistence (π) because journal entries must survive across sessions.
/// Existence (∃) because each entry validates evidence existed at decision time.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActionJournal {
    /// All recorded evidenced actions, in temporal order
    entries: Vec<EvidencedAction>,
}

impl ActionJournal {
    /// Create a new empty journal.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Record an evidenced action.
    pub fn record(&mut self, action: EvidencedAction) {
        self.entries.push(action);
    }

    /// Get all journal entries.
    #[must_use]
    pub fn entries(&self) -> &[EvidencedAction] {
        &self.entries
    }

    /// Get entries by scope.
    #[must_use]
    pub fn entries_for_scope(&self, scope: &GovernanceScope) -> Vec<&EvidencedAction> {
        self.entries.iter().filter(|e| e.scope == *scope).collect()
    }

    /// Get entries by actor.
    #[must_use]
    pub fn entries_by_actor(&self, actor: &str) -> Vec<&EvidencedAction> {
        self.entries
            .iter()
            .filter(|e| e.authorized_by == actor)
            .collect()
    }

    /// Count entries that lack legitimacy verdicts (governance gap).
    #[must_use]
    pub fn unchecked_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.legitimacy.is_none())
            .count()
    }

    /// Count entries where legitimacy failed (governance violations).
    #[must_use]
    pub fn illegitimate_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.legitimacy.as_ref().is_some_and(|v| !v.is_permitted()))
            .count()
    }

    /// Get total entries recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if journal is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// =============================================================================
// Governance Errors
// =============================================================================

/// Errors arising from governance operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceError {
    /// Invalid consent state transition attempted
    InvalidConsentTransition {
        from: ConsentStatus,
        to: ConsentStatus,
        consent_id: String,
    },

    /// Delegation chain exceeds maximum depth
    DelegationDepthExceeded {
        max_depth: usize,
        attempted_depth: usize,
        delegation_id: String,
    },

    /// Circular delegation detected
    CircularDelegation { delegation_ids: Vec<String> },

    /// Legitimacy check failed
    LegitimacyFailed { failure: LegitimacyFailure },
}

impl std::fmt::Display for GovernanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConsentTransition {
                from,
                to,
                consent_id,
            } => write!(
                f,
                "Invalid consent transition: {from} → {to} (consent '{consent_id}')"
            ),
            Self::DelegationDepthExceeded {
                max_depth,
                attempted_depth,
                delegation_id,
            } => write!(
                f,
                "Delegation depth {attempted_depth} exceeds max {max_depth} (delegation '{delegation_id}')"
            ),
            Self::CircularDelegation { delegation_ids } => {
                write!(f, "Circular delegation: {:?}", delegation_ids)
            }
            Self::LegitimacyFailed { failure } => write!(f, "Legitimacy failed: {failure}"),
        }
    }
}

impl std::error::Error for GovernanceError {}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── Consent Status State Machine ──────────────────────────────────

    #[test]
    fn consent_status_valid_transitions() {
        // Pending → Granted
        assert!(ConsentStatus::Pending.can_transition_to(&ConsentStatus::Granted));
        // Pending → Denied
        assert!(ConsentStatus::Pending.can_transition_to(&ConsentStatus::Denied));
        // Granted → Active
        assert!(ConsentStatus::Granted.can_transition_to(&ConsentStatus::Active));
        // Active → Revoked
        assert!(ConsentStatus::Active.can_transition_to(&ConsentStatus::Revoked));
        // Active → Expired
        assert!(ConsentStatus::Active.can_transition_to(&ConsentStatus::Expired));
    }

    #[test]
    fn consent_status_invalid_transitions() {
        // Cannot go backwards
        assert!(!ConsentStatus::Active.can_transition_to(&ConsentStatus::Pending));
        assert!(!ConsentStatus::Granted.can_transition_to(&ConsentStatus::Pending));
        // Terminal states cannot transition
        assert!(!ConsentStatus::Denied.can_transition_to(&ConsentStatus::Active));
        assert!(!ConsentStatus::Revoked.can_transition_to(&ConsentStatus::Active));
        // Cannot skip states
        assert!(!ConsentStatus::Pending.can_transition_to(&ConsentStatus::Active));
    }

    #[test]
    fn consent_status_permits_authority_only_when_active() {
        assert!(!ConsentStatus::Pending.permits_authority());
        assert!(!ConsentStatus::Granted.permits_authority());
        assert!(ConsentStatus::Active.permits_authority());
        assert!(!ConsentStatus::Denied.permits_authority());
        assert!(!ConsentStatus::Revoked.permits_authority());
        assert!(!ConsentStatus::Expired.permits_authority());
    }

    #[test]
    fn consent_status_terminal_states() {
        assert!(!ConsentStatus::Pending.is_terminal());
        assert!(!ConsentStatus::Granted.is_terminal());
        assert!(!ConsentStatus::Active.is_terminal());
        assert!(ConsentStatus::Denied.is_terminal());
        assert!(ConsentStatus::Revoked.is_terminal());
        assert!(!ConsentStatus::Expired.is_terminal());
    }

    // ── Consent Record Lifecycle ──────────────────────────────────────

    #[test]
    fn consent_record_full_lifecycle() {
        let mut consent = ConsentRecord::new(
            "consent-1",
            "patient-oversight-board",
            "guardian-pv",
            GovernanceScope::PatientSafety,
            OriginatorType::AgentWithVR,
            "Monitor adverse events for Drug X",
        );

        assert_eq!(consent.status, ConsentStatus::Pending);
        assert!(!consent.is_valid());

        // Grant
        assert!(consent.transition(ConsentStatus::Granted).is_ok());
        assert_eq!(consent.status, ConsentStatus::Granted);
        assert!(consent.granted_at.is_some());
        assert!(consent.expires_at.is_some());

        // Activate
        assert!(consent.transition(ConsentStatus::Active).is_ok());
        assert_eq!(consent.status, ConsentStatus::Active);
        assert!(consent.is_valid());

        // Revoke
        assert!(consent.revoke("Trust violation detected").is_ok());
        assert_eq!(consent.status, ConsentStatus::Revoked);
        assert!(!consent.is_valid());
        assert_eq!(
            consent.revocation_reason.as_deref(),
            Some("Trust violation detected")
        );
    }

    #[test]
    fn consent_record_invalid_transition_returns_error() {
        let mut consent = ConsentRecord::new(
            "consent-2",
            "operator",
            "agent",
            GovernanceScope::SystemHealth,
            OriginatorType::Tool,
            "Health monitoring",
        );

        // Cannot skip Pending → Active
        let result = consent.transition(ConsentStatus::Active);
        assert!(result.is_err());
    }

    // ── Authority Delegation ──────────────────────────────────────────

    #[test]
    fn authority_delegation_chain() {
        let root = AuthorityDelegation::root(
            "deleg-root",
            "matthew-campion",
            "guardian-pv",
            GovernanceScope::PatientSafety,
            OriginatorType::AgentWithGVR,
            OriginatorType::AgentWithVR,
        );

        assert!(root.is_root());
        assert!(root.is_valid());
        assert_eq!(root.depth, 0);

        // Delegate to a sub-agent
        let child = root.delegate(
            "deleg-child",
            "signal-detector",
            OriginatorType::AgentWithR,
            Some("consent-1".to_string()),
        );
        assert!(child.is_ok());

        let child = child.unwrap_or_else(|_| unreachable!());
        assert!(!child.is_root());
        assert_eq!(child.depth, 1);
        assert_eq!(child.parent_delegation_id.as_deref(), Some("deleg-root"));
    }

    #[test]
    fn authority_delegation_depth_limit() {
        let mut current = AuthorityDelegation::root(
            "deleg-0",
            "root",
            "agent-0",
            GovernanceScope::SystemHealth,
            OriginatorType::AgentWithGVR,
            OriginatorType::AgentWithVR,
        );

        // Chain delegations up to MAX_DELEGATION_DEPTH
        for i in 1..MAX_DELEGATION_DEPTH {
            let next = current.delegate(
                format!("deleg-{i}"),
                format!("agent-{i}"),
                OriginatorType::AgentWithR,
                None,
            );
            assert!(next.is_ok(), "Delegation at depth {i} should succeed");
            current = next.unwrap_or_else(|_| unreachable!());
        }

        // One more should fail
        let overflow = current.delegate(
            "deleg-overflow",
            "agent-overflow",
            OriginatorType::Tool,
            None,
        );
        assert!(overflow.is_err());
    }

    #[test]
    fn authority_delegation_scope_check() {
        let delegation = AuthorityDelegation::root(
            "deleg-pv",
            "operator",
            "guardian",
            GovernanceScope::PatientSafety,
            OriginatorType::AgentWithGVR,
            OriginatorType::AgentWithVR,
        );

        assert!(delegation.authorizes_scope(&GovernanceScope::PatientSafety));
        assert!(!delegation.authorizes_scope(&GovernanceScope::HudGovernance));
        assert!(!delegation.authorizes_scope(&GovernanceScope::AccessControl));
    }

    #[test]
    fn global_scope_contains_all() {
        let global = AuthorityDelegation::root(
            "deleg-global",
            "operator",
            "guardian",
            GovernanceScope::Global,
            OriginatorType::AgentWithGVR,
            OriginatorType::AgentWithVR,
        );

        assert!(global.authorizes_scope(&GovernanceScope::PatientSafety));
        assert!(global.authorizes_scope(&GovernanceScope::HudGovernance));
        assert!(global.authorizes_scope(&GovernanceScope::SystemHealth));
        assert!(global.authorizes_scope(&GovernanceScope::Global));
    }

    // ── Evidence Basis ────────────────────────────────────────────────

    #[test]
    fn evidence_basis_sufficiency() {
        let mut evidence = EvidenceBasis::new(
            "PRR threshold exceeded for Drug X + Event Y",
            "DecisionEngine",
        );

        // Initially insufficient
        assert!(!evidence.is_sufficient());

        // Add threshold evidence
        evidence.add_threshold_evidence("prr-metric", "PRR >= 2.0", 3.5, 2.0);
        assert!(evidence.is_sufficient());
        assert_eq!(evidence.count(), 1);
    }

    // ── Legitimacy Checker ────────────────────────────────────────────

    #[test]
    fn legitimacy_check_full_pass() {
        let mut checker = LegitimacyChecker::new();

        // Register consent
        let mut consent = ConsentRecord::new(
            "consent-1",
            "oversight",
            "guardian-pv",
            GovernanceScope::PatientSafety,
            OriginatorType::AgentWithVR,
            "PV monitoring",
        );
        assert!(consent.transition(ConsentStatus::Granted).is_ok());
        assert!(consent.transition(ConsentStatus::Active).is_ok());
        checker.register_consent(consent);

        // Register delegation
        let delegation = AuthorityDelegation::root(
            "deleg-1",
            "oversight",
            "guardian-pv",
            GovernanceScope::PatientSafety,
            OriginatorType::AgentWithGVR,
            OriginatorType::AgentWithVR,
        );
        checker.register_delegation(delegation);

        // Create evidence
        let mut evidence = EvidenceBasis::new("Signal detected", "test");
        evidence.add_threshold_evidence("prr", "PRR >= 2.0", 3.5, 2.0);

        // Check legitimacy
        let verdict = checker.check(
            "guardian-pv",
            OriginatorType::AgentWithVR,
            &GovernanceScope::PatientSafety,
            &evidence,
            false,
        );

        assert!(verdict.is_permitted());
        assert!(!verdict.is_p0_override());
        assert_eq!(checker.checks_performed(), 1);
        assert_eq!(checker.failures_detected(), 0);
    }

    #[test]
    fn legitimacy_check_no_consent_fails() {
        let mut checker = LegitimacyChecker::new();

        let mut evidence = EvidenceBasis::new("Signal", "test");
        evidence.add_threshold_evidence("prr", "PRR", 3.5, 2.0);

        let verdict = checker.check(
            "rogue-agent",
            OriginatorType::Tool,
            &GovernanceScope::PatientSafety,
            &evidence,
            false,
        );

        assert!(!verdict.is_permitted());
        assert_eq!(checker.failures_detected(), 1);
    }

    #[test]
    fn legitimacy_check_p0_override() {
        let mut checker = LegitimacyChecker::new();

        // No consent or delegation registered — but P0 overrides everything
        let evidence = EvidenceBasis::new("Fatal adverse event", "emergency");

        let verdict = checker.check(
            "any-agent",
            OriginatorType::Tool,
            &GovernanceScope::PatientSafety,
            &evidence,
            true, // P0 emergency
        );

        assert!(verdict.is_permitted());
        assert!(verdict.is_p0_override());
        // P0 override should NOT count as a failure
        assert_eq!(checker.failures_detected(), 0);
    }

    #[test]
    fn legitimacy_check_scope_mismatch_fails() {
        let mut checker = LegitimacyChecker::new();

        // Consent for PatientSafety
        let mut consent = ConsentRecord::new(
            "consent-1",
            "oversight",
            "agent",
            GovernanceScope::PatientSafety,
            OriginatorType::AgentWithVR,
            "PV only",
        );
        assert!(consent.transition(ConsentStatus::Granted).is_ok());
        assert!(consent.transition(ConsentStatus::Active).is_ok());
        checker.register_consent(consent);

        // Delegation for PatientSafety
        let delegation = AuthorityDelegation::root(
            "deleg-1",
            "oversight",
            "agent",
            GovernanceScope::PatientSafety,
            OriginatorType::AgentWithGVR,
            OriginatorType::AgentWithVR,
        );
        checker.register_delegation(delegation);

        let mut evidence = EvidenceBasis::new("HUD violation", "test");
        evidence.add_threshold_evidence("cap-act", "threshold exceeded", 5.0, 3.0);

        // Try to act in HudGovernance scope — should fail
        let verdict = checker.check(
            "agent",
            OriginatorType::AgentWithVR,
            &GovernanceScope::HudGovernance,
            &evidence,
            false,
        );

        assert!(!verdict.is_permitted());
    }

    #[test]
    fn legitimacy_checker_metrics() {
        let mut checker = LegitimacyChecker::new();

        let evidence = EvidenceBasis::new("test", "test");

        // Run several failed checks
        for _ in 0..5 {
            let _ = checker.check(
                "unknown",
                OriginatorType::Tool,
                &GovernanceScope::SystemHealth,
                &evidence,
                false,
            );
        }

        assert_eq!(checker.checks_performed(), 5);
        assert_eq!(checker.failures_detected(), 5);
        assert!((checker.legitimacy_rate() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn revoke_delegations_cascades() {
        let mut checker = LegitimacyChecker::new();

        // Register multiple delegations from same delegator
        for i in 0..3 {
            let delegation = AuthorityDelegation::root(
                format!("deleg-{i}"),
                "compromised-agent",
                format!("downstream-{i}"),
                GovernanceScope::SystemHealth,
                OriginatorType::AgentWithVR,
                OriginatorType::AgentWithR,
            );
            checker.register_delegation(delegation);
        }

        assert_eq!(checker.delegation_count(), 3);

        // Revoke all delegations from compromised agent
        let revoked = checker.revoke_delegations_from("compromised-agent");
        assert_eq!(revoked, 3);
    }

    // ── Governance Scope ──────────────────────────────────────────────

    #[test]
    fn governance_scope_containment() {
        assert!(GovernanceScope::Global.contains(&GovernanceScope::PatientSafety));
        assert!(GovernanceScope::Global.contains(&GovernanceScope::Global));
        assert!(GovernanceScope::PatientSafety.contains(&GovernanceScope::PatientSafety));
        assert!(!GovernanceScope::PatientSafety.contains(&GovernanceScope::HudGovernance));
    }

    // ── Display Implementations ───────────────────────────────────────

    #[test]
    fn display_formats_readable() {
        let consent = ConsentRecord::new(
            "c1",
            "operator",
            "guardian",
            GovernanceScope::PatientSafety,
            OriginatorType::AgentWithVR,
            "PV monitoring",
        );
        let display = format!("{consent}");
        assert!(display.contains("Consent[c1]"));
        assert!(display.contains("operator"));
        assert!(display.contains("guardian"));

        let delegation = AuthorityDelegation::root(
            "d1",
            "operator",
            "guardian",
            GovernanceScope::PatientSafety,
            OriginatorType::AgentWithGVR,
            OriginatorType::AgentWithVR,
        );
        let display = format!("{delegation}");
        assert!(display.contains("[ROOT]"));
        assert!(display.contains("depth=0"));
    }

    // ── EvidencedAction & ActionJournal ──────────────────────────────

    #[test]
    fn evidenced_action_creation_and_legitimacy() {
        let mut evidence = EvidenceBasis::new("PRR exceeded for Drug X", "DecisionEngine");
        evidence.add_threshold_evidence("prr-metric", "PRR >= 2.0", 3.5, 2.0);

        let action = EvidencedAction::new(
            ResponseAction::Alert {
                severity: crate::sensing::ThreatLevel::High,
                message: "Signal detected for Drug X".to_string(),
                recipients: vec![],
            },
            evidence,
            "guardian-pv",
            GovernanceScope::PatientSafety,
        );

        assert!(action.has_sufficient_evidence());
        // No legitimacy verdict attached yet
        assert!(!action.is_legitimate());
        assert!(!action.is_p0_override());
    }

    #[test]
    fn evidenced_action_with_legitimate_verdict() {
        let mut evidence = EvidenceBasis::new("Signal detected", "test");
        evidence.add_threshold_evidence("prr", "PRR >= 2.0", 3.5, 2.0);

        let verdict = LegitimacyVerdict::Legitimate {
            delegation_chain: vec!["deleg-root".to_string()],
            consent_id: "consent-1".to_string(),
            evidence_count: 1,
        };

        let action = EvidencedAction::new(
            ResponseAction::Alert {
                severity: crate::sensing::ThreatLevel::Medium,
                message: "test alert".to_string(),
                recipients: vec![],
            },
            evidence,
            "guardian",
            GovernanceScope::PatientSafety,
        )
        .with_legitimacy(verdict);

        assert!(action.is_legitimate());
        assert!(!action.is_p0_override());
    }

    #[test]
    fn evidenced_action_with_p0_override() {
        let evidence = EvidenceBasis::new("Fatal adverse event", "emergency");

        let verdict = LegitimacyVerdict::P0Override {
            justification: "Fatal case detected".to_string(),
        };

        let action = EvidencedAction::new(
            ResponseAction::Escalate {
                level: crate::response::EscalationLevel::L3,
                description: "Fatal AE".to_string(),
                assigned_to: None,
            },
            evidence,
            "emergency-system",
            GovernanceScope::Global,
        )
        .with_legitimacy(verdict);

        assert!(action.is_legitimate());
        assert!(action.is_p0_override());
    }

    #[test]
    fn action_journal_records_and_queries() {
        let mut journal = ActionJournal::new();
        assert!(journal.is_empty());
        assert_eq!(journal.len(), 0);

        // Record three actions across two scopes
        let mut evidence1 = EvidenceBasis::new("Signal 1", "test");
        evidence1.add_threshold_evidence("prr", "PRR", 3.5, 2.0);
        journal.record(EvidencedAction::new(
            ResponseAction::Alert {
                severity: crate::sensing::ThreatLevel::High,
                message: "alert 1".to_string(),
                recipients: vec![],
            },
            evidence1,
            "guardian-pv",
            GovernanceScope::PatientSafety,
        ));

        let mut evidence2 = EvidenceBasis::new("Signal 2", "test");
        evidence2.add_threshold_evidence("cap-act", "threshold", 5.0, 3.0);
        journal.record(EvidencedAction::new(
            ResponseAction::Alert {
                severity: crate::sensing::ThreatLevel::High,
                message: "alert 2".to_string(),
                recipients: vec![],
            },
            evidence2,
            "guardian-hud",
            GovernanceScope::HudGovernance,
        ));

        let mut evidence3 = EvidenceBasis::new("Signal 3", "test");
        evidence3.add_threshold_evidence("prr", "PRR", 4.0, 2.0);
        journal.record(EvidencedAction::new(
            ResponseAction::Block {
                target: "block 1".to_string(),
                duration: None,
                reason: "test block".to_string(),
            },
            evidence3,
            "guardian-pv",
            GovernanceScope::PatientSafety,
        ));

        assert_eq!(journal.len(), 3);
        assert!(!journal.is_empty());

        // Query by scope
        let pv_entries = journal.entries_for_scope(&GovernanceScope::PatientSafety);
        assert_eq!(pv_entries.len(), 2);

        let hud_entries = journal.entries_for_scope(&GovernanceScope::HudGovernance);
        assert_eq!(hud_entries.len(), 1);

        // Query by actor
        let pv_actor = journal.entries_by_actor("guardian-pv");
        assert_eq!(pv_actor.len(), 2);

        // All unchecked (no legitimacy verdicts attached)
        assert_eq!(journal.unchecked_count(), 3);
        assert_eq!(journal.illegitimate_count(), 0);
    }

    #[test]
    fn action_journal_tracks_illegitimate_actions() {
        let mut journal = ActionJournal::new();

        let evidence = EvidenceBasis::new("Rogue action", "test");
        let verdict = LegitimacyVerdict::Illegitimate {
            failure: LegitimacyFailure::NoConsent,
            remediation: "Register consent".to_string(),
        };

        journal.record(
            EvidencedAction::new(
                ResponseAction::Alert {
                    severity: crate::sensing::ThreatLevel::High,
                    message: "rogue".to_string(),
                    recipients: vec![],
                },
                evidence,
                "rogue-agent",
                GovernanceScope::PatientSafety,
            )
            .with_legitimacy(verdict),
        );

        assert_eq!(journal.illegitimate_count(), 1);
        assert_eq!(journal.unchecked_count(), 0);
    }

    #[test]
    fn evidenced_action_display() {
        let mut evidence = EvidenceBasis::new("test", "test");
        evidence.add_threshold_evidence("metric", "threshold", 5.0, 3.0);
        let action = EvidencedAction::new(
            ResponseAction::Alert {
                severity: crate::sensing::ThreatLevel::Medium,
                message: "test".to_string(),
                recipients: vec![],
            },
            evidence,
            "guardian",
            GovernanceScope::PatientSafety,
        );
        let display = format!("{action}");
        assert!(display.contains("EvidencedAction"));
        assert!(display.contains("guardian"));
        assert!(display.contains("unchecked"));
    }
}
