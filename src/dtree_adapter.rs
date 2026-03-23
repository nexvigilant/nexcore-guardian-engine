//! # Decision Tree Adapter for Guardian
//!
//! Bridges nexcore-dtree CART engine with Guardian domain types.
//! Extracts feature vectors from `RiskContext`, trains on historical
//! (risk → response_label) pairs, and predicts response actions.
//!
//! Tier: T2-C (composes T1 mapping + state with T3 domain types)
//! Grounds to: T1::Mapping (μ) — feature extraction, T1::State (ς) — trained model

use nexcore_dtree::prelude::*;

use super::RiskContext;
use super::response::ResponseAction;

// ============================================================================
// Feature extraction
// ============================================================================

/// Feature indices for the risk context vector
pub mod feature_index {
    /// PRR (Proportional Reporting Ratio)
    pub const PRR: usize = 0;
    /// ROR lower confidence interval bound
    pub const ROR_LOWER: usize = 1;
    /// IC025 (Information Component 2.5th percentile)
    pub const IC025: usize = 2;
    /// EB05 (EBGM 5th percentile)
    pub const EB05: usize = 3;
    /// Case count (log2-transformed for scale normalization)
    pub const N_LOG2: usize = 4;
    /// Total feature count
    pub const COUNT: usize = 5;
}

/// Feature names for explainability
const FEATURE_NAMES: [&str; feature_index::COUNT] = ["prr", "ror_lower", "ic025", "eb05", "n_log2"];

/// Extract a feature vector from a RiskContext.
///
/// Returns 5 continuous features:
/// `[prr, ror_lower, ic025, eb05, log2(n)]`
///
/// Tier: T1 Mapping (μ) — domain → numeric
#[must_use]
pub fn extract_features(ctx: &RiskContext) -> Vec<Feature> {
    let n_log2 = if ctx.n > 0 {
        (ctx.n as f64).log2()
    } else {
        0.0
    };

    vec![
        Feature::Continuous(ctx.prr),
        Feature::Continuous(ctx.ror_lower),
        Feature::Continuous(ctx.ic025),
        Feature::Continuous(ctx.eb05),
        Feature::Continuous(n_log2),
    ]
}

/// Extract raw f64 values (for batch training)
#[must_use]
pub fn extract_raw(ctx: &RiskContext) -> Vec<f64> {
    let n_log2 = if ctx.n > 0 {
        (ctx.n as f64).log2()
    } else {
        0.0
    };
    vec![ctx.prr, ctx.ror_lower, ctx.ic025, ctx.eb05, n_log2]
}

// ============================================================================
// Response labels
// ============================================================================

/// Canonical response labels for classification
pub mod response_label {
    /// Escalation (Critical risk)
    pub const ESCALATE: &str = "Escalate";
    /// Alert (High risk)
    pub const ALERT: &str = "Alert";
    /// Audit log (Medium risk)
    pub const AUDIT_LOG: &str = "AuditLog";
    /// No action (Low risk)
    pub const NO_ACTION: &str = "NoAction";
}

/// Map a ResponseAction variant to a canonical label.
///
/// Tier: T1 Mapping (μ) — variant → string
#[must_use]
pub fn action_to_label(action: &ResponseAction) -> &'static str {
    match action {
        ResponseAction::Escalate { .. } => response_label::ESCALATE,
        ResponseAction::Alert { .. } => response_label::ALERT,
        ResponseAction::Block { .. } => response_label::ALERT,
        ResponseAction::AuditLog { .. } => response_label::AUDIT_LOG,
        ResponseAction::NoAction { .. } => response_label::NO_ACTION,
        ResponseAction::RateLimit { .. } => response_label::ALERT,
        ResponseAction::Quarantine { .. } => response_label::ESCALATE,
        ResponseAction::StepUpAuth { .. } => response_label::ALERT,
        ResponseAction::TerminateSession { .. } => response_label::ESCALATE,
    }
}

/// Map a label back to a default ResponseAction template.
///
/// These are templates — callers should enrich with context-specific details.
#[must_use]
pub fn label_to_action(label: &str, ctx: &RiskContext) -> ResponseAction {
    match label {
        response_label::ESCALATE => ResponseAction::Escalate {
            level: super::response::EscalationLevel::L3,
            description: format!("DTree: Critical signal for {} + {}", ctx.drug, ctx.event),
            assigned_to: Some("pv-team@example.com".to_string()),
        },
        response_label::ALERT => ResponseAction::Alert {
            severity: super::sensing::ThreatLevel::High,
            message: format!("DTree: High-risk signal for {} + {}", ctx.drug, ctx.event),
            recipients: vec!["pv-team@example.com".to_string()],
        },
        response_label::AUDIT_LOG => ResponseAction::AuditLog {
            category: "pv-dtree".to_string(),
            message: format!("DTree: Medium-risk signal for {} + {}", ctx.drug, ctx.event),
            data: std::collections::HashMap::new(),
        },
        _ => ResponseAction::NoAction {
            reason: format!("DTree: Low risk for {} + {}", ctx.drug, ctx.event),
        },
    }
}

// ============================================================================
// Guardian Decision Backend
// ============================================================================

/// Decision tree-backed risk classifier for Guardian.
///
/// Wraps a trained `DecisionTree` and provides domain-typed prediction.
/// Falls back to `None` when confidence is below threshold.
///
/// Tier: T2-C (composed mapping + state)
pub struct DtreeDecisionBackend {
    /// The trained decision tree
    tree: DecisionTree,
    /// Minimum confidence to trust the prediction
    min_confidence: f64,
}

impl DtreeDecisionBackend {
    /// Train a new backend from historical risk/response pairs.
    ///
    /// # Errors
    /// Returns `Err` if training data is empty or training fails.
    pub fn train(
        contexts: &[RiskContext],
        actions: &[ResponseAction],
        config: TreeConfig,
    ) -> Result<Self, nexcore_dtree::train::TrainError> {
        if contexts.is_empty() || contexts.len() != actions.len() {
            return Err(nexcore_dtree::train::TrainError::EmptyData);
        }

        let features: Vec<Vec<Feature>> = contexts.iter().map(|c| extract_features(c)).collect();

        let labels: Vec<String> = actions
            .iter()
            .map(|a| action_to_label(a).to_string())
            .collect();

        let mut tree = fit(&features, &labels, config)?;
        tree.set_feature_names(FEATURE_NAMES.iter().map(|s| (*s).to_string()).collect());

        Ok(Self {
            tree,
            min_confidence: 0.6,
        })
    }

    /// Set the minimum confidence threshold.
    #[must_use]
    pub fn with_min_confidence(mut self, threshold: f64) -> Self {
        self.min_confidence = threshold.clamp(0.0, 1.0);
        self
    }

    /// Predict a response action for a risk context.
    ///
    /// Returns `None` if the tree's confidence is below `min_confidence`,
    /// signaling the caller to fall back to the rule-based engine.
    #[must_use]
    pub fn predict(&self, ctx: &RiskContext) -> Option<GuardianPrediction> {
        let features = extract_features(ctx);
        let result = predict(&self.tree, &features).ok()?;

        if result.confidence.value() < self.min_confidence {
            return None;
        }

        let action = label_to_action(&result.prediction, ctx);
        let path: Vec<String> = result.path.iter().map(|step| format!("{step}")).collect();

        Some(GuardianPrediction {
            action,
            label: result.prediction,
            confidence: result.confidence.value(),
            path,
            leaf_samples: result.leaf_samples,
        })
    }

    /// Get feature importance scores.
    #[must_use]
    pub fn importance(&self) -> Vec<FeatureImportance> {
        feature_importance(&self.tree)
    }

    /// Get the underlying tree reference.
    #[must_use]
    pub fn tree(&self) -> &DecisionTree {
        &self.tree
    }
}

/// Prediction result with Guardian-specific context
#[derive(Debug, Clone)]
pub struct GuardianPrediction {
    /// The predicted response action
    pub action: ResponseAction,
    /// The raw label (Escalate/Alert/AuditLog/NoAction)
    pub label: String,
    /// Tree confidence (0.0-1.0)
    pub confidence: f64,
    /// Explainable decision path
    pub path: Vec<String>,
    /// Number of training samples in the matching leaf
    pub leaf_samples: usize,
}

// ============================================================================
// DecisionMaker Implementation
// ============================================================================

impl super::homeostasis::DecisionMaker for DtreeDecisionBackend {
    fn evaluate_signals(
        &mut self,
        signals: &[super::sensing::ThreatSignal<String>],
    ) -> Vec<ResponseAction> {
        let mut actions = Vec::new();

        for signal in signals {
            // Extract drug+event from metadata or signal pattern
            let drug = signal
                .metadata
                .get("drug")
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            let event = signal
                .metadata
                .get("event")
                .cloned()
                .unwrap_or_else(|| signal.pattern.clone());

            let ctx = RiskContext {
                drug,
                event,
                prr: signal
                    .metadata
                    .get("prr")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0.0),
                ror_lower: signal
                    .metadata
                    .get("ror_lower")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0.0),
                ic025: signal
                    .metadata
                    .get("ic025")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0.0),
                eb05: signal
                    .metadata
                    .get("eb05")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0.0),
                n: signal
                    .metadata
                    .get("n")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0),
                originator: Default::default(),
            };

            match self.predict(&ctx) {
                Some(prediction) => actions.push(prediction.action),
                None => actions.push(ResponseAction::NoAction {
                    reason: format!("DTree: low confidence for {}", signal.pattern),
                }),
            }
        }

        actions
    }

    fn decay(&mut self, _elapsed_seconds: f64) {
        // Decision trees are stateless w.r.t. time — no decay needed
    }

    fn reset(&mut self) {
        // Decision trees are stateless w.r.t. accumulated state — no reset needed
    }

    fn name(&self) -> &str {
        "dtree-decision-backend"
    }

    fn get_threshold(&self) -> f64 {
        // Map 0.0-1.0 confidence to 0-100 threshold scale.
        (self.min_confidence * 100.0).clamp(0.0, 100.0)
    }

    fn set_threshold(&mut self, threshold: f64) -> f64 {
        let old = self.get_threshold();
        let clamped = threshold.clamp(0.0, 100.0) / 100.0;
        self.min_confidence = clamped;
        old
    }
}

// ============================================================================
// Fallback Engine (DTree + Rule-Based)
// ============================================================================

/// Composite decision engine: tries the decision tree first, falls back
/// to the rule-based engine when tree confidence is below threshold.
///
/// Tier: T2-C (composed T2-C dtree + T2-C rule-based)
pub struct FallbackEngine {
    /// Primary: decision tree backend
    dtree: DtreeDecisionBackend,
    /// Fallback: rule-based engine
    rule_based: super::homeostasis::RuleBasedEngine,
}

impl FallbackEngine {
    /// Create a new fallback engine from a trained tree and default rule-based engine.
    #[must_use]
    pub fn new(dtree: DtreeDecisionBackend) -> Self {
        Self {
            dtree,
            rule_based: super::homeostasis::RuleBasedEngine::new(),
        }
    }

    /// Create with a custom rule-based fallback.
    #[must_use]
    pub fn with_rule_based(
        dtree: DtreeDecisionBackend,
        rule_based: super::homeostasis::RuleBasedEngine,
    ) -> Self {
        Self { dtree, rule_based }
    }
}

impl super::homeostasis::DecisionMaker for FallbackEngine {
    fn evaluate_signals(
        &mut self,
        signals: &[super::sensing::ThreatSignal<String>],
    ) -> Vec<ResponseAction> {
        // Try dtree first
        let dtree_actions = self.dtree.evaluate_signals(signals);

        // Check if any actions are NoAction due to low confidence — replace with rule-based
        let mut final_actions = Vec::new();
        for (i, action) in dtree_actions.into_iter().enumerate() {
            if matches!(&action, ResponseAction::NoAction { reason } if reason.contains("low confidence"))
            {
                // Fall back to rule-based for this signal
                let fallback = self.rule_based.evaluate_signals(&signals[i..=i]);
                final_actions.extend(fallback);
            } else {
                final_actions.push(action);
            }
        }
        final_actions
    }

    fn decay(&mut self, elapsed_seconds: f64) {
        self.rule_based.decay(elapsed_seconds);
    }

    fn reset(&mut self) {
        self.rule_based.reset();
    }

    fn name(&self) -> &str {
        "fallback-engine"
    }

    fn get_threshold(&self) -> f64 {
        self.rule_based.get_threshold()
    }

    fn set_threshold(&mut self, threshold: f64) -> f64 {
        self.rule_based.set_threshold(threshold)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OriginatorType;

    fn ctx(prr: f64, ror: f64, ic: f64, eb: f64, n: u64) -> RiskContext {
        RiskContext {
            drug: "TestDrug".to_string(),
            event: "TestEvent".to_string(),
            prr,
            ror_lower: ror,
            ic025: ic,
            eb05: eb,
            n,
            originator: OriginatorType::default(),
        }
    }

    fn escalate_action() -> ResponseAction {
        ResponseAction::Escalate {
            level: super::super::response::EscalationLevel::L3,
            description: String::new(),
            assigned_to: None,
        }
    }

    fn no_action() -> ResponseAction {
        ResponseAction::NoAction {
            reason: String::new(),
        }
    }

    fn training_data() -> (Vec<RiskContext>, Vec<ResponseAction>) {
        let contexts = vec![
            ctx(5.0, 3.0, 1.5, 4.0, 50),
            ctx(4.5, 2.8, 1.2, 3.5, 40),
            ctx(6.0, 4.0, 2.0, 5.0, 100),
            ctx(0.5, 0.3, -0.5, 0.4, 3),
            ctx(0.8, 0.5, -0.2, 0.6, 5),
            ctx(0.3, 0.2, -1.0, 0.2, 2),
        ];
        let actions = vec![
            escalate_action(),
            escalate_action(),
            escalate_action(),
            no_action(),
            no_action(),
            no_action(),
        ];
        (contexts, actions)
    }

    fn trained_backend() -> DtreeDecisionBackend {
        let (contexts, actions) = training_data();
        DtreeDecisionBackend::train(&contexts, &actions, TreeConfig::default())
            .ok()
            .expect("train succeeded")
    }

    #[test]
    fn extract_features_produces_5_values() {
        let features = extract_features(&ctx(3.5, 2.0, 0.5, 2.5, 10));
        assert_eq!(features.len(), feature_index::COUNT);
    }

    #[test]
    fn extract_features_zero_n() {
        let raw = extract_raw(&ctx(1.0, 0.5, -0.3, 0.8, 0));
        assert!((raw[feature_index::N_LOG2]).abs() < f64::EPSILON);
    }

    #[test]
    fn action_label_roundtrip() {
        let c = ctx(3.5, 2.0, 0.5, 2.5, 10);
        for action in &[escalate_action(), no_action()] {
            let label = action_to_label(action);
            let reconstructed = label_to_action(label, &c);
            assert_eq!(action_to_label(&reconstructed), label);
        }
    }

    #[test]
    fn predict_strong_signal() {
        let backend = trained_backend();
        let strong = ctx(5.5, 3.5, 1.8, 4.5, 60);
        let pred = backend.predict(&strong);
        assert!(pred.is_some());
        let p = pred.expect("predicted");
        assert_eq!(p.label, response_label::ESCALATE);
        assert!(p.confidence > 0.5);
    }

    #[test]
    fn predict_weak_signal() {
        let backend = trained_backend();
        let weak = ctx(0.4, 0.2, -0.8, 0.3, 2);
        let pred = backend.predict(&weak);
        assert!(pred.is_some());
        let p = pred.expect("predicted");
        assert_eq!(p.label, response_label::NO_ACTION);
    }

    #[test]
    fn feature_importance_nonzero() {
        let backend = trained_backend();
        let imp = backend.importance();
        assert!(!imp.is_empty());
        assert!(imp.iter().any(|fi| fi.importance > 0.0));
    }

    #[test]
    fn min_confidence_filter() {
        let backend = trained_backend().with_min_confidence(0.99);
        let borderline = ctx(2.0, 1.0, 0.0, 1.0, 10);
        // With only 6 samples, leaf confidence is 1.0 (pure leaves)
        // Just verify no panic
        let _pred = backend.predict(&borderline);
    }
}
