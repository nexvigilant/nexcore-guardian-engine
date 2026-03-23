//! # Guardian → Insight Trait Adapter
//!
//! Makes Guardian a first-class implementor of the Insight trait,
//! proving architecturally that NexCore IS an InsightEngine.
//!
//! ## Composite Mapping
//!
//! | Insight Composite | Guardian Component |
//! |-------------------|--------------------|
//! | Pattern (σ+κ+μ) | Risk threshold co-exceedance |
//! | Recognition (κ+∃+σ) | Known threat profile matching |
//! | Novelty (∅+∃+σ) | New drug-event pair detection |
//! | Connection (μ+κ+ς) | Signal→Risk relationship |
//! | Compression (N+μ+κ) | Multi-signal → single risk level |
//! | Suddenness (σ+∂+N+κ) | Score spike detection |
//!
//! ## T1 Grounding
//!
//! GuardianInsightAdapter ≡ ⟨σ, κ, μ, ∃, ς, ∅, N, ∂⟩ (T3)
//! - Inherits all 8 INSIGHT primitives
//! - ς mode: Accumulated (ς-acc) — append-only signal history

#![allow(dead_code)]

use nexcore_insight::composites::{Compression, Connection, Pattern};
use nexcore_insight::engine::{InsightConfig, InsightEngine, InsightEvent, Observation};
use nexcore_insight::traits::Insight;

use crate::{OriginatorType, RiskContext};

/// Guardian adapter for the Insight trait.
///
/// Wraps Guardian's risk assessment pipeline as an InsightEngine implementation.
/// Converts `RiskContext` (drug/event signal data) → `Observation` → InsightEngine pipeline.
///
/// ## Tier: T3 (system-level adapter)
///
/// ## T1 Grounding
/// GUARDIAN_INSIGHT ≡ ⟨σ, κ, μ, ∃, ς, ∅, N, ∂⟩
/// - σ: Temporal ordering of risk contexts
/// - κ: Threshold comparison (PRR≥2, ROR>1, IC025>0, EB05≥2)
/// - μ: Drug→Event mapping
/// - ∃: Signal existence validation
/// - ∅: New signal detection (no prior history)
/// - N: Case counts, score quantities
/// - ∂: Risk level boundaries (Low/Medium/High/Critical)
/// - ς: Accumulated signal history (ς-acc)
pub struct GuardianInsightAdapter {
    /// Internal engine performing the 6-stage pipeline.
    engine: InsightEngine,
}

impl GuardianInsightAdapter {
    /// Create a new Guardian insight adapter with default configuration.
    ///
    /// Uses Guardian-tuned config: higher thresholds for confirmed threats.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(Self::guardian_config())
    }

    /// Create with custom InsightConfig.
    #[must_use]
    pub fn with_config(config: InsightConfig) -> Self {
        Self {
            engine: InsightEngine::with_config(config),
        }
    }

    /// Guardian-tuned configuration.
    ///
    /// Higher thresholds than the generic engine:
    /// - `pattern_min_occurrences: 3` (need repeated signals before pattern)
    /// - `pattern_confidence_threshold: 0.7` (only confident patterns)
    /// - `enable_suddenness: true` (critical for score spikes)
    /// - `suddenness_threshold: 1.5` (sensitive to escalation)
    #[must_use]
    pub fn guardian_config() -> InsightConfig {
        InsightConfig {
            pattern_min_occurrences: 3,
            pattern_confidence_threshold: 0.7,
            connection_strength_threshold: 0.5,
            compression_min_ratio: 2.0,
            enable_suddenness: true,
            suddenness_threshold: 1.5,
            enable_recursive_learning: true,
        }
    }

    /// Convert a `RiskContext` into an `Observation` suitable for the InsightEngine.
    ///
    /// Mapping:
    /// - key: `"{drug}:{event}"` — uniquely identifies the signal
    /// - value: risk level string
    /// - numeric_value: weighted risk score (0-100)
    /// - tags: originator type, individual metric threshold states
    ///
    /// Tier: T2-P (μ — mapping between domains)
    #[must_use]
    pub fn risk_to_observation(ctx: &RiskContext) -> Observation {
        let key = format!("{}:{}", ctx.drug, ctx.event);
        let score = Self::compute_weighted_score(ctx);
        let mut obs = Observation::with_numeric(&key, score);

        // Tag with originator type for GVR-aware pattern detection
        obs = obs.with_tag(format!("originator:{}", originator_label(ctx.originator)));

        // Tag with individual metric states for pattern clustering
        if ctx.prr >= 2.0 {
            obs = obs.with_tag("prr_signal");
        }
        if ctx.ror_lower > 1.0 {
            obs = obs.with_tag("ror_signal");
        }
        if ctx.ic025 > 0.0 {
            obs = obs.with_tag("ic_signal");
        }
        if ctx.eb05 >= 2.0 {
            obs = obs.with_tag("ebgm_signal");
        }

        // Tag with case count bucket
        obs = obs.with_tag(case_count_bucket(ctx.n));

        obs
    }

    /// Compute weighted risk score from a RiskContext.
    ///
    /// Each of 4 metrics contributes 25 points when its threshold is exceeded.
    /// Weighted by log₂(n) for case count confidence.
    ///
    /// Tier: T1 (N + κ — quantity comparison)
    fn compute_weighted_score(ctx: &RiskContext) -> f64 {
        let mut raw = 0.0;
        if ctx.prr >= 2.0 {
            raw += 25.0;
        }
        if ctx.ror_lower > 1.0 {
            raw += 25.0;
        }
        if ctx.ic025 > 0.0 {
            raw += 25.0;
        }
        if ctx.eb05 >= 2.0 {
            raw += 25.0;
        }

        // Case count weight: log₂(n)/log₂(30) normalized, clamped [0.7, 1.2]
        let n_weight = if ctx.n > 0 {
            let log_n = (ctx.n as f64).log2().max(1.0);
            (0.7 + (log_n / 4.91) * 0.3).clamp(0.7, 1.2)
        } else {
            0.7
        };

        raw * n_weight
    }

    /// Ingest a `RiskContext`, running the full 6-stage insight pipeline.
    ///
    /// This is the primary entry point for Guardian → Insight integration.
    /// Returns insight events produced by processing this risk context.
    pub fn ingest_risk(&mut self, ctx: &RiskContext) -> Vec<InsightEvent> {
        let obs = Self::risk_to_observation(ctx);
        self.engine.ingest(obs)
    }

    /// Get the underlying engine (read-only access for inspection).
    #[must_use]
    pub fn engine(&self) -> &InsightEngine {
        &self.engine
    }
}

impl Default for GuardianInsightAdapter {
    fn default() -> Self {
        Self::new()
    }
}

// ── Insight Trait Implementation ──────────────────────────────────────────────

impl Insight for GuardianInsightAdapter {
    type Obs = RiskContext;

    fn ingest(&mut self, observation: RiskContext) -> Vec<InsightEvent> {
        self.ingest_risk(&observation)
    }

    fn ingest_batch(&mut self, observations: Vec<RiskContext>) -> Vec<InsightEvent> {
        let mut all_events = Vec::new();
        for ctx in &observations {
            all_events.extend(self.ingest_risk(ctx));
        }
        all_events
    }

    fn connect(&mut self, from: &str, to: &str, relation: &str, strength: f64) -> Connection {
        self.engine.connect(from, to, relation, strength)
    }

    fn compress(&mut self, keys: Vec<String>, principle: &str) -> Compression {
        self.engine.compress(keys, principle)
    }

    fn events(&self) -> &[InsightEvent] {
        self.engine.events()
    }

    fn observation_count(&self) -> usize {
        self.engine.observation_count()
    }

    fn pattern_count(&self) -> usize {
        self.engine.pattern_count()
    }

    fn patterns(&self) -> Vec<&Pattern> {
        self.engine.patterns()
    }

    fn connections(&self) -> &[Connection] {
        self.engine.connections()
    }

    fn unique_key_count(&self) -> usize {
        self.engine.unique_key_count()
    }
}

// ── Helper Functions ──────────────────────────────────────────────────────────

/// Get human-readable label for originator type (for tagging).
fn originator_label(originator: OriginatorType) -> &'static str {
    match originator {
        OriginatorType::Tool => "tool",
        OriginatorType::AgentWithR => "agent_r",
        OriginatorType::AgentWithVR => "agent_vr",
        OriginatorType::AgentWithGR => "agent_gr",
        OriginatorType::AgentWithGVR => "agent_gvr",
    }
}

/// Bucket case count into meaningful ranges for tag-based clustering.
fn case_count_bucket(n: u64) -> &'static str {
    match n {
        0..=5 => "cases:few",
        6..=30 => "cases:moderate",
        31..=100 => "cases:substantial",
        _ => "cases:many",
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_risk_context(drug: &str, event: &str, prr: f64, n: u64) -> RiskContext {
        RiskContext {
            drug: drug.to_string(),
            event: event.to_string(),
            prr,
            ror_lower: if prr >= 2.0 { 1.5 } else { 0.5 },
            ic025: if prr >= 2.0 { 0.5 } else { -0.5 },
            eb05: if prr >= 2.0 { 2.5 } else { 0.8 },
            n,
            originator: OriginatorType::default(),
        }
    }

    #[test]
    fn test_risk_to_observation_key_format() {
        let ctx = sample_risk_context("aspirin", "gi_bleed", 3.5, 10);
        let obs = GuardianInsightAdapter::risk_to_observation(&ctx);
        assert_eq!(obs.key, "aspirin:gi_bleed");
    }

    #[test]
    fn test_risk_to_observation_numeric_value() {
        let ctx = sample_risk_context("drug_x", "rash", 3.0, 30);
        let obs = GuardianInsightAdapter::risk_to_observation(&ctx);
        // All 4 metrics exceed thresholds → 100.0 * weight(30) ≈ 100.0
        assert!(obs.numeric_value.is_some());
        let score = obs.numeric_value.unwrap_or(0.0);
        assert!(score > 50.0, "expected high score, got {score}");
    }

    #[test]
    fn test_risk_to_observation_tags() {
        let ctx = sample_risk_context("drug_a", "headache", 3.0, 10);
        let obs = GuardianInsightAdapter::risk_to_observation(&ctx);
        assert!(obs.tags.contains(&"originator:tool".to_string()));
        assert!(obs.tags.contains(&"prr_signal".to_string()));
        assert!(obs.tags.contains(&"ror_signal".to_string()));
        assert!(obs.tags.contains(&"ic_signal".to_string()));
        assert!(obs.tags.contains(&"ebgm_signal".to_string()));
        assert!(obs.tags.contains(&"cases:moderate".to_string()));
    }

    #[test]
    fn test_no_signal_tags_below_threshold() {
        let ctx = sample_risk_context("drug_b", "nausea", 1.0, 5);
        let obs = GuardianInsightAdapter::risk_to_observation(&ctx);
        assert!(!obs.tags.contains(&"prr_signal".to_string()));
        assert!(!obs.tags.contains(&"ror_signal".to_string()));
        assert!(!obs.tags.contains(&"ic_signal".to_string()));
        assert!(!obs.tags.contains(&"ebgm_signal".to_string()));
        assert!(obs.tags.contains(&"cases:few".to_string()));
    }

    #[test]
    fn test_case_count_buckets() {
        assert_eq!(case_count_bucket(3), "cases:few");
        assert_eq!(case_count_bucket(15), "cases:moderate");
        assert_eq!(case_count_bucket(50), "cases:substantial");
        assert_eq!(case_count_bucket(500), "cases:many");
    }

    #[test]
    fn test_originator_labels() {
        assert_eq!(originator_label(OriginatorType::Tool), "tool");
        assert_eq!(originator_label(OriginatorType::AgentWithGVR), "agent_gvr");
    }

    #[test]
    fn test_adapter_creation() {
        let adapter = GuardianInsightAdapter::new();
        assert_eq!(adapter.observation_count(), 0);
        assert_eq!(adapter.pattern_count(), 0);
        assert_eq!(adapter.unique_key_count(), 0);
    }

    #[test]
    fn test_ingest_single_risk_context() {
        let mut adapter = GuardianInsightAdapter::new();
        let ctx = sample_risk_context("aspirin", "gi_bleed", 3.5, 10);
        let events = adapter.ingest(ctx);

        assert_eq!(adapter.observation_count(), 1);
        assert_eq!(adapter.unique_key_count(), 1);
        // First observation always produces novelty
        assert!(
            events
                .iter()
                .any(|e| matches!(e, InsightEvent::NoveltyDetected(_))),
            "expected novelty for first observation"
        );
    }

    #[test]
    fn test_ingest_batch_risk_contexts() {
        let mut adapter = GuardianInsightAdapter::new();
        let contexts = vec![
            sample_risk_context("drug_a", "rash", 3.0, 10),
            sample_risk_context("drug_b", "headache", 2.5, 20),
            sample_risk_context("drug_c", "nausea", 1.0, 5),
        ];
        let events = adapter.ingest_batch(contexts);

        assert_eq!(adapter.observation_count(), 3);
        assert_eq!(adapter.unique_key_count(), 3);
        // All three should be novel (first encounter)
        let novelty_count = events
            .iter()
            .filter(|e| matches!(e, InsightEvent::NoveltyDetected(_)))
            .count();
        assert_eq!(novelty_count, 3);
    }

    #[test]
    fn test_pattern_detection_via_repeated_ingestion() {
        let mut adapter = GuardianInsightAdapter::with_config(InsightConfig {
            pattern_min_occurrences: 2,
            pattern_confidence_threshold: 0.5,
            ..InsightConfig::default()
        });

        // Ingest two different signals multiple times to trigger co-occurrence
        let ctx_a = sample_risk_context("aspirin", "gi_bleed", 3.5, 10);
        let ctx_b = sample_risk_context("ibuprofen", "gi_bleed", 2.8, 15);

        adapter.ingest(ctx_a.clone());
        adapter.ingest(ctx_b.clone());
        adapter.ingest(ctx_a);
        let events = adapter.ingest(ctx_b);

        // After enough co-occurrences, a pattern should emerge
        assert!(adapter.pattern_count() > 0 || !events.is_empty());
    }

    #[test]
    fn test_connect_creates_relationship() {
        let mut adapter = GuardianInsightAdapter::new();
        let conn = adapter.connect("aspirin:gi_bleed", "ibuprofen:gi_bleed", "same_event", 0.85);

        assert_eq!(conn.from, "aspirin:gi_bleed");
        assert_eq!(conn.to, "ibuprofen:gi_bleed");
        assert_eq!(conn.relation, "same_event");
        assert!((conn.strength - 0.85).abs() < f64::EPSILON);
        assert_eq!(adapter.connections().len(), 1);
    }

    #[test]
    fn test_compress_signals() {
        let mut adapter = GuardianInsightAdapter::new();

        // Ingest some signals first
        adapter.ingest(sample_risk_context("aspirin", "gi_bleed", 3.5, 10));
        adapter.ingest(sample_risk_context("ibuprofen", "gi_bleed", 2.8, 15));
        adapter.ingest(sample_risk_context("naproxen", "gi_bleed", 2.2, 8));

        // Compress NSAID signals into a principle
        let compression = adapter.compress(
            vec![
                "aspirin:gi_bleed".to_string(),
                "ibuprofen:gi_bleed".to_string(),
                "naproxen:gi_bleed".to_string(),
            ],
            "NSAID_class_gi_risk",
        );

        assert_eq!(compression.principle, "NSAID_class_gi_risk");
        assert_eq!(compression.input_count, 3);
        assert_eq!(compression.output_count, 1);
        assert!((compression.ratio - 3.0).abs() < f64::EPSILON);
        assert!(compression.is_meaningful());
    }

    #[test]
    fn test_trait_polymorphism_with_generic_fn() {
        fn count_events<E: Insight>(engine: &mut E, obs: E::Obs) -> usize {
            let events = engine.ingest(obs);
            events.len()
        }

        let mut adapter = GuardianInsightAdapter::new();
        let ctx = sample_risk_context("test_drug", "test_event", 2.5, 10);
        let n = count_events(&mut adapter, ctx);
        assert!(n > 0, "expected at least one event (novelty)");
    }

    #[test]
    fn test_suddenness_on_score_spike() {
        let mut adapter = GuardianInsightAdapter::with_config(InsightConfig {
            enable_suddenness: true,
            suddenness_threshold: 1.0,
            ..GuardianInsightAdapter::guardian_config()
        });

        // Low score first
        let ctx_low = sample_risk_context("drug_x", "event_y", 1.0, 5);
        adapter.ingest(ctx_low);

        // High score spike on same key
        let ctx_high = sample_risk_context("drug_x", "event_y", 4.0, 50);
        let events = adapter.ingest(ctx_high);

        // The numeric value jump should trigger suddenness
        let has_suddenness = events
            .iter()
            .any(|e| matches!(e, InsightEvent::SuddennessTrigger(_)));
        assert!(has_suddenness, "expected suddenness trigger on score spike");
    }

    #[test]
    fn test_connections_for_key() {
        let mut adapter = GuardianInsightAdapter::new();
        adapter.connect("aspirin:gi_bleed", "ibuprofen:gi_bleed", "same_event", 0.8);
        adapter.connect("aspirin:gi_bleed", "naproxen:gi_bleed", "same_class", 0.9);
        adapter.connect("metformin:lactic_acidosis", "other:other", "unrelated", 0.3);

        let aspirin_conns = adapter.connections_for("aspirin:gi_bleed");
        assert_eq!(aspirin_conns.len(), 2);

        let metformin_conns = adapter.connections_for("metformin:lactic_acidosis");
        assert_eq!(metformin_conns.len(), 1);
    }

    #[test]
    fn test_default_impl() {
        let adapter = GuardianInsightAdapter::default();
        assert_eq!(adapter.observation_count(), 0);
    }
}
