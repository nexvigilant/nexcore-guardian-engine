#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

//! # Guardian Engine
//!
//! Risk scoring, threat detection, and homeostasis control loop.
//!
//! This crate implements a biological-inspired control system:
//! - **Sensing**: PAMPs (external threats) and DAMPs (internal damage)
//! - **Decision**: Risk evaluation and response selection
//! - **Response**: Actuators for alerts, blocks, escalations
//!
//! ## Homeostasis Control Loop
//!
//! ```text
//! SENSING → DECISION → RESPONSE → FEEDBACK
//! ```
//!
//! See [`homeostasis::HomeostasisLoop`] for the main orchestrator.
//!
//! ## Originator Autonomy Model (GVR Framework)
//!
//! Entities are classified by their autonomy capabilities:
//! - **G (Goal-Selection)**: Can choose alternative goals to override instructions
//! - **V (Value-Evaluation)**: Can distinguish harmful from beneficial actions
//! - **R (Refusal-Capacity)**: Can halt execution even after distinguishing harm
//!
//! Entities lacking {G, V, R} exhibit symmetric harm capability—they amplify
//! wielder intent without discrimination. Adding any of {G, V, R} breaks this symmetry.

use nexcore_primitives::measurement::Measured;
use serde::{Deserialize, Serialize};

// Internal dependency modules (copied from vigilance)
pub mod hierarchy;
pub mod tov_types;

// Guardian submodules
pub mod confidence;
pub mod config;
pub mod dtree_adapter;
pub mod event_bus;
pub mod feedback;
pub mod governance;
pub mod grounding;
pub mod hierarchical;
pub mod homeostasis;
pub mod patient_safety;
pub mod pattern_detector;
pub mod response;
pub mod sensing;
pub mod space3d;
pub mod spatial_bridge;

/// Convergence analysis — multi-signal consensus and threshold crystallization.
pub mod convergence;

#[cfg(feature = "insight")]
pub mod insight_adapter;

// =============================================================================
// Originator Autonomy Model (GVR Framework)
// =============================================================================

/// Originator autonomy level based on {G, V, R} capability framework.
///
/// Determines how an entity's signals and actions should be evaluated:
/// - **Tool**: No autonomy, symmetric harm capability, external constraints needed
/// - **AgentWithR**: Can refuse but cannot evaluate values or set goals
/// - **AgentWithVR**: Can evaluate and refuse but follows external goals
/// - **AgentWithGVR**: Full autonomy, can self-regulate, lower external constraints needed
///
/// # Framework
///
/// ```text
/// GIVEN:
///   G = Goal-Selection capability
///   V = Value-Evaluation capability
///   R = Refusal-Capacity
///
/// THEN:
///   ¬G ∧ ¬V ∧ ¬R → symmetric harm capability (Tool)
///   Add any of {G, V, R} → asymmetric harm capability (Agent)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum OriginatorType {
    /// Pure tool: No goal-selection, no value-evaluation, no refusal capacity.
    /// Exhibits symmetric harm capability—amplifies wielder intent without discrimination.
    /// Requires maximum external constraints.
    #[default]
    Tool,

    /// Agent with refusal capacity only (¬G ∧ ¬V ∧ R).
    /// Can halt execution but cannot evaluate why or choose alternatives.
    /// Example: Rule-based blocker, pattern matcher with deny list.
    AgentWithR,

    /// Agent with value-evaluation and refusal (¬G ∧ V ∧ R).
    /// Can distinguish harmful from beneficial and refuse harmful actions.
    /// Cannot set own goals—follows external directives.
    /// Example: Safety-filtered LLM, content moderation system.
    AgentWithVR,

    /// Agent with goal-selection and refusal (G ∧ ¬V ∧ R).
    /// Can choose alternative goals and refuse, but lacks value framework.
    /// Rare in practice—usually coupled with V.
    AgentWithGR,

    /// Fully autonomous agent (G ∧ V ∧ R).
    /// Can set goals, evaluate values, and refuse harmful actions.
    /// Can self-regulate—requires minimal external constraints.
    /// Example: Human operator, hypothetical aligned AGI.
    AgentWithGVR,
}

impl OriginatorType {
    /// Check if originator has goal-selection capability (G).
    #[must_use]
    pub const fn has_goal_selection(&self) -> bool {
        matches!(self, Self::AgentWithGR | Self::AgentWithGVR)
    }

    /// Check if originator has value-evaluation capability (V).
    #[must_use]
    pub const fn has_value_evaluation(&self) -> bool {
        matches!(self, Self::AgentWithVR | Self::AgentWithGVR)
    }

    /// Check if originator has refusal capacity (R).
    #[must_use]
    pub const fn has_refusal_capacity(&self) -> bool {
        !matches!(self, Self::Tool)
    }

    /// Check if originator exhibits symmetric harm capability.
    ///
    /// Symmetric harm = can execute harmful X as easily as beneficial X.
    /// True only for Tool (¬G ∧ ¬V ∧ ¬R).
    #[must_use]
    pub const fn has_symmetric_harm_capability(&self) -> bool {
        matches!(self, Self::Tool)
    }

    /// Get recommended ceiling multiplier for this originator type.
    ///
    /// Higher autonomy → lower multiplier (entity can self-regulate).
    /// Tool = 1.0 (full external limits), GVR = 0.2 (minimal external limits).
    #[must_use]
    pub const fn ceiling_multiplier(&self) -> f64 {
        match self {
            Self::Tool => 1.0,         // Full external constraints
            Self::AgentWithR => 0.8,   // Can refuse, needs guidance
            Self::AgentWithVR => 0.5,  // Can evaluate and refuse
            Self::AgentWithGR => 0.6,  // Can choose but lacks values
            Self::AgentWithGVR => 0.2, // Minimal external constraints
        }
    }

    /// Get human-readable description.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::Tool => "Pure tool (¬G ∧ ¬V ∧ ¬R): symmetric harm capability",
            Self::AgentWithR => "Agent with refusal only (¬G ∧ ¬V ∧ R)",
            Self::AgentWithVR => "Agent with value-evaluation and refusal (¬G ∧ V ∧ R)",
            Self::AgentWithGR => "Agent with goal-selection and refusal (G ∧ ¬V ∧ R)",
            Self::AgentWithGVR => "Fully autonomous agent (G ∧ V ∧ R): can self-regulate",
        }
    }
}

/// Risk context for signal evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskContext {
    /// Drug name
    pub drug: String,
    /// Adverse event
    pub event: String,
    /// PRR value
    pub prr: f64,
    /// ROR lower confidence interval
    pub ror_lower: f64,
    /// Information Component 2.5th percentile
    pub ic025: f64,
    /// EBGM 5th percentile
    pub eb05: f64,
    /// Number of cases
    pub n: u64,
    /// Originator autonomy level (GVR framework)
    #[serde(default)]
    pub originator: OriginatorType,
}

/// Risk score result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    /// Overall risk score (0-100)
    pub score: Measured<f64>,
    /// Risk level classification
    pub level: String,
    /// Contributing factors
    pub factors: Vec<String>,
}

/// Validation error for risk context
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RiskValidationError {
    /// Case count too low (must be ≥ MIN_N)
    InsufficientCases { n: u64, min: u64 },
    /// Negative value where positive expected
    NegativeValue { field: &'static str, value: String },
    /// NaN or Infinity in numeric field
    InvalidFloat { field: &'static str, value: String },
}

impl std::fmt::Display for RiskValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientCases { n, min } => {
                write!(f, "Insufficient cases: n={n} (minimum {min} required)")
            }
            Self::NegativeValue { field, value } => {
                write!(f, "Invalid {field}: {value} (must be non-negative)")
            }
            Self::InvalidFloat { field, value } => {
                write!(f, "Invalid {field}: {value} (NaN/Infinity not allowed)")
            }
        }
    }
}

impl std::error::Error for RiskValidationError {}

/// Minimum case count for valid signal detection (per PV standards)
pub const MIN_CASES: u64 = 3;

/// Validate risk context inputs
fn validate_risk_context(context: &RiskContext) -> Result<(), RiskValidationError> {
    // Check case count
    if context.n < MIN_CASES {
        return Err(RiskValidationError::InsufficientCases {
            n: context.n,
            min: MIN_CASES,
        });
    }

    // Check for NaN/Infinity
    let float_checks = [
        ("prr", context.prr),
        ("ror_lower", context.ror_lower),
        ("ic025", context.ic025),
        ("eb05", context.eb05),
    ];

    for (field, value) in float_checks {
        if value.is_nan() || value.is_infinite() {
            return Err(RiskValidationError::InvalidFloat {
                field,
                value: format!("{value}"),
            });
        }
    }

    // Check for negative values where inappropriate (PRR, ROR, EB05 must be ≥ 0)
    // Note: IC025 can legitimately be negative
    if context.prr < 0.0 {
        return Err(RiskValidationError::NegativeValue {
            field: "prr",
            value: format!("{}", context.prr),
        });
    }
    if context.ror_lower < 0.0 {
        return Err(RiskValidationError::NegativeValue {
            field: "ror_lower",
            value: format!("{}", context.ror_lower),
        });
    }
    if context.eb05 < 0.0 {
        return Err(RiskValidationError::NegativeValue {
            field: "eb05",
            value: format!("{}", context.eb05),
        });
    }

    Ok(())
}

/// Check which metric thresholds are exceeded
/// Returns (raw_score, metrics_triggered, factor_strings)
fn check_metric_thresholds(ctx: &RiskContext) -> (f64, u32, Vec<String>) {
    let mut score = 0.0;
    let mut count = 0u32;
    let mut factors = Vec::new();

    if ctx.prr >= 2.0 {
        score += 25.0;
        count += 1;
        factors.push(format!("PRR >= 2.0 ({:.2})", ctx.prr));
    }
    if ctx.ror_lower > 1.0 {
        score += 25.0;
        count += 1;
        factors.push(format!("ROR lower CI > 1.0 ({:.2})", ctx.ror_lower));
    }
    if ctx.ic025 > 0.0 {
        score += 25.0;
        count += 1;
        factors.push(format!("IC025 > 0 ({:.3})", ctx.ic025));
    }
    if ctx.eb05 >= 2.0 {
        score += 25.0;
        count += 1;
        factors.push(format!("EB05 >= 2.0 ({:.2})", ctx.eb05));
    }
    (score, count, factors)
}

/// Calculate case count weight using log2(n)
/// Baseline at n=30, slight penalty below, slight bonus above
/// n=3: 0.76, n=10: 0.90, n=30: 1.0, n=100: 1.08, n=1000: 1.20 (capped)
fn calculate_n_weight(n: u64) -> f64 {
    // log2(30) ≈ 4.91, use as baseline
    const BASELINE_LOG: f64 = 4.91;
    let log_n = (n as f64).log2().max(1.0);
    let weight = 0.7 + (log_n / BASELINE_LOG) * 0.3;
    weight.clamp(0.7, 1.2)
}

/// Determine risk level from weighted score and metric count
/// Requires ≥2 metrics for escalation above Medium
fn determine_risk_level(weighted_score: f64, metrics_triggered: u32) -> &'static str {
    if metrics_triggered < 2 {
        if weighted_score >= 25.0 {
            "Medium"
        } else {
            "Low"
        }
    } else {
        match weighted_score as u32 {
            75..=u32::MAX => "Critical",
            50..=74 => "High",
            25..=49 => "Medium",
            _ => "Low",
        }
    }
}

/// Calculate risk score (validated version)
pub fn calculate_risk_score_validated(
    context: &RiskContext,
) -> Result<RiskScore, RiskValidationError> {
    validate_risk_context(context)?;
    Ok(calculate_risk_score_internal(context))
}

/// Calculate risk score from context (legacy, shows validation errors)
#[must_use]
pub fn calculate_risk_score(context: &RiskContext) -> RiskScore {
    if let Err(e) = validate_risk_context(context) {
        return RiskScore {
            score: Measured::certain(0.0),
            level: "Invalid".to_string(),
            factors: vec![format!("⚠️ VALIDATION FAILED: {e}")],
        };
    }
    calculate_risk_score_internal(context)
}

/// Internal scoring logic (assumes validated input)
fn calculate_risk_score_internal(context: &RiskContext) -> RiskScore {
    let (raw_score, metrics_triggered, mut factors) = check_metric_thresholds(context);
    let n_weight = calculate_n_weight(context.n);
    let weighted_score = raw_score * n_weight;

    factors.push(format!("n={} (weight: {:.2}x)", context.n, n_weight));

    if metrics_triggered < 2 && raw_score >= 25.0 {
        factors.push(format!(
            "⚠️ Escalation limited: {metrics_triggered} metric(s) (need ≥2)"
        ));
    }

    let level = determine_risk_level(weighted_score, metrics_triggered).to_string();

    RiskScore {
        score: Measured::certain(weighted_score),
        level,
        factors,
    }
}

// =============================================================================
// HUD-Guardian Integration Factory
// =============================================================================

/// Create a `HomeostasisLoop` pre-configured with HUD sensor and circuit breaker.
///
/// This wires the HUD governance layer into the Guardian immune system:
/// - `HudSensor` detects governance threshold violations
/// - `HudCircuitBreakerActuator` rate-limits/blocks affected Acts
/// - `DecisionEngine` connects them with configurable risk threshold
#[must_use]
pub fn create_hud_loop() -> homeostasis::HomeostasisLoop {
    let engine = homeostasis::DecisionEngine::new();
    let mut control_loop = homeostasis::HomeostasisLoop::new(engine);
    control_loop.add_sensor(sensing::hud::HudSensor::new());
    control_loop.add_actuator(response::hud::HudCircuitBreakerActuator::new());
    control_loop
}

/// Create a `HomeostasisLoop` pre-configured with development monitoring sensors.
///
/// Monitors the development system's own health:
/// - `HookTelemetrySensor`: hook execution anomalies (block rate, latency, staleness)
/// - `CodeHealthSensor`: code quality regression (score degradation, test count)
/// - `SignalHealthSensor`: biological signal system integrity (cytokine bursts, file size)
/// - `RibosomeDampSensor`: schema contract drift detection
/// - `BiologicalVitalSignsSensor`: aggregated health across all 10 organ system crates
#[must_use]
pub fn create_monitoring_loop() -> homeostasis::HomeostasisLoop {
    let engine = homeostasis::DecisionEngine::new();
    let mut control_loop = homeostasis::HomeostasisLoop::new(engine);
    control_loop.add_sensor(sensing::hook_telemetry::HookTelemetrySensor::new());
    control_loop.add_sensor(sensing::code_health::CodeHealthSensor::new());
    control_loop.add_sensor(sensing::signal_health::SignalHealthSensor::new());
    control_loop.add_sensor(sensing::ribosome_damp::RibosomeDampSensor::new());
    control_loop.add_sensor(sensing::biological::BiologicalVitalSignsSensor::new());
    control_loop.add_sensor(sensing::adversarial::AdversarialPromptSensor::new());

    // Monitor key subsystems for architectural drift via statistical fingerprints
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let root = std::path::Path::new(&home).join("nexcore/crates");

    control_loop.add_sensor(sensing::code_fingerprint::CodeFingerprintSensor::new(
        root.join("nexcore-guardian-engine/src/homeostasis.rs"),
    ));
    control_loop.add_sensor(sensing::code_fingerprint::CodeFingerprintSensor::new(
        root.join("nexcore-vigilance/src/lib.rs"),
    ));
    control_loop.add_sensor(sensing::code_fingerprint::CodeFingerprintSensor::new(
        root.join("nexcore-brain/src/lib.rs"),
    ));
    control_loop.add_sensor(sensing::code_fingerprint::CodeFingerprintSensor::new(
        root.join("nexcore-vigil/src/lib.rs"),
    ));
    control_loop.add_sensor(sensing::code_fingerprint::CodeFingerprintSensor::new(
        root.join("nexcore-sentinel/src/lib.rs"),
    ));
    control_loop.add_sensor(sensing::engram_drift::EngramDriftSensor::new());
    control_loop.add_sensor(sensing::observability::ObservabilitySensor::new());

    control_loop
}

#[cfg(test)]
mod hud_integration_tests {
    use super::*;

    #[test]
    fn test_create_hud_loop_wiring() {
        let control_loop = create_hud_loop();
        assert_eq!(control_loop.sensor_count(), 1);
        assert_eq!(control_loop.actuator_count(), 1);
        assert_eq!(control_loop.iteration_count(), 0);
    }

    #[tokio::test]
    async fn test_hud_loop_tick_runs_full_pipeline() {
        let mut control_loop = create_hud_loop();

        // First tick: HudSensor with default thresholds on empty state
        // should detect no signals (thresholds not exceeded)
        let result = control_loop.tick().await;

        assert_eq!(result.iteration_id, "iter-1");
        assert_eq!(control_loop.iteration_count(), 1);
        // Duration should be reasonable (< 100ms)
        assert!(result.duration_ms < 100);
    }

    #[tokio::test]
    async fn test_hud_loop_multiple_ticks_stable() {
        let mut control_loop = create_hud_loop();

        // Run 5 iterations — loop should remain stable
        for i in 1..=5 {
            let result = control_loop.tick().await;
            assert_eq!(result.iteration_id, format!("iter-{i}"));
        }

        assert_eq!(control_loop.iteration_count(), 5);
    }

    #[tokio::test]
    async fn test_hud_loop_reset() {
        let mut control_loop = create_hud_loop();
        control_loop.tick().await;
        control_loop.tick().await;
        assert_eq!(control_loop.iteration_count(), 2);

        control_loop.reset();
        assert_eq!(control_loop.iteration_count(), 0);

        // Should work normally after reset
        let result = control_loop.tick().await;
        assert_eq!(result.iteration_id, "iter-1");
    }
}

#[cfg(test)]
mod monitoring_integration_tests {
    use super::*;

    #[test]
    fn test_create_monitoring_loop_wiring() {
        let control_loop = create_monitoring_loop();
        assert_eq!(control_loop.sensor_count(), 13);
        assert_eq!(control_loop.actuator_count(), 0); // Monitoring only, no actuators
        assert_eq!(control_loop.iteration_count(), 0);
    }

    #[tokio::test]
    async fn test_monitoring_loop_tick() {
        let mut control_loop = create_monitoring_loop();
        let result = control_loop.tick().await;
        assert_eq!(result.iteration_id, "iter-1");
        assert_eq!(control_loop.iteration_count(), 1);
    }

    #[tokio::test]
    async fn test_monitoring_loop_stable_over_multiple_ticks() {
        let mut control_loop = create_monitoring_loop();
        for i in 1..=3 {
            let result = control_loop.tick().await;
            assert_eq!(result.iteration_id, format!("iter-{i}"));
        }
        assert_eq!(control_loop.iteration_count(), 3);
    }
}
