//! # Homeostasis Control Loop
//!
//! Biological-inspired control loop for threat detection and response.
//! Implements the immune system model:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    HOMEOSTASIS LOOP                         │
//! │                                                             │
//! │  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
//! │  │   SENSING   │───▶│  DECISION   │───▶│  RESPONSE   │     │
//! │  │  (PAMPs/    │    │   ENGINE    │    │ (Actuators) │     │
//! │  │   DAMPs)    │    │             │    │             │     │
//! │  └─────────────┘    └─────────────┘    └─────────────┘     │
//! │        ▲                                      │             │
//! │        │              FEEDBACK                │             │
//! │        └──────────────────────────────────────┘             │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Example
//!
//! ```ignore
//! use nexcore_vigilance::guardian::homeostasis::{HomeostasisLoop, DecisionEngine};
//! use nexcore_vigilance::guardian::sensing::ExternalSensor;
//! use nexcore_vigilance::guardian::response::AlertActuator;
//!
//! let mut loop_controller = HomeostasisLoop::new(DecisionEngine::default());
//! loop_controller.add_sensor(Box::new(ExternalSensor::new()));
//! loop_controller.add_actuator(Box::new(AlertActuator::new()));
//!
//! // Run one iteration
//! let results = loop_controller.tick();
//! ```

// ============================================================================
// Constants - Homeostasis Control Loop
// ============================================================================

/// Decision engine configuration
pub mod decision_config {
    /// Default risk threshold (50 out of 100)
    /// Rationale: Balanced between false positives and missed signals
    pub const DEFAULT_RISK_THRESHOLD: f64 = 50.0;
}

/// Response action durations
pub mod response_durations {
    /// Block duration for high-severity external threats (1 hour)
    /// Rationale: Long enough for investigation, short enough for false positive recovery
    pub const HIGH_SEVERITY_BLOCK_SECONDS: u64 = 3600;
}

use std::sync::Arc;

use nexcore_chrono::DateTime;
use serde::{Deserialize, Serialize};
use tracing::{Instrument, instrument};

use super::response::{Actuator, ActuatorResult, Amplifier, ResponseAction, ResponseCeiling};
use super::sensing::{Sensor, ThreatLevel, ThreatSignal};
use super::{RiskContext, RiskScore};
use nexcore_tov::grounded::{MetaVigilance, RecognitionR};

// ============================================================================
// Loop State Machine
// ============================================================================

/// State of the homeostasis control loop.
///
/// Transition diagram:
/// ```text
/// Running ──pause()──▶ Paused ──resume()──▶ Running
///    │                   │
///    └──shutdown()──▶ ShuttingDown ──▶ Stopped
///                        ▲
///                        └──shutdown()──┘ (from Paused)
/// ```
///
/// Tier: T2-P (Sum type over state transitions)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LoopState {
    /// Loop is actively processing ticks
    Running,
    /// Loop is paused; tick returns empty results
    Paused,
    /// Loop is flushing state before stopping
    ShuttingDown,
    /// Loop has fully stopped; tick is a permanent no-op
    Stopped,
}

// ============================================================================
// DecisionMaker Trait
// ============================================================================

/// Trait for pluggable decision backends in the homeostasis loop.
///
/// The default implementation is `RuleBasedEngine` (threshold + amplification).
/// Alternative: `DtreeDecisionBackend` (CART tree) or custom implementations.
///
/// Tier: T1 Mapping (μ) — signals → actions
pub trait DecisionMaker: Send + Sync {
    /// Evaluate signals and return response actions.
    fn evaluate_signals(&mut self, signals: &[ThreatSignal<String>]) -> Vec<ResponseAction>;

    /// Decay internal state (e.g., amplification) over elapsed time.
    fn decay(&mut self, elapsed_seconds: f64);

    /// Reset internal state.
    fn reset(&mut self);

    /// Human-readable name for logging.
    fn name(&self) -> &str;

    /// Get the current risk threshold (0-100).
    fn get_threshold(&self) -> f64;

    /// Set the risk threshold (clamped to 0-100), returning the old value.
    fn set_threshold(&mut self, threshold: f64) -> f64;
}

// ============================================================================
// Rule-Based Decision Engine (default)
// ============================================================================

/// Rule-based decision engine for evaluating signals and selecting responses.
///
/// Uses severity thresholds with amplification and ceiling limits.
/// This is the default `DecisionMaker` implementation.
#[derive(Debug, Clone)]
pub struct RuleBasedEngine {
    /// Risk threshold for action (0-100)
    risk_threshold: f64,
    /// Response amplifier
    amplifier: Amplifier,
    /// Response ceiling
    ceiling: ResponseCeiling,
}

/// Backward-compatible type alias.
///
/// Downstream consumers (e.g., `nexcore-mcp`) use `DecisionEngine::new()`.
/// This alias preserves that API while the struct is now `RuleBasedEngine`.
pub type DecisionEngine = RuleBasedEngine;

impl Default for RuleBasedEngine {
    fn default() -> Self {
        Self {
            risk_threshold: decision_config::DEFAULT_RISK_THRESHOLD,
            amplifier: Amplifier::new(),
            ceiling: ResponseCeiling::default(),
        }
    }
}

impl RuleBasedEngine {
    /// Create a new rule-based decision engine
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with custom risk threshold
    #[must_use]
    pub fn with_threshold(mut self, threshold: f64) -> Self {
        self.risk_threshold = threshold.clamp(0.0, 100.0);
        self
    }

    /// Get the current risk threshold
    #[must_use]
    pub fn get_threshold(&self) -> f64 {
        self.risk_threshold
    }

    /// Set the risk threshold (clamped to 0-100), returning the old value
    pub fn set_threshold(&mut self, threshold: f64) -> f64 {
        let old = self.risk_threshold;
        self.risk_threshold = threshold.clamp(0.0, 100.0);
        old
    }

    /// Evaluate signals and decide on responses
    #[instrument(skip(self, signals), fields(signal_count = signals.len()))]
    pub fn evaluate<T: std::fmt::Debug + Clone + Send + Sync>(
        &mut self,
        signals: &[ThreatSignal<T>],
    ) -> Vec<ResponseAction> {
        let mut actions = Vec::new();

        for signal in signals {
            // Amplify severity based on repeated signals
            let amplified_severity = self.amplifier.amplify(signal.severity);
            let effective_score = f64::from(amplified_severity.score()) * signal.confidence.value;

            // Skip if below threshold
            if effective_score < self.risk_threshold {
                actions.push(ResponseAction::AuditLog {
                    category: "signal-below-threshold".to_string(),
                    message: format!(
                        "Signal {} below threshold ({:.1} < {:.1})",
                        signal.id, effective_score, self.risk_threshold
                    ),
                    data: std::collections::HashMap::new(),
                });
                continue;
            }

            // Select response based on severity
            let response = self.select_response(&signal.id, amplified_severity, &signal.source);

            // Check ceiling before adding
            if self.ceiling.allow(&response) {
                actions.push(response);
            } else {
                actions.push(ResponseAction::AuditLog {
                    category: "response-ceiling-reached".to_string(),
                    message: format!("Response ceiling reached for signal {}", signal.id),
                    data: std::collections::HashMap::new(),
                });
            }
        }

        actions
    }

    /// Select appropriate response based on severity
    fn select_response(
        &self,
        signal_id: &str,
        severity: ThreatLevel,
        source: &super::sensing::SignalSource,
    ) -> ResponseAction {
        match severity {
            ThreatLevel::Critical => ResponseAction::Escalate {
                level: super::response::EscalationLevel::L3,
                description: format!("Critical signal detected: {signal_id}"),
                assigned_to: None,
            },
            ThreatLevel::High => {
                if source.is_external() {
                    ResponseAction::Block {
                        target: signal_id.to_string(),
                        duration: Some(response_durations::HIGH_SEVERITY_BLOCK_SECONDS),
                        reason: "High severity external threat".to_string(),
                    }
                } else {
                    ResponseAction::Alert {
                        severity,
                        message: format!("High severity internal signal: {signal_id}"),
                        recipients: vec!["ops@example.com".to_string()],
                    }
                }
            }
            ThreatLevel::Medium => ResponseAction::Alert {
                severity,
                message: format!("Medium severity signal: {signal_id}"),
                recipients: vec!["security@example.com".to_string()],
            },
            ThreatLevel::Low | ThreatLevel::Info => ResponseAction::AuditLog {
                category: "low-severity-signal".to_string(),
                message: format!("Low severity signal logged: {signal_id}"),
                data: std::collections::HashMap::new(),
            },
        }
    }

    /// Decay amplification over time
    pub fn decay(&mut self, elapsed_seconds: f64) {
        self.amplifier.decay(elapsed_seconds);
    }

    /// Reset the decision engine state
    pub fn reset(&mut self) {
        self.amplifier.reset();
    }
}

impl DecisionMaker for RuleBasedEngine {
    fn evaluate_signals(&mut self, signals: &[ThreatSignal<String>]) -> Vec<ResponseAction> {
        self.evaluate(signals)
    }

    fn decay(&mut self, elapsed_seconds: f64) {
        self.decay(elapsed_seconds);
    }

    fn reset(&mut self) {
        self.reset();
    }

    fn name(&self) -> &str {
        "rule-based-engine"
    }

    fn get_threshold(&self) -> f64 {
        self.risk_threshold
    }

    fn set_threshold(&mut self, threshold: f64) -> f64 {
        RuleBasedEngine::set_threshold(self, threshold)
    }
}

// ── Throughput Conservation Monitor ──────────────────────────────────────────

/// Monitors pipeline throughput to detect signal accumulation (queue explosion).
///
/// When `signals_in_rate > signals_out_rate`, signals pile up and throughput
/// is NOT conserved. Grounded in the conservation-of-flow invariant: a healthy
/// pipeline must drain at least as fast as it fills.
///
/// ## T1 Grounding
/// - `N` (Quantity) — tracks in/out rates and queue depth
/// - `∂` (Boundary) — enforces the accumulation ceiling
/// - `→` (Causality) — in-rate causally determines queue growth
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ThroughputMonitor {
    /// Signal ingestion rate (signals per tick window).
    pub signals_in_rate: f64,
    /// Signal processing / drain rate (signals per tick window).
    pub signals_out_rate: f64,
    /// Current queue depth (unprocessed signals).
    pub queue_depth: f64,
    /// Whether signals are accumulating (in_rate > out_rate).
    pub is_accumulating: bool,
    /// Ratio of in_rate to out_rate. Values > 1.0 indicate accumulation.
    pub accumulation_ratio: f64,
    /// Severity classification of the current accumulation state.
    pub status: ThroughputStatus,
}

/// Severity classification for throughput accumulation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThroughputStatus {
    /// Accumulation ratio <= 1.5 — pipeline draining normally.
    #[default]
    Normal,
    /// Accumulation ratio 1.5–3.0 — monitor closely.
    Concerning,
    /// Accumulation ratio > 3.0 — pipeline critically overloaded.
    Critical,
}

impl ThroughputMonitor {
    /// Update monitor with current rate measurements.
    ///
    /// `signals_in` and `signals_out` are counts for the current tick window.
    /// `queue` is the current depth of unprocessed signals.
    pub fn update(&mut self, signals_in: f64, signals_out: f64, queue: f64) {
        self.signals_in_rate = signals_in;
        self.signals_out_rate = signals_out;
        self.queue_depth = queue;
        self.accumulation_ratio = if signals_out > 0.0 {
            signals_in / signals_out
        } else if signals_in > 0.0 {
            f64::INFINITY
        } else {
            1.0
        };
        self.is_accumulating = self.accumulation_ratio > 1.0;
        self.status = match self.accumulation_ratio {
            r if r <= 1.5 => ThroughputStatus::Normal,
            r if r <= 3.0 => ThroughputStatus::Concerning,
            _ => ThroughputStatus::Critical,
        };
    }
}

/// Result of a homeostasis loop iteration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoopIterationResult {
    /// Iteration ID
    pub iteration_id: String,
    /// Timestamp
    pub timestamp: DateTime,
    /// Number of signals detected
    pub signals_detected: usize,
    /// Number of actions taken
    pub actions_taken: usize,
    /// Actuator results
    pub results: Vec<ActuatorResultSummary>,
    /// Duration in milliseconds
    pub duration_ms: u64,
    /// Throughput conservation monitor snapshot for this iteration.
    #[serde(default)]
    pub throughput: ThroughputMonitor,
}

/// Summary of an actuator result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActuatorResultSummary {
    /// Actuator name
    pub actuator: String,
    /// Success status
    pub success: bool,
    /// Message
    pub message: String,
}

impl From<(&str, &ActuatorResult)> for ActuatorResultSummary {
    fn from((name, result): (&str, &ActuatorResult)) -> Self {
        Self {
            actuator: name.to_string(),
            success: result.success,
            message: result.message.clone(),
        }
    }
}

/// The main homeostasis control loop
pub struct HomeostasisLoop {
    /// Decision engine (pluggable via `DecisionMaker` trait)
    decision_engine: Box<dyn DecisionMaker>,
    /// Registered sensors (type-erased)
    sensors: Vec<Arc<dyn ErasedSensor>>,
    /// Registered actuators
    actuators: Vec<Arc<dyn Actuator>>,
    /// Iteration counter
    iteration_count: u64,
    /// Last tick timestamp
    last_tick: Option<DateTime>,
    /// Meta-vigilance monitor
    pub meta_vigilance: MetaVigilance,
    /// Current loop state (Running, Paused, ShuttingDown, Stopped)
    state: LoopState,
    /// Optional pattern detector for emergent signal patterns
    pattern_detector: Option<super::pattern_detector::PatternDetector>,
    /// Optional feedback persistence store
    feedback_store: Option<super::feedback::FeedbackStore>,
    /// Injected signals queue (consumed on next tick)
    injected_signals: Vec<ThreatSignal<String>>,
}

/// Type-erased sensor trait for heterogeneous sensor storage
trait ErasedSensor: Send + Sync {
    /// Detect and return signals as boxed Any
    fn detect_erased(&self) -> Vec<ThreatSignal<String>>;
    /// Sensor name
    fn name(&self) -> &str;
    /// Is active
    fn is_active(&self) -> bool;
}

impl<T> ErasedSensor for T
where
    T: Sensor,
    T::Pattern: ToString,
{
    fn detect_erased(&self) -> Vec<ThreatSignal<String>> {
        self.detect()
            .into_iter()
            .map(|s| ThreatSignal {
                id: s.id,
                pattern: s.pattern.to_string(),
                severity: s.severity,
                timestamp: s.timestamp,
                source: s.source,
                confidence: s.confidence,
                metadata: s.metadata,
            })
            .collect()
    }

    fn name(&self) -> &str {
        Sensor::name(self)
    }

    fn is_active(&self) -> bool {
        Sensor::is_active(self)
    }
}

impl HomeostasisLoop {
    /// Create a new homeostasis loop
    #[must_use]
    pub fn new(decision_engine: DecisionEngine) -> Self {
        Self {
            decision_engine: Box::new(decision_engine),
            sensors: Vec::new(),
            actuators: Vec::new(),
            iteration_count: 0,
            last_tick: None,
            meta_vigilance: MetaVigilance {
                loop_latency_ms: 0,
                calibration_overhead_ms: 0,
                detection_drift: 0.0,
                apparatus_integrity: RecognitionR(1.0),
            },
            state: LoopState::Running,
            pattern_detector: None,
            feedback_store: None,
            injected_signals: Vec::new(),
        }
    }

    /// Create a loop with a custom `DecisionMaker` backend.
    ///
    /// Use this instead of `new()` when supplying a non-default engine
    /// (e.g., `DtreeDecisionBackend` or `FallbackEngine`).
    #[must_use]
    pub fn with_decision_maker(decision_maker: Box<dyn DecisionMaker>) -> Self {
        Self {
            decision_engine: decision_maker,
            sensors: Vec::new(),
            actuators: Vec::new(),
            iteration_count: 0,
            last_tick: None,
            meta_vigilance: MetaVigilance {
                loop_latency_ms: 0,
                calibration_overhead_ms: 0,
                detection_drift: 0.0,
                apparatus_integrity: RecognitionR(1.0),
            },
            state: LoopState::Running,
            pattern_detector: None,
            feedback_store: None,
            injected_signals: Vec::new(),
        }
    }

    /// Attach a pattern detector to the loop.
    ///
    /// When present, detected signals are fed into the pattern detector
    /// after the SENSING phase to identify emergent patterns (BlockStorm,
    /// InflammatoryCascade, CompileFlood, HookMalfunction).
    #[must_use]
    pub fn with_pattern_detector(
        mut self,
        detector: super::pattern_detector::PatternDetector,
    ) -> Self {
        self.pattern_detector = Some(detector);
        self
    }

    /// Attach a feedback store for persisting decision outcomes.
    ///
    /// When present, each tick appends a `FeedbackRecord` per action
    /// to the JSONL file for offline analysis.
    #[must_use]
    pub fn with_feedback_store(mut self, store: super::feedback::FeedbackStore) -> Self {
        self.feedback_store = Some(store);
        self
    }

    /// Add a sensor to the loop
    pub fn add_sensor<S>(&mut self, sensor: S)
    where
        S: Sensor + 'static,
        S::Pattern: ToString,
    {
        self.sensors.push(Arc::new(sensor));
    }

    /// Add an actuator to the loop
    pub fn add_actuator<A: Actuator + 'static>(&mut self, actuator: A) {
        self.actuators.push(Arc::new(actuator));
    }

    /// Run one iteration of the control loop
    ///
    /// Returns an empty result when the loop is paused.
    ///
    /// Note: Uses `Instrument` trait instead of `#[instrument]` because the
    /// `#[instrument]` macro generates a `PhantomNotSend` guard that poisons
    /// the `Send` bound required by the MCP `#[tool]` async dispatch.
    pub async fn tick(&mut self) -> LoopIterationResult {
        if self.state != LoopState::Running {
            return LoopIterationResult {
                iteration_id: format!(
                    "iter-{}-{}",
                    self.iteration_count,
                    match self.state {
                        LoopState::Paused => "paused",
                        LoopState::ShuttingDown => "shutting-down",
                        LoopState::Stopped => "stopped",
                        LoopState::Running => "running", // unreachable but exhaustive
                    }
                ),
                timestamp: DateTime::now(),
                signals_detected: 0,
                actions_taken: 0,
                results: Vec::new(),
                duration_ms: 0,
                throughput: ThroughputMonitor::default(),
            };
        }

        let span = tracing::info_span!(
            "tick",
            iteration = self.iteration_count + 1,
            sensors = self.sensors.len(),
            actuators = self.actuators.len()
        );
        self.tick_inner().instrument(span).await
    }

    /// Inner implementation of tick, instrumented via `Instrument` trait.
    async fn tick_inner(&mut self) -> LoopIterationResult {
        let start = std::time::Instant::now();
        let now = DateTime::now();

        // Decay amplification based on elapsed time
        if let Some(last) = self.last_tick {
            let elapsed = now.signed_duration_since(last).num_seconds() as f64;
            self.decision_engine.decay(elapsed);
        }
        self.last_tick = Some(now);
        self.iteration_count += 1;

        // Phase 1: SENSING - Collect signals from all sensors
        let all_signals = {
            let _span = tracing::info_span!("sensing_phase", phase = 1).entered();
            let mut signals = Vec::new();

            // Drain any injected signals first (Fix #9)
            signals.append(&mut self.injected_signals);

            for sensor in &self.sensors {
                if sensor.is_active() {
                    let detected = sensor.detect_erased();
                    tracing::debug!(
                        sensor = sensor.name(),
                        count = detected.len(),
                        "Sensor detection complete"
                    );
                    signals.extend(detected);
                }
            }
            tracing::info!(total_signals = signals.len(), "SENSING phase complete");
            signals
        };

        // Phase 1.5: PATTERN DETECTION - Feed signals into pattern detector
        let mut all_signals = all_signals;
        if let Some(ref mut detector) = self.pattern_detector {
            let now_ms = now.timestamp_millis() as u128;

            // Feed each signal into the pattern detector
            for signal in &all_signals {
                let family = signal
                    .metadata
                    .get("family")
                    .map_or("unknown", |s| s.as_str());
                let hook = signal
                    .metadata
                    .get("hook")
                    .map_or("unknown", |s| s.as_str());
                detector.ingest(now_ms, family, hook, &signal.pattern);
            }

            // Analyze for emergent patterns
            let pattern_alerts = detector.analyze(now_ms);
            for alert in pattern_alerts {
                let severity = match alert.severity {
                    super::pattern_detector::AlertSeverity::Critical => ThreatLevel::Critical,
                    super::pattern_detector::AlertSeverity::High => ThreatLevel::High,
                    super::pattern_detector::AlertSeverity::Warning => ThreatLevel::Medium,
                };

                let signal = ThreatSignal::new(
                    format!("pattern:{}", alert.pattern),
                    severity,
                    super::sensing::SignalSource::Damp {
                        subsystem: "pattern-detector".to_string(),
                        damage_type: format!("{}", alert.pattern),
                    },
                )
                .with_metadata("evidence_count", alert.evidence_count.to_string())
                .with_metadata("pattern_description", &alert.description);

                all_signals.push(signal);
            }
        }

        // Phase 2: DECISION - Evaluate signals and select responses
        //
        // Build (signal_index, action) pairs for proper feedback correlation (Fix #2).
        // The decision engine produces one action per signal; we track which signal
        // index each action came from so Phase 4 can correlate correctly.
        let (actions, action_signal_indices) = {
            let _span = tracing::info_span!("decision_phase", phase = 2).entered();
            let actions = self.decision_engine.evaluate_signals(&all_signals);
            // The RuleBasedEngine produces exactly one action per input signal (in order),
            // so the mapping is 1:1 for the standard engine. Build the index list.
            let indices: Vec<usize> = (0..actions.len())
                .map(|i| i.min(all_signals.len().saturating_sub(1)))
                .collect();
            tracing::info!(actions_count = actions.len(), "DECISION phase complete");
            (actions, indices)
        };

        // Phase 3: RESPONSE - Execute actions through actuators
        // Note: Cannot use .entered() here — the guard is !Send and would
        // cross the actuator.execute().await boundary. Use Instrument instead.
        //
        // Fix #5: Sort actuators once before the action loop (was O(n·m log m), now O(m log m)).
        // Fix #6: All matching actuators execute per action (removed single-actuator break).
        let response_span = tracing::info_span!("response_phase", phase = 3);
        let results = (async {
            // Sort actuators by priority once (highest first)
            let mut sorted_actuators: Vec<_> = self.actuators.iter().collect();
            sorted_actuators.sort_by(|a, b| b.priority().cmp(&a.priority()));

            let mut results = Vec::new();
            for action in &actions {
                for actuator in &sorted_actuators {
                    if actuator.is_active() && actuator.can_execute(action) {
                        let result = actuator.execute(action).await;
                        tracing::debug!(
                            actuator = actuator.name(),
                            success = result.success,
                            "Actuator executed"
                        );
                        results.push(ActuatorResultSummary::from((actuator.name(), &result)));
                    }
                }
            }
            tracing::info!(results_count = results.len(), "RESPONSE phase complete");
            results
        })
        .instrument(response_span)
        .await;

        // Phase 4: FEEDBACK — persist decision outcomes for offline analysis
        //
        // Fix #2: Use action_signal_indices for proper signal↔action correlation
        // instead of assuming actions[i] corresponds to signals[i].
        if let Some(ref store) = self.feedback_store {
            let iter_id = format!("iter-{}", self.iteration_count);
            for (i, action) in actions.iter().enumerate() {
                let signal_idx = action_signal_indices.get(i).copied().unwrap_or(0);
                let signal_pattern = all_signals
                    .get(signal_idx)
                    .map(|s| s.pattern.clone())
                    .unwrap_or_else(|| "unknown".to_string());
                let severity = all_signals
                    .get(signal_idx)
                    .map(|s| format!("{:?}", s.severity))
                    .unwrap_or_else(|| "Unknown".to_string());
                let (outcome_success, actuator_name) = results
                    .get(i)
                    .map(|r| (r.success, r.actuator.clone()))
                    .unwrap_or((false, "none".to_string()));

                store.append(
                    &(super::feedback::FeedbackRecord {
                        timestamp: nexcore_chrono::DateTime::now(),
                        signal_pattern,
                        severity,
                        decision: format!("{action:?}"),
                        outcome_success,
                        actuator: actuator_name,
                        iteration_id: iter_id.clone(),
                    }),
                );
            }
        }

        let duration_ms = start.elapsed().as_millis() as u64;
        self.meta_vigilance.loop_latency_ms = duration_ms;

        if !self.meta_vigilance.is_healthy() {
            tracing::warn!(
                latency = duration_ms,
                integrity = self.meta_vigilance.apparatus_integrity.0,
                "Vigilance Loop UNHEALTHY (Meta-Vigilance Alert)"
            );
        }

        let mut throughput = ThroughputMonitor::default();
        throughput.update(
            all_signals.len() as f64,
            actions.len() as f64,
            self.injected_signals.len() as f64,
        );

        LoopIterationResult {
            iteration_id: format!("iter-{}", self.iteration_count),
            timestamp: now,
            signals_detected: all_signals.len(),
            actions_taken: actions.len(),
            results,
            duration_ms,
            throughput,
        }
    }

    /// Get current iteration count
    #[must_use]
    pub fn iteration_count(&self) -> u64 {
        self.iteration_count
    }

    /// Get number of registered sensors
    #[must_use]
    pub fn sensor_count(&self) -> usize {
        self.sensors.len()
    }

    /// Get number of registered actuators
    #[must_use]
    pub fn actuator_count(&self) -> usize {
        self.actuators.len()
    }

    /// Pause the control loop (tick becomes a no-op returning an empty result).
    ///
    /// Only transitions `Running → Paused`. No-op in other states.
    pub fn pause(&mut self) {
        if self.state == LoopState::Running {
            self.state = LoopState::Paused;
        }
    }

    /// Resume the control loop.
    ///
    /// Only transitions `Paused → Running`. No-op in other states.
    pub fn resume(&mut self) {
        if self.state == LoopState::Paused {
            self.state = LoopState::Running;
        }
    }

    /// Check whether the control loop is paused
    #[must_use]
    pub fn is_paused(&self) -> bool {
        self.state == LoopState::Paused
    }

    /// Get the current loop state
    #[must_use]
    pub fn state(&self) -> LoopState {
        self.state
    }

    /// Gracefully shut down the loop.
    ///
    /// Transitions to `ShuttingDown`, then `Stopped`.
    /// After shutdown, `tick()` is a permanent no-op.
    pub async fn shutdown(&mut self) {
        if matches!(self.state, LoopState::Stopped) {
            return;
        }
        self.state = LoopState::ShuttingDown;
        tracing::info!(
            "Guardian loop shutting down after {} iterations",
            self.iteration_count
        );

        // Log shutdown event to feedback store
        if let Some(ref store) = self.feedback_store {
            store.append(
                &(super::feedback::FeedbackRecord {
                    timestamp: nexcore_chrono::DateTime::now(),
                    signal_pattern: "shutdown".to_string(),
                    severity: "Info".to_string(),
                    decision: "Shutdown".to_string(),
                    outcome_success: true,
                    actuator: "loop-controller".to_string(),
                    iteration_id: format!("iter-{}-shutdown", self.iteration_count),
                }),
            );
        }

        self.state = LoopState::Stopped;
    }

    /// Get the current risk threshold (delegated to decision engine)
    #[must_use]
    pub fn get_threshold(&self) -> f64 {
        self.decision_engine.get_threshold()
    }

    /// Set the risk threshold (delegated to decision engine, clamped to 0-100)
    pub fn set_threshold(&mut self, threshold: f64) -> f64 {
        self.decision_engine.set_threshold(threshold)
    }

    /// Inject a signal to be processed on the next tick.
    ///
    /// Unlike `inject_signal` in MCP tools, this actually queues the signal
    /// into the sensing pipeline so it will be evaluated by the decision
    /// engine and trigger actuator responses.
    pub fn inject_signal(&mut self, signal: ThreatSignal<String>) {
        self.injected_signals.push(signal);
    }

    /// Reset the loop state
    pub fn reset(&mut self) {
        self.decision_engine.reset();
        self.iteration_count = 0;
        self.last_tick = None;
        self.state = LoopState::Running;
        self.injected_signals.clear();
    }

    /// Configure the loop with a cytokine bus for immune-style signaling.
    ///
    /// Adds:
    /// - `CytokineSensor` to detect cytokine signals as Guardian signals
    /// - `CytokineActuator` to emit cytokines in response to actions
    ///
    /// # T1 Grounding
    ///
    /// - Bidirectional bridge: cytokines ↔ Guardian signals
    /// - μ (mapping): CytokineFamily ↔ Signal/ResponseAction
    #[must_use]
    pub fn with_cytokine_bus(mut self, bus: std::sync::Arc<nexcore_cytokine::CytokineBus>) -> Self {
        use super::response::cytokine::CytokineActuator;
        use super::sensing::cytokine::CytokineSensor;

        self.add_sensor(CytokineSensor::new(bus.clone()));
        self.add_actuator(CytokineActuator::new(bus));
        self
    }
}

/// Evaluate risk from PV signal context
#[must_use]
#[instrument(skip(context), fields(drug = %context.drug, event = %context.event))]
pub fn evaluate_pv_risk(context: &RiskContext) -> (RiskScore, Vec<ResponseAction>) {
    let score = super::calculate_risk_score(context);
    tracing::info!(
        risk_level = %score.level,
        risk_score = %score.score.value,
        "PV risk evaluated"
    );
    let mut actions = Vec::new();

    // Generate response based on risk level
    match score.level.as_str() {
        "Critical" => {
            actions.push(ResponseAction::Escalate {
                level: super::response::EscalationLevel::L3,
                description: format!(
                    "Critical PV signal: {} + {} (score: {})",
                    context.drug, context.event, score.score.value
                ),
                assigned_to: Some("pv-team@example.com".to_string()),
            });
            actions.push(ResponseAction::Alert {
                severity: ThreatLevel::Critical,
                message: format!(
                    "CRITICAL: Signal detected for {} + {}",
                    context.drug, context.event
                ),
                recipients: vec!["pv-team@example.com".to_string()],
            });
        }
        "High" => {
            actions.push(ResponseAction::Alert {
                severity: ThreatLevel::High,
                message: format!(
                    "High-risk signal: {} + {} (score: {})",
                    context.drug, context.event, score.score.value
                ),
                recipients: vec!["pv-team@example.com".to_string()],
            });
        }
        "Medium" => {
            actions.push(ResponseAction::AuditLog {
                category: "pv-signal".to_string(),
                message: format!(
                    "Medium-risk signal: {} + {} (score: {})",
                    context.drug, context.event, score.score.value
                ),
                data: std::collections::HashMap::from([
                    ("drug".to_string(), context.drug.clone()),
                    ("event".to_string(), context.event.clone()),
                ]),
            });
        }
        _ => {
            // Low risk - just log
            actions.push(ResponseAction::NoAction {
                reason: format!("Low risk signal (score: {})", score.score.value),
            });
        }
    }

    (score, actions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::response::AlertActuator;
    use crate::sensing::ExternalSensor;

    #[test]
    fn test_decision_engine_default() {
        let engine = DecisionEngine::new();
        assert!(
            (engine.risk_threshold - decision_config::DEFAULT_RISK_THRESHOLD).abs() < f64::EPSILON
        );
    }

    #[test]
    fn test_homeostasis_loop_creation() {
        let mut control_loop = HomeostasisLoop::new(DecisionEngine::new());
        control_loop.add_sensor(ExternalSensor::new());
        control_loop.add_actuator(AlertActuator::new());

        assert_eq!(control_loop.sensor_count(), 1);
        assert_eq!(control_loop.actuator_count(), 1);
        assert_eq!(control_loop.iteration_count(), 0);
    }

    #[tokio::test]
    async fn test_homeostasis_tick() {
        let mut control_loop = HomeostasisLoop::new(DecisionEngine::new());
        control_loop.add_sensor(ExternalSensor::new());
        control_loop.add_actuator(AlertActuator::new());

        let result = control_loop.tick().await;

        assert_eq!(result.iteration_id, "iter-1");
        assert_eq!(control_loop.iteration_count(), 1);
    }

    #[test]
    fn test_pv_risk_evaluation() {
        let context = RiskContext {
            drug: "TestDrug".to_string(),
            event: "TestEvent".to_string(),
            prr: 3.5,
            ror_lower: 2.0,
            ic025: 0.5,
            eb05: 2.5,
            n: 10,
            originator: Default::default(),
        };

        let (score, actions) = evaluate_pv_risk(&context);

        assert_eq!(score.level, "Critical");
        assert!(!actions.is_empty());
    }
}
