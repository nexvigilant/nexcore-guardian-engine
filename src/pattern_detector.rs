//! # Adaptive Pattern Detection
//!
//! Detects emergent cytokine patterns that indicate systemic issues
//! beyond individual signal severity. Inspired by clinical inflammation
//! cascade recognition.
//!
//! ## T1 Primitive Grounding
//!
//! | Concept | Primitive | Symbol |
//! |---------|-----------|--------|
//! | Pattern window | Sequence | σ |
//! | Threshold comparison | Comparison | κ |
//! | Time decay | Quantity | N |
//! | Pattern classification | Sum type | Σ |
//! | Alert emission | Causality | → |
//!
//! ## 4 Detection Patterns
//!
//! 1. **BlockStorm** — 5+ tool_blocked in 60s → IFN-gamma amplification
//! 2. **InflammatoryCascade** — IL-1 → IL-6 → TNF-α within 500ms → critical alert
//! 3. **CompileFlood** — 3+ compile failures in 120s → incremental verifier warning
//! 4. **HookMalfunction** — same hook 10+ signals/min → quarantine alert

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

// ============================================================================
// T2-P Primitives
// ============================================================================

/// Detected adaptive pattern type.
///
/// # Tier: T2-P (Sum Type)
/// Grounds to: T1(u8) via discriminant.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PatternType {
    /// Multiple tool blocks in rapid succession
    BlockStorm,
    /// IL-1 → IL-6 → TNF-α cascade within time window
    InflammatoryCascade,
    /// Repeated compile/check failures
    CompileFlood,
    /// Single hook emitting too many signals
    HookMalfunction,

    /// Same entity repeatedly violating governance boundaries.
    ///
    /// "a long train of abuses and usurpations, pursuing invariably
    /// the same Object evinces a design to reduce them under absolute Despotism"
    ///
    /// Detects when a single actor accumulates governance violations
    /// (consent failures, scope breaches, authority overreach) within
    /// a time window — indicating systematic abuse of authority.
    TyrannyPattern,
}

impl std::fmt::Display for PatternType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BlockStorm => write!(f, "block_storm"),
            Self::InflammatoryCascade => write!(f, "inflammatory_cascade"),
            Self::CompileFlood => write!(f, "compile_flood"),
            Self::HookMalfunction => write!(f, "hook_malfunction"),
            Self::TyrannyPattern => write!(f, "tyranny_pattern"),
        }
    }
}

/// Severity of a detected pattern.
///
/// # Tier: T2-P
/// Grounds to: T1(u8) via repr.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AlertSeverity {
    Warning = 1,
    High = 2,
    Critical = 3,
}

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Warning => write!(f, "warning"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

// ============================================================================
// T2-C Composites
// ============================================================================

/// A detected pattern alert.
///
/// # Tier: T2-C
/// Grounds to: T2-P(PatternType, AlertSeverity) + T1(String, u128).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternAlert {
    /// The pattern that was detected
    pub pattern: PatternType,
    /// Alert severity
    pub severity: AlertSeverity,
    /// Human-readable description
    pub description: String,
    /// Timestamp of detection (ms since epoch)
    pub detected_at_ms: u128,
    /// Evidence: the signals that triggered this pattern
    pub evidence_count: usize,
}

/// Timestamped cytokine event for pattern window tracking.
///
/// # Tier: T2-C
#[derive(Debug, Clone)]
struct TimestampedEvent {
    timestamp_ms: u128,
    family: String,
    hook: String,
    signal_type: String,
}

/// A governance violation event for tyranny pattern detection.
///
/// Tracks violations from the governance layer (consent failures,
/// scope breaches, authority overreach) to detect systematic abuse.
///
/// # Tier: T2-C (σ · κ · μ)
#[derive(Debug, Clone)]
struct GovernanceViolation {
    /// When the violation occurred (ms since epoch)
    timestamp_ms: u128,
    /// The actor who committed the violation
    actor: String,
    /// The type of governance violation
    violation_type: String,
    /// The scope in which the violation occurred
    scope: String,
}

/// Configuration for pattern detection thresholds.
///
/// # Tier: T2-C
#[derive(Debug, Clone)]
pub struct PatternConfig {
    /// BlockStorm: minimum blocks within window
    pub block_storm_threshold: usize,
    /// BlockStorm: window in milliseconds
    pub block_storm_window_ms: u128,
    /// CompileFlood: minimum failures within window
    pub compile_flood_threshold: usize,
    /// CompileFlood: window in milliseconds
    pub compile_flood_window_ms: u128,
    /// InflammatoryCascade: max time between IL-1 → IL-6 → TNF-α
    pub cascade_window_ms: u128,
    /// HookMalfunction: max signals per hook within window
    pub hook_malfunction_threshold: usize,
    /// HookMalfunction: window in milliseconds
    pub hook_malfunction_window_ms: u128,
    /// TyrannyPattern: minimum governance violations from same actor within window
    pub tyranny_threshold: usize,
    /// TyrannyPattern: window in milliseconds
    pub tyranny_window_ms: u128,
}

impl Default for PatternConfig {
    fn default() -> Self {
        Self {
            block_storm_threshold: 5,
            block_storm_window_ms: 60_000, // 60 seconds
            compile_flood_threshold: 3,
            compile_flood_window_ms: 120_000, // 120 seconds
            cascade_window_ms: 500,           // 500ms for cascade
            hook_malfunction_threshold: 10,
            hook_malfunction_window_ms: 60_000, // 1 minute
            tyranny_threshold: 3,               // 3 violations from same actor
            tyranny_window_ms: 300_000,         // 5 minutes
        }
    }
}

// ============================================================================
// T3 Domain Type: Pattern Detector
// ============================================================================

/// Adaptive pattern detector that identifies emergent cytokine patterns.
///
/// Maintains a sliding window of recent cytokine events and checks
/// for known pathological patterns on each `analyze()` call.
///
/// # Tier: T3 (Full Domain Type)
/// Composes T2-C(PatternConfig, TimestampedEvent) with T2-P(PatternType).
pub struct PatternDetector {
    config: PatternConfig,
    /// Rolling event window (bounded, oldest evicted first)
    events: VecDeque<TimestampedEvent>,
    /// Rolling governance violation window for tyranny detection
    governance_violations: VecDeque<GovernanceViolation>,
    /// Maximum events to retain
    max_events: usize,
}

impl PatternDetector {
    /// Create a new pattern detector with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: PatternConfig::default(),
            events: VecDeque::new(),
            governance_violations: VecDeque::new(),
            max_events: 1000,
        }
    }

    /// Create with custom configuration.
    #[must_use]
    pub fn with_config(config: PatternConfig) -> Self {
        Self {
            config,
            events: VecDeque::new(),
            governance_violations: VecDeque::new(),
            max_events: 1000,
        }
    }

    /// Ingest a governance violation for tyranny pattern tracking.
    ///
    /// "a long train of abuses and usurpations" — each violation is
    /// recorded and checked for systematic patterns by the same actor.
    ///
    /// # Arguments
    /// - `timestamp_ms`: when the violation occurred
    /// - `actor`: the entity that committed the violation
    /// - `violation_type`: classification (e.g., "no_consent", "scope_exceeded")
    /// - `scope`: the governance scope where violation occurred
    pub fn ingest_governance_violation(
        &mut self,
        timestamp_ms: u128,
        actor: &str,
        violation_type: &str,
        scope: &str,
    ) {
        self.governance_violations.push_back(GovernanceViolation {
            timestamp_ms,
            actor: actor.to_string(),
            violation_type: violation_type.to_string(),
            scope: scope.to_string(),
        });

        // Evict oldest violations if over capacity
        while self.governance_violations.len() > self.max_events {
            self.governance_violations.pop_front();
        }
    }

    /// Ingest a cytokine event for pattern tracking.
    ///
    /// # Arguments
    /// - `timestamp_ms`: event timestamp in milliseconds since epoch
    /// - `family`: cytokine family slug (e.g., "tnf_alpha", "il6")
    /// - `hook`: originating hook name
    /// - `signal_type`: full signal type string
    pub fn ingest(&mut self, timestamp_ms: u128, family: &str, hook: &str, signal_type: &str) {
        self.events.push_back(TimestampedEvent {
            timestamp_ms,
            family: family.to_string(),
            hook: hook.to_string(),
            signal_type: signal_type.to_string(),
        });

        // Evict oldest events if over capacity
        while self.events.len() > self.max_events {
            self.events.pop_front();
        }
    }

    /// Analyze current event window for all known patterns.
    ///
    /// Returns a list of detected pattern alerts (may be empty).
    pub fn analyze(&self, now_ms: u128) -> Vec<PatternAlert> {
        let mut alerts = Vec::new();

        if let Some(alert) = self.detect_block_storm(now_ms) {
            alerts.push(alert);
        }
        if let Some(alert) = self.detect_inflammatory_cascade(now_ms) {
            alerts.push(alert);
        }
        if let Some(alert) = self.detect_compile_flood(now_ms) {
            alerts.push(alert);
        }
        for alert in self.detect_hook_malfunction(now_ms) {
            alerts.push(alert);
        }
        for alert in self.detect_tyranny(now_ms) {
            alerts.push(alert);
        }

        alerts
    }

    /// Clear the event window and governance violations.
    pub fn clear(&mut self) {
        self.events.clear();
        self.governance_violations.clear();
    }

    /// Get the current event count.
    #[must_use]
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    // ── Pattern Detectors ──────────────────────────────────

    /// **BlockStorm**: 5+ tool_blocked in 60s
    ///
    /// Indicates that hooks are aggressively blocking tool usage,
    /// possibly due to code quality issues or misconfigured hooks.
    fn detect_block_storm(&self, now_ms: u128) -> Option<PatternAlert> {
        let window_start = now_ms.saturating_sub(self.config.block_storm_window_ms);

        let block_count = self
            .events
            .iter()
            .filter(|e| e.timestamp_ms >= window_start)
            .filter(|e| e.signal_type.contains("blocked") || e.family == "tnf_alpha")
            .count();

        if block_count >= self.config.block_storm_threshold {
            Some(PatternAlert {
                pattern: PatternType::BlockStorm,
                severity: AlertSeverity::High,
                description: format!(
                    "BlockStorm: {} tool blocks in {:.0}s window (threshold: {}). \
                     Hooks are aggressively blocking — check code quality or hook config.",
                    block_count,
                    self.config.block_storm_window_ms as f64 / 1000.0,
                    self.config.block_storm_threshold
                ),
                detected_at_ms: now_ms,
                evidence_count: block_count,
            })
        } else {
            None
        }
    }

    /// **InflammatoryCascade**: IL-1 → IL-6 → TNF-α within 500ms
    ///
    /// The biological inflammatory cascade: alarm → acute → terminate.
    /// If all three fire in sequence within the window, it indicates
    /// a severe systemic issue.
    fn detect_inflammatory_cascade(&self, now_ms: u128) -> Option<PatternAlert> {
        let window_start = now_ms.saturating_sub(self.config.cascade_window_ms);

        let recent: Vec<_> = self
            .events
            .iter()
            .filter(|e| e.timestamp_ms >= window_start)
            .collect();

        // Look for the cascade sequence
        let has_il1 = recent.iter().any(|e| e.family == "il1");
        let has_il6 = recent.iter().any(|e| e.family == "il6");
        let has_tnf = recent.iter().any(|e| e.family == "tnf_alpha");

        if has_il1 && has_il6 && has_tnf {
            Some(PatternAlert {
                pattern: PatternType::InflammatoryCascade,
                severity: AlertSeverity::Critical,
                description: format!(
                    "InflammatoryCascade: IL-1 → IL-6 → TNF-α all detected within {}ms. \
                     Full inflammatory response — immediate attention required.",
                    self.config.cascade_window_ms
                ),
                detected_at_ms: now_ms,
                evidence_count: recent.len(),
            })
        } else {
            None
        }
    }

    /// **CompileFlood**: 3+ compile failures in 120s
    ///
    /// Suggests the incremental verifier should trigger, or that
    /// the code being written has fundamental issues.
    fn detect_compile_flood(&self, now_ms: u128) -> Option<PatternAlert> {
        let window_start = now_ms.saturating_sub(self.config.compile_flood_window_ms);

        let failure_count = self
            .events
            .iter()
            .filter(|e| e.timestamp_ms >= window_start)
            .filter(|e| {
                e.signal_type.contains("check_failed")
                    || e.signal_type.contains("compile")
                    || e.family == "il6"
            })
            .count();

        if failure_count >= self.config.compile_flood_threshold {
            Some(PatternAlert {
                pattern: PatternType::CompileFlood,
                severity: AlertSeverity::Warning,
                description: format!(
                    "CompileFlood: {} compile/check failures in {:.0}s window. \
                     Consider running `cargo check` before more edits.",
                    failure_count,
                    self.config.compile_flood_window_ms as f64 / 1000.0
                ),
                detected_at_ms: now_ms,
                evidence_count: failure_count,
            })
        } else {
            None
        }
    }

    /// **HookMalfunction**: same hook 10+ signals/min
    ///
    /// A single hook emitting too many signals suggests it's
    /// misconfigured, stuck in a loop, or encountering repeated issues.
    fn detect_hook_malfunction(&self, now_ms: u128) -> Vec<PatternAlert> {
        let window_start = now_ms.saturating_sub(self.config.hook_malfunction_window_ms);

        let mut hook_counts: HashMap<&str, usize> = HashMap::new();
        for event in &self.events {
            if event.timestamp_ms >= window_start && !event.hook.is_empty() {
                *hook_counts.entry(&event.hook).or_default() += 1;
            }
        }

        hook_counts
            .into_iter()
            .filter(|&(_, count)| count >= self.config.hook_malfunction_threshold)
            .map(|(hook, count)| PatternAlert {
                pattern: PatternType::HookMalfunction,
                severity: AlertSeverity::High,
                description: format!(
                    "HookMalfunction: hook '{}' emitted {} signals in {:.0}s. \
                     Possible misconfiguration or repeated trigger.",
                    hook,
                    count,
                    self.config.hook_malfunction_window_ms as f64 / 1000.0
                ),
                detected_at_ms: now_ms,
                evidence_count: count,
            })
            .collect()
    }

    /// **TyrannyPattern**: Same actor committing 3+ governance violations in 5 minutes.
    ///
    /// "a long train of abuses and usurpations, pursuing invariably the same Object
    /// evinces a design to reduce them under absolute Despotism"
    ///
    /// Detects when a single entity systematically violates governance boundaries.
    /// This pattern justifies escalation: the actor is not making isolated mistakes
    /// but demonstrating a pattern of authority abuse.
    fn detect_tyranny(&self, now_ms: u128) -> Vec<PatternAlert> {
        let window_start = now_ms.saturating_sub(self.config.tyranny_window_ms);

        let mut actor_counts: HashMap<&str, usize> = HashMap::new();
        let mut actor_violations: HashMap<&str, Vec<&str>> = HashMap::new();

        for violation in &self.governance_violations {
            if violation.timestamp_ms >= window_start {
                *actor_counts.entry(&violation.actor).or_default() += 1;
                actor_violations
                    .entry(&violation.actor)
                    .or_default()
                    .push(&violation.violation_type);
            }
        }

        actor_counts
            .into_iter()
            .filter(|&(_, count)| count >= self.config.tyranny_threshold)
            .map(|(actor, count)| {
                let violations = actor_violations
                    .get(actor)
                    .map(|v| v.join(", "))
                    .unwrap_or_default();

                PatternAlert {
                    pattern: PatternType::TyrannyPattern,
                    severity: AlertSeverity::Critical,
                    description: format!(
                        "TyrannyPattern: actor '{}' committed {} governance violations \
                         in {:.0}s window (threshold: {}). Violations: [{}]. \
                         \"a long train of abuses\" — escalation warranted.",
                        actor,
                        count,
                        self.config.tyranny_window_ms as f64 / 1000.0,
                        self.config.tyranny_threshold,
                        violations,
                    ),
                    detected_at_ms: now_ms,
                    evidence_count: count,
                }
            })
            .collect()
    }
}

impl Default for PatternDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn now_ms() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    }

    #[test]
    fn test_block_storm_detection() {
        let mut detector = PatternDetector::new();
        let now = now_ms();

        // Ingest 6 tool blocks within 60s window
        for i in 0..6 {
            detector.ingest(
                now - 1000 * i as u128, // spread across last 6 seconds
                "tnf_alpha",
                "unwrap-guardian",
                "cytokine:tnf_alpha:blocked:test",
            );
        }

        let alerts = detector.analyze(now);
        let storm = alerts.iter().find(|a| a.pattern == PatternType::BlockStorm);

        assert!(storm.is_some(), "Expected BlockStorm alert");
        let storm = storm.expect("just checked");
        assert_eq!(storm.severity, AlertSeverity::High);
        assert!(storm.evidence_count >= 5);
    }

    #[test]
    fn test_inflammatory_cascade_detection() {
        let mut detector = PatternDetector::new();
        let now = now_ms();

        // IL-1 → IL-6 → TNF-α within 500ms
        detector.ingest(now - 400, "il1", "hook-a", "cytokine:il1:alarm");
        detector.ingest(now - 200, "il6", "hook-b", "cytokine:il6:acute");
        detector.ingest(
            now - 50,
            "tnf_alpha",
            "hook-c",
            "cytokine:tnf_alpha:terminate",
        );

        let alerts = detector.analyze(now);
        let cascade = alerts
            .iter()
            .find(|a| a.pattern == PatternType::InflammatoryCascade);

        assert!(cascade.is_some(), "Expected InflammatoryCascade alert");
        assert_eq!(
            cascade.expect("just checked").severity,
            AlertSeverity::Critical
        );
    }

    #[test]
    fn test_no_cascade_when_outside_window() {
        let mut detector = PatternDetector::new();
        let now = now_ms();

        // IL-1 too old (outside 500ms window)
        detector.ingest(now - 1000, "il1", "hook-a", "cytokine:il1:alarm");
        detector.ingest(now - 200, "il6", "hook-b", "cytokine:il6:acute");
        detector.ingest(
            now - 50,
            "tnf_alpha",
            "hook-c",
            "cytokine:tnf_alpha:terminate",
        );

        let alerts = detector.analyze(now);
        let cascade = alerts
            .iter()
            .find(|a| a.pattern == PatternType::InflammatoryCascade);

        assert!(
            cascade.is_none(),
            "Should NOT detect cascade when IL-1 is outside window"
        );
    }

    #[test]
    fn test_compile_flood_detection() {
        let mut detector = PatternDetector::new();
        let now = now_ms();

        // 4 compile failures within 120s
        for i in 0..4 {
            detector.ingest(
                now - 10_000 * i as u128,
                "il6",
                "compile-verifier",
                "cytokine:il6:check_failed:compile",
            );
        }

        let alerts = detector.analyze(now);
        let flood = alerts
            .iter()
            .find(|a| a.pattern == PatternType::CompileFlood);

        assert!(flood.is_some(), "Expected CompileFlood alert");
        assert_eq!(
            flood.expect("just checked").severity,
            AlertSeverity::Warning
        );
    }

    #[test]
    fn test_hook_malfunction_detection() {
        let mut detector = PatternDetector::new();
        let now = now_ms();

        // Same hook emitting 12 signals in 1 minute
        for i in 0..12 {
            detector.ingest(
                now - 1000 * i as u128,
                "il1",
                "broken-hook",
                &format!("cytokine:il1:error:{i}"),
            );
        }

        let alerts = detector.analyze(now);
        let malfunction = alerts
            .iter()
            .find(|a| a.pattern == PatternType::HookMalfunction);

        assert!(malfunction.is_some(), "Expected HookMalfunction alert");
        let m = malfunction.expect("just checked");
        assert_eq!(m.severity, AlertSeverity::High);
        assert!(m.description.contains("broken-hook"));
    }

    #[test]
    fn test_no_alerts_when_below_thresholds() {
        let mut detector = PatternDetector::new();
        let now = now_ms();

        // Only 2 blocks (below threshold of 5)
        detector.ingest(
            now - 1000,
            "tnf_alpha",
            "hook-a",
            "cytokine:tnf_alpha:blocked",
        );
        detector.ingest(
            now - 2000,
            "tnf_alpha",
            "hook-b",
            "cytokine:tnf_alpha:blocked",
        );

        let alerts = detector.analyze(now);
        assert!(
            alerts.is_empty(),
            "Expected no alerts below thresholds, got: {:?}",
            alerts.iter().map(|a| &a.pattern).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_event_eviction() {
        let config = PatternConfig::default();
        let mut detector = PatternDetector::with_config(config);

        // Fill beyond max_events
        let now = now_ms();
        for i in 0..1500 {
            detector.ingest(now - i, "il2", "test-hook", "cytokine:il2:growth");
        }

        assert!(
            detector.event_count() <= 1000,
            "Events should be bounded to max_events"
        );
    }

    #[test]
    fn test_custom_config_thresholds() {
        let config = PatternConfig {
            block_storm_threshold: 2, // Lower threshold
            block_storm_window_ms: 10_000,
            ..PatternConfig::default()
        };
        let mut detector = PatternDetector::with_config(config);
        let now = now_ms();

        // Only 2 blocks, but threshold is 2
        detector.ingest(
            now - 1000,
            "tnf_alpha",
            "hook-a",
            "cytokine:tnf_alpha:blocked",
        );
        detector.ingest(
            now - 2000,
            "tnf_alpha",
            "hook-b",
            "cytokine:tnf_alpha:blocked",
        );

        let alerts = detector.analyze(now);
        let storm = alerts.iter().find(|a| a.pattern == PatternType::BlockStorm);
        assert!(
            storm.is_some(),
            "Expected BlockStorm with lowered threshold"
        );
    }

    #[test]
    fn test_multiple_simultaneous_patterns() {
        let mut detector = PatternDetector::new();
        let now = now_ms();

        // Trigger BlockStorm (5+ tnf_alpha)
        for i in 0..6 {
            detector.ingest(
                now - 100 * i as u128,
                "tnf_alpha",
                "broken-hook",
                "cytokine:tnf_alpha:blocked:test",
            );
        }

        // Also trigger CompileFlood (3+ il6 check_failed)
        for i in 0..4 {
            detector.ingest(
                now - 200 * i as u128,
                "il6",
                "broken-hook",
                "cytokine:il6:check_failed:compile",
            );
        }

        // Also trigger cascade (IL-1 + IL-6 + TNF-α within 500ms)
        detector.ingest(now - 300, "il1", "broken-hook", "cytokine:il1:alarm");

        // Also trigger HookMalfunction (10+ from same hook)
        // Already have 10+ from "broken-hook" above

        let alerts = detector.analyze(now);

        // Should detect multiple patterns simultaneously
        assert!(
            alerts.len() >= 2,
            "Expected multiple simultaneous patterns, got {}: {:?}",
            alerts.len(),
            alerts.iter().map(|a| &a.pattern).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_clear_resets_state() {
        let mut detector = PatternDetector::new();
        let now = now_ms();

        for i in 0..10 {
            detector.ingest(now - i, "tnf_alpha", "hook", "cytokine:tnf_alpha:blocked");
        }

        assert!(detector.event_count() > 0);
        detector.clear();
        assert_eq!(detector.event_count(), 0);

        let alerts = detector.analyze(now);
        assert!(alerts.is_empty());
    }

    // ── TyrannyPattern Tests ──────────────────────────────────────────

    #[test]
    fn test_tyranny_pattern_detection() {
        let mut detector = PatternDetector::new();
        let now = now_ms();

        // Same actor commits 4 governance violations within 5 minutes
        detector.ingest_governance_violation(
            now - 200_000,
            "rogue-agent",
            "no_consent",
            "patient-safety",
        );
        detector.ingest_governance_violation(
            now - 150_000,
            "rogue-agent",
            "scope_exceeded",
            "hud-governance",
        );
        detector.ingest_governance_violation(
            now - 100_000,
            "rogue-agent",
            "authority_revoked",
            "system-health",
        );
        detector.ingest_governance_violation(
            now - 50_000,
            "rogue-agent",
            "no_authority",
            "patient-safety",
        );

        let alerts = detector.analyze(now);
        let tyranny = alerts
            .iter()
            .find(|a| a.pattern == PatternType::TyrannyPattern);

        assert!(tyranny.is_some(), "Expected TyrannyPattern alert");
        let tyranny = tyranny.expect("just checked");
        assert_eq!(tyranny.severity, AlertSeverity::Critical);
        assert!(tyranny.evidence_count >= 3);
        assert!(tyranny.description.contains("rogue-agent"));
    }

    #[test]
    fn test_no_tyranny_below_threshold() {
        let mut detector = PatternDetector::new();
        let now = now_ms();

        // Only 2 violations (threshold is 3)
        detector.ingest_governance_violation(
            now - 60_000,
            "minor-offender",
            "no_consent",
            "system-health",
        );
        detector.ingest_governance_violation(
            now - 30_000,
            "minor-offender",
            "scope_exceeded",
            "system-health",
        );

        let alerts = detector.analyze(now);
        let tyranny = alerts
            .iter()
            .find(|a| a.pattern == PatternType::TyrannyPattern);
        assert!(
            tyranny.is_none(),
            "Should NOT detect tyranny below threshold"
        );
    }

    #[test]
    fn test_tyranny_not_detected_outside_window() {
        let mut detector = PatternDetector::new();
        let now = now_ms();

        // 4 violations, but first two are outside the 5-minute window
        detector.ingest_governance_violation(
            now - 400_000,
            "old-offender",
            "no_consent",
            "system-health",
        );
        detector.ingest_governance_violation(
            now - 350_000,
            "old-offender",
            "scope_exceeded",
            "system-health",
        );
        // Only 2 within window
        detector.ingest_governance_violation(
            now - 100_000,
            "old-offender",
            "no_authority",
            "system-health",
        );
        detector.ingest_governance_violation(
            now - 50_000,
            "old-offender",
            "authority_revoked",
            "system-health",
        );

        let alerts = detector.analyze(now);
        let tyranny = alerts
            .iter()
            .find(|a| a.pattern == PatternType::TyrannyPattern);
        assert!(
            tyranny.is_none(),
            "Violations outside window should not count"
        );
    }

    #[test]
    fn test_tyranny_different_actors_not_merged() {
        let mut detector = PatternDetector::new();
        let now = now_ms();

        // 4 violations total, but from 4 different actors
        detector.ingest_governance_violation(
            now - 100_000,
            "actor-a",
            "no_consent",
            "system-health",
        );
        detector.ingest_governance_violation(
            now - 80_000,
            "actor-b",
            "scope_exceeded",
            "system-health",
        );
        detector.ingest_governance_violation(
            now - 60_000,
            "actor-c",
            "no_authority",
            "system-health",
        );
        detector.ingest_governance_violation(
            now - 40_000,
            "actor-d",
            "authority_revoked",
            "system-health",
        );

        let alerts = detector.analyze(now);
        let tyranny = alerts
            .iter()
            .find(|a| a.pattern == PatternType::TyrannyPattern);
        assert!(
            tyranny.is_none(),
            "Different actors should not be merged into tyranny pattern"
        );
    }

    #[test]
    fn test_clear_also_clears_governance_violations() {
        let mut detector = PatternDetector::new();
        let now = now_ms();

        for i in 0..5 {
            detector.ingest_governance_violation(
                now - i * 10_000,
                "agent",
                "no_consent",
                "system-health",
            );
        }

        detector.clear();

        let alerts = detector.analyze(now);
        let tyranny = alerts
            .iter()
            .find(|a| a.pattern == PatternType::TyrannyPattern);
        assert!(
            tyranny.is_none(),
            "Clear should remove governance violations"
        );
    }
}
