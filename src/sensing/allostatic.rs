//! Allostatic Load Sensor
//!
//! DAMP sensor tracking accumulated stress from chronic hook override patterns.
//!
//! ## Biological Analog
//!
//! Allostatic load is the accumulated wear imposed on the body when it adapts
//! continuously to stressors without returning to baseline — cortisol buildup
//! from chronic HPA-axis activation is the canonical example.
//!
//! This sensor tracks the computational equivalent: hooks that are manually
//! overridden or bypassed accumulate "stress" that degrades system calibration
//! over time. When any hook exceeds the recalibration threshold, it is flagged
//! for review.
//!
//! ## Data Source
//!
//! Reads `~/.claude/telemetry/hook-overrides.jsonl` (one JSON object per line).
//! Each record describes one override event. If the file is absent the sensor
//! returns a clean baseline — an empty override log means zero load.
//!
//! ## Tier: T3 (Domain-Specific DAMP Sensor)
//!
//! T1 Grounding:
//! - `ς` (State) — tracks accumulated override state per hook
//! - `ν` (Frequency) — computes override rate per rolling window
//! - `∂` (Boundary) — recalibration threshold enforces the load ceiling
//! - `→` (Causality) — chronic overrides causally degrade calibration

use crate::sensing::{Measured, Sensor, SignalSource, ThreatLevel, ThreatSignal};
use nexcore_chrono::{DateTime, Duration};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

// =============================================================================
// Constants
// =============================================================================

/// Default rolling window width in days.
const DEFAULT_WINDOW_DAYS: u32 = 30;

/// Default recalibration threshold: overrides per hook per window before alert.
const DEFAULT_RECAL_THRESHOLD: u32 = 10;

/// Override count above threshold at which load escalates from Medium → High.
const HIGH_LOAD_MULTIPLIER: u32 = 2;

// =============================================================================
// Override Record
// =============================================================================

/// A single hook override event persisted to the telemetry log.
///
/// Tier: T2-P (State record with causality and boundary)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OverrideRecord {
    /// Name of the hook that was overridden (e.g. `"security-guidance"`).
    pub hook_name: String,

    /// UTC timestamp when the override occurred.
    pub timestamp: DateTime,

    /// Description of the operation the hook attempted to block.
    pub blocked_operation: String,

    /// Human-provided reason the override was permitted.
    pub override_reason: String,
}

// =============================================================================
// Allostatic Load State
// =============================================================================

/// Accumulated override state for a rolling time window.
///
/// This is the "HPA-axis activation log" equivalent — every override that falls
/// inside `window_days` is retained; older records are pruned on access.
///
/// Tier: T2-C (composed state + frequency tracking)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllostaticLoadState {
    /// All override records within the rolling window.
    pub overrides: Vec<OverrideRecord>,

    /// Width of the rolling observation window in days.
    pub window_days: u32,
}

impl Default for AllostaticLoadState {
    fn default() -> Self {
        Self {
            overrides: Vec::new(),
            window_days: DEFAULT_WINDOW_DAYS,
        }
    }
}

impl AllostaticLoadState {
    /// Create a new, empty state with the default 30-day window.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with a custom window width.
    #[must_use]
    pub fn with_window(window_days: u32) -> Self {
        Self {
            overrides: Vec::new(),
            window_days,
        }
    }

    /// Append a new override event to the state.
    pub fn add_override(&mut self, record: OverrideRecord) {
        self.overrides.push(record);
    }

    /// Remove records that fall outside the rolling window.
    ///
    /// Cutoff is `now - window_days`. Records at or after the cutoff are kept.
    pub fn prune_expired(&mut self) {
        let cutoff = DateTime::now() - Duration::days(i64::from(self.window_days));
        self.overrides.retain(|r| r.timestamp >= cutoff);
    }

    /// Count overrides grouped by hook name for records currently in the window.
    ///
    /// Expired records are pruned before counting.
    pub fn per_hook_counts(&mut self) -> HashMap<String, u32> {
        self.prune_expired();
        let mut counts: HashMap<String, u32> = HashMap::new();
        for record in &self.overrides {
            *counts.entry(record.hook_name.clone()).or_insert(0) += 1;
        }
        counts
    }

    /// Compute the aggregate allostatic score across all hooks.
    ///
    /// Formula: `min(1.0, total_overrides / (hooks_count * threshold))`
    ///
    /// - `0.0` — no overrides recorded (fully rested system)
    /// - `0.5` — moderate override activity
    /// - `1.0` — chronic override pattern (system approaching burnout)
    ///
    /// When no hooks are present the score is `0.0`.
    pub fn total_load(&mut self, threshold: u32) -> f64 {
        let counts = self.per_hook_counts();
        if counts.is_empty() {
            return 0.0;
        }
        let hooks_count = counts.len() as f64;
        let total_overrides: u32 = counts.values().sum();
        let denominator = hooks_count * f64::from(threshold);
        if denominator <= 0.0 {
            return 0.0;
        }
        (f64::from(total_overrides) / denominator).min(1.0)
    }
}

// =============================================================================
// Recalibration Flag
// =============================================================================

/// Describes a hook that has exceeded the recalibration threshold.
///
/// Issued when a hook's accumulated override count inside the rolling window
/// surpasses `threshold`, signalling that the hook's rules may need revision.
///
/// Tier: T2-P (Boundary violation record)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecalibrationFlag {
    /// Name of the hook that needs recalibration.
    pub hook_name: String,

    /// Number of overrides observed inside the window.
    pub override_count: u32,

    /// Threshold that was exceeded.
    pub threshold: u32,

    /// Human-readable recommendation for addressing the load.
    pub recommendation: String,
}

impl RecalibrationFlag {
    /// Build a flag with a generated recommendation string.
    #[must_use]
    pub fn new(hook_name: impl Into<String>, override_count: u32, threshold: u32) -> Self {
        let hook_name = hook_name.into();
        let recommendation = format!(
            "Hook '{}' has been overridden {} time(s) in the last window \
             (threshold: {}). Review hook rules for false-positive patterns \
             and recalibrate blocking criteria.",
            hook_name, override_count, threshold
        );
        Self {
            hook_name,
            override_count,
            threshold,
            recommendation,
        }
    }
}

// =============================================================================
// Allostatic Load Sensor
// =============================================================================

/// Allostatic Load Sensor — tracks hook override accumulation.
///
/// Reads `~/.claude/telemetry/hook-overrides.jsonl` and evaluates the
/// rolling per-hook override count against a recalibration threshold.
///
/// ## Signal Emission
///
/// | Condition | Level | Confidence |
/// |-----------|-------|------------|
/// | hook count ≥ threshold and < 2× threshold | Medium | 0.85 |
/// | hook count ≥ 2× threshold | High | 0.95 |
///
/// ## Allostatic Score
///
/// `total_load()` maps the overall override density onto `[0.0, 1.0]`:
/// - `0.0` — no overrides (fully rested)
/// - `0.5` — moderate activity
/// - `1.0` — chronic override pattern (system burnout risk)
///
/// # Tier: T3 (Domain-Specific DAMP Sensor)
///
/// # Example
///
/// ```rust
/// use nexcore_guardian_engine::sensing::allostatic::AllostaticLoadSensor;
/// use nexcore_guardian_engine::sensing::Sensor;
///
/// let sensor = AllostaticLoadSensor::new();
/// assert_eq!(sensor.name(), "allostatic-load-sensor");
/// // detect() returns an empty vec when the telemetry file is absent.
/// let signals = sensor.detect();
/// assert!(signals.is_empty() || !signals.is_empty()); // no panic
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllostaticLoadSensor {
    sensitivity: f64,
    /// Override log file path.
    log_path: PathBuf,
    /// Override count per hook that triggers a recalibration flag.
    recal_threshold: u32,
    /// Rolling window width in days.
    window_days: u32,
}

impl Default for AllostaticLoadSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl AllostaticLoadSensor {
    /// Create with default settings, reading from the standard telemetry path.
    ///
    /// Default path: `~/.claude/telemetry/hook-overrides.jsonl`
    #[must_use]
    pub fn new() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        Self {
            sensitivity: 0.85,
            log_path: PathBuf::from(home)
                .join(".claude")
                .join("telemetry")
                .join("hook-overrides.jsonl"),
            recal_threshold: DEFAULT_RECAL_THRESHOLD,
            window_days: DEFAULT_WINDOW_DAYS,
        }
    }

    /// Create with a custom log file path (primarily for testing).
    #[must_use]
    pub fn with_path(path: PathBuf) -> Self {
        Self {
            log_path: path,
            ..Self::new()
        }
    }

    /// Override the recalibration threshold.
    #[must_use]
    pub fn with_threshold(mut self, threshold: u32) -> Self {
        self.recal_threshold = threshold;
        self
    }

    /// Override the rolling window width in days.
    #[must_use]
    pub fn with_window(mut self, window_days: u32) -> Self {
        self.window_days = window_days;
        self
    }

    /// Load override records from the JSONL file.
    ///
    /// Returns an empty `AllostaticLoadState` when the file is absent or
    /// unreadable — missing data is treated as zero load, not an error.
    fn load_state(&self) -> AllostaticLoadState {
        let content = match std::fs::read_to_string(&self.log_path) {
            Ok(c) => c,
            Err(_) => return AllostaticLoadState::with_window(self.window_days),
        };

        let mut state = AllostaticLoadState::with_window(self.window_days);
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(record) = serde_json::from_str::<OverrideRecord>(trimmed) {
                state.add_override(record);
            }
        }
        state
    }

    /// Evaluate loaded state and emit signals for over-threshold hooks.
    fn evaluate_signals(&self, state: &mut AllostaticLoadState) -> Vec<ThreatSignal<String>> {
        let counts = state.per_hook_counts();
        let mut signals = Vec::new();

        for (hook_name, count) in &counts {
            if *count < self.recal_threshold {
                continue;
            }

            let flag = RecalibrationFlag::new(hook_name, *count, self.recal_threshold);

            let (severity, confidence) = if *count >= self.recal_threshold * HIGH_LOAD_MULTIPLIER {
                (ThreatLevel::High, 0.95_f64)
            } else {
                (ThreatLevel::Medium, 0.85_f64)
            };

            let signal = ThreatSignal::new(
                format!("allostatic_overload:{}:{}", hook_name, count),
                severity,
                SignalSource::Damp {
                    subsystem: "allostatic-load".to_string(),
                    damage_type: "hook-override-accumulation".to_string(),
                },
            )
            .with_confidence(Measured::certain(confidence))
            .with_metadata("hook", hook_name.clone())
            .with_metadata("override_count", count.to_string())
            .with_metadata("threshold", self.recal_threshold.to_string())
            .with_metadata("window_days", self.window_days.to_string())
            .with_metadata("recommendation", flag.recommendation.clone());

            signals.push(signal);
        }

        signals
    }

    /// Compute the composite allostatic score for the current window.
    ///
    /// Returns a value in `[0.0, 1.0]`:
    /// - `0.0` — no overrides (fully rested)
    /// - `0.5` — moderate activity
    /// - `1.0` — chronic override pattern (burnout risk)
    #[must_use]
    pub fn allostatic_score(&self) -> f64 {
        let mut state = self.load_state();
        state.total_load(self.recal_threshold)
    }

    /// Return all recalibration flags for hooks that exceed the threshold.
    #[must_use]
    pub fn recalibration_flags(&self) -> Vec<RecalibrationFlag> {
        let mut state = self.load_state();
        let counts = state.per_hook_counts();
        counts
            .into_iter()
            .filter(|(_, count)| *count >= self.recal_threshold)
            .map(|(hook, count)| RecalibrationFlag::new(hook, count, self.recal_threshold))
            .collect()
    }
}

impl Sensor for AllostaticLoadSensor {
    type Pattern = String;

    fn detect(&self) -> Vec<ThreatSignal<Self::Pattern>> {
        let mut state = self.load_state();
        let signals = self.evaluate_signals(&mut state);

        // Apply sensitivity filter — only emit signals above the confidence floor.
        signals
            .into_iter()
            .filter(|s| s.confidence.value >= (1.0 - self.sensitivity))
            .collect()
    }

    fn sensitivity(&self) -> f64 {
        self.sensitivity
    }

    fn name(&self) -> &str {
        "allostatic-load-sensor"
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    fn make_record(hook: &str, days_ago: i64) -> OverrideRecord {
        OverrideRecord {
            hook_name: hook.to_string(),
            timestamp: DateTime::now() - Duration::days(days_ago),
            blocked_operation: "Write /etc/hosts".to_string(),
            override_reason: "Approved by operator".to_string(),
        }
    }

    fn write_jsonl(path: &std::path::Path, records: &[OverrideRecord]) {
        let mut file = std::fs::File::create(path).expect("create test file");
        for r in records {
            let line = serde_json::to_string(r).expect("serialize record");
            writeln!(file, "{line}").expect("write line");
        }
    }

    // -------------------------------------------------------------------------
    // AllostaticLoadState
    // -------------------------------------------------------------------------

    #[test]
    fn test_state_default_empty() {
        let state = AllostaticLoadState::new();
        assert!(state.overrides.is_empty());
        assert_eq!(state.window_days, DEFAULT_WINDOW_DAYS);
    }

    #[test]
    fn test_state_add_override() {
        let mut state = AllostaticLoadState::new();
        state.add_override(make_record("security-guidance", 1));
        assert_eq!(state.overrides.len(), 1);
    }

    #[test]
    fn test_state_prune_expired() {
        let mut state = AllostaticLoadState::with_window(7);
        // Within window
        state.add_override(make_record("hook-a", 3));
        // Outside window
        state.add_override(make_record("hook-b", 10));
        state.prune_expired();
        assert_eq!(state.overrides.len(), 1);
        assert_eq!(state.overrides[0].hook_name, "hook-a");
    }

    #[test]
    fn test_state_per_hook_counts() {
        let mut state = AllostaticLoadState::new();
        state.add_override(make_record("hook-a", 1));
        state.add_override(make_record("hook-a", 2));
        state.add_override(make_record("hook-b", 1));

        let counts = state.per_hook_counts();
        assert_eq!(counts.get("hook-a"), Some(&2));
        assert_eq!(counts.get("hook-b"), Some(&1));
    }

    #[test]
    fn test_state_total_load_zero_when_empty() {
        let mut state = AllostaticLoadState::new();
        assert!((state.total_load(10) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_state_total_load_capped_at_one() {
        let mut state = AllostaticLoadState::with_window(DEFAULT_WINDOW_DAYS);
        // 100 overrides for one hook with threshold 10 → would be 10.0 → clamped to 1.0
        for i in 0..100_i64 {
            state.add_override(make_record("heavy-hook", i % 28));
        }
        let score = state.total_load(10);
        assert!(score <= 1.0);
        assert!((score - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_state_total_load_partial() {
        let mut state = AllostaticLoadState::new();
        // 5 overrides, one hook, threshold 10 → 5 / (1 * 10) = 0.5
        for day in 0..5_i64 {
            state.add_override(make_record("partial-hook", day));
        }
        let score = state.total_load(10);
        assert!((score - 0.5).abs() < f64::EPSILON);
    }

    // -------------------------------------------------------------------------
    // RecalibrationFlag
    // -------------------------------------------------------------------------

    #[test]
    fn test_recalibration_flag_recommendation_contains_hook_name() {
        let flag = RecalibrationFlag::new("my-hook", 15, 10);
        assert_eq!(flag.hook_name, "my-hook");
        assert_eq!(flag.override_count, 15);
        assert_eq!(flag.threshold, 10);
        assert!(flag.recommendation.contains("my-hook"));
        assert!(flag.recommendation.contains("15"));
        assert!(flag.recommendation.contains("10"));
    }

    // -------------------------------------------------------------------------
    // AllostaticLoadSensor — file-absent case
    // -------------------------------------------------------------------------

    #[test]
    fn test_sensor_creation() {
        let sensor = AllostaticLoadSensor::new();
        assert_eq!(sensor.name(), "allostatic-load-sensor");
        assert!((sensor.sensitivity() - 0.85).abs() < f64::EPSILON);
    }

    #[test]
    fn test_sensor_no_signals_when_file_absent() {
        let sensor =
            AllostaticLoadSensor::with_path(PathBuf::from("/nonexistent/no-overrides.jsonl"));
        let signals = sensor.detect();
        assert!(signals.is_empty());
    }

    #[test]
    fn test_allostatic_score_zero_when_file_absent() {
        let sensor =
            AllostaticLoadSensor::with_path(PathBuf::from("/nonexistent/no-overrides.jsonl"));
        assert!((sensor.allostatic_score() - 0.0).abs() < f64::EPSILON);
    }

    // -------------------------------------------------------------------------
    // AllostaticLoadSensor — threshold detection
    // -------------------------------------------------------------------------

    #[test]
    fn test_sensor_medium_signal_at_threshold() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("hook-overrides.jsonl");

        // Exactly at threshold (10 overrides for one hook)
        let records: Vec<OverrideRecord> = (0..10_i64)
            .map(|day| make_record("security-guidance", day))
            .collect();
        write_jsonl(&path, &records);

        let sensor = AllostaticLoadSensor::with_path(path).with_threshold(10);
        let signals = sensor.detect();

        assert!(!signals.is_empty());
        assert!(signals[0].pattern.contains("security-guidance"));
        assert_eq!(signals[0].severity, ThreatLevel::Medium);
    }

    #[test]
    fn test_sensor_high_signal_at_double_threshold() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("hook-overrides.jsonl");

        // 20 overrides — 2× threshold → High
        let records: Vec<OverrideRecord> = (0..20_i64)
            .map(|day| make_record("security-guidance", day % 28))
            .collect();
        write_jsonl(&path, &records);

        let sensor = AllostaticLoadSensor::with_path(path).with_threshold(10);
        let signals = sensor.detect();

        assert!(!signals.is_empty());
        assert_eq!(signals[0].severity, ThreatLevel::High);
    }

    #[test]
    fn test_sensor_no_signal_below_threshold() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("hook-overrides.jsonl");

        // 5 overrides — below threshold of 10
        let records: Vec<OverrideRecord> = (0..5_i64)
            .map(|day| make_record("minor-hook", day))
            .collect();
        write_jsonl(&path, &records);

        let sensor = AllostaticLoadSensor::with_path(path).with_threshold(10);
        let signals = sensor.detect();
        assert!(signals.is_empty());
    }

    #[test]
    fn test_sensor_expired_records_ignored() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("hook-overrides.jsonl");

        // Records outside the 7-day window should not count
        let records: Vec<OverrideRecord> = (0..15_i64)
            .map(|i| make_record("old-hook", 10 + i)) // 10–24 days ago
            .collect();
        write_jsonl(&path, &records);

        let sensor = AllostaticLoadSensor::with_path(path)
            .with_threshold(10)
            .with_window(7);
        let signals = sensor.detect();
        assert!(signals.is_empty());
    }

    #[test]
    fn test_sensor_multiple_hooks_flagged_independently() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("hook-overrides.jsonl");

        let mut records = Vec::new();
        for day in 0..12_i64 {
            records.push(make_record("hook-a", day % 28));
        }
        for day in 0..11_i64 {
            records.push(make_record("hook-b", day % 28));
        }
        write_jsonl(&path, &records);

        let sensor = AllostaticLoadSensor::with_path(path).with_threshold(10);
        let signals = sensor.detect();

        // Both hooks exceed threshold
        assert_eq!(signals.len(), 2);
    }

    #[test]
    fn test_sensor_metadata_present() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("hook-overrides.jsonl");

        let records: Vec<OverrideRecord> = (0..10_i64)
            .map(|day| make_record("metadata-hook", day))
            .collect();
        write_jsonl(&path, &records);

        let sensor = AllostaticLoadSensor::with_path(path).with_threshold(10);
        let signals = sensor.detect();

        assert!(!signals.is_empty());
        let signal = &signals[0];
        assert!(signal.metadata.contains_key("hook"));
        assert!(signal.metadata.contains_key("override_count"));
        assert!(signal.metadata.contains_key("threshold"));
        assert!(signal.metadata.contains_key("recommendation"));
    }

    #[test]
    fn test_recalibration_flags_returned() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("hook-overrides.jsonl");

        let records: Vec<OverrideRecord> = (0..12_i64)
            .map(|day| make_record("flagged-hook", day % 28))
            .collect();
        write_jsonl(&path, &records);

        let sensor = AllostaticLoadSensor::with_path(path).with_threshold(10);
        let flags = sensor.recalibration_flags();
        assert_eq!(flags.len(), 1);
        assert_eq!(flags[0].hook_name, "flagged-hook");
        assert_eq!(flags[0].override_count, 12);
    }

    #[test]
    fn test_allostatic_score_increases_with_overrides() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("hook-overrides.jsonl");

        // 5 overrides, threshold 10, one hook → score = 0.5
        let records: Vec<OverrideRecord> = (0..5_i64)
            .map(|day| make_record("score-hook", day))
            .collect();
        write_jsonl(&path, &records);

        let sensor = AllostaticLoadSensor::with_path(path).with_threshold(10);
        let score = sensor.allostatic_score();
        assert!((score - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_sensor_ignores_malformed_json_lines() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("hook-overrides.jsonl");

        let mut file = std::fs::File::create(&path).expect("create file");
        // Valid record
        let good = make_record("good-hook", 1);
        writeln!(file, "{}", serde_json::to_string(&good).expect("json")).expect("write");
        // Malformed line — must not panic
        writeln!(file, "{{not valid json}}").expect("write");
        // Another valid record
        writeln!(file, "{}", serde_json::to_string(&good).expect("json")).expect("write");

        // 2 valid records, threshold 1 → signal expected
        let sensor = AllostaticLoadSensor::with_path(path).with_threshold(1);
        let signals = sensor.detect();
        // Should detect signals from the 2 good records, ignoring the malformed one
        assert!(!signals.is_empty());
    }
}
