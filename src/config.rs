#![allow(dead_code)]

//! # Guardian Configuration
//!
//! Type-safe configuration for the Guardian homeostasis engine.
//! Loads from `~/nexcore/guardian.toml` or `GUARDIAN_CONFIG` env var.
//! Falls back to embedded defaults matching existing constants.
//!
//! ## T1 Primitive Grounding
//!
//! | Concept | Primitive | Symbol |
//! |---------|-----------|--------|
//! | Config structure | Product | x |
//! | Threshold comparison | Comparison | k |
//! | File path | Location | l |
//! | Persistence | Persistence | p |
//! | Config variants | Sum | S |

use serde::{Deserialize, Serialize};

use crate::homeostasis::decision_config;
use crate::pattern_detector::PatternConfig;
use crate::response::{amplifier_config, ceiling_limits};

/// Errors from configuration loading.
///
/// Tier: T2-P (Sum type over T1 strings)
#[derive(Debug, nexcore_error::Error)]
pub enum ConfigError {
    /// Failed to read configuration file
    #[error("Failed to read config file: {0}")]
    ReadError(#[from] std::io::Error),

    /// Failed to parse TOML
    #[error("Failed to parse TOML config: {0}")]
    ParseError(#[from] toml::de::Error),
}

/// Top-level Guardian configuration.
///
/// All fields have `#[serde(default)]` so partial configs work.
///
/// Tier: T2-C (composed product of sub-configs)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GuardianConfig {
    /// Decision engine settings
    pub decision: DecisionConfig,
    /// Amplifier settings
    pub amplifier: AmplifierConfig,
    /// Response ceiling limits
    pub ceiling: CeilingConfig,
    /// Pattern detector thresholds
    pub pattern: PatternDetectorConfig,
    /// Tick interval in milliseconds (for scheduled loops)
    pub tick_interval_ms: u64,
    /// Feedback persistence settings
    pub feedback: FeedbackConfig,
}

impl Default for GuardianConfig {
    fn default() -> Self {
        Self {
            decision: DecisionConfig::default(),
            amplifier: AmplifierConfig::default(),
            ceiling: CeilingConfig::default(),
            pattern: PatternDetectorConfig::default(),
            tick_interval_ms: 1000,
            feedback: FeedbackConfig::default(),
        }
    }
}

impl GuardianConfig {
    /// Load configuration from file.
    ///
    /// Resolution order:
    /// 1. `GUARDIAN_CONFIG` environment variable (path to .toml)
    /// 2. `~/nexcore/guardian.toml`
    /// 3. Embedded defaults (if file missing)
    ///
    /// # Errors
    ///
    /// Returns `ConfigError` if the file exists but is unreadable or unparseable.
    pub fn load() -> Result<Self, ConfigError> {
        let path = std::env::var("GUARDIAN_CONFIG")
            .ok()
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                let mut p = dirs_path();
                p.push("guardian.toml");
                p
            });

        if !path.exists() {
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(&path)?;
        let config: Self = toml::from_str(&content)?;
        Ok(config)
    }
}

/// Resolve `~/nexcore/` path.
fn dirs_path() -> std::path::PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        let mut p = std::path::PathBuf::from(home);
        p.push("nexcore");
        p
    } else {
        std::path::PathBuf::from("nexcore")
    }
}

/// Decision engine configuration.
///
/// Tier: T2-P (newtype-like product)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DecisionConfig {
    /// Risk threshold for action (0-100)
    pub risk_threshold: f64,
}

impl Default for DecisionConfig {
    fn default() -> Self {
        Self {
            risk_threshold: decision_config::DEFAULT_RISK_THRESHOLD,
        }
    }
}

/// Amplifier configuration.
///
/// Tier: T2-P
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AmplifierConfig {
    /// Maximum amplification factor
    pub max_factor: f64,
    /// Decay rate per second
    pub decay_rate: f64,
    /// Amplification step per signal
    pub step: f64,
}

impl Default for AmplifierConfig {
    fn default() -> Self {
        Self {
            max_factor: amplifier_config::MAX_FACTOR,
            decay_rate: amplifier_config::DECAY_RATE_PER_SECOND,
            step: amplifier_config::AMPLIFICATION_STEP,
        }
    }
}

/// Response ceiling configuration.
///
/// Tier: T2-P
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CeilingConfig {
    /// Maximum blocks per minute
    pub max_blocks_per_minute: u32,
    /// Maximum alerts per minute
    pub max_alerts_per_minute: u32,
    /// Maximum escalations per hour
    pub max_escalations_per_hour: u32,
}

impl Default for CeilingConfig {
    fn default() -> Self {
        Self {
            max_blocks_per_minute: ceiling_limits::MAX_BLOCKS_PER_MINUTE,
            max_alerts_per_minute: ceiling_limits::MAX_ALERTS_PER_MINUTE,
            max_escalations_per_hour: ceiling_limits::MAX_ESCALATIONS_PER_HOUR,
        }
    }
}

/// Pattern detector configuration.
///
/// Tier: T2-C
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PatternDetectorConfig {
    /// BlockStorm: minimum blocks within window
    pub block_storm_threshold: usize,
    /// BlockStorm: window in milliseconds
    pub block_storm_window_ms: u128,
    /// CompileFlood: minimum failures within window
    pub compile_flood_threshold: usize,
    /// CompileFlood: window in milliseconds
    pub compile_flood_window_ms: u128,
    /// InflammatoryCascade: max time between IL-1 -> IL-6 -> TNF-a
    pub cascade_window_ms: u128,
    /// HookMalfunction: max signals per hook within window
    pub hook_malfunction_threshold: usize,
    /// HookMalfunction: window in milliseconds
    pub hook_malfunction_window_ms: u128,
    /// TyrannyPattern: minimum governance violations per actor within window
    pub tyranny_threshold: usize,
    /// TyrannyPattern: window in milliseconds
    pub tyranny_window_ms: u128,
}

impl Default for PatternDetectorConfig {
    fn default() -> Self {
        let defaults = PatternConfig::default();
        Self {
            block_storm_threshold: defaults.block_storm_threshold,
            block_storm_window_ms: defaults.block_storm_window_ms,
            compile_flood_threshold: defaults.compile_flood_threshold,
            compile_flood_window_ms: defaults.compile_flood_window_ms,
            cascade_window_ms: defaults.cascade_window_ms,
            hook_malfunction_threshold: defaults.hook_malfunction_threshold,
            hook_malfunction_window_ms: defaults.hook_malfunction_window_ms,
            tyranny_threshold: defaults.tyranny_threshold,
            tyranny_window_ms: defaults.tyranny_window_ms,
        }
    }
}

impl From<PatternDetectorConfig> for PatternConfig {
    fn from(cfg: PatternDetectorConfig) -> Self {
        Self {
            block_storm_threshold: cfg.block_storm_threshold,
            block_storm_window_ms: cfg.block_storm_window_ms,
            compile_flood_threshold: cfg.compile_flood_threshold,
            compile_flood_window_ms: cfg.compile_flood_window_ms,
            cascade_window_ms: cfg.cascade_window_ms,
            hook_malfunction_threshold: cfg.hook_malfunction_threshold,
            hook_malfunction_window_ms: cfg.hook_malfunction_window_ms,
            tyranny_threshold: cfg.tyranny_threshold,
            tyranny_window_ms: cfg.tyranny_window_ms,
        }
    }
}

/// Feedback persistence configuration.
///
/// Tier: T2-P
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FeedbackConfig {
    /// File path for feedback JSONL (relative to ~/nexcore/)
    pub path: String,
    /// Whether feedback persistence is enabled
    pub enabled: bool,
}

impl Default for FeedbackConfig {
    fn default() -> Self {
        Self {
            path: "guardian_feedback.jsonl".to_string(),
            enabled: false,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_matches_constants() {
        let config = GuardianConfig::default();

        // Decision
        assert!(
            (config.decision.risk_threshold - decision_config::DEFAULT_RISK_THRESHOLD).abs()
                < f64::EPSILON
        );

        // Amplifier
        assert!((config.amplifier.max_factor - amplifier_config::MAX_FACTOR).abs() < f64::EPSILON);
        assert!(
            (config.amplifier.decay_rate - amplifier_config::DECAY_RATE_PER_SECOND).abs()
                < f64::EPSILON
        );
        assert!(
            (config.amplifier.step - amplifier_config::AMPLIFICATION_STEP).abs() < f64::EPSILON
        );

        // Ceiling
        assert_eq!(
            config.ceiling.max_blocks_per_minute,
            ceiling_limits::MAX_BLOCKS_PER_MINUTE
        );
        assert_eq!(
            config.ceiling.max_alerts_per_minute,
            ceiling_limits::MAX_ALERTS_PER_MINUTE
        );
        assert_eq!(
            config.ceiling.max_escalations_per_hour,
            ceiling_limits::MAX_ESCALATIONS_PER_HOUR
        );

        // Pattern detector
        let pattern_defaults = PatternConfig::default();
        assert_eq!(
            config.pattern.block_storm_threshold,
            pattern_defaults.block_storm_threshold
        );
        assert_eq!(
            config.pattern.cascade_window_ms,
            pattern_defaults.cascade_window_ms
        );
    }

    #[test]
    fn test_partial_toml_fills_defaults() {
        let toml_str = r#"
[decision]
risk_threshold = 75.0
"#;
        let config: GuardianConfig = toml::from_str(toml_str).ok().expect("valid TOML");
        assert!((config.decision.risk_threshold - 75.0).abs() < f64::EPSILON);
        // Other fields should be default
        assert!((config.amplifier.max_factor - amplifier_config::MAX_FACTOR).abs() < f64::EPSILON);
    }

    #[test]
    fn test_pattern_config_conversion() {
        let pdc = PatternDetectorConfig {
            block_storm_threshold: 10,
            ..Default::default()
        };
        let pc: PatternConfig = pdc.into();
        assert_eq!(pc.block_storm_threshold, 10);
    }

    #[test]
    fn test_feedback_config_defaults() {
        let config = FeedbackConfig::default();
        assert!(!config.enabled);
        assert!(config.path.contains("feedback"));
    }
}
