//! Engram Drift Sensor
//!
//! DAMP sensor that monitors the statistical integrity of engrams (learned patterns)
//! in nexcore-brain. Detects if implicit knowledge is drifting toward
//! low-entropy "generated" territory.
//!
//! # Detection Logic
//! High generatedness probability in pattern descriptions or examples signals:
//! - Pattern ingestion loop has been "polluted" by raw model output.
//! - Loss of specific human-context markers in the learning store.
//! - Engram erosion: complex learned patterns being flattened into generic boilerplate.
//!
//! Tier: T3 (μ Mapping + σ Sequence + ∂ Boundary)
//! Grounding: ρ (Recursion) + Σ (Sum) + κ (Comparison)

use crate::sensing::{Measured, Sensor, SignalSource, ThreatLevel, ThreatSignal};
use antitransformer::pipeline::{self, AnalysisConfig, AnalysisResult};
use nexcore_brain::implicit::ImplicitKnowledge;

/// Engram Drift Sensor — monitors the "naturalness" of learned patterns.
#[derive(Debug, Clone)]
pub struct EngramDriftSensor {
    sensitivity: f64,
    config: AnalysisConfig,
}

impl Default for EngramDriftSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl EngramDriftSensor {
    /// Create a new engram drift sensor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sensitivity: 0.80,
            config: AnalysisConfig {
                threshold: 0.55, // Moderate threshold for natural language patterns
                window_size: 50,
            },
        }
    }

    /// Create with custom sensitivity.
    #[must_use]
    pub fn with_sensitivity(mut self, sensitivity: f64) -> Self {
        self.sensitivity = sensitivity.clamp(0.0, 1.0);
        self
    }
}

impl Sensor for EngramDriftSensor {
    type Pattern = AnalysisResult;

    fn detect(&self) -> Vec<ThreatSignal<Self::Pattern>> {
        let Ok(brain) = ImplicitKnowledge::load() else {
            return vec![];
        };

        let mut signals = Vec::new();
        let patterns = brain.list_patterns();

        // Sample the most recent/high-confidence patterns
        for pattern in patterns.iter().take(20) {
            // Concatenate description and examples for a robust sample
            let mut text = pattern.description.clone();
            for example in &pattern.examples {
                text.push_str(" ");
                text.push_str(example);
            }

            if text.len() < 100 {
                continue;
            }

            let result = pipeline::analyze(&text, &self.config);

            // If an engram is flagged as "generated" with high confidence, it's drifting
            if result.verdict == "generated" && result.probability > 0.75 {
                let signal = ThreatSignal::new(
                    result.clone(),
                    ThreatLevel::Medium,
                    SignalSource::Damp {
                        subsystem: "implicit_knowledge".to_string(),
                        damage_type: "engram_statistical_drift".to_string(),
                    },
                )
                .with_confidence(Measured::certain(result.confidence))
                .with_metadata("pattern_id", &pattern.id)
                .with_metadata("pattern_type", &pattern.pattern_type)
                .with_metadata("probability", format!("{:.3}", result.probability))
                .with_metadata("zipf_alpha", format!("{:.3}", result.features.zipf_alpha));

                signals.push(signal);
            }
        }

        signals
            .into_iter()
            .filter(|s| s.confidence.value >= (1.0 - self.sensitivity))
            .collect()
    }

    fn sensitivity(&self) -> f64 {
        self.sensitivity
    }

    fn name(&self) -> &str {
        "engram-drift-sensor"
    }
}
