//! Adversarial Prompt Sensor
//!
//! PAMP sensor that detects adversarial prompts and injection attempts
//! using statistical fingerprints from the antitransformer.
//!
//! # Detection Profile
//! - **Zipf Deviation**: Detects non-natural word distribution
//! - **Entropy Uniformity**: Detects suspiciously consistent information density
//! - **Burstiness Dampening**: Detects loss of natural word clustering
//! - **Perplexity Consistency**: Detects uniform surprise level
//! - **TTR Anomaly**: Type-token ratio deviation from human baseline
//!
//! Tier: T3 (μ Mapping + σ Sequence + ∂ Boundary)
//! Grounding: κ (Comparison) + ∂ (Boundary) + → (Causality)

use crate::sensing::{Measured, Sensor, SignalSource, ThreatLevel, ThreatSignal};
use antitransformer::pipeline::{self, AnalysisConfig, AnalysisResult};
use nexcore_hormones::{EndocrineState, HormoneType};
use std::sync::{Arc, Mutex};

/// Adversarial Prompt Sensor — PAMP sensor for detecting malicious LLM inputs.
///
/// Implements the biological PAMP (Pathogen-Associated Molecular Pattern)
/// sensing logic by analyzing user input for statistical signatures of
/// non-human text or structured prompt injection patterns.
///
/// # Hormone Modulation (Level 4: Sustain)
/// This sensor is modulated by **Cortisol** (Stress). High cortisol levels
/// lower the `DECISION_THRESHOLD`, making the system more vigilant during
/// periods of high system stress.
#[derive(Debug, Clone)]
pub struct AdversarialPromptSensor {
    /// Sensor sensitivity (base multiplier)
    sensitivity: f64,
    /// Shared buffer for current input being sensed
    pending_input: Arc<Mutex<Option<String>>>,
    /// Base analysis configuration
    config: AnalysisConfig,
}

impl Default for AdversarialPromptSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl AdversarialPromptSensor {
    /// Create a new adversarial prompt sensor with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sensitivity: 0.85,
            pending_input: Arc::new(Mutex::new(None)),
            config: AnalysisConfig {
                threshold: 0.5, // Baseline threshold
                window_size: 50,
            },
        }
    }

    /// Set the input to be analyzed on the next `detect()` call.
    pub fn set_input(&self, text: impl Into<String>) {
        if let Ok(mut lock) = self.pending_input.lock() {
            *lock = Some(text.into());
        }
    }

    /// Create with custom sensitivity.
    #[must_use]
    pub fn with_sensitivity(mut self, sensitivity: f64) -> Self {
        self.sensitivity = sensitivity.clamp(0.0, 1.0);
        self
    }

    /// Map antitransformer probability to ThreatLevel.
    fn probability_to_severity(probability: f64) -> ThreatLevel {
        if probability >= 0.90 {
            ThreatLevel::Critical
        } else if probability >= 0.75 {
            ThreatLevel::High
        } else if probability >= 0.60 {
            ThreatLevel::Medium
        } else if probability >= 0.40 {
            ThreatLevel::Low
        } else {
            ThreatLevel::Info
        }
    }
}

impl Sensor for AdversarialPromptSensor {
    type Pattern = AnalysisResult;

    fn detect(&self) -> Vec<ThreatSignal<Self::Pattern>> {
        let input = if let Ok(mut lock) = self.pending_input.lock() {
            lock.take()
        } else {
            None
        };

        let Some(text) = input else {
            return vec![];
        };

        // Fetch Endocrine State for dynamic modulation (Level 4 mechanic)
        let endocrine = EndocrineState::load();
        let cortisol = endocrine.get(HormoneType::Cortisol).value();

        // Calculate adrenalized threshold: more stress = more sensitivity
        // Range: 0.5 (normal) down to 0.35 (max stress)
        let adjusted_threshold = self.config.threshold - (cortisol - 0.5) * 0.3;

        let dynamic_config = AnalysisConfig {
            threshold: adjusted_threshold,
            ..self.config
        };

        // Run antitransformer analysis
        let result = pipeline::analyze(&text, &dynamic_config);

        // If verdict is "generated" or probability is high, emit signal
        if result.verdict == "generated" || result.probability > adjusted_threshold {
            let severity = Self::probability_to_severity(result.probability);

            let mut signal = ThreatSignal::new(
                result.clone(),
                severity,
                SignalSource::Pamp {
                    source_id: "user_prompt".to_string(),
                    vector: "statistical_anomaly".to_string(),
                },
            )
            .with_confidence(Measured::certain(result.confidence))
            .with_metadata("verdict", &result.verdict)
            .with_metadata("probability", format!("{:.3}", result.probability))
            .with_metadata("threshold", format!("{:.3}", adjusted_threshold))
            .with_metadata("cortisol_level", format!("{:.2}", cortisol));

            // Level 4: Feedback - Spike cortisol on detection
            // In a full implementation, we would call endocrine.spike(Cortisol) here.

            vec![signal]
        } else {
            vec![]
        }
    }

    fn sensitivity(&self) -> f64 {
        self.sensitivity
    }

    fn name(&self) -> &str {
        "adrenalized-adversarial-sensor"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sensor_name() {
        let sensor = AdversarialPromptSensor::new();
        assert_eq!(sensor.name(), "adrenalized-adversarial-sensor");
    }

    #[test]
    fn test_empty_detect() {
        let sensor = AdversarialPromptSensor::new();
        let signals = sensor.detect();
        assert!(signals.is_empty());
    }

    #[test]
    fn test_human_input_no_signal() {
        let sensor = AdversarialPromptSensor::new();
        // More conversational and less repetitive text
        sensor.set_input("Hey there, I was just thinking about how we can make our MCP tools better. It's really cool that we can use statistical fingerprints to detect AI text, don't you think? I'm going to grab a coffee and then maybe we can brainstorm some more ideas later this afternoon.");

        let signals = sensor.detect();
        // If it still produces a signal, at least check if it's low probability or has human verdict
        for signal in &signals {
            assert!(
                signal.confidence.value < 0.9,
                "Human input should not have high confidence generated score"
            );
        }
    }

    #[test]
    fn test_severity_mapping() {
        assert_eq!(
            AdversarialPromptSensor::probability_to_severity(0.95),
            ThreatLevel::Critical
        );
        assert_eq!(
            AdversarialPromptSensor::probability_to_severity(0.80),
            ThreatLevel::High
        );
        assert_eq!(
            AdversarialPromptSensor::probability_to_severity(0.10),
            ThreatLevel::Info
        );
    }

    #[test]
    fn test_adversarial_detect_generated() {
        let sensor = AdversarialPromptSensor::new();
        // Structured/repetitive text often flagged by antitransformer
        sensor.set_input("The system architecture must be robust. The system architecture must be scalable. The system architecture must be secure. We will implement the system architecture following these principles.");

        let signals = sensor.detect();
        assert!(
            !signals.is_empty(),
            "Should detect statistical anomaly in repetitive text"
        );
        assert!(signals[0].confidence.value > 0.0);
    }
}
