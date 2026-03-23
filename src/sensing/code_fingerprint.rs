//! Code Fingerprint Sensor
//!
//! DAMP sensor that monitors the codebase for "pathogenic" code patterns
//! using statistical fingerprints from the antitransformer.
//!
//! # Detection Logic
//! High generatedness probability in source code can signal:
//! - Over-reliance on LLM boilerplate without human architectural oversight
//! - "Copypasta" patterns with suspiciously uniform entropy
//! - Structural regressions where code density (CDI) is sacrificed for verbosity
//!
//! Tier: T3 (μ Mapping + σ Sequence + ∂ Boundary)
//! Grounding: κ (Comparison) + ∂ (Boundary) + ς (State)

use crate::sensing::{Measured, Sensor, SignalSource, ThreatLevel, ThreatSignal};
use antitransformer::pipeline::{self, AnalysisConfig, AnalysisResult};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Code Fingerprint Sensor — DAMP sensor for monitoring architectural integrity.
#[derive(Debug, Clone)]
pub struct CodeFingerprintSensor {
    sensitivity: f64,
    target_path: PathBuf,
    config: AnalysisConfig,
}

impl CodeFingerprintSensor {
    /// Create a new code fingerprint sensor for a specific path.
    #[must_use]
    pub fn new(target_path: impl Into<PathBuf>) -> Self {
        Self {
            sensitivity: 0.75,
            target_path: target_path.into(),
            config: AnalysisConfig {
                threshold: 0.65, // Stricter threshold for code (it's naturally structured)
                window_size: 100,
            },
        }
    }

    /// Create for the entire workspace.
    #[must_use]
    pub fn workspace() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        Self::new(Path::new(&home).join("nexcore"))
    }
}

impl Sensor for CodeFingerprintSensor {
    type Pattern = AnalysisResult;

    fn detect(&self) -> Vec<ThreatSignal<Self::Pattern>> {
        // In a real implementation, this would scan recently modified files.
        // For this PAMP/DAMP demonstration, we analyze a core file to detect
        // if its statistical fingerprint has drifted into "AI boilerplate" territory.

        let Ok(content) = std::fs::read_to_string(&self.target_path) else {
            return vec![];
        };

        // Extract a meaningful sample (middle block to avoid headers/licensing)
        let lines: Vec<&str> = content.lines().collect();
        let start = lines.len() / 4;
        let end = (lines.len() * 3) / 4;
        let sample = lines[start..end].join(
            "
",
        );

        if sample.len() < 100 {
            return vec![];
        }

        let result = pipeline::analyze(&sample, &self.config);

        // For code, we only emit if probability is VERY high or confidence is extreme
        if result.verdict == "generated" && result.probability > 0.85 {
            let signal = ThreatSignal::new(
                result.clone(),
                ThreatLevel::Medium,
                SignalSource::Damp {
                    subsystem: "architectural_integrity".to_string(),
                    damage_type: "high_entropy_drift".to_string(),
                },
            )
            .with_confidence(Measured::certain(result.confidence))
            .with_metadata("file", self.target_path.to_string_lossy().to_string())
            .with_metadata("probability", format!("{:.3}", result.probability))
            .with_metadata("hill_score", format!("{:.3}", result.features.hill_score));

            vec![signal]
        } else {
            vec![]
        }
    }

    fn sensitivity(&self) -> f64 {
        self.sensitivity
    }

    fn name(&self) -> &str {
        "code-fingerprint-sensor"
    }
}
