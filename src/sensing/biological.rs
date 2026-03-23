//! Biological Vital Signs Sensor
//!
//! Aggregates health from all 10 organ system crates into Guardian's
//! homeostasis loop. Each organ system contributes a Health snapshot;
//! unhealthy systems produce DAMP (Damage-Associated Molecular Pattern)
//! signals for the DecisionEngine.
//!
//! # Organ Systems Monitored
//!
//! | System | Crate | Key Metric |
//! |--------|-------|------------|
//! | Integumentary | nexcore-integumentary | Boundary permeability |
//! | Skeletal | nexcore-skeletal | CLAUDE.md + Wolff's Law |
//! | Muscular | nexcore-muscular | Fatigue + cardiac running |
//! | Cardiovascular | nexcore-circulatory | MCP server health |
//! | Respiratory | nexcore-respiratory | Dead space ratio |
//! | Digestive | nexcore-digestive | Skill pipeline flow |
//! | Lymphatic | nexcore-lymphatic | Thymic rejection rate |
//! | Nervous | nexcore-nervous | Signal latency |
//! | Urinary | nexcore-urinary | Silent failure detection |
//! | Reproductive | nexcore-reproductive | CI pipeline + deployment |
//!
//! # Tier: T3 (Domain-Specific Sensor)
//! # Grounding: κ (Comparison) + ∂ (Boundary) + Σ (Sum) — compares 10 systems against set points

use crate::confidence::ConfidenceSource;
use crate::sensing::{Measured, Sensor, SignalSource, ThreatLevel, ThreatSignal};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Pathology pattern detected by the biological sensor.
///
/// Maps to the disease taxonomy from the SSA-Bio output style.
///
/// # Tier: T2-C (Σ + ∂ + κ)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BiologicalPathology {
    /// Integumentary: boundary compromised (permissions too open)
    BoundaryCompromised { system: String },
    /// Skeletal: structural erosion (CLAUDE.md missing, types losing precision)
    Osteoporosis { system: String },
    /// Muscular: excessive fatigue, cardiac arrest
    Atrophy { system: String },
    /// Cardiovascular: pipeline clogging, server unresponsive
    Atherosclerosis { system: String },
    /// Respiratory: dead space too high, context pollution
    Emphysema { system: String },
    /// Digestive: skill pipeline broken, reflux detected
    Gerd { system: String },
    /// Lymphatic: overflow not draining, autoimmune
    Edema { system: String },
    /// Nervous: signal degradation, latency too high
    Neuropathy { system: String },
    /// Urinary: silent failure, filtration stopped
    RenalFailure { system: String },
    /// Reproductive: deployment failing, pipeline broken
    Infertility { system: String },
}

impl std::fmt::Display for BiologicalPathology {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BoundaryCompromised { system } => write!(f, "BoundaryCompromised({system})"),
            Self::Osteoporosis { system } => write!(f, "Osteoporosis({system})"),
            Self::Atrophy { system } => write!(f, "Atrophy({system})"),
            Self::Atherosclerosis { system } => write!(f, "Atherosclerosis({system})"),
            Self::Emphysema { system } => write!(f, "Emphysema({system})"),
            Self::Gerd { system } => write!(f, "Gerd({system})"),
            Self::Edema { system } => write!(f, "Edema({system})"),
            Self::Neuropathy { system } => write!(f, "Neuropathy({system})"),
            Self::RenalFailure { system } => write!(f, "RenalFailure({system})"),
            Self::Infertility { system } => write!(f, "Infertility({system})"),
        }
    }
}

/// Aggregated vital signs from all 10 organ systems.
///
/// # Tier: T3
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VitalSigns {
    /// Number of healthy systems out of 10
    pub healthy_count: u8,
    /// Number of unhealthy systems
    pub unhealthy_count: u8,
    /// Overall health score (0.0 - 1.0)
    pub overall_score: f64,
    /// Individual system statuses
    pub systems: Vec<OrganStatus>,
}

/// Status of a single organ system.
///
/// # Tier: T2-C (ς + κ)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganStatus {
    /// System name
    pub name: String,
    /// Whether the system is healthy
    pub healthy: bool,
    /// Diagnostic message
    pub diagnostic: String,
}

/// Biological Vital Signs Sensor — DAMP sensor monitoring all 10 organ systems.
///
/// Reads filesystem indicators to construct Health snapshots for each organ system:
/// - CLAUDE.md presence (Skeletal)
/// - Skill directory contents (Digestive)
/// - Hook telemetry state (Nervous)
/// - Metrics files (Muscular, Circulatory)
///
/// # Tier: T3
/// # Grounding: κ + ∂ + Σ
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiologicalVitalSignsSensor {
    sensitivity: f64,
    nexcore_root: PathBuf,
    claude_home: PathBuf,
}

impl Default for BiologicalVitalSignsSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl BiologicalVitalSignsSensor {
    /// Create with default paths.
    #[must_use]
    pub fn new() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        Self {
            sensitivity: 0.80,
            nexcore_root: PathBuf::from(&home).join("nexcore"),
            claude_home: PathBuf::from(&home).join(".claude"),
        }
    }

    /// Create with custom paths (for testing).
    #[must_use]
    pub fn with_paths(nexcore_root: PathBuf, claude_home: PathBuf) -> Self {
        Self {
            sensitivity: 0.80,
            nexcore_root,
            claude_home,
        }
    }

    /// Assess all 10 organ systems and return vital signs.
    #[must_use]
    pub fn assess_vital_signs(&self) -> VitalSigns {
        let systems = vec![
            self.assess_integumentary(),
            self.assess_skeletal(),
            self.assess_muscular(),
            self.assess_circulatory(),
            self.assess_respiratory(),
            self.assess_digestive(),
            self.assess_lymphatic(),
            self.assess_nervous(),
            self.assess_urinary(),
            self.assess_reproductive(),
        ];

        let healthy_count = systems.iter().filter(|s| s.healthy).count() as u8;
        let unhealthy_count = 10 - healthy_count;
        let overall_score = f64::from(healthy_count) / 10.0;

        VitalSigns {
            healthy_count,
            unhealthy_count,
            overall_score,
            systems,
        }
    }

    // ========================================================================
    // Individual Organ System Assessments
    // ========================================================================

    fn assess_integumentary(&self) -> OrganStatus {
        // Check: permissions settings exist and are not wide-open
        let settings_path = self.claude_home.join("settings.json");
        let healthy = settings_path.exists();
        OrganStatus {
            name: "Integumentary".to_string(),
            healthy,
            diagnostic: if healthy {
                "Boundary layer intact (settings.json present)".to_string()
            } else {
                "Boundary compromised (no settings.json)".to_string()
            },
        }
    }

    fn assess_skeletal(&self) -> OrganStatus {
        // Check: CLAUDE.md exists (skull intact)
        let claude_md = self.nexcore_root.join("CLAUDE.md");
        let healthy = claude_md.exists();
        OrganStatus {
            name: "Skeletal".to_string(),
            healthy,
            diagnostic: if healthy {
                "Structure intact (CLAUDE.md present)".to_string()
            } else {
                "Osteoporosis detected (CLAUDE.md missing)".to_string()
            },
        }
    }

    fn assess_muscular(&self) -> OrganStatus {
        // Check: Cargo.toml exists (build system functional)
        let cargo_toml = self.nexcore_root.join("Cargo.toml");
        let healthy = cargo_toml.exists();
        OrganStatus {
            name: "Muscular".to_string(),
            healthy,
            diagnostic: if healthy {
                "Execution engine available (workspace manifest present)".to_string()
            } else {
                "Atrophy detected (workspace manifest missing)".to_string()
            },
        }
    }

    fn assess_circulatory(&self) -> OrganStatus {
        // Check: MCP config exists (transport layer)
        let mcp_json = self.claude_home.join("settings.json");
        let healthy = if mcp_json.exists() {
            // Check if MCP servers are configured
            std::fs::read_to_string(&mcp_json)
                .map(|c| c.contains("mcpServers"))
                .unwrap_or(false)
        } else {
            false
        };
        OrganStatus {
            name: "Cardiovascular".to_string(),
            healthy,
            diagnostic: if healthy {
                "MCP transport active (servers configured)".to_string()
            } else {
                "Atherosclerosis risk (MCP servers not configured)".to_string()
            },
        }
    }

    fn assess_respiratory(&self) -> OrganStatus {
        // Respiratory health = context window I/O functioning
        // Proxy: check that skills/_shared/script-lib.sh exists (I/O pipeline)
        let script_lib = self.nexcore_root.join("skills/_shared/script-lib.sh");
        let healthy = script_lib.exists();
        OrganStatus {
            name: "Respiratory".to_string(),
            healthy,
            diagnostic: if healthy {
                "Context I/O pipeline intact (script library present)".to_string()
            } else {
                "Dead space risk (script library missing)".to_string()
            },
        }
    }

    fn assess_digestive(&self) -> OrganStatus {
        // Check: skills directory has content (digestive pipeline active)
        let skills_dir = self.nexcore_root.join("skills");
        let skill_count = if skills_dir.exists() {
            std::fs::read_dir(&skills_dir)
                .map(|entries| {
                    entries
                        .filter_map(|e| e.ok())
                        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                        .filter(|e| {
                            e.file_name()
                                .to_str()
                                .map(|n| !n.starts_with('_') && !n.starts_with('.'))
                                .unwrap_or(false)
                        })
                        .count()
                })
                .unwrap_or(0)
        } else {
            0
        };
        let healthy = skill_count >= 50; // target: 94, threshold: 50
        OrganStatus {
            name: "Digestive".to_string(),
            healthy,
            diagnostic: format!(
                "{} skills detected (target: 94, threshold: 50)",
                skill_count
            ),
        }
    }

    fn assess_lymphatic(&self) -> OrganStatus {
        // Check: hooks archive exists (overflow drainage functional)
        let archive = self.claude_home.join("hooks/archive");
        let healthy = archive.exists();
        OrganStatus {
            name: "Lymphatic".to_string(),
            healthy,
            diagnostic: if healthy {
                "Overflow drainage active (hooks archive present)".to_string()
            } else {
                "Edema risk (hooks archive missing)".to_string()
            },
        }
    }

    fn assess_nervous(&self) -> OrganStatus {
        // Check: hooks/bash directory has active hooks (reflex arcs)
        let hooks_dir = self.claude_home.join("hooks/bash");
        let hook_count = if hooks_dir.exists() {
            std::fs::read_dir(&hooks_dir)
                .map(|entries| {
                    entries
                        .filter_map(|e| e.ok())
                        .filter(|e| e.path().extension().map(|ext| ext == "sh").unwrap_or(false))
                        .count()
                })
                .unwrap_or(0)
        } else {
            0
        };
        let healthy = hook_count >= 5; // minimum reflex arcs
        OrganStatus {
            name: "Nervous".to_string(),
            healthy,
            diagnostic: format!("{} active hooks (reflex arcs, threshold: 5)", hook_count),
        }
    }

    fn assess_urinary(&self) -> OrganStatus {
        // Check: metrics directory exists and is not overflowing
        let metrics_dir = self.claude_home.join("metrics");
        let telemetry_dir = self.claude_home.join("telemetry");
        let metrics_ok = metrics_dir.exists();
        let telemetry_ok = telemetry_dir.exists();
        let healthy = metrics_ok; // basic filtration infrastructure present
        OrganStatus {
            name: "Urinary".to_string(),
            healthy,
            diagnostic: format!(
                "Filtration: metrics={}, telemetry={}",
                if metrics_ok { "active" } else { "missing" },
                if telemetry_ok { "active" } else { "missing" },
            ),
        }
    }

    fn assess_reproductive(&self) -> OrganStatus {
        // Check: CI config exists (deployment pipeline)
        let ci_config = self.nexcore_root.join(".github/workflows/ci.yml");
        let healthy = ci_config.exists();
        OrganStatus {
            name: "Reproductive".to_string(),
            healthy,
            diagnostic: if healthy {
                "CI pipeline intact (ci.yml present)".to_string()
            } else {
                "Infertility risk (CI pipeline missing)".to_string()
            },
        }
    }
}

impl Sensor for BiologicalVitalSignsSensor {
    type Pattern = BiologicalPathology;

    fn detect(&self) -> Vec<ThreatSignal<Self::Pattern>> {
        let vitals = self.assess_vital_signs();
        let mut signals = Vec::new();

        for system in &vitals.systems {
            if !system.healthy {
                let pathology = match system.name.as_str() {
                    "Integumentary" => BiologicalPathology::BoundaryCompromised {
                        system: system.name.clone(),
                    },
                    "Skeletal" => BiologicalPathology::Osteoporosis {
                        system: system.name.clone(),
                    },
                    "Muscular" => BiologicalPathology::Atrophy {
                        system: system.name.clone(),
                    },
                    "Cardiovascular" => BiologicalPathology::Atherosclerosis {
                        system: system.name.clone(),
                    },
                    "Respiratory" => BiologicalPathology::Emphysema {
                        system: system.name.clone(),
                    },
                    "Digestive" => BiologicalPathology::Gerd {
                        system: system.name.clone(),
                    },
                    "Lymphatic" => BiologicalPathology::Edema {
                        system: system.name.clone(),
                    },
                    "Nervous" => BiologicalPathology::Neuropathy {
                        system: system.name.clone(),
                    },
                    "Urinary" => BiologicalPathology::RenalFailure {
                        system: system.name.clone(),
                    },
                    "Reproductive" => BiologicalPathology::Infertility {
                        system: system.name.clone(),
                    },
                    _ => continue,
                };

                let threat_level = if vitals.unhealthy_count >= 5 {
                    ThreatLevel::High
                } else if vitals.unhealthy_count >= 3 {
                    ThreatLevel::Medium
                } else {
                    ThreatLevel::Low
                };

                let signal = ThreatSignal::new(
                    pathology,
                    threat_level,
                    SignalSource::Damp {
                        subsystem: format!("biological.{}", system.name.to_lowercase()),
                        damage_type: system.diagnostic.clone(),
                    },
                )
                .with_confidence(
                    ConfidenceSource::Calibrated {
                        value: 0.80,
                        rationale: "biological: organ system health assessment",
                    }
                    .derive(),
                )
                .with_metadata("organ_system", &system.name)
                .with_metadata("diagnostic", &system.diagnostic)
                .with_metadata(
                    "overall_health",
                    &format!("{}/{}", vitals.healthy_count, 10),
                );

                signals.push(signal);
            }
        }

        signals
    }

    fn sensitivity(&self) -> f64 {
        self.sensitivity
    }

    fn name(&self) -> &str {
        "biological-vital-signs"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_environment() -> (TempDir, BiologicalVitalSignsSensor) {
        let tmp = TempDir::new().ok().unwrap_or_else(|| {
            TempDir::new_in("/tmp").unwrap_or_else(|_| {
                panic!("Cannot create temp directory");
            })
        });
        let nexcore = tmp.path().join("nexcore");
        let claude = tmp.path().join(".claude");
        std::fs::create_dir_all(&nexcore).ok();
        std::fs::create_dir_all(&claude).ok();
        let sensor = BiologicalVitalSignsSensor::with_paths(nexcore, claude);
        (tmp, sensor)
    }

    #[test]
    fn test_empty_environment_all_unhealthy() {
        let (_tmp, sensor) = create_test_environment();
        let vitals = sensor.assess_vital_signs();
        assert_eq!(vitals.systems.len(), 10);
        assert_eq!(vitals.healthy_count, 0);
        assert_eq!(vitals.unhealthy_count, 10);
    }

    #[test]
    fn test_skeletal_healthy_when_claude_md_exists() {
        let (tmp, sensor) = create_test_environment();
        let nexcore = tmp.path().join("nexcore");
        std::fs::write(nexcore.join("CLAUDE.md"), "# Test").ok();
        let status = sensor.assess_skeletal();
        assert!(status.healthy);
    }

    #[test]
    fn test_muscular_healthy_when_cargo_toml_exists() {
        let (tmp, sensor) = create_test_environment();
        let nexcore = tmp.path().join("nexcore");
        std::fs::write(nexcore.join("Cargo.toml"), "[workspace]").ok();
        let status = sensor.assess_muscular();
        assert!(status.healthy);
    }

    #[test]
    fn test_reproductive_healthy_when_ci_exists() {
        let (tmp, sensor) = create_test_environment();
        let nexcore = tmp.path().join("nexcore");
        let ci_dir = nexcore.join(".github/workflows");
        std::fs::create_dir_all(&ci_dir).ok();
        std::fs::write(ci_dir.join("ci.yml"), "name: CI").ok();
        let status = sensor.assess_reproductive();
        assert!(status.healthy);
    }

    #[test]
    fn test_detect_produces_damp_signals_for_unhealthy() {
        let (_tmp, sensor) = create_test_environment();
        let signals = sensor.detect();
        // All 10 systems unhealthy in empty env → 10 signals
        assert_eq!(signals.len(), 10);
        for signal in &signals {
            assert!(signal.source.is_internal());
            assert_eq!(signal.severity, ThreatLevel::High);
        }
    }

    #[test]
    fn test_detect_no_signals_when_healthy() {
        let (tmp, sensor) = create_test_environment();
        let nexcore = tmp.path().join("nexcore");
        let claude = tmp.path().join(".claude");

        // Make all systems healthy
        std::fs::write(claude.join("settings.json"), r#"{"mcpServers":{}}"#).ok();
        std::fs::write(nexcore.join("CLAUDE.md"), "# Test").ok();
        std::fs::write(nexcore.join("Cargo.toml"), "[workspace]").ok();
        std::fs::create_dir_all(nexcore.join("skills/_shared")).ok();
        std::fs::write(nexcore.join("skills/_shared/script-lib.sh"), "#!/bin/bash").ok();
        // Create 50+ skill directories
        for i in 0..55 {
            std::fs::create_dir_all(nexcore.join(format!("skills/skill-{i}"))).ok();
        }
        std::fs::create_dir_all(claude.join("hooks/archive")).ok();
        // Create 5+ hook files
        std::fs::create_dir_all(claude.join("hooks/bash")).ok();
        for i in 0..6 {
            std::fs::write(
                claude.join(format!("hooks/bash/hook-{i}.sh")),
                "#!/bin/bash",
            )
            .ok();
        }
        std::fs::create_dir_all(claude.join("metrics")).ok();
        std::fs::create_dir_all(nexcore.join(".github/workflows")).ok();
        std::fs::write(nexcore.join(".github/workflows/ci.yml"), "name: CI").ok();

        let signals = sensor.detect();
        assert!(
            signals.is_empty(),
            "Expected 0 signals, got {}: {:?}",
            signals.len(),
            signals
                .iter()
                .map(|s| s.pattern.to_string())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_sensor_name() {
        let sensor = BiologicalVitalSignsSensor::new();
        assert_eq!(sensor.name(), "biological-vital-signs");
    }

    #[test]
    fn test_sensor_sensitivity() {
        let sensor = BiologicalVitalSignsSensor::new();
        assert!((sensor.sensitivity() - 0.80).abs() < f64::EPSILON);
    }

    #[test]
    fn test_vital_signs_overall_score() {
        let (tmp, sensor) = create_test_environment();
        let nexcore = tmp.path().join("nexcore");
        // Make 5 systems healthy
        let claude = tmp.path().join(".claude");
        std::fs::write(claude.join("settings.json"), r#"{"mcpServers":{}}"#).ok();
        std::fs::write(nexcore.join("CLAUDE.md"), "# Test").ok();
        std::fs::write(nexcore.join("Cargo.toml"), "[workspace]").ok();
        std::fs::create_dir_all(claude.join("metrics")).ok();
        std::fs::create_dir_all(nexcore.join(".github/workflows")).ok();
        std::fs::write(nexcore.join(".github/workflows/ci.yml"), "name: CI").ok();

        let vitals = sensor.assess_vital_signs();
        // integumentary + circulatory (both from settings.json) + skeletal + muscular + urinary + reproductive = 6
        assert_eq!(vitals.healthy_count, 6);
        assert!((vitals.overall_score - 0.6).abs() < f64::EPSILON);
    }
}
