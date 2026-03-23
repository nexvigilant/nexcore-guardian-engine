//! # Sensing Layer (PAMPs/DAMPs Detection)
//!
//! Biological-inspired threat detection following the immune system model:
//! - **PAMPs** (Pathogen-Associated Molecular Patterns): External threats
//! - **DAMPs** (Damage-Associated Molecular Patterns): Internal damage signals
//!
//! ## Example
//!
//! ```ignore
//! use nexcore_vigilance::guardian::sensing::{Sensor, ThreatSignal, SignalSource, ThreatLevel};
//!
//! struct ApiThreatSensor;
//!
//! impl Sensor for ApiThreatSensor {
//!     type Pattern = String;
//!
//!     fn detect(&self) -> Vec<ThreatSignal<Self::Pattern>> {
//!         // Detect API-based threats
//!         vec![]
//!     }
//!
//!     fn sensitivity(&self) -> f64 {
//!         0.8 // 80% sensitivity
//!     }
//!
//!     fn name(&self) -> &str {
//!         "api-threat-sensor"
//!     }
//! }
//! ```

pub mod adversarial;
pub mod allostatic;
pub mod biological;
#[cfg(feature = "browser")]
pub mod browser;
pub mod code_fingerprint;
pub mod code_health;
pub mod cytokine;
pub mod engram_drift;
pub mod hook_telemetry;
pub mod hud;
pub mod observability;
pub mod ribosome_damp;
pub mod signal_health;

use nexcore_chrono::DateTime;
use nexcore_primitives::measurement::Measured;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

use crate::confidence::ConfidenceSource;

/// Ordinal escalation scale for real-time operational threat detection.
///
/// Tier: T2-P (κ + ∂ — comparison with boundary)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ThreatLevel {
    /// Informational - no action required
    Info,
    /// Low threat - monitor
    Low,
    /// Medium threat - investigate
    Medium,
    /// High threat - respond immediately
    High,
    /// Critical - emergency response
    Critical,
}

/// Backward-compatible alias.
#[deprecated(note = "use ThreatLevel — F2 equivocation fix")]
pub type Severity = ThreatLevel;

impl ThreatLevel {
    /// Convert to numeric score (0-100)
    #[must_use]
    pub fn score(&self) -> u8 {
        match self {
            Self::Info => 0,
            Self::Low => 25,
            Self::Medium => 50,
            Self::High => 75,
            Self::Critical => 100,
        }
    }
}

/// Signal source classification
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignalSource {
    /// External threat (PAMP - Pathogen-Associated Molecular Pattern)
    /// Examples: API attacks, malformed requests, injection attempts
    Pamp {
        /// Source identifier (IP, user agent, etc.)
        source_id: String,
        /// Attack vector description
        vector: String,
    },
    /// Internal damage signal (DAMP - Damage-Associated Molecular Pattern)
    /// Examples: Memory leaks, failed services, data corruption
    Damp {
        /// Affected subsystem
        subsystem: String,
        /// Damage type
        damage_type: String,
    },
    /// Hybrid signal (both external and internal components)
    Hybrid {
        /// External component
        external: String,
        /// Internal component
        internal: String,
    },
}

impl SignalSource {
    /// Check if this is an external threat (PAMP)
    #[must_use]
    pub fn is_external(&self) -> bool {
        matches!(self, Self::Pamp { .. } | Self::Hybrid { .. })
    }

    /// Check if this is internal damage (DAMP)
    #[must_use]
    pub fn is_internal(&self) -> bool {
        matches!(self, Self::Damp { .. } | Self::Hybrid { .. })
    }
}

/// A detected threat pattern (PAMP/DAMP) with severity and confidence.
///
/// Tier: T3 (∃ + ∂ + κ — existence with boundary and comparison)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatSignal<T> {
    /// Unique signal identifier
    pub id: String,
    /// Detected pattern
    pub pattern: T,
    /// Signal severity
    pub severity: ThreatLevel,
    /// Detection timestamp
    pub timestamp: DateTime,
    /// Signal source (PAMP/DAMP/Hybrid)
    pub source: SignalSource,
    /// Confidence score (0.0-1.0)
    pub confidence: Measured<f64>,
    /// Additional metadata
    pub metadata: std::collections::HashMap<String, String>,
}

/// Backward-compatible alias.
#[deprecated(note = "use ThreatSignal — F2 equivocation fix")]
pub type Signal<T> = ThreatSignal<T>;

impl<T: Debug> ThreatSignal<T> {
    /// Create a new signal
    #[must_use]
    pub fn new(pattern: T, severity: ThreatLevel, source: SignalSource) -> Self {
        Self {
            id: nexcore_id::NexId::v4().to_string(),
            pattern,
            severity,
            timestamp: DateTime::now(),
            source,
            confidence: Measured::certain(1.0),
            metadata: std::collections::HashMap::new(),
        }
    }

    /// Create with custom confidence
    #[must_use]
    pub fn with_confidence(mut self, confidence: Measured<f64>) -> Self {
        self.confidence = confidence;
        self
    }

    /// Add metadata
    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Calculate effective severity (severity * confidence)
    #[must_use]
    pub fn effective_severity(&self) -> f64 {
        f64::from(self.severity.score()) * self.confidence.value
    }
}

/// Sensor trait for threat detection
///
/// Implement this trait to create custom sensors for detecting
/// specific types of threats or damage patterns.
pub trait Sensor: Send + Sync {
    /// The pattern type this sensor detects
    type Pattern: Debug + Clone + Send + Sync;

    /// Detect signals in the current environment
    fn detect(&self) -> Vec<ThreatSignal<Self::Pattern>>;

    /// Sensor sensitivity (0.0-1.0)
    /// Higher values mean more sensitive detection
    fn sensitivity(&self) -> f64;

    /// Sensor name for logging/metrics
    fn name(&self) -> &str;

    /// Check if sensor is active
    fn is_active(&self) -> bool {
        true
    }
}

// ============================================================================
// Threat Patterns
// ============================================================================

/// Common SQL injection patterns
pub static SQL_INJECTION_PATTERNS: &[&str] = &[
    "' OR '1'='1",
    "'; DROP TABLE",
    "UNION SELECT",
    "1=1--",
    "' OR ''='",
    "/**/",
    "@@version",
    "EXEC xp_",
    "WAITFOR DELAY",
    "BENCHMARK(",
];

/// Common XSS patterns
pub static XSS_PATTERNS: &[&str] = &[
    "<script>",
    "javascript:",
    "onerror=",
    "onload=",
    "onclick=",
    "<img src=x",
    "eval(",
    "document.cookie",
    "innerHTML",
    "<iframe",
];

/// Path traversal patterns
pub static PATH_TRAVERSAL_PATTERNS: &[&str] = &[
    "../",
    "..\\",
    "%2e%2e/",
    "%2e%2e\\",
    "....//",
    "/etc/passwd",
    "/etc/shadow",
    "C:\\Windows",
];

/// Request context for external threat detection
#[derive(Debug, Clone, Default)]
pub struct RequestContext {
    /// Request path
    pub path: String,
    /// Query string
    pub query: String,
    /// Request body
    pub body: String,
    /// Headers as key-value pairs
    pub headers: Vec<(String, String)>,
    /// Source IP
    pub source_ip: String,
    /// User agent
    pub user_agent: String,
    /// Request rate (requests per second from this IP)
    pub request_rate: f64,
    /// Failed auth attempts in last minute
    pub failed_auth_count: u32,
}

// ============================================================================
// Built-in Sensors
// ============================================================================

/// External threat sensor for API-based attacks
#[derive(Debug, Clone, Default)]
pub struct ExternalSensor {
    /// Sensitivity level
    sensitivity: f64,
    /// Current request context (set before calling detect)
    context: Option<RequestContext>,
    /// Rate limit threshold (requests per second)
    rate_limit_threshold: f64,
    /// Max failed auth attempts before alert
    max_failed_auth: u32,
}

impl ExternalSensor {
    /// Create a new external sensor with default sensitivity
    #[must_use]
    pub fn new() -> Self {
        Self {
            sensitivity: 0.8,
            context: None,
            rate_limit_threshold: 100.0,
            max_failed_auth: 5,
        }
    }

    /// Create with custom sensitivity
    #[must_use]
    pub fn with_sensitivity(sensitivity: f64) -> Self {
        Self {
            sensitivity: sensitivity.clamp(0.0, 1.0),
            ..Self::new()
        }
    }

    /// Set the request context for detection
    pub fn set_context(&mut self, context: RequestContext) {
        self.context = Some(context);
    }

    /// Clear the current context
    pub fn clear_context(&mut self) {
        self.context = None;
    }

    /// Set rate limit threshold
    #[must_use]
    pub fn with_rate_limit(mut self, threshold: f64) -> Self {
        self.rate_limit_threshold = threshold;
        self
    }

    /// Check for pattern matches in input
    fn check_patterns(input: &str, patterns: &[&str]) -> Vec<String> {
        let input_lower = input.to_lowercase();
        patterns
            .iter()
            .filter(|p| input_lower.contains(&p.to_lowercase()))
            .map(|p| (*p).to_string())
            .collect()
    }

    /// Detect SQL injection in input
    fn detect_sql_injection(&self, input: &str) -> Option<ThreatSignal<String>> {
        let matches = Self::check_patterns(input, SQL_INJECTION_PATTERNS);
        if matches.is_empty() {
            return None;
        }

        let ctx = self.context.as_ref();
        Some(
            ThreatSignal::new(
                format!("sql_injection:{}", matches.join(",")),
                ThreatLevel::High,
                SignalSource::Pamp {
                    source_id: ctx.map_or_else(|| "unknown".to_string(), |c| c.source_ip.clone()),
                    vector: "sql-injection".to_string(),
                },
            )
            .with_confidence(
                ConfidenceSource::Calibrated {
                    value: 0.9,
                    rationale: "sql injection: regex pattern match",
                }
                .derive(),
            )
            .with_metadata("patterns_matched", matches.join(",")),
        )
    }

    /// Detect XSS in input
    fn detect_xss(&self, input: &str) -> Option<ThreatSignal<String>> {
        let matches = Self::check_patterns(input, XSS_PATTERNS);
        if matches.is_empty() {
            return None;
        }

        let ctx = self.context.as_ref();
        Some(
            ThreatSignal::new(
                format!("xss:{}", matches.join(",")),
                ThreatLevel::High,
                SignalSource::Pamp {
                    source_id: ctx.map_or_else(|| "unknown".to_string(), |c| c.source_ip.clone()),
                    vector: "xss".to_string(),
                },
            )
            .with_confidence(
                ConfidenceSource::Calibrated {
                    value: 0.85,
                    rationale: "xss: heuristic tag detection",
                }
                .derive(),
            )
            .with_metadata("patterns_matched", matches.join(",")),
        )
    }

    /// Detect path traversal in input
    fn detect_path_traversal(&self, input: &str) -> Option<ThreatSignal<String>> {
        let matches = Self::check_patterns(input, PATH_TRAVERSAL_PATTERNS);
        if matches.is_empty() {
            return None;
        }

        let ctx = self.context.as_ref();
        Some(
            ThreatSignal::new(
                format!("path_traversal:{}", matches.join(",")),
                ThreatLevel::Medium,
                SignalSource::Pamp {
                    source_id: ctx.map_or_else(|| "unknown".to_string(), |c| c.source_ip.clone()),
                    vector: "path-traversal".to_string(),
                },
            )
            .with_confidence(
                ConfidenceSource::Calibrated {
                    value: 0.8,
                    rationale: "path traversal: indirect pattern",
                }
                .derive(),
            )
            .with_metadata("patterns_matched", matches.join(",")),
        )
    }

    /// Detect rate limit violations
    fn detect_rate_limit(&self) -> Option<ThreatSignal<String>> {
        let ctx = self.context.as_ref()?;
        if ctx.request_rate <= self.rate_limit_threshold {
            return None;
        }

        Some(
            ThreatSignal::new(
                format!("rate_limit:{}rps", ctx.request_rate as u32),
                if ctx.request_rate > self.rate_limit_threshold * 2.0 {
                    ThreatLevel::High
                } else {
                    ThreatLevel::Medium
                },
                SignalSource::Pamp {
                    source_id: ctx.source_ip.clone(),
                    vector: "rate-limit-violation".to_string(),
                },
            )
            .with_confidence(
                ConfidenceSource::Calibrated {
                    value: 0.95,
                    rationale: "rate limit: threshold violation",
                }
                .derive(),
            )
            .with_metadata("rate", ctx.request_rate.to_string())
            .with_metadata("threshold", self.rate_limit_threshold.to_string()),
        )
    }

    /// Detect brute force auth attempts
    fn detect_auth_brute_force(&self) -> Option<ThreatSignal<String>> {
        let ctx = self.context.as_ref()?;
        if ctx.failed_auth_count <= self.max_failed_auth {
            return None;
        }

        let severity = if ctx.failed_auth_count > self.max_failed_auth * 3 {
            ThreatLevel::Critical
        } else if ctx.failed_auth_count > self.max_failed_auth * 2 {
            ThreatLevel::High
        } else {
            ThreatLevel::Medium
        };

        Some(
            ThreatSignal::new(
                format!("auth_brute_force:{}_attempts", ctx.failed_auth_count),
                severity,
                SignalSource::Pamp {
                    source_id: ctx.source_ip.clone(),
                    vector: "authentication-brute-force".to_string(),
                },
            )
            .with_confidence(
                ConfidenceSource::Calibrated {
                    value: 0.9,
                    rationale: "auth brute force: failure count",
                }
                .derive(),
            )
            .with_metadata("failed_attempts", ctx.failed_auth_count.to_string()),
        )
    }
}

impl Sensor for ExternalSensor {
    type Pattern = String;

    fn detect(&self) -> Vec<ThreatSignal<Self::Pattern>> {
        let mut signals = Vec::new();

        if let Some(ctx) = &self.context {
            // Check all inputs for injection patterns
            let inputs = [&ctx.path, &ctx.query, &ctx.body];

            for input in inputs {
                if let Some(signal) = self.detect_sql_injection(input) {
                    signals.push(signal);
                }
                if let Some(signal) = self.detect_xss(input) {
                    signals.push(signal);
                }
                if let Some(signal) = self.detect_path_traversal(input) {
                    signals.push(signal);
                }
            }

            // Check rate limiting
            if let Some(signal) = self.detect_rate_limit() {
                signals.push(signal);
            }

            // Check auth brute force
            if let Some(signal) = self.detect_auth_brute_force() {
                signals.push(signal);
            }
        }

        // Apply sensitivity filter - only return signals above threshold
        signals
            .into_iter()
            .filter(|s| s.confidence.value >= (1.0 - self.sensitivity))
            .collect()
    }

    fn sensitivity(&self) -> f64 {
        self.sensitivity
    }

    fn name(&self) -> &str {
        "external-sensor"
    }
}

/// System health metrics for internal damage detection
#[derive(Debug, Clone, Default)]
pub struct SystemMetrics {
    /// Memory usage percentage (0-100)
    pub memory_percent: f64,
    /// CPU usage percentage (0-100)
    pub cpu_percent: f64,
    /// Disk usage percentage (0-100)
    pub disk_percent: f64,
    /// Error rate (errors per second)
    pub error_rate: f64,
    /// Database connection pool usage (0-100)
    pub db_pool_percent: f64,
    /// Active connections count
    pub active_connections: u32,
    /// Max connections allowed
    pub max_connections: u32,
    /// Failed health check subsystems
    pub failed_health_checks: Vec<String>,
    /// Latency in milliseconds (p99)
    pub latency_p99_ms: f64,
}

/// Internal damage sensor for system health
#[derive(Debug, Clone, Default)]
pub struct InternalSensor {
    /// Sensitivity level
    sensitivity: f64,
    /// Current system metrics (set before calling detect)
    metrics: Option<SystemMetrics>,
    /// Memory threshold (percent)
    memory_threshold: f64,
    /// CPU threshold (percent)
    cpu_threshold: f64,
    /// Disk threshold (percent)
    disk_threshold: f64,
    /// Error rate threshold (per second)
    error_rate_threshold: f64,
    /// Latency threshold (ms)
    latency_threshold: f64,
}

impl InternalSensor {
    /// Create a new internal sensor with default sensitivity
    #[must_use]
    pub fn new() -> Self {
        Self {
            sensitivity: 0.9,
            metrics: None,
            memory_threshold: 85.0,
            cpu_threshold: 90.0,
            disk_threshold: 90.0,
            error_rate_threshold: 10.0,
            latency_threshold: 1000.0,
        }
    }

    /// Create with custom sensitivity
    #[must_use]
    pub fn with_sensitivity(sensitivity: f64) -> Self {
        Self {
            sensitivity: sensitivity.clamp(0.0, 1.0),
            ..Self::new()
        }
    }

    /// Set the system metrics for detection
    pub fn set_metrics(&mut self, metrics: SystemMetrics) {
        self.metrics = Some(metrics);
    }

    /// Clear the current metrics
    pub fn clear_metrics(&mut self) {
        self.metrics = None;
    }

    /// Configure thresholds
    #[must_use]
    pub fn with_thresholds(
        mut self,
        memory: f64,
        cpu: f64,
        disk: f64,
        error_rate: f64,
        latency: f64,
    ) -> Self {
        self.memory_threshold = memory;
        self.cpu_threshold = cpu;
        self.disk_threshold = disk;
        self.error_rate_threshold = error_rate;
        self.latency_threshold = latency;
        self
    }

    /// Detect memory pressure
    fn detect_memory_pressure(&self) -> Option<ThreatSignal<String>> {
        let m = self.metrics.as_ref()?;
        if m.memory_percent <= self.memory_threshold {
            return None;
        }

        let severity = if m.memory_percent > 95.0 {
            ThreatLevel::Critical
        } else if m.memory_percent > 90.0 {
            ThreatLevel::High
        } else {
            ThreatLevel::Medium
        };

        Some(
            ThreatSignal::new(
                format!("memory_pressure:{:.1}%", m.memory_percent),
                severity,
                SignalSource::Damp {
                    subsystem: "memory".to_string(),
                    damage_type: "resource-exhaustion".to_string(),
                },
            )
            .with_confidence(
                ConfidenceSource::Calibrated {
                    value: 0.95,
                    rationale: "memory: threshold violation",
                }
                .derive(),
            )
            .with_metadata("usage_percent", format!("{:.1}", m.memory_percent))
            .with_metadata("threshold", format!("{:.1}", self.memory_threshold)),
        )
    }

    /// Detect CPU saturation
    fn detect_cpu_saturation(&self) -> Option<ThreatSignal<String>> {
        let m = self.metrics.as_ref()?;
        if m.cpu_percent <= self.cpu_threshold {
            return None;
        }

        let severity = if m.cpu_percent > 98.0 {
            ThreatLevel::Critical
        } else if m.cpu_percent > 95.0 {
            ThreatLevel::High
        } else {
            ThreatLevel::Medium
        };

        Some(
            ThreatSignal::new(
                format!("cpu_saturation:{:.1}%", m.cpu_percent),
                severity,
                SignalSource::Damp {
                    subsystem: "cpu".to_string(),
                    damage_type: "resource-exhaustion".to_string(),
                },
            )
            .with_confidence(
                ConfidenceSource::Calibrated {
                    value: 0.9,
                    rationale: "cpu: utilization pattern",
                }
                .derive(),
            )
            .with_metadata("usage_percent", format!("{:.1}", m.cpu_percent)),
        )
    }

    /// Detect disk space issues
    fn detect_disk_pressure(&self) -> Option<ThreatSignal<String>> {
        let m = self.metrics.as_ref()?;
        if m.disk_percent <= self.disk_threshold {
            return None;
        }

        let severity = if m.disk_percent > 98.0 {
            ThreatLevel::Critical
        } else if m.disk_percent > 95.0 {
            ThreatLevel::High
        } else {
            ThreatLevel::Medium
        };

        Some(
            ThreatSignal::new(
                format!("disk_pressure:{:.1}%", m.disk_percent),
                severity,
                SignalSource::Damp {
                    subsystem: "disk".to_string(),
                    damage_type: "resource-exhaustion".to_string(),
                },
            )
            .with_confidence(
                ConfidenceSource::Calibrated {
                    value: 0.95,
                    rationale: "disk: threshold violation",
                }
                .derive(),
            )
            .with_metadata("usage_percent", format!("{:.1}", m.disk_percent)),
        )
    }

    /// Detect error rate spike
    fn detect_error_spike(&self) -> Option<ThreatSignal<String>> {
        let m = self.metrics.as_ref()?;
        if m.error_rate <= self.error_rate_threshold {
            return None;
        }

        let severity = if m.error_rate > self.error_rate_threshold * 5.0 {
            ThreatLevel::Critical
        } else if m.error_rate > self.error_rate_threshold * 2.0 {
            ThreatLevel::High
        } else {
            ThreatLevel::Medium
        };

        Some(
            ThreatSignal::new(
                format!("error_spike:{:.1}/s", m.error_rate),
                severity,
                SignalSource::Damp {
                    subsystem: "application".to_string(),
                    damage_type: "error-rate-spike".to_string(),
                },
            )
            .with_confidence(
                ConfidenceSource::Calibrated {
                    value: 0.85,
                    rationale: "error rate: heuristic detection",
                }
                .derive(),
            )
            .with_metadata("error_rate", format!("{:.1}", m.error_rate))
            .with_metadata("threshold", format!("{:.1}", self.error_rate_threshold)),
        )
    }

    /// Detect database connection pool exhaustion
    fn detect_db_pool_exhaustion(&self) -> Option<ThreatSignal<String>> {
        let m = self.metrics.as_ref()?;
        if m.db_pool_percent <= 90.0 {
            return None;
        }

        let severity = if m.db_pool_percent > 99.0 {
            ThreatLevel::Critical
        } else if m.db_pool_percent > 95.0 {
            ThreatLevel::High
        } else {
            ThreatLevel::Medium
        };

        Some(
            ThreatSignal::new(
                format!("db_pool_exhaustion:{:.1}%", m.db_pool_percent),
                severity,
                SignalSource::Damp {
                    subsystem: "database".to_string(),
                    damage_type: "connection-pool-exhaustion".to_string(),
                },
            )
            .with_confidence(
                ConfidenceSource::Calibrated {
                    value: 0.9,
                    rationale: "db pool: saturation pattern",
                }
                .derive(),
            )
            .with_metadata("pool_usage", format!("{:.1}", m.db_pool_percent)),
        )
    }

    /// Detect latency degradation
    fn detect_latency_degradation(&self) -> Option<ThreatSignal<String>> {
        let m = self.metrics.as_ref()?;
        if m.latency_p99_ms <= self.latency_threshold {
            return None;
        }

        let severity = if m.latency_p99_ms > self.latency_threshold * 5.0 {
            ThreatLevel::High
        } else if m.latency_p99_ms > self.latency_threshold * 2.0 {
            ThreatLevel::Medium
        } else {
            ThreatLevel::Low
        };

        Some(
            ThreatSignal::new(
                format!("latency_degradation:{:.0}ms", m.latency_p99_ms),
                severity,
                SignalSource::Damp {
                    subsystem: "performance".to_string(),
                    damage_type: "latency-degradation".to_string(),
                },
            )
            .with_confidence(
                ConfidenceSource::Calibrated {
                    value: 0.8,
                    rationale: "latency: deviation signal",
                }
                .derive(),
            )
            .with_metadata("latency_p99_ms", format!("{:.0}", m.latency_p99_ms))
            .with_metadata("threshold_ms", format!("{:.0}", self.latency_threshold)),
        )
    }

    /// Detect failed health checks
    fn detect_health_check_failures(&self) -> Vec<ThreatSignal<String>> {
        let m = match self.metrics.as_ref() {
            Some(m) => m,
            None => return vec![],
        };

        m.failed_health_checks
            .iter()
            .map(|subsystem| {
                ThreatSignal::new(
                    format!("health_check_failed:{}", subsystem),
                    ThreatLevel::High,
                    SignalSource::Damp {
                        subsystem: subsystem.clone(),
                        damage_type: "health-check-failure".to_string(),
                    },
                )
                .with_confidence(
                    ConfidenceSource::Calibrated {
                        value: 1.0,
                        rationale: "health check: binary pass/fail",
                    }
                    .derive(),
                )
                .with_metadata("subsystem", subsystem.clone())
            })
            .collect()
    }
}

impl Sensor for InternalSensor {
    type Pattern = String;

    fn detect(&self) -> Vec<ThreatSignal<Self::Pattern>> {
        let mut signals = Vec::new();

        // Check all internal health metrics
        if let Some(signal) = self.detect_memory_pressure() {
            signals.push(signal);
        }
        if let Some(signal) = self.detect_cpu_saturation() {
            signals.push(signal);
        }
        if let Some(signal) = self.detect_disk_pressure() {
            signals.push(signal);
        }
        if let Some(signal) = self.detect_error_spike() {
            signals.push(signal);
        }
        if let Some(signal) = self.detect_db_pool_exhaustion() {
            signals.push(signal);
        }
        if let Some(signal) = self.detect_latency_degradation() {
            signals.push(signal);
        }

        // Add all health check failures
        signals.extend(self.detect_health_check_failures());

        // Apply sensitivity filter
        signals
            .into_iter()
            .filter(|s| s.confidence.value >= (1.0 - self.sensitivity))
            .collect()
    }

    fn sensitivity(&self) -> f64 {
        self.sensitivity
    }

    fn name(&self) -> &str {
        "internal-sensor"
    }
}

/// PV Signal sensor for pharmacovigilance signal detection.
///
/// Accepts injected `RiskContext` values via a shared buffer.
/// On each `detect()`, drains the buffer, runs risk scoring, and
/// emits `Signal<String>` with proper severity mapping.
///
/// Tier: T2-C (composed mapping + state)
#[derive(Debug, Clone)]
pub struct PvSignalSensor {
    /// Sensitivity level
    sensitivity: f64,
    /// Injection buffer for external risk contexts
    pending: std::sync::Arc<std::sync::Mutex<Vec<crate::RiskContext>>>,
}

impl Default for PvSignalSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl PvSignalSensor {
    /// Create a new PV signal sensor
    #[must_use]
    pub fn new() -> Self {
        Self {
            sensitivity: 0.95,
            pending: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    /// Inject a risk context for processing on next `detect()` call.
    pub fn inject(&self, ctx: crate::RiskContext) {
        if let Ok(mut buf) = self.pending.lock() {
            buf.push(ctx);
        }
    }

    /// Get a cloneable handle to the injection buffer.
    #[must_use]
    pub fn injector(&self) -> std::sync::Arc<std::sync::Mutex<Vec<crate::RiskContext>>> {
        self.pending.clone()
    }

    /// Map risk level string to Severity
    fn level_to_severity(level: &str) -> ThreatLevel {
        match level {
            "Critical" => ThreatLevel::Critical,
            "High" => ThreatLevel::High,
            "Medium" => ThreatLevel::Medium,
            "Low" => ThreatLevel::Low,
            _ => ThreatLevel::Info,
        }
    }
}

impl Sensor for PvSignalSensor {
    type Pattern = String;

    fn detect(&self) -> Vec<ThreatSignal<Self::Pattern>> {
        let contexts = if let Ok(mut buf) = self.pending.lock() {
            std::mem::take(&mut *buf)
        } else {
            return vec![];
        };

        let mut signals = Vec::new();

        for ctx in &contexts {
            if let Ok(score) = crate::calculate_risk_score_validated(ctx) {
                let severity = Self::level_to_severity(&score.level);

                let mut signal = ThreatSignal::new(
                    format!("pv_signal:{}+{}", ctx.drug, ctx.event),
                    severity,
                    SignalSource::Damp {
                        subsystem: "pharmacovigilance".to_string(),
                        damage_type: "signal-detection".to_string(),
                    },
                )
                .with_confidence(nexcore_primitives::measurement::Measured::certain(
                    score.score.value / 100.0,
                ))
                .with_metadata("drug", &ctx.drug)
                .with_metadata("event", &ctx.event)
                .with_metadata("risk_level", &score.level)
                .with_metadata("risk_score", format!("{:.1}", score.score.value))
                .with_metadata("prr", format!("{:.3}", ctx.prr))
                .with_metadata("ror_lower", format!("{:.3}", ctx.ror_lower))
                .with_metadata("ic025", format!("{:.3}", ctx.ic025))
                .with_metadata("eb05", format!("{:.3}", ctx.eb05))
                .with_metadata("n", ctx.n.to_string());

                for factor in &score.factors {
                    let key = format!("factor_{}", signals.len());
                    signal = signal.with_metadata(key, factor.as_str());
                }

                signals.push(signal);
            }
        }

        signals
    }

    fn sensitivity(&self) -> f64 {
        self.sensitivity
    }

    fn name(&self) -> &str {
        "pv-signal-sensor"
    }
}

// ============================================================================
// CISA KEV Sensor (Known Exploited Vulnerabilities)
// ============================================================================

/// Errors from KEV sensor operations.
#[derive(Debug, nexcore_error::Error)]
pub enum KevError {
    /// HTTP client construction failed
    #[error("Failed to build HTTP client: {0}")]
    ClientBuild(#[from] reqwest::Error),

    /// Network request failed
    #[error("KEV API request failed: {0}")]
    NetworkError(String),

    /// Invalid response from API
    #[error("Invalid KEV response: HTTP {0}")]
    InvalidResponse(u16),

    /// JSON parsing failed
    #[error("Failed to parse KEV catalog: {0}")]
    ParseError(String),

    /// No data available (API failed and no cache)
    #[error("KEV unavailable: {reason} (no cached fallback)")]
    Unavailable {
        /// Why the KEV data is unavailable
        reason: String,
    },
}

/// A Known Exploited Vulnerability from CISA KEV catalog.
///
/// Data source: <https://github.com/cisagov/kev-data>
/// Updated daily by CISA.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KevVulnerability {
    /// CVE identifier (e.g., "CVE-2024-1234")
    pub cve_id: String,
    /// Vendor name
    pub vendor_project: String,
    /// Product name
    pub product: String,
    /// Vulnerability name/description
    pub vulnerability_name: String,
    /// Date added to KEV catalog
    pub date_added: String,
    /// Short description
    pub short_description: String,
    /// Required action
    pub required_action: String,
    /// Due date for remediation
    pub due_date: String,
    /// Known ransomware campaign use
    #[serde(default)]
    pub known_ransomware_campaign_use: String,
}

/// CISA KEV catalog response structure.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KevCatalog {
    /// Catalog title
    pub title: String,
    /// Catalog version
    pub catalog_version: String,
    /// Last updated timestamp
    pub date_released: String,
    /// Total vulnerability count
    pub count: u32,
    /// List of vulnerabilities
    pub vulnerabilities: Vec<KevVulnerability>,
}

/// KEV Sensor for detecting known exploited vulnerabilities in dependencies.
///
/// Polls CISA's Known Exploited Vulnerabilities catalog and matches
/// against project dependencies to emit PAMP signals.
///
/// # Contingency (V33)
///
/// Includes fallback caching: if API is unavailable, uses last-known-good
/// cached data to maintain threat detection capability.
///
/// # Example
///
/// ```ignore
/// use nexcore_vigilance::guardian::sensing::{KevSensor, Sensor};
///
/// let sensor = KevSensor::new()
///     .with_dependency_cves(vec!["CVE-2024-1234".into()]);
/// // In async context:
/// // let signals = sensor.detect_async().await;
/// ```
#[derive(Debug, Clone)]
pub struct KevSensor {
    /// Sensitivity level (0.0-1.0)
    sensitivity: f64,
    /// KEV API URL
    kev_url: String,
    /// Cached catalog for fallback (V33 contingency)
    cached_catalog: std::sync::Arc<std::sync::RwLock<Option<KevCatalog>>>,
    /// Known CVEs in project dependencies (populated externally)
    dependency_cves: Vec<String>,
}

impl Default for KevSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl KevSensor {
    /// CISA KEV catalog URL (JSON format)
    pub const KEV_URL: &'static str =
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

    /// Create a new KEV sensor with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sensitivity: 0.95,
            kev_url: Self::KEV_URL.to_string(),
            cached_catalog: std::sync::Arc::new(std::sync::RwLock::new(None)),
            dependency_cves: Vec::new(),
        }
    }

    /// Create with custom sensitivity.
    #[must_use]
    pub fn with_sensitivity(sensitivity: f64) -> Self {
        Self {
            sensitivity: sensitivity.clamp(0.0, 1.0),
            ..Self::new()
        }
    }

    /// Set CVEs found in project dependencies (from Cargo.lock, package.json, etc.)
    #[must_use]
    pub fn with_dependency_cves(mut self, cves: Vec<String>) -> Self {
        self.dependency_cves = cves;
        self
    }

    /// Add a dependency CVE to check against KEV.
    pub fn add_dependency_cve(&mut self, cve: impl Into<String>) {
        self.dependency_cves.push(cve.into());
    }

    /// Fetch KEV catalog from CISA (async).
    ///
    /// Returns cached data if fetch fails (V33 contingency).
    pub async fn fetch_catalog(&self) -> Result<KevCatalog, KevError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        match client.get(&self.kev_url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    match response.json::<KevCatalog>().await {
                        Ok(catalog) => {
                            // Update cache on success
                            if let Ok(mut cache) = self.cached_catalog.write() {
                                *cache = Some(catalog.clone());
                            }
                            Ok(catalog)
                        }
                        Err(e) => self.fallback_to_cache(format!("JSON parse: {e}")),
                    }
                } else {
                    self.fallback_to_cache(format!("HTTP {}", response.status()))
                }
            }
            Err(e) => self.fallback_to_cache(format!("Network: {e}")),
        }
    }

    /// Fallback to cached catalog (V33 contingency).
    fn fallback_to_cache(&self, reason: String) -> Result<KevCatalog, KevError> {
        if let Ok(cache) = self.cached_catalog.read() {
            if let Some(catalog) = cache.as_ref() {
                tracing::warn!(
                    "KEV API unavailable ({}), using cached catalog from {}",
                    reason,
                    catalog.date_released
                );
                return Ok(catalog.clone());
            }
        }
        Err(KevError::Unavailable { reason })
    }

    /// Detect known exploited vulnerabilities in dependencies (async).
    pub async fn detect_async(&self) -> Vec<ThreatSignal<KevVulnerability>> {
        let catalog = match self.fetch_catalog().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("KEV detection failed: {e}");
                return vec![];
            }
        };

        self.match_vulnerabilities(&catalog)
    }

    /// Match catalog vulnerabilities against dependency CVEs.
    fn match_vulnerabilities(&self, catalog: &KevCatalog) -> Vec<ThreatSignal<KevVulnerability>> {
        let mut signals = Vec::new();

        for vuln in &catalog.vulnerabilities {
            // Check if this CVE is in our dependencies
            if self.dependency_cves.iter().any(|cve| cve == &vuln.cve_id) {
                let severity = if vuln.known_ransomware_campaign_use.to_lowercase() == "known" {
                    ThreatLevel::Critical
                } else {
                    ThreatLevel::High
                };

                let signal = ThreatSignal::new(
                    vuln.clone(),
                    severity,
                    SignalSource::Pamp {
                        source_id: format!("cisa-kev:{}", vuln.cve_id),
                        vector: "known-exploited-vulnerability".to_string(),
                    },
                )
                .with_confidence(ConfidenceSource::Deterministic.derive())
                .with_metadata("vendor", &vuln.vendor_project)
                .with_metadata("product", &vuln.product)
                .with_metadata("due_date", &vuln.due_date)
                .with_metadata("ransomware", &vuln.known_ransomware_campaign_use);

                signals.push(signal);
            }
        }

        // Apply sensitivity filter
        signals
            .into_iter()
            .filter(|s| s.confidence.value >= (1.0 - self.sensitivity))
            .collect()
    }

    /// Get cached catalog if available.
    #[must_use]
    pub fn get_cached_catalog(&self) -> Option<KevCatalog> {
        self.cached_catalog.read().ok()?.clone()
    }

    /// Manually set cached catalog (for testing or pre-seeding).
    pub fn set_cached_catalog(&self, catalog: KevCatalog) {
        if let Ok(mut cache) = self.cached_catalog.write() {
            *cache = Some(catalog);
        }
    }

    /// Get count of vulnerabilities in cache.
    #[must_use]
    pub fn cached_vulnerability_count(&self) -> Option<u32> {
        self.get_cached_catalog().map(|c| c.count)
    }
}

impl Sensor for KevSensor {
    type Pattern = KevVulnerability;

    fn detect(&self) -> Vec<ThreatSignal<Self::Pattern>> {
        // Synchronous wrapper - returns cached results or empty
        // For full detection, use detect_async() in async context
        if let Some(catalog) = self.get_cached_catalog() {
            self.match_vulnerabilities(&catalog)
        } else {
            vec![]
        }
    }

    fn sensitivity(&self) -> f64 {
        self.sensitivity
    }

    fn name(&self) -> &str {
        "kev-sensor"
    }
}

// =============================================================================
// API Health Sensor - Monitors external data source availability
// =============================================================================

/// Status of a monitored API endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApiStatus {
    /// API is healthy and responding.
    Healthy,
    /// API is degraded (slow but functional).
    Degraded {
        /// Response latency in milliseconds.
        latency_ms: u64,
    },
    /// API is unavailable.
    Unavailable {
        /// Reason for unavailability.
        reason: String,
    },
    /// Status unknown (not yet checked).
    Unknown,
}

/// A monitored API endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoredEndpoint {
    /// Endpoint name for identification.
    pub name: String,
    /// Health check URL.
    pub url: String,
    /// Expected response status code (default 200).
    pub expected_status: u16,
    /// Timeout in milliseconds.
    pub timeout_ms: u64,
    /// Latency threshold for degraded status (ms).
    pub degraded_threshold_ms: u64,
}

impl MonitoredEndpoint {
    /// Create a new monitored endpoint with defaults.
    #[must_use]
    pub fn new(name: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            url: url.into(),
            expected_status: 200,
            timeout_ms: 5000,
            degraded_threshold_ms: 2000,
        }
    }

    /// Set expected HTTP status code.
    #[must_use]
    pub fn with_expected_status(mut self, status: u16) -> Self {
        self.expected_status = status;
        self
    }

    /// Set timeout.
    #[must_use]
    pub fn with_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }
}

/// Health check result for an endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    /// Endpoint name.
    pub endpoint: String,
    /// Current status.
    pub status: ApiStatus,
    /// Last check timestamp.
    pub checked_at: DateTime,
    /// Response latency (if available).
    pub latency_ms: Option<u64>,
}

/// API Health Sensor - monitors availability of external data sources.
///
/// Generates DAMP signals when monitored APIs become unavailable or degraded.
/// Designed for integration with Guardian homeostasis loop.
///
/// # Built-in Endpoints
///
/// - OpenFDA FAERS API
/// - CISA KEV (Known Exploited Vulnerabilities)
///
/// # Example
///
/// ```ignore
/// use nexcore_vigilance::guardian::sensing::{ApiHealthSensor, MonitoredEndpoint};
///
/// let sensor = ApiHealthSensor::new()
///     .with_endpoint(MonitoredEndpoint::new("custom-api", "https://api.example.com/health"));
/// ```
pub struct ApiHealthSensor {
    /// Monitored endpoints.
    endpoints: Vec<MonitoredEndpoint>,
    /// Cached health status for each endpoint.
    status_cache: std::sync::RwLock<std::collections::HashMap<String, HealthCheckResult>>,
    /// Sensitivity threshold (0.0-1.0).
    sensitivity: f64,
    /// Whether sensor is active.
    active: bool,
}

impl Default for ApiHealthSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHealthSensor {
    /// Create a new API health sensor with default endpoints.
    #[must_use]
    pub fn new() -> Self {
        let endpoints = vec![
            MonitoredEndpoint::new("openfda-faers", "https://api.fda.gov/drug/event.json?limit=1")
                .with_expected_status(200)
                .with_timeout_ms(5000),
            MonitoredEndpoint::new(
                "cisa-kev",
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            )
            .with_expected_status(200)
            .with_timeout_ms(10000),
        ];

        Self {
            endpoints,
            status_cache: std::sync::RwLock::new(std::collections::HashMap::new()),
            sensitivity: 0.9, // High sensitivity - we want to know about API issues
            active: true,
        }
    }

    /// Add a custom endpoint to monitor.
    #[must_use]
    pub fn with_endpoint(mut self, endpoint: MonitoredEndpoint) -> Self {
        self.endpoints.push(endpoint);
        self
    }

    /// Set sensitivity threshold.
    #[must_use]
    pub fn with_sensitivity(mut self, sensitivity: f64) -> Self {
        self.sensitivity = sensitivity.clamp(0.0, 1.0);
        self
    }

    /// Get current status for an endpoint.
    #[must_use]
    pub fn get_status(&self, endpoint_name: &str) -> Option<HealthCheckResult> {
        self.status_cache.read().ok()?.get(endpoint_name).cloned()
    }

    /// Update status for an endpoint (called after async health check).
    pub fn update_status(&self, result: HealthCheckResult) {
        if let Ok(mut cache) = self.status_cache.write() {
            cache.insert(result.endpoint.clone(), result);
        }
    }

    /// Generate signals from current cached status.
    fn generate_signals(&self) -> Vec<ThreatSignal<String>> {
        let cache = match self.status_cache.read() {
            Ok(c) => c,
            Err(_) => return vec![],
        };

        let mut signals = Vec::new();

        for result in cache.values() {
            match &result.status {
                ApiStatus::Unavailable { reason } => {
                    signals.push(
                        ThreatSignal::new(
                            format!("api_unavailable:{}", result.endpoint),
                            ThreatLevel::High,
                            SignalSource::Damp {
                                subsystem: "external-api".to_string(),
                                damage_type: "availability".to_string(),
                            },
                        )
                        .with_confidence(
                            ConfidenceSource::Calibrated {
                                value: 0.95,
                                rationale: "api dependency: availability check",
                            }
                            .derive(),
                        )
                        .with_metadata("endpoint", result.endpoint.clone())
                        .with_metadata("reason", reason.clone()),
                    );
                }
                ApiStatus::Degraded { latency_ms } => {
                    signals.push(
                        ThreatSignal::new(
                            format!("api_degraded:{}", result.endpoint),
                            ThreatLevel::Medium,
                            SignalSource::Damp {
                                subsystem: "external-api".to_string(),
                                damage_type: "performance".to_string(),
                            },
                        )
                        .with_confidence(
                            ConfidenceSource::Calibrated {
                                value: 0.8,
                                rationale: "api dependency: latency heuristic",
                            }
                            .derive(),
                        )
                        .with_metadata("endpoint", result.endpoint.clone())
                        .with_metadata("latency_ms", latency_ms.to_string()),
                    );
                }
                ApiStatus::Healthy | ApiStatus::Unknown => {}
            }
        }

        signals
    }

    /// Get all monitored endpoints.
    #[must_use]
    pub fn endpoints(&self) -> &[MonitoredEndpoint] {
        &self.endpoints
    }

    /// Get count of unhealthy endpoints.
    #[must_use]
    pub fn unhealthy_count(&self) -> usize {
        self.status_cache
            .read()
            .map(|cache| {
                cache
                    .values()
                    .filter(|r| matches!(r.status, ApiStatus::Unavailable { .. }))
                    .count()
            })
            .unwrap_or(0)
    }

    /// Get count of degraded endpoints.
    #[must_use]
    pub fn degraded_count(&self) -> usize {
        self.status_cache
            .read()
            .map(|cache| {
                cache
                    .values()
                    .filter(|r| matches!(r.status, ApiStatus::Degraded { .. }))
                    .count()
            })
            .unwrap_or(0)
    }
}

impl Sensor for ApiHealthSensor {
    type Pattern = String;

    fn detect(&self) -> Vec<ThreatSignal<Self::Pattern>> {
        self.generate_signals()
    }

    fn sensitivity(&self) -> f64 {
        self.sensitivity
    }

    fn name(&self) -> &str {
        "api-health-sensor"
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_score() {
        assert_eq!(ThreatLevel::Info.score(), 0);
        assert_eq!(ThreatLevel::Critical.score(), 100);
    }

    #[test]
    fn test_signal_source_classification() {
        let pamp = SignalSource::Pamp {
            source_id: "192.168.1.1".to_string(),
            vector: "sql-injection".to_string(),
        };
        assert!(pamp.is_external());
        assert!(!pamp.is_internal());

        let damp = SignalSource::Damp {
            subsystem: "database".to_string(),
            damage_type: "connection-pool-exhaustion".to_string(),
        };
        assert!(!damp.is_external());
        assert!(damp.is_internal());
    }

    #[test]
    fn test_signal_effective_severity() {
        let signal = ThreatSignal::new(
            "test-pattern".to_string(),
            ThreatLevel::High,
            SignalSource::Pamp {
                source_id: "test".to_string(),
                vector: "test".to_string(),
            },
        )
        .with_confidence(Measured::certain(0.5));

        // High (75) * 0.5 = 37.5
        assert!((signal.effective_severity() - 37.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_external_sensor() {
        let sensor = ExternalSensor::new();
        assert_eq!(sensor.name(), "external-sensor");
        assert!((sensor.sensitivity() - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn test_external_sensor_sql_injection() {
        let mut sensor = ExternalSensor::new();
        sensor.set_context(RequestContext {
            path: "/api/users".to_string(),
            query: "id=1' OR '1'='1".to_string(),
            body: String::new(),
            source_ip: "192.168.1.100".to_string(),
            ..Default::default()
        });

        let signals = sensor.detect();
        assert!(!signals.is_empty());
        assert!(signals[0].pattern.contains("sql_injection"));
        assert_eq!(signals[0].severity, ThreatLevel::High);
    }

    #[test]
    fn test_external_sensor_xss() {
        let mut sensor = ExternalSensor::new();
        sensor.set_context(RequestContext {
            body: "<script>alert('xss')</script>".to_string(),
            source_ip: "10.0.0.1".to_string(),
            ..Default::default()
        });

        let signals = sensor.detect();
        assert!(!signals.is_empty());
        assert!(signals[0].pattern.contains("xss"));
    }

    #[test]
    fn test_external_sensor_rate_limit() {
        let mut sensor = ExternalSensor::new();
        sensor.set_context(RequestContext {
            request_rate: 150.0, // Above default 100 threshold
            source_ip: "attacker.ip".to_string(),
            ..Default::default()
        });

        let signals = sensor.detect();
        assert!(!signals.is_empty());
        assert!(signals[0].pattern.contains("rate_limit"));
    }

    #[test]
    fn test_external_sensor_no_threats() {
        let mut sensor = ExternalSensor::new();
        sensor.set_context(RequestContext {
            path: "/api/users".to_string(),
            query: "id=123".to_string(),
            body: r#"{"name": "John"}"#.to_string(),
            source_ip: "192.168.1.1".to_string(),
            request_rate: 10.0,
            ..Default::default()
        });

        let signals = sensor.detect();
        assert!(signals.is_empty());
    }

    #[test]
    fn test_internal_sensor() {
        let sensor = InternalSensor::new();
        assert_eq!(sensor.name(), "internal-sensor");
        assert!((sensor.sensitivity() - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn test_internal_sensor_memory_pressure() {
        let mut sensor = InternalSensor::new();
        sensor.set_metrics(SystemMetrics {
            memory_percent: 92.0,
            ..Default::default()
        });

        let signals = sensor.detect();
        assert!(!signals.is_empty());
        assert!(signals[0].pattern.contains("memory_pressure"));
        assert_eq!(signals[0].severity, ThreatLevel::High);
    }

    #[test]
    fn test_internal_sensor_cpu_saturation() {
        let mut sensor = InternalSensor::new();
        sensor.set_metrics(SystemMetrics {
            cpu_percent: 96.0,
            ..Default::default()
        });

        let signals = sensor.detect();
        assert!(!signals.is_empty());
        assert!(signals[0].pattern.contains("cpu_saturation"));
    }

    #[test]
    fn test_internal_sensor_error_spike() {
        let mut sensor = InternalSensor::new();
        sensor.set_metrics(SystemMetrics {
            error_rate: 25.0, // Above default 10.0 threshold
            ..Default::default()
        });

        let signals = sensor.detect();
        assert!(!signals.is_empty());
        assert!(signals[0].pattern.contains("error_spike"));
        assert_eq!(signals[0].severity, ThreatLevel::High);
    }

    #[test]
    fn test_internal_sensor_health_checks() {
        let mut sensor = InternalSensor::new();
        sensor.set_metrics(SystemMetrics {
            failed_health_checks: vec!["redis".to_string(), "postgres".to_string()],
            ..Default::default()
        });

        let signals = sensor.detect();
        assert_eq!(signals.len(), 2);
        assert!(
            signals
                .iter()
                .all(|s| s.pattern.contains("health_check_failed"))
        );
    }

    #[test]
    fn test_internal_sensor_healthy() {
        let mut sensor = InternalSensor::new();
        sensor.set_metrics(SystemMetrics {
            memory_percent: 50.0,
            cpu_percent: 30.0,
            disk_percent: 40.0,
            error_rate: 1.0,
            latency_p99_ms: 100.0,
            ..Default::default()
        });

        let signals = sensor.detect();
        assert!(signals.is_empty());
    }

    #[test]
    fn test_internal_sensor_critical_memory() {
        let mut sensor = InternalSensor::new();
        sensor.set_metrics(SystemMetrics {
            memory_percent: 97.0,
            ..Default::default()
        });

        let signals = sensor.detect();
        assert!(!signals.is_empty());
        assert_eq!(signals[0].severity, ThreatLevel::Critical);
    }

    // ========================================================================
    // KEV Sensor Tests
    // ========================================================================

    #[test]
    fn test_kev_sensor_new() {
        let sensor = KevSensor::new();
        assert_eq!(sensor.name(), "kev-sensor");
        assert!((sensor.sensitivity() - 0.95).abs() < f64::EPSILON);
    }

    #[test]
    fn test_kev_sensor_with_dependency_cves() {
        let sensor = KevSensor::new()
            .with_dependency_cves(vec!["CVE-2024-1234".into(), "CVE-2024-5678".into()]);
        assert_eq!(sensor.dependency_cves.len(), 2);
    }

    #[test]
    fn test_kev_sensor_cache_operations() {
        let sensor = KevSensor::new();

        // Initially no cache
        assert!(sensor.get_cached_catalog().is_none());

        // Set cache
        let catalog = KevCatalog {
            title: "Test Catalog".into(),
            catalog_version: "2024.01.01".into(),
            date_released: "2024-01-01".into(),
            count: 1,
            vulnerabilities: vec![KevVulnerability {
                cve_id: "CVE-2024-1234".into(),
                vendor_project: "TestVendor".into(),
                product: "TestProduct".into(),
                vulnerability_name: "Test Vuln".into(),
                date_added: "2024-01-01".into(),
                short_description: "Test description".into(),
                required_action: "Update".into(),
                due_date: "2024-02-01".into(),
                known_ransomware_campaign_use: "Unknown".into(),
            }],
        };
        sensor.set_cached_catalog(catalog);

        // Cache should now exist
        assert!(sensor.get_cached_catalog().is_some());
        assert_eq!(sensor.cached_vulnerability_count(), Some(1));
    }

    #[test]
    fn test_kev_sensor_detect_with_matching_cve() {
        let sensor = KevSensor::new().with_dependency_cves(vec!["CVE-2024-1234".into()]);

        // Pre-seed cache with a vulnerability
        let catalog = KevCatalog {
            title: "Test".into(),
            catalog_version: "1.0".into(),
            date_released: "2024-01-01".into(),
            count: 1,
            vulnerabilities: vec![KevVulnerability {
                cve_id: "CVE-2024-1234".into(),
                vendor_project: "Apache".into(),
                product: "Log4j".into(),
                vulnerability_name: "Log4Shell".into(),
                date_added: "2024-01-01".into(),
                short_description: "RCE vulnerability".into(),
                required_action: "Update to 2.17.1".into(),
                due_date: "2024-02-01".into(),
                known_ransomware_campaign_use: "Known".into(),
            }],
        };
        sensor.set_cached_catalog(catalog);

        let signals = sensor.detect();
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].pattern.cve_id, "CVE-2024-1234");
        assert_eq!(signals[0].severity, ThreatLevel::Critical); // Ransomware = Critical
    }

    #[test]
    fn test_kev_sensor_detect_no_matching_cve() {
        let sensor = KevSensor::new().with_dependency_cves(vec!["CVE-2024-9999".into()]);

        let catalog = KevCatalog {
            title: "Test".into(),
            catalog_version: "1.0".into(),
            date_released: "2024-01-01".into(),
            count: 1,
            vulnerabilities: vec![KevVulnerability {
                cve_id: "CVE-2024-1234".into(),
                vendor_project: "Test".into(),
                product: "Test".into(),
                vulnerability_name: "Test".into(),
                date_added: "2024-01-01".into(),
                short_description: "Test".into(),
                required_action: "Test".into(),
                due_date: "2024-02-01".into(),
                known_ransomware_campaign_use: "Unknown".into(),
            }],
        };
        sensor.set_cached_catalog(catalog);

        let signals = sensor.detect();
        assert!(signals.is_empty()); // No match
    }

    #[test]
    fn test_kev_sensor_high_severity_no_ransomware() {
        let sensor = KevSensor::new().with_dependency_cves(vec!["CVE-2024-1234".into()]);

        let catalog = KevCatalog {
            title: "Test".into(),
            catalog_version: "1.0".into(),
            date_released: "2024-01-01".into(),
            count: 1,
            vulnerabilities: vec![KevVulnerability {
                cve_id: "CVE-2024-1234".into(),
                vendor_project: "Test".into(),
                product: "Test".into(),
                vulnerability_name: "Test".into(),
                date_added: "2024-01-01".into(),
                short_description: "Test".into(),
                required_action: "Test".into(),
                due_date: "2024-02-01".into(),
                known_ransomware_campaign_use: "Unknown".into(), // Not ransomware
            }],
        };
        sensor.set_cached_catalog(catalog);

        let signals = sensor.detect();
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].severity, ThreatLevel::High); // High (not Critical)
    }

    #[test]
    fn test_kev_error_display() {
        let err = KevError::Unavailable {
            reason: "test".into(),
        };
        assert!(err.to_string().contains("test"));
    }
}
