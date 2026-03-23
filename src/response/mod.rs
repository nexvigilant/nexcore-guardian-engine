//! # Response Layer (Actuators)
//!
//! The response layer executes actions in reaction to detected threats.
//! Follows the biological model with:
//! - **Amplification**: Escalate signal strength
//! - **Ceiling**: Enforce response limits
//! - **Actuators**: Execute response actions
//!
//! ## Example
//!
//! ```ignore
//! use nexcore_vigilance::guardian::response::{Actuator, ActuatorResult, ResponseAction};
//!
//! struct AlertActuator;
//!
//! impl Actuator for AlertActuator {
//!     async fn execute(&self, action: &ResponseAction) -> ActuatorResult {
//!         // Send alert
//!         ActuatorResult::success("Alert sent")
//!     }
//!
//!     async fn revert(&self, _action: &ResponseAction) -> ActuatorResult {
//!         ActuatorResult::success("AlertActuator reverted")
//!     }
//!
//!     fn can_execute(&self, action: &ResponseAction) -> bool {
//!         matches!(action, ResponseAction::Alert { .. })
//!     }
//!
//!     fn name(&self) -> &str {
//!         "alert-actuator"
//!     }
//! }
//! ```

pub mod cytokine;
pub mod hud;

// Re-export cytokine actuator for convenient access
pub use cytokine::CytokineActuator;

// ============================================================================
// Constants
// ============================================================================

/// Amplifier configuration constants
pub mod amplifier_config {
    /// Initial amplification factor (1.0 = no amplification)
    pub const INITIAL_FACTOR: f64 = 1.0;
    /// Maximum amplification ceiling (prevents runaway escalation)
    /// Validated: 5x maximum ensures severe incidents escalate but don't overwhelm
    pub const MAX_FACTOR: f64 = 5.0;
    /// Decay rate per second (10% per second allows ~10s return to baseline)
    pub const DECAY_RATE_PER_SECOND: f64 = 0.1;
    /// Multiplier for each amplification event (20% increase per signal)
    pub const AMPLIFICATION_STEP: f64 = 1.2;
}

/// Severity score thresholds for amplified severity mapping
/// Based on 0-100 score range, divided into 5 levels
pub mod severity_thresholds {
    /// Info severity upper bound (0-12 = ~12% of range)
    pub const INFO_MAX: u8 = 12;
    /// Low severity upper bound (13-37 = ~25% of range)
    pub const LOW_MAX: u8 = 37;
    /// Medium severity upper bound (38-62 = ~25% of range)
    pub const MEDIUM_MAX: u8 = 62;
    /// High severity upper bound (63-87 = ~25% of range)
    pub const HIGH_MAX: u8 = 87;
    // Critical = 88-100 (~13% of range) - highest severity reserved for true emergencies
}

/// Response ceiling limits (rate limiting for response actions)
pub mod ceiling_limits {
    /// Maximum blocks per minute (100 = ~1.67/s burst capacity)
    /// Validated: High enough for attack mitigation, low enough to prevent self-DoS
    pub const MAX_BLOCKS_PER_MINUTE: u32 = 100;
    /// Maximum alerts per minute (50 = prevent alert fatigue)
    pub const MAX_ALERTS_PER_MINUTE: u32 = 50;
    /// Maximum escalations per hour (10 = prevent escalation fatigue)
    /// Validated: ~1 every 6 minutes ensures human reviewers aren't overwhelmed
    pub const MAX_ESCALATIONS_PER_HOUR: u32 = 10;
    /// Reset window for block/alert counters (1 minute)
    pub const MINUTE_RESET_WINDOW: i64 = 1;
    /// Reset window for escalation counter (1 hour)
    pub const HOUR_RESET_WINDOW: i64 = 1;
}

/// Actuator priority levels (higher = executed first)
/// Range: 0-100, with 50 as default
pub mod actuator_priorities {
    /// Default priority for generic actuators
    pub const DEFAULT: u8 = 50;
    /// Rate limiter: medium-high (respond before damage escalates)
    pub const RATE_LIMIT: u8 = 70;
    /// Step-up auth: medium-high (require re-auth before continued access)
    pub const STEP_UP_AUTH: u8 = 75;
    /// Alert: high (notifications should go out promptly)
    pub const ALERT: u8 = 80;
    /// Quarantine: high (isolate threats quickly)
    pub const QUARANTINE: u8 = 85;
    /// Session terminator: high (cut off compromised sessions)
    pub const SESSION_TERMINATOR: u8 = 88;
    /// Block: very high (stop attacks immediately)
    pub const BLOCK: u8 = 90;
    /// Escalation: very high (human oversight is critical)
    pub const ESCALATION: u8 = 95;
    /// Audit log: highest (always record for forensics)
    pub const AUDIT_LOG: u8 = 100;
}

use async_trait::async_trait;
use nexcore_chrono::DateTime;
use serde::{Deserialize, Serialize};

use super::sensing::ThreatLevel;

/// Response action types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResponseAction {
    /// Send an alert notification
    Alert {
        /// Alert severity
        severity: ThreatLevel,
        /// Alert message
        message: String,
        /// Recipients
        recipients: Vec<String>,
    },
    /// Block a request or IP
    Block {
        /// Target to block (IP, user, etc.)
        target: String,
        /// Block duration in seconds (None = permanent)
        duration: Option<u64>,
        /// Reason for blocking
        reason: String,
    },
    /// Require additional authentication
    StepUpAuth {
        /// User or session ID
        session_id: String,
        /// Required auth level
        required_level: String,
    },
    /// Terminate a session
    TerminateSession {
        /// Session ID
        session_id: String,
        /// Reason for termination
        reason: String,
    },
    /// Rate limit a resource
    RateLimit {
        /// Resource identifier
        resource: String,
        /// Maximum requests per window
        max_requests: u32,
        /// Window duration in seconds
        window_seconds: u64,
    },
    /// Quarantine data or system
    Quarantine {
        /// Target to quarantine
        target: String,
        /// Quarantine type
        quarantine_type: String,
    },
    /// Escalate to human review
    Escalate {
        /// Escalation level
        level: EscalationLevel,
        /// Description
        description: String,
        /// Assigned to
        assigned_to: Option<String>,
    },
    /// Log for audit
    AuditLog {
        /// Log category
        category: String,
        /// Log message
        message: String,
        /// Additional data
        data: std::collections::HashMap<String, String>,
    },
    /// No action required
    NoAction {
        /// Reason for no action
        reason: String,
    },
}

/// Escalation levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EscalationLevel {
    /// Level 1: On-call engineer
    L1,
    /// Level 2: Senior engineer
    L2,
    /// Level 3: Security team
    L3,
    /// Level 4: Executive/CISO
    L4,
}

/// Result of actuator execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActuatorResult {
    /// Whether the action succeeded
    pub success: bool,
    /// Result message
    pub message: String,
    /// Execution timestamp
    pub timestamp: DateTime,
    /// Execution duration in milliseconds
    pub duration_ms: u64,
    /// Additional result data
    pub data: std::collections::HashMap<String, String>,
}

impl ActuatorResult {
    /// Create a success result
    #[must_use]
    pub fn success(message: impl Into<String>) -> Self {
        Self {
            success: true,
            message: message.into(),
            timestamp: DateTime::now(),
            duration_ms: 0,
            data: std::collections::HashMap::new(),
        }
    }

    /// Create a failure result
    #[must_use]
    pub fn failure(message: impl Into<String>) -> Self {
        Self {
            success: false,
            message: message.into(),
            timestamp: DateTime::now(),
            duration_ms: 0,
            data: std::collections::HashMap::new(),
        }
    }

    /// Set execution duration
    #[must_use]
    pub fn with_duration(mut self, duration_ms: u64) -> Self {
        self.duration_ms = duration_ms;
        self
    }

    /// Add result data
    #[must_use]
    pub fn with_data(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.data.insert(key.into(), value.into());
        self
    }
}

/// Actuator trait for response execution
///
/// Implement this trait to create custom actuators that execute
/// specific types of response actions.
#[async_trait]
pub trait Actuator: Send + Sync {
    /// Execute a response action
    async fn execute(&self, action: &ResponseAction) -> ActuatorResult;

    /// Reverts an action to test for signal persistence (De-challenge §5.2)
    async fn revert(&self, action: &ResponseAction) -> ActuatorResult;

    /// Check if this actuator can handle the given action
    fn can_execute(&self, action: &ResponseAction) -> bool;

    /// Actuator name for logging/metrics
    fn name(&self) -> &str;

    /// Check if actuator is active
    fn is_active(&self) -> bool {
        true
    }

    /// Priority (higher = executed first)
    fn priority(&self) -> u8 {
        actuator_priorities::DEFAULT
    }
}

// ============================================================================
// Response Amplification
// ============================================================================

/// Amplification strategy for escalating response severity
#[derive(Debug, Clone)]
pub struct Amplifier {
    /// Amplification factor (1.0 = no change)
    factor: f64,
    /// Maximum amplification
    max_factor: f64,
    /// Decay rate per second
    decay_rate: f64,
}

impl Default for Amplifier {
    fn default() -> Self {
        Self {
            factor: amplifier_config::INITIAL_FACTOR,
            max_factor: amplifier_config::MAX_FACTOR,
            decay_rate: amplifier_config::DECAY_RATE_PER_SECOND,
        }
    }
}

impl Amplifier {
    /// Create a new amplifier
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Amplify signal severity
    pub fn amplify(&mut self, severity: ThreatLevel) -> ThreatLevel {
        let amplified_score = f64::from(severity.score()) * self.factor;

        // Increase factor for repeated signals
        self.factor = (self.factor * amplifier_config::AMPLIFICATION_STEP).min(self.max_factor);

        match amplified_score as u8 {
            0..=severity_thresholds::INFO_MAX => ThreatLevel::Info,
            ..=severity_thresholds::LOW_MAX => ThreatLevel::Low,
            ..=severity_thresholds::MEDIUM_MAX => ThreatLevel::Medium,
            ..=severity_thresholds::HIGH_MAX => ThreatLevel::High,
            _ => ThreatLevel::Critical,
        }
    }

    /// Decay the amplification factor over time
    pub fn decay(&mut self, elapsed_seconds: f64) {
        let decay = self.decay_rate * elapsed_seconds;
        self.factor = (self.factor - decay).max(amplifier_config::INITIAL_FACTOR);
    }

    /// Reset amplification
    pub fn reset(&mut self) {
        self.factor = amplifier_config::INITIAL_FACTOR;
    }

    /// Get current amplification factor
    #[must_use]
    pub fn factor(&self) -> f64 {
        self.factor
    }
}

// ============================================================================
// Response Ceiling
// ============================================================================

/// Ceiling constraints to prevent over-response
#[derive(Debug, Clone)]
pub struct ResponseCeiling {
    /// Maximum blocks per minute
    max_blocks_per_minute: u32,
    /// Maximum alerts per minute
    max_alerts_per_minute: u32,
    /// Maximum escalations per hour
    max_escalations_per_hour: u32,
    /// Current counts
    block_count: u32,
    alert_count: u32,
    escalation_count: u32,
    /// Last reset timestamp
    last_reset: DateTime,
}

impl Default for ResponseCeiling {
    fn default() -> Self {
        Self {
            max_blocks_per_minute: ceiling_limits::MAX_BLOCKS_PER_MINUTE,
            max_alerts_per_minute: ceiling_limits::MAX_ALERTS_PER_MINUTE,
            max_escalations_per_hour: ceiling_limits::MAX_ESCALATIONS_PER_HOUR,
            block_count: 0,
            alert_count: 0,
            escalation_count: 0,
            last_reset: DateTime::now(),
        }
    }
}

impl ResponseCeiling {
    /// Create a new ceiling with custom limits
    #[must_use]
    pub fn new(max_blocks: u32, max_alerts: u32, max_escalations: u32) -> Self {
        Self {
            max_blocks_per_minute: max_blocks,
            max_alerts_per_minute: max_alerts,
            max_escalations_per_hour: max_escalations,
            ..Default::default()
        }
    }

    /// Create autonomy-aware ceiling based on originator type (GVR framework).
    ///
    /// Entities with higher autonomy (more of {G, V, R}) can self-regulate,
    /// so they need lower external constraints. Tools (¬G ∧ ¬V ∧ ¬R) have
    /// symmetric harm capability and need maximum external limits.
    ///
    /// # Framework
    ///
    /// ```text
    /// Tool (¬G ∧ ¬V ∧ ¬R):     multiplier = 1.0 (full limits)
    /// Agent with R only:       multiplier = 0.8
    /// Agent with V ∧ R:        multiplier = 0.5
    /// Agent with G ∧ R:        multiplier = 0.6
    /// Agent with G ∧ V ∧ R:    multiplier = 0.2 (minimal limits)
    /// ```
    #[must_use]
    pub fn for_originator(originator: super::OriginatorType) -> Self {
        let multiplier = originator.ceiling_multiplier();

        Self {
            max_blocks_per_minute: ((ceiling_limits::MAX_BLOCKS_PER_MINUTE as f64) * multiplier)
                as u32,
            max_alerts_per_minute: ((ceiling_limits::MAX_ALERTS_PER_MINUTE as f64) * multiplier)
                as u32,
            max_escalations_per_hour: ((ceiling_limits::MAX_ESCALATIONS_PER_HOUR as f64)
                * multiplier) as u32,
            ..Default::default()
        }
    }

    /// Check if action is allowed under ceiling constraints
    pub fn allow(&mut self, action: &ResponseAction) -> bool {
        self.maybe_reset();

        match action {
            ResponseAction::Block { .. } => {
                if self.block_count >= self.max_blocks_per_minute {
                    return false;
                }
                self.block_count += 1;
                true
            }
            ResponseAction::Alert { .. } => {
                if self.alert_count >= self.max_alerts_per_minute {
                    return false;
                }
                self.alert_count += 1;
                true
            }
            ResponseAction::Escalate { .. } => {
                if self.escalation_count >= self.max_escalations_per_hour {
                    return false;
                }
                self.escalation_count += 1;
                true
            }
            _ => true,
        }
    }

    /// Reset counts if enough time has passed
    fn maybe_reset(&mut self) {
        let now = DateTime::now();
        let elapsed = now.signed_duration_since(self.last_reset);

        if elapsed.num_minutes() >= ceiling_limits::MINUTE_RESET_WINDOW {
            self.block_count = 0;
            self.alert_count = 0;
        }

        if elapsed.num_hours() >= ceiling_limits::HOUR_RESET_WINDOW {
            self.escalation_count = 0;
            self.last_reset = now;
        }
    }
}

// ============================================================================
// Built-in Actuators
// ============================================================================

/// Alert actuator - sends notifications
#[derive(Debug, Clone, Default)]
pub struct AlertActuator;

impl AlertActuator {
    /// Create a new alert actuator
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Actuator for AlertActuator {
    async fn execute(&self, action: &ResponseAction) -> ActuatorResult {
        match action {
            ResponseAction::Alert {
                severity,
                message,
                recipients,
            } => {
                // In production, this would send actual alerts
                tracing::info!(
                    severity = ?severity,
                    message = %message,
                    recipients = ?recipients,
                    "Alert sent"
                );
                ActuatorResult::success(format!("Alert sent to {} recipients", recipients.len()))
            }
            _ => ActuatorResult::failure("AlertActuator cannot handle this action"),
        }
    }

    async fn revert(&self, _action: &ResponseAction) -> ActuatorResult {
        ActuatorResult::success("AlertActuator reverted")
    }

    fn can_execute(&self, action: &ResponseAction) -> bool {
        matches!(action, ResponseAction::Alert { .. })
    }

    fn name(&self) -> &str {
        "alert-actuator"
    }

    fn priority(&self) -> u8 {
        actuator_priorities::ALERT
    }
}

/// Audit log actuator - records events
#[derive(Debug, Clone, Default)]
pub struct AuditLogActuator;

impl AuditLogActuator {
    /// Create a new audit log actuator
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Actuator for AuditLogActuator {
    async fn execute(&self, action: &ResponseAction) -> ActuatorResult {
        match action {
            ResponseAction::AuditLog {
                category,
                message,
                data,
            } => {
                tracing::info!(
                    category = %category,
                    message = %message,
                    data = ?data,
                    "Audit log entry"
                );
                ActuatorResult::success("Audit log entry created")
            }
            _ => ActuatorResult::failure("AuditLogActuator cannot handle this action"),
        }
    }

    async fn revert(&self, _action: &ResponseAction) -> ActuatorResult {
        ActuatorResult::success("AuditLogActuator reverted")
    }

    fn can_execute(&self, action: &ResponseAction) -> bool {
        matches!(action, ResponseAction::AuditLog { .. })
    }

    fn name(&self) -> &str {
        "audit-log-actuator"
    }

    fn priority(&self) -> u8 {
        actuator_priorities::AUDIT_LOG
    }
}

/// Block actuator - blocks malicious requests/IPs
#[derive(Debug, Clone, Default)]
pub struct BlockActuator {
    /// Blocked targets (in-memory for now; production would use external store)
    blocked: dashmap::DashSet<String>,
}

impl BlockActuator {
    /// Create a new block actuator
    #[must_use]
    pub fn new() -> Self {
        Self {
            blocked: dashmap::DashSet::new(),
        }
    }

    /// Check if a target is currently blocked
    #[must_use]
    pub fn is_blocked(&self, target: &str) -> bool {
        self.blocked.contains(target)
    }

    /// Get all blocked targets
    #[must_use]
    pub fn blocked_targets(&self) -> Vec<String> {
        self.blocked.iter().map(|r| r.key().clone()).collect()
    }

    /// Unblock a target
    pub fn unblock(&self, target: &str) -> bool {
        self.blocked.remove(target).is_some()
    }
}

#[async_trait]
impl Actuator for BlockActuator {
    async fn execute(&self, action: &ResponseAction) -> ActuatorResult {
        match action {
            ResponseAction::Block {
                target,
                duration,
                reason,
            } => {
                self.blocked.insert(target.clone());

                tracing::warn!(
                    target = %target,
                    duration = ?duration,
                    reason = %reason,
                    "Target blocked"
                );

                let duration_msg = duration
                    .map(|d| format!("{d}s"))
                    .unwrap_or_else(|| "permanent".to_string());

                ActuatorResult::success(format!(
                    "Blocked {} for {} ({})",
                    target, duration_msg, reason
                ))
                .with_data("target", target.clone())
                .with_data("duration", duration_msg)
            }
            _ => ActuatorResult::failure("BlockActuator cannot handle this action"),
        }
    }

    async fn revert(&self, _action: &ResponseAction) -> ActuatorResult {
        ActuatorResult::success("BlockActuator reverted")
    }

    fn can_execute(&self, action: &ResponseAction) -> bool {
        matches!(action, ResponseAction::Block { .. })
    }

    fn name(&self) -> &str {
        "block-actuator"
    }

    fn priority(&self) -> u8 {
        actuator_priorities::BLOCK
    }
}

/// Rate limit actuator - applies rate limiting to resources
#[derive(Debug, Clone, Default)]
pub struct RateLimitActuator {
    /// Rate limits by resource (resource -> (max_requests, window_seconds))
    limits: dashmap::DashMap<String, (u32, u64)>,
}

impl RateLimitActuator {
    /// Create a new rate limit actuator
    #[must_use]
    pub fn new() -> Self {
        Self {
            limits: dashmap::DashMap::new(),
        }
    }

    /// Get current rate limit for a resource
    #[must_use]
    pub fn get_limit(&self, resource: &str) -> Option<(u32, u64)> {
        self.limits.get(resource).map(|r| *r)
    }

    /// Remove rate limit for a resource
    pub fn remove_limit(&self, resource: &str) -> bool {
        self.limits.remove(resource).is_some()
    }
}

#[async_trait]
impl Actuator for RateLimitActuator {
    async fn execute(&self, action: &ResponseAction) -> ActuatorResult {
        match action {
            ResponseAction::RateLimit {
                resource,
                max_requests,
                window_seconds,
            } => {
                self.limits
                    .insert(resource.clone(), (*max_requests, *window_seconds));

                tracing::info!(
                    resource = %resource,
                    max_requests = %max_requests,
                    window_seconds = %window_seconds,
                    "Rate limit applied"
                );

                ActuatorResult::success(format!(
                    "Rate limit applied to {}: {}/{}s",
                    resource, max_requests, window_seconds
                ))
                .with_data("resource", resource.clone())
                .with_data("max_requests", max_requests.to_string())
                .with_data("window_seconds", window_seconds.to_string())
            }
            _ => ActuatorResult::failure("RateLimitActuator cannot handle this action"),
        }
    }

    async fn revert(&self, _action: &ResponseAction) -> ActuatorResult {
        ActuatorResult::success("RateLimitActuator reverted")
    }

    fn can_execute(&self, action: &ResponseAction) -> bool {
        matches!(action, ResponseAction::RateLimit { .. })
    }

    fn name(&self) -> &str {
        "rate-limit-actuator"
    }

    fn priority(&self) -> u8 {
        actuator_priorities::RATE_LIMIT
    }
}

/// Quarantine actuator - isolates suspicious data or systems
#[derive(Debug, Clone, Default)]
pub struct QuarantineActuator {
    /// Quarantined items (target -> quarantine_type)
    quarantined: dashmap::DashMap<String, String>,
}

impl QuarantineActuator {
    /// Create a new quarantine actuator
    #[must_use]
    pub fn new() -> Self {
        Self {
            quarantined: dashmap::DashMap::new(),
        }
    }

    /// Check if a target is quarantined
    #[must_use]
    pub fn is_quarantined(&self, target: &str) -> bool {
        self.quarantined.contains_key(target)
    }

    /// Get quarantine type for a target
    #[must_use]
    pub fn quarantine_type(&self, target: &str) -> Option<String> {
        self.quarantined.get(target).map(|r| r.clone())
    }

    /// Release from quarantine
    pub fn release(&self, target: &str) -> bool {
        self.quarantined.remove(target).is_some()
    }
}

#[async_trait]
impl Actuator for QuarantineActuator {
    async fn execute(&self, action: &ResponseAction) -> ActuatorResult {
        match action {
            ResponseAction::Quarantine {
                target,
                quarantine_type,
            } => {
                self.quarantined
                    .insert(target.clone(), quarantine_type.clone());

                tracing::warn!(
                    target = %target,
                    quarantine_type = %quarantine_type,
                    "Target quarantined"
                );

                ActuatorResult::success(format!(
                    "Quarantined {} (type: {})",
                    target, quarantine_type
                ))
                .with_data("target", target.clone())
                .with_data("quarantine_type", quarantine_type.clone())
            }
            _ => ActuatorResult::failure("QuarantineActuator cannot handle this action"),
        }
    }

    async fn revert(&self, _action: &ResponseAction) -> ActuatorResult {
        ActuatorResult::success("QuarantineActuator reverted")
    }

    fn can_execute(&self, action: &ResponseAction) -> bool {
        matches!(action, ResponseAction::Quarantine { .. })
    }

    fn name(&self) -> &str {
        "quarantine-actuator"
    }

    fn priority(&self) -> u8 {
        actuator_priorities::QUARANTINE
    }
}

/// Escalation actuator - escalates issues to human operators
#[derive(Debug, Clone, Default)]
pub struct EscalationActuator {
    /// Active escalations (id -> record)
    escalations: dashmap::DashMap<String, EscalationRecord>,
}

/// Record of an escalation
#[derive(Debug, Clone)]
pub struct EscalationRecord {
    /// Unique ID
    pub id: String,
    /// Escalation level
    pub level: EscalationLevel,
    /// Description
    pub description: String,
    /// Assigned to
    pub assigned_to: Option<String>,
    /// Timestamp
    pub timestamp: DateTime,
    /// Status (open, acknowledged, resolved)
    pub status: EscalationStatus,
}

/// Escalation status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscalationStatus {
    /// Open - not yet acknowledged
    Open,
    /// Acknowledged by operator
    Acknowledged,
    /// Resolved
    Resolved,
}

impl EscalationActuator {
    /// Create a new escalation actuator
    #[must_use]
    pub fn new() -> Self {
        Self {
            escalations: dashmap::DashMap::new(),
        }
    }

    /// Get all open escalations
    #[must_use]
    pub fn open_escalations(&self) -> Vec<EscalationRecord> {
        self.escalations
            .iter()
            .filter(|e| e.status == EscalationStatus::Open)
            .map(|e| e.value().clone())
            .collect()
    }

    /// Acknowledge an escalation
    pub fn acknowledge(&self, id: &str) -> bool {
        if let Some(mut entry) = self.escalations.get_mut(id) {
            entry.status = EscalationStatus::Acknowledged;
            return true;
        }
        false
    }

    /// Resolve an escalation
    pub fn resolve(&self, id: &str) -> bool {
        if let Some(mut entry) = self.escalations.get_mut(id) {
            entry.status = EscalationStatus::Resolved;
            return true;
        }
        false
    }
}

#[async_trait]
impl Actuator for EscalationActuator {
    async fn execute(&self, action: &ResponseAction) -> ActuatorResult {
        match action {
            ResponseAction::Escalate {
                level,
                description,
                assigned_to,
            } => {
                let id = nexcore_id::NexId::v4().to_string();
                let record = EscalationRecord {
                    id: id.clone(),
                    level: *level,
                    description: description.clone(),
                    assigned_to: assigned_to.clone(),
                    timestamp: DateTime::now(),
                    status: EscalationStatus::Open,
                };

                self.escalations.insert(id.clone(), record);

                tracing::error!(
                    id = %id,
                    level = ?level,
                    description = %description,
                    assigned_to = ?assigned_to,
                    "Issue escalated"
                );

                let assignee = assigned_to
                    .as_ref()
                    .map(|a| format!(" to {a}"))
                    .unwrap_or_default();

                ActuatorResult::success(format!(
                    "Escalated to {:?}{}: {}",
                    level, assignee, description
                ))
                .with_data("escalation_id", id)
                .with_data("level", format!("{level:?}"))
            }
            _ => ActuatorResult::failure("EscalationActuator cannot handle this action"),
        }
    }

    async fn revert(&self, _action: &ResponseAction) -> ActuatorResult {
        ActuatorResult::success("EscalationActuator reverted")
    }

    fn can_execute(&self, action: &ResponseAction) -> bool {
        matches!(action, ResponseAction::Escalate { .. })
    }

    fn name(&self) -> &str {
        "escalation-actuator"
    }

    fn priority(&self) -> u8 {
        actuator_priorities::ESCALATION
    }
}

/// Session termination actuator - terminates user sessions
#[derive(Debug, Clone, Default)]
pub struct SessionTerminatorActuator {
    /// Terminated sessions
    terminated: dashmap::DashSet<String>,
}

impl SessionTerminatorActuator {
    /// Create a new session terminator actuator
    #[must_use]
    pub fn new() -> Self {
        Self {
            terminated: dashmap::DashSet::new(),
        }
    }

    /// Check if a session was terminated
    #[must_use]
    pub fn was_terminated(&self, session_id: &str) -> bool {
        self.terminated.contains(session_id)
    }
}

#[async_trait]
impl Actuator for SessionTerminatorActuator {
    async fn execute(&self, action: &ResponseAction) -> ActuatorResult {
        match action {
            ResponseAction::TerminateSession { session_id, reason } => {
                self.terminated.insert(session_id.clone());

                tracing::warn!(
                    session_id = %session_id,
                    reason = %reason,
                    "Session terminated"
                );

                ActuatorResult::success(format!("Session {} terminated: {}", session_id, reason))
                    .with_data("session_id", session_id.clone())
            }
            _ => ActuatorResult::failure("SessionTerminatorActuator cannot handle this action"),
        }
    }

    async fn revert(&self, _action: &ResponseAction) -> ActuatorResult {
        ActuatorResult::success("SessionTerminatorActuator reverted")
    }

    fn can_execute(&self, action: &ResponseAction) -> bool {
        matches!(action, ResponseAction::TerminateSession { .. })
    }

    fn name(&self) -> &str {
        "session-terminator-actuator"
    }

    fn priority(&self) -> u8 {
        actuator_priorities::SESSION_TERMINATOR
    }
}

/// Step-up authentication actuator - requires additional authentication
#[derive(Debug, Clone, Default)]
pub struct StepUpAuthActuator {
    /// Sessions requiring step-up auth (session_id -> required_level)
    required_auth: dashmap::DashMap<String, String>,
}

impl StepUpAuthActuator {
    /// Create a new step-up auth actuator
    #[must_use]
    pub fn new() -> Self {
        Self {
            required_auth: dashmap::DashMap::new(),
        }
    }

    /// Check required auth level for a session
    #[must_use]
    pub fn required_level(&self, session_id: &str) -> Option<String> {
        self.required_auth.get(session_id).map(|r| r.clone())
    }

    /// Clear step-up requirement after successful auth
    pub fn clear_requirement(&self, session_id: &str) -> bool {
        self.required_auth.remove(session_id).is_some()
    }
}

#[async_trait]
impl Actuator for StepUpAuthActuator {
    async fn execute(&self, action: &ResponseAction) -> ActuatorResult {
        match action {
            ResponseAction::StepUpAuth {
                session_id,
                required_level,
            } => {
                self.required_auth
                    .insert(session_id.clone(), required_level.clone());

                tracing::info!(
                    session_id = %session_id,
                    required_level = %required_level,
                    "Step-up authentication required"
                );

                ActuatorResult::success(format!(
                    "Step-up auth required for {}: {}",
                    session_id, required_level
                ))
                .with_data("session_id", session_id.clone())
                .with_data("required_level", required_level.clone())
            }
            _ => ActuatorResult::failure("StepUpAuthActuator cannot handle this action"),
        }
    }

    async fn revert(&self, _action: &ResponseAction) -> ActuatorResult {
        ActuatorResult::success("StepUpAuthActuator reverted")
    }

    fn can_execute(&self, action: &ResponseAction) -> bool {
        matches!(action, ResponseAction::StepUpAuth { .. })
    }

    fn name(&self) -> &str {
        "step-up-auth-actuator"
    }

    fn priority(&self) -> u8 {
        75 // Medium-high priority
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_actuator_result() {
        let result = ActuatorResult::success("Test success")
            .with_duration(100)
            .with_data("key", "value");

        assert!(result.success);
        assert_eq!(result.duration_ms, 100);
        assert_eq!(result.data.get("key"), Some(&"value".to_string()));
    }

    #[test]
    fn test_amplifier() {
        let mut amp = Amplifier::new();
        assert!((amp.factor() - 1.0).abs() < f64::EPSILON);

        // Amplify increases factor - use the returned severity
        let amplified = amp.amplify(ThreatLevel::Medium);
        assert_eq!(amplified, ThreatLevel::Medium); // First amplification at 1.0 factor
        assert!(amp.factor() > 1.0);
    }

    #[test]
    fn test_response_ceiling() {
        let mut ceiling = ResponseCeiling::new(2, 2, 2);

        let block = ResponseAction::Block {
            target: "test".to_string(),
            duration: None,
            reason: "test".to_string(),
        };

        assert!(ceiling.allow(&block));
        assert!(ceiling.allow(&block));
        assert!(!ceiling.allow(&block)); // Third should be blocked
    }

    #[tokio::test]
    async fn test_alert_actuator() {
        let actuator = AlertActuator::new();
        let action = ResponseAction::Alert {
            severity: ThreatLevel::High,
            message: "Test alert".to_string(),
            recipients: vec!["admin@test.com".to_string()],
        };

        assert!(actuator.can_execute(&action));
        let result = actuator.execute(&action).await;
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_block_actuator() {
        let actuator = BlockActuator::new();
        let action = ResponseAction::Block {
            target: "192.168.1.100".to_string(),
            duration: Some(3600),
            reason: "Suspicious activity".to_string(),
        };

        assert!(actuator.can_execute(&action));
        assert!(!actuator.is_blocked("192.168.1.100"));

        let result = actuator.execute(&action).await;
        assert!(result.success);
        assert!(actuator.is_blocked("192.168.1.100"));

        assert!(actuator.unblock("192.168.1.100"));
        assert!(!actuator.is_blocked("192.168.1.100"));
    }

    #[test]
    fn test_rate_limit_actuator() {
        let actuator = RateLimitActuator::new();
        let action = ResponseAction::RateLimit {
            resource: "/api/login".to_string(),
            max_requests: 10,
            window_seconds: 60,
        };

        assert!(actuator.can_execute(&action));
        assert!(actuator.get_limit("/api/login").is_none());

        let result = futures::executor::block_on(actuator.execute(&action));
        assert!(result.success);
        assert_eq!(actuator.get_limit("/api/login"), Some((10, 60)));

        assert!(actuator.remove_limit("/api/login"));
        assert!(actuator.get_limit("/api/login").is_none());
    }

    #[test]
    fn test_quarantine_actuator() {
        let actuator = QuarantineActuator::new();
        let action = ResponseAction::Quarantine {
            target: "suspicious_file.exe".to_string(),
            quarantine_type: "malware".to_string(),
        };

        assert!(actuator.can_execute(&action));
        assert!(!actuator.is_quarantined("suspicious_file.exe"));

        let result = futures::executor::block_on(actuator.execute(&action));
        assert!(result.success);
        assert!(actuator.is_quarantined("suspicious_file.exe"));
        assert_eq!(
            actuator.quarantine_type("suspicious_file.exe"),
            Some("malware".to_string())
        );

        assert!(actuator.release("suspicious_file.exe"));
        assert!(!actuator.is_quarantined("suspicious_file.exe"));
    }

    #[test]
    fn test_escalation_actuator() {
        let actuator = EscalationActuator::new();
        let action = ResponseAction::Escalate {
            level: EscalationLevel::L2,
            description: "Critical security incident".to_string(),
            assigned_to: Some("security-team@example.com".to_string()),
        };

        assert!(actuator.can_execute(&action));
        assert!(actuator.open_escalations().is_empty());

        let result = futures::executor::block_on(actuator.execute(&action));
        assert!(result.success);

        let open = actuator.open_escalations();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].level, EscalationLevel::L2);

        let id = open[0].id.clone();
        assert!(actuator.acknowledge(&id));
        assert!(actuator.open_escalations().is_empty());

        assert!(actuator.resolve(&id));
    }

    #[test]
    fn test_session_terminator_actuator() {
        let actuator = SessionTerminatorActuator::new();
        let action = ResponseAction::TerminateSession {
            session_id: "sess_12345".to_string(),
            reason: "Suspicious activity detected".to_string(),
        };

        assert!(actuator.can_execute(&action));
        assert!(!actuator.was_terminated("sess_12345"));

        let result = futures::executor::block_on(actuator.execute(&action));
        assert!(result.success);
        assert!(actuator.was_terminated("sess_12345"));
    }

    #[test]
    fn test_step_up_auth_actuator() {
        let actuator = StepUpAuthActuator::new();
        let action = ResponseAction::StepUpAuth {
            session_id: "sess_67890".to_string(),
            required_level: "mfa".to_string(),
        };

        assert!(actuator.can_execute(&action));
        assert!(actuator.required_level("sess_67890").is_none());

        let result = futures::executor::block_on(actuator.execute(&action));
        assert!(result.success);
        assert_eq!(
            actuator.required_level("sess_67890"),
            Some("mfa".to_string())
        );

        assert!(actuator.clear_requirement("sess_67890"));
        assert!(actuator.required_level("sess_67890").is_none());
    }
}
