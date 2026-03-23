//! # Cytokine Actuator
//!
//! Emits cytokine signals in response to Guardian actions.
//!
//! ## T1 Grounding
//!
//! | Concept | Primitive | Role |
//! |---------|-----------|------|
//! | Emission | → (causality) | Action causes cytokine release |
//! | Action mapping | μ (mapping) | ResponseAction → Cytokine family |
//! | Priority | N (quantity) | Actuator execution order |

use std::sync::Arc;

use async_trait::async_trait;
use nexcore_cytokine::{
    Cytokine, CytokineBus, CytokineFamily, Emitter, Scope, ThreatLevel as CytokineSeverity,
};

use super::{Actuator, ActuatorResult, ResponseAction, actuator_priorities};
use crate::sensing::ThreatLevel;

/// Priority level for cytokine actuator (between Alert:80 and Quarantine:85).
pub const CYTOKINE_PRIORITY: u8 = 82;

/// Actuator that emits cytokine signals in response to Guardian actions.
///
/// Maps ResponseActions to appropriate cytokine families:
/// - `Escalate` → IL-1 alarm (systemic alert)
/// - `Block` → TNF-α terminate (destroy threat)
/// - `Alert` → IL-6 acute (coordinate response)
/// - `RateLimit` → IL-10 suppress (dampen activity)
///
/// # T1 Primitive Grounding
///
/// - `execute()` → → (causality): Action triggers cytokine emission
/// - Action mapping → μ: Each ResponseAction maps to specific cytokine
pub struct CytokineActuator {
    /// Reference to the cytokine bus
    bus: Arc<CytokineBus>,
    /// Whether actuator is active
    active: bool,
}

impl CytokineActuator {
    /// Create a new cytokine actuator.
    #[must_use]
    pub fn new(bus: Arc<CytokineBus>) -> Self {
        Self { bus, active: true }
    }

    /// Set active state.
    pub fn set_active(&mut self, active: bool) {
        self.active = active;
    }

    /// Map Guardian severity to cytokine severity.
    fn map_severity(severity: &ThreatLevel) -> CytokineSeverity {
        match severity {
            ThreatLevel::Info => CytokineSeverity::Trace,
            ThreatLevel::Low => CytokineSeverity::Low,
            ThreatLevel::Medium => CytokineSeverity::Medium,
            ThreatLevel::High => CytokineSeverity::High,
            ThreatLevel::Critical => CytokineSeverity::Critical,
        }
    }

    /// Create cytokine for Escalate action.
    fn cytokine_for_escalate(description: &str) -> Cytokine {
        Cytokine::new(CytokineFamily::Il1, "guardian_escalation")
            .with_severity(CytokineSeverity::High)
            .with_scope(Scope::Systemic)
            .with_payload(serde_json::json!({
                "action": "escalate",
                "description": description,
            }))
            .with_source("guardian-actuator")
    }

    /// Create cytokine for Block action.
    fn cytokine_for_block(target: &str, reason: &str) -> Cytokine {
        Cytokine::new(CytokineFamily::TnfAlpha, "guardian_block")
            .with_severity(CytokineSeverity::Critical)
            .with_scope(Scope::Endocrine)
            .with_payload(serde_json::json!({
                "action": "block",
                "target": target,
                "reason": reason,
            }))
            .with_source("guardian-actuator")
    }

    /// Create cytokine for Alert action.
    fn cytokine_for_alert(severity: &ThreatLevel, message: &str) -> Cytokine {
        Cytokine::new(CytokineFamily::Il6, "guardian_alert")
            .with_severity(Self::map_severity(severity))
            .with_scope(Scope::Endocrine)
            .with_payload(serde_json::json!({
                "action": "alert",
                "message": message,
            }))
            .with_source("guardian-actuator")
    }

    /// Create cytokine for RateLimit action.
    fn cytokine_for_rate_limit(resource: &str, max_requests: u32) -> Cytokine {
        Cytokine::new(CytokineFamily::Il10, "guardian_rate_limit")
            .with_severity(CytokineSeverity::Medium)
            .with_scope(Scope::Paracrine)
            .with_payload(serde_json::json!({
                "action": "rate_limit",
                "resource": resource,
                "max_requests": max_requests,
            }))
            .with_source("guardian-actuator")
    }

    /// Create cytokine for Quarantine action.
    fn cytokine_for_quarantine(target: &str, quarantine_type: &str) -> Cytokine {
        Cytokine::new(CytokineFamily::IfnGamma, "guardian_quarantine")
            .with_severity(CytokineSeverity::High)
            .with_scope(Scope::Endocrine)
            .with_payload(serde_json::json!({
                "action": "quarantine",
                "target": target,
                "type": quarantine_type,
            }))
            .with_source("guardian-actuator")
    }

    /// Create cytokine for TerminateSession action.
    fn cytokine_for_terminate_session(session_id: &str, reason: &str) -> Cytokine {
        Cytokine::new(CytokineFamily::TnfAlpha, "guardian_terminate_session")
            .with_severity(CytokineSeverity::High)
            .with_scope(Scope::Endocrine)
            .with_payload(serde_json::json!({
                "action": "terminate_session",
                "session_id": session_id,
                "reason": reason,
            }))
            .with_source("guardian-actuator")
    }
}

#[async_trait]
impl Actuator for CytokineActuator {
    async fn execute(&self, action: &ResponseAction) -> ActuatorResult {
        let cytokine = match action {
            ResponseAction::Escalate { description, .. } => {
                Some(Self::cytokine_for_escalate(description))
            }
            ResponseAction::Block { target, reason, .. } => {
                Some(Self::cytokine_for_block(target, reason))
            }
            ResponseAction::Alert {
                severity, message, ..
            } => Some(Self::cytokine_for_alert(severity, message)),
            ResponseAction::RateLimit {
                resource,
                max_requests,
                ..
            } => Some(Self::cytokine_for_rate_limit(resource, *max_requests)),
            ResponseAction::Quarantine {
                target,
                quarantine_type,
            } => Some(Self::cytokine_for_quarantine(target, quarantine_type)),
            ResponseAction::TerminateSession { session_id, reason } => {
                Some(Self::cytokine_for_terminate_session(session_id, reason))
            }
            // No cytokine emission for these actions
            ResponseAction::StepUpAuth { .. }
            | ResponseAction::AuditLog { .. }
            | ResponseAction::NoAction { .. } => None,
        };

        if let Some(signal) = cytokine {
            let family = signal.family.to_string();
            let name = signal.name.clone();

            // Emit to the bus (fire-and-forget)
            if let Err(e) = self.bus.emit(signal).await {
                return ActuatorResult::failure(format!("Failed to emit cytokine: {e}"));
            }

            ActuatorResult::success(format!("Emitted {} cytokine: {}", family, name))
                .with_data("family", family)
                .with_data("signal_name", name)
        } else {
            ActuatorResult::success("No cytokine emission required for this action")
        }
    }

    async fn revert(&self, _action: &ResponseAction) -> ActuatorResult {
        // Cytokines are fire-and-forget signals that decay naturally
        // No explicit revert needed
        ActuatorResult::success("CytokineActuator: no revert needed (signals decay naturally)")
    }

    fn can_execute(&self, _action: &ResponseAction) -> bool {
        // Cytokine actuator can emit for most action types
        // (actual emission decision is made in execute())
        true
    }

    fn name(&self) -> &str {
        "cytokine-actuator"
    }

    fn is_active(&self) -> bool {
        self.active
    }

    fn priority(&self) -> u8 {
        CYTOKINE_PRIORITY
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::response::EscalationLevel;

    #[tokio::test]
    async fn test_cytokine_actuator_creation() {
        let bus = Arc::new(CytokineBus::new("test"));
        let actuator = CytokineActuator::new(bus);
        assert_eq!(actuator.name(), "cytokine-actuator");
        assert_eq!(actuator.priority(), CYTOKINE_PRIORITY);
        assert!(actuator.is_active());
    }

    #[tokio::test]
    async fn test_execute_escalate() {
        let bus = Arc::new(CytokineBus::new("test"));
        let actuator = CytokineActuator::new(bus.clone());

        let action = ResponseAction::Escalate {
            level: EscalationLevel::L2,
            description: "Test escalation".to_string(),
            assigned_to: None,
        };

        let result = actuator.execute(&action).await;
        assert!(result.success);
        assert!(result.message.contains("IL-1"));

        // Verify bus stats
        let stats = bus.stats().await;
        assert!(stats.signals_emitted >= 1);
    }

    #[tokio::test]
    async fn test_execute_block() {
        let bus = Arc::new(CytokineBus::new("test"));
        let actuator = CytokineActuator::new(bus.clone());

        let action = ResponseAction::Block {
            target: "192.168.1.1".to_string(),
            duration: Some(3600),
            reason: "Suspicious activity".to_string(),
        };

        let result = actuator.execute(&action).await;
        assert!(result.success);
        assert!(result.message.contains("TNF"));
    }

    #[tokio::test]
    async fn test_execute_alert() {
        let bus = Arc::new(CytokineBus::new("test"));
        let actuator = CytokineActuator::new(bus);

        let action = ResponseAction::Alert {
            severity: ThreatLevel::High,
            message: "Test alert".to_string(),
            recipients: vec!["admin@test.com".to_string()],
        };

        let result = actuator.execute(&action).await;
        assert!(result.success);
        assert!(result.message.contains("IL-6"));
    }

    #[tokio::test]
    async fn test_execute_rate_limit() {
        let bus = Arc::new(CytokineBus::new("test"));
        let actuator = CytokineActuator::new(bus);

        let action = ResponseAction::RateLimit {
            resource: "/api/login".to_string(),
            max_requests: 10,
            window_seconds: 60,
        };

        let result = actuator.execute(&action).await;
        assert!(result.success);
        assert!(result.message.contains("IL-10"));
    }

    #[tokio::test]
    async fn test_execute_no_action() {
        let bus = Arc::new(CytokineBus::new("test"));
        let actuator = CytokineActuator::new(bus);

        let action = ResponseAction::NoAction {
            reason: "Below threshold".to_string(),
        };

        let result = actuator.execute(&action).await;
        assert!(result.success);
        assert!(result.message.contains("No cytokine"));
    }

    #[tokio::test]
    async fn test_can_execute_all_actions() {
        let bus = Arc::new(CytokineBus::new("test"));
        let actuator = CytokineActuator::new(bus);

        assert!(actuator.can_execute(&ResponseAction::NoAction {
            reason: "test".to_string()
        }));
    }

    #[tokio::test]
    async fn test_revert() {
        let bus = Arc::new(CytokineBus::new("test"));
        let actuator = CytokineActuator::new(bus);

        let action = ResponseAction::NoAction {
            reason: "test".to_string(),
        };
        let result = actuator.revert(&action).await;
        assert!(result.success);
    }

    #[test]
    fn test_severity_mapping() {
        assert!(matches!(
            CytokineActuator::map_severity(&ThreatLevel::Info),
            CytokineSeverity::Trace
        ));
        assert!(matches!(
            CytokineActuator::map_severity(&ThreatLevel::Critical),
            CytokineSeverity::Critical
        ));
    }
}
