//! # HUD Governance Actuator
//!
//! Circuit breaker actuator for HUD governance operations.
//! Rate limits, blocks, or alerts based on Guardian signals.

use super::{Actuator, ActuatorResult, ResponseAction};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
/// HUD Circuit Breaker Actuator
///
/// Controls HUD Act operations based on Guardian signals:
/// - Rate limiting when approaching capacity
/// - Blocking when integrity failures detected
/// - Alerting on governance threshold violations
pub struct HudCircuitBreakerActuator {
    /// Circuit breaker state per Act (true = open/blocked)
    circuit_states: HashMap<String, AtomicBool>,
    /// Rate limit counters per Act
    rate_counters: HashMap<String, AtomicU64>,
    /// Whether actuator is active
    active: bool,
    /// Priority level
    priority: u8,
}
impl HudCircuitBreakerActuator {
    /// Create a new HUD circuit breaker actuator
    #[must_use]
    pub fn new() -> Self {
        Self {
            circuit_states: HashMap::new(),
            rate_counters: HashMap::new(),
            active: true,
            priority: super::super::response::actuator_priorities::RATE_LIMIT,
        }
    }
    /// Check if circuit is open (blocked) for an Act
    #[must_use]
    pub fn is_circuit_open(&self, act_id: &str) -> bool {
        self.circuit_states
            .get(act_id)
            .map(|state| state.load(Ordering::Relaxed))
            .unwrap_or(false)
    }
    /// Open circuit (block) for an Act
    pub fn open_circuit(&mut self, act_id: &str) {
        self.circuit_states
            .entry(act_id.to_string())
            .or_insert_with(|| AtomicBool::new(false))
            .store(true, Ordering::Relaxed);
    }
    /// Close circuit (allow) for an Act
    pub fn close_circuit(&mut self, act_id: &str) {
        if let Some(state) = self.circuit_states.get(act_id) {
            state.store(false, Ordering::Relaxed);
        }
    }
    /// Get current rate counter for an Act
    #[must_use]
    pub fn get_rate_count(&self, act_id: &str) -> u64 {
        self.rate_counters
            .get(act_id)
            .map(|counter| counter.load(Ordering::Relaxed))
            .unwrap_or(0)
    }
    /// Increment rate counter for an Act
    pub fn increment_rate(&mut self, act_id: &str) -> u64 {
        self.rate_counters
            .entry(act_id.to_string())
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed)
            + 1
    }
    /// Reset rate counter for an Act
    pub fn reset_rate(&mut self, act_id: &str) {
        if let Some(counter) = self.rate_counters.get(act_id) {
            counter.store(0, Ordering::Relaxed);
        }
    }
    /// Set active state
    pub fn set_active(&mut self, active: bool) {
        self.active = active;
    }
    /// Set priority
    pub fn set_priority(&mut self, priority: u8) {
        self.priority = priority;
    }
    /// Handle rate limit action for HUD
    #[allow(dead_code)] // Planned: integrate with ResponseAction::RateLimit
    fn handle_rate_limit(&mut self, resource: &str, max_requests: u32) -> ActuatorResult {
        // Extract act_id from resource (format: "hud.ACT_ID")
        let act_id = resource.strip_prefix("hud.").unwrap_or(resource);
        let current = self.increment_rate(act_id);
        if current > u64::from(max_requests) {
            self.open_circuit(act_id);
            ActuatorResult::success(format!(
                "HUD circuit breaker OPENED for {}: rate limit exceeded ({}/{})",
                act_id, current, max_requests
            ))
            .with_data("act_id", act_id)
            .with_data("action", "circuit_opened")
            .with_data("current_rate", current.to_string())
            .with_data("max_requests", max_requests.to_string())
        } else {
            ActuatorResult::success(format!(
                "HUD rate tracked for {}: {}/{}",
                act_id, current, max_requests
            ))
            .with_data("act_id", act_id)
            .with_data("action", "rate_tracked")
        }
    }
    /// Handle block action for HUD
    #[allow(dead_code)] // Planned: integrate with ResponseAction::Block
    fn handle_block(&mut self, target: &str, reason: &str) -> ActuatorResult {
        // Extract act_id from target (format: "hud.ACT_ID")
        let act_id = target.strip_prefix("hud.").unwrap_or(target);
        self.open_circuit(act_id);
        ActuatorResult::success(format!(
            "HUD circuit breaker OPENED for {}: {}",
            act_id, reason
        ))
        .with_data("act_id", act_id)
        .with_data("action", "blocked")
        .with_data("reason", reason)
    }
}
impl Default for HudCircuitBreakerActuator {
    fn default() -> Self {
        Self::new()
    }
}
#[async_trait]
impl Actuator for HudCircuitBreakerActuator {
    async fn execute(&self, action: &ResponseAction) -> ActuatorResult {
        // Note: We need &mut self for state changes, but trait requires &self
        // In practice, use interior mutability or wrap in Mutex at call site
        match action {
            ResponseAction::RateLimit {
                resource,
                max_requests,
                ..
            } if resource.starts_with("hud.") => ActuatorResult::success(format!(
                "HUD rate limit would be applied to {} (max: {})",
                resource, max_requests
            ))
            .with_data("resource", resource.clone())
            .with_data("action", "rate_limit_logged"),
            ResponseAction::Block { target, reason, .. } if target.starts_with("hud.") => {
                ActuatorResult::success(format!(
                    "HUD block would be applied to {}: {}",
                    target, reason
                ))
                .with_data("target", target.clone())
                .with_data("action", "block_logged")
            }
            ResponseAction::Alert {
                severity, message, ..
            } => ActuatorResult::success(format!("HUD alert [{:?}]: {}", severity, message))
                .with_data("action", "alert_sent"),
            _ => ActuatorResult::failure("Action not applicable to HUD actuator"),
        }
    }
    fn can_execute(&self, action: &ResponseAction) -> bool {
        match action {
            ResponseAction::RateLimit { resource, .. } => resource.starts_with("hud."),
            ResponseAction::Block { target, .. } => target.starts_with("hud."),
            ResponseAction::Alert { .. } => true,
            _ => false,
        }
    }
    async fn revert(&self, _action: &ResponseAction) -> ActuatorResult {
        ActuatorResult::success("HudCircuitBreakerActuator reverted")
    }
    fn name(&self) -> &str {
        "hud-circuit-breaker"
    }
    fn is_active(&self) -> bool {
        self.active
    }
    fn priority(&self) -> u8 {
        self.priority
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::sensing::ThreatLevel;
    #[test]
    fn test_circuit_initially_closed() {
        let actuator = HudCircuitBreakerActuator::new();
        assert!(!actuator.is_circuit_open("SSA"));
    }
    #[test]
    fn test_open_and_close_circuit() {
        let mut actuator = HudCircuitBreakerActuator::new();
        actuator.open_circuit("SSA");
        assert!(actuator.is_circuit_open("SSA"));
        actuator.close_circuit("SSA");
        assert!(!actuator.is_circuit_open("SSA"));
    }
    #[test]
    fn test_rate_counting() {
        let mut actuator = HudCircuitBreakerActuator::new();
        assert_eq!(actuator.get_rate_count("EPA"), 0);
        let count1 = actuator.increment_rate("EPA");
        assert_eq!(count1, 1);
        let count2 = actuator.increment_rate("EPA");
        assert_eq!(count2, 2);
        actuator.reset_rate("EPA");
        assert_eq!(actuator.get_rate_count("EPA"), 0);
    }
    #[test]
    fn test_can_execute_hud_actions() {
        let actuator = HudCircuitBreakerActuator::new();
        let rate_limit = ResponseAction::RateLimit {
            resource: "hud.SSA".to_string(),
            max_requests: 100,
            window_seconds: 60,
        };
        assert!(actuator.can_execute(&rate_limit));
        let block = ResponseAction::Block {
            target: "hud.FRA".to_string(),
            duration: None,
            reason: "Integrity failure".to_string(),
        };
        assert!(actuator.can_execute(&block));
        let alert = ResponseAction::Alert {
            severity: ThreatLevel::High,
            message: "HUD threshold exceeded".to_string(),
            recipients: vec![],
        };
        assert!(actuator.can_execute(&alert));
    }
    #[test]
    fn test_cannot_execute_non_hud_actions() {
        let actuator = HudCircuitBreakerActuator::new();
        let rate_limit = ResponseAction::RateLimit {
            resource: "api.users".to_string(),
            max_requests: 100,
            window_seconds: 60,
        };
        assert!(!actuator.can_execute(&rate_limit));
        let block = ResponseAction::Block {
            target: "192.168.1.1".to_string(),
            duration: Some(3600),
            reason: "Suspicious activity".to_string(),
        };
        assert!(!actuator.can_execute(&block));
    }
    #[tokio::test]
    async fn test_execute_rate_limit() {
        let actuator = HudCircuitBreakerActuator::new();
        let action = ResponseAction::RateLimit {
            resource: "hud.EPA".to_string(),
            max_requests: 50,
            window_seconds: 60,
        };
        let result = actuator.execute(&action).await;
        assert!(result.success);
        assert!(result.data.contains_key("resource"));
    }
    #[tokio::test]
    async fn test_execute_block() {
        let actuator = HudCircuitBreakerActuator::new();
        let action = ResponseAction::Block {
            target: "hud.FRA".to_string(),
            duration: None,
            reason: "Integrity verification failed".to_string(),
        };
        let result = actuator.execute(&action).await;
        assert!(result.success);
        assert!(result.data.contains_key("target"));
    }
}
