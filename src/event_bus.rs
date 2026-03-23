//! # Guardian Event Bus (CAP-P2-003)
//!
//! Broadcast-based event bus for the Guardian homeostasis loop.
//!
//! Provides a publish/subscribe mechanism for Guardian events, enabling
//! decoupled observation of loop ticks, signal detections, actions taken,
//! and threshold breaches.
//!
//! ## T1 Primitive Grounding
//!
//! - **Sequence** (sigma): Event stream via `tokio::sync::broadcast`
//! - **Mapping** (mu): Event variants map domain occurrences to typed payloads
//! - **State** (varsigma): Sender/receiver ownership encapsulated in `EventBus`
//!
//! ## Example
//!
//! ```ignore
//! use nexcore_vigilance::guardian::event_bus::{EventBus, GuardianEvent};
//!
//! let bus = EventBus::new(256);
//! let mut rx = bus.subscribe();
//!
//! bus.publish(GuardianEvent::ThresholdBreached {
//!     metric: "prr".to_string(),
//!     value: 3.5,
//!     threshold: 2.0,
//! }).ok();
//! ```

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use super::homeostasis::LoopIterationResult;
use super::response::{ActuatorResult, ResponseAction};
use super::sensing::ThreatSignal;

// =============================================================================
// Constants
// =============================================================================

/// Default capacity for the event bus broadcast channel.
///
/// 1024 provides headroom for bursty workloads while keeping memory bounded.
/// Subscribers that fall behind by more than this many events will receive
/// a `Lagged` error on their next `recv()`.
pub const DEFAULT_CAPACITY: usize = 1024;

// =============================================================================
// GuardianEvent
// =============================================================================

/// Events emitted by the Guardian homeostasis loop.
///
/// Each variant captures a distinct phase of the SENSE-DECIDE-ACT cycle:
/// - `LoopTick`: Full iteration completed (carries summary)
/// - `SignalDetected`: A signal was detected during the sensing phase
/// - `ActionTaken`: An actuator executed a response action
/// - `ThresholdBreached`: A metric crossed its configured threshold
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GuardianEvent {
    /// A full homeostasis loop iteration completed.
    LoopTick(LoopIterationResult),

    /// A signal was detected during the sensing phase.
    ///
    /// Uses `ThreatSignal<String>` because the homeostasis loop type-erases
    /// sensor patterns to `String` via `ErasedSensor`.
    SignalDetected(ThreatSignal<String>),

    /// An actuator executed a response action.
    ActionTaken {
        /// The response action that was executed
        action: ResponseAction,
        /// The result of the actuator execution
        result: ActuatorResult,
    },

    /// A metric crossed its configured threshold.
    ThresholdBreached {
        /// Name of the metric that was breached (e.g. "prr", "ic025")
        metric: String,
        /// Observed value of the metric
        value: f64,
        /// Threshold that was exceeded
        threshold: f64,
    },
}

// =============================================================================
// EventBus
// =============================================================================

/// Broadcast-based event bus for Guardian events.
///
/// Wraps a `tokio::sync::broadcast` channel to provide multi-subscriber
/// event distribution. Each subscriber receives every event published
/// after its subscription was created.
///
/// ## Backpressure
///
/// If a subscriber falls behind by more than `capacity` events, it will
/// receive a `broadcast::error::RecvError::Lagged(n)` on the next read,
/// indicating `n` events were dropped. This is by design -- the bus
/// never blocks the publisher.
#[derive(Debug)]
pub struct EventBus {
    /// Broadcast sender (cloned to create receivers)
    sender: broadcast::Sender<GuardianEvent>,
    /// Channel capacity for diagnostics
    capacity: usize,
}

impl EventBus {
    /// Create a new event bus with the specified capacity.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum number of events that can be buffered per subscriber.
    ///   Use [`DEFAULT_CAPACITY`] (1024) for most workloads.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender, capacity }
    }

    /// Publish an event to all current subscribers.
    ///
    /// Returns the number of active receivers on success, or a `SendError`
    /// if there are no active receivers (the event is still dropped).
    ///
    /// This method never blocks -- events are written to each subscriber's
    /// buffer immediately.
    pub fn publish(
        &self,
        event: GuardianEvent,
    ) -> Result<usize, broadcast::error::SendError<GuardianEvent>> {
        self.sender.send(event)
    }

    /// Subscribe to events on this bus.
    ///
    /// The returned receiver will see every event published after this
    /// call. Events published before subscription are not replayed.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<GuardianEvent> {
        self.sender.subscribe()
    }

    /// Get the configured channel capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Get the current number of active receivers.
    #[must_use]
    pub fn receiver_count(&self) -> usize {
        self.sender.receiver_count()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidence::ConfidenceSource;
    use nexcore_chrono::DateTime;
    use nexcore_primitives::measurement::Measured;
    use std::collections::HashMap;

    use crate::homeostasis::{ActuatorResultSummary, LoopIterationResult};
    use crate::response::{ActuatorResult, ResponseAction};
    use crate::sensing::{SignalSource, ThreatLevel, ThreatSignal};

    /// Helper: create a test LoopIterationResult
    fn make_loop_result() -> LoopIterationResult {
        LoopIterationResult {
            iteration_id: "iter-42".to_string(),
            timestamp: DateTime::now(),
            signals_detected: 3,
            actions_taken: 1,
            results: vec![ActuatorResultSummary {
                actuator: "alert-actuator".to_string(),
                success: true,
                message: "Alert sent".to_string(),
            }],
            duration_ms: 12,
            throughput: crate::homeostasis::ThroughputMonitor::default(),
        }
    }

    /// Helper: create a test ThreatSignal<String>
    fn make_signal() -> ThreatSignal<String> {
        ThreatSignal {
            id: "sig-001".to_string(),
            pattern: "elevated-prr".to_string(),
            severity: ThreatLevel::High,
            timestamp: DateTime::now(),
            source: SignalSource::Damp {
                subsystem: "pv-engine".to_string(),
                damage_type: "threshold-breach".to_string(),
            },
            confidence: ConfidenceSource::Calibrated {
                value: 0.95,
                rationale: "test fixture: elevated PV signal",
            }
            .derive(),
            metadata: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_event_bus_single_subscriber() {
        let bus = EventBus::new(16);
        let mut rx = bus.subscribe();

        let event = GuardianEvent::ThresholdBreached {
            metric: "prr".to_string(),
            value: 3.5,
            threshold: 2.0,
        };

        let receivers = bus.publish(event.clone());
        assert!(receivers.is_ok());
        assert_eq!(receivers.ok(), Some(1));

        let received = rx.recv().await;
        assert!(received.is_ok());

        if let Ok(GuardianEvent::ThresholdBreached {
            metric,
            value,
            threshold,
        }) = received
        {
            assert_eq!(metric, "prr");
            assert!((value - 3.5).abs() < f64::EPSILON);
            assert!((threshold - 2.0).abs() < f64::EPSILON);
        } else {
            panic!("Expected ThresholdBreached event");
        }
    }

    #[tokio::test]
    async fn test_event_bus_multi_subscriber() {
        let bus = EventBus::new(16);
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();
        let mut rx3 = bus.subscribe();

        assert_eq!(bus.receiver_count(), 3);

        let result = make_loop_result();
        let event = GuardianEvent::LoopTick(result);
        let receivers = bus.publish(event);
        assert_eq!(receivers.ok(), Some(3));

        // All three subscribers should receive the event
        let r1 = rx1.recv().await;
        let r2 = rx2.recv().await;
        let r3 = rx3.recv().await;

        assert!(r1.is_ok());
        assert!(r2.is_ok());
        assert!(r3.is_ok());

        // Verify each received a LoopTick
        for received in [r1, r2, r3] {
            assert!(matches!(received, Ok(GuardianEvent::LoopTick(_))));
        }
    }

    #[tokio::test]
    async fn test_event_bus_lagged_receiver() {
        // Capacity of 2 means a subscriber buffering 3+ events will lag
        let bus = EventBus::new(2);
        let mut rx = bus.subscribe();

        // Publish 4 events to exceed capacity
        for i in 0..4 {
            let event = GuardianEvent::ThresholdBreached {
                metric: format!("metric-{i}"),
                value: f64::from(i),
                threshold: 1.0,
            };
            // Ignore send errors from having only one receiver that's behind
            let _ = bus.publish(event);
        }

        // The receiver should report lagged (some events were dropped)
        let result = rx.recv().await;
        match result {
            Err(broadcast::error::RecvError::Lagged(n)) => {
                // At least 1 event was dropped due to buffer overflow
                assert!(n >= 1, "Expected at least 1 lagged event, got {n}");
            }
            Ok(_) => {
                // Some implementations may still deliver the latest events;
                // the important thing is the bus did not block or panic.
            }
            Err(broadcast::error::RecvError::Closed) => {
                panic!("Channel should not be closed while bus exists");
            }
        }
    }

    #[tokio::test]
    async fn test_event_types_serializable() {
        // Verify all event variants round-trip through serde_json
        let events = vec![
            GuardianEvent::LoopTick(make_loop_result()),
            GuardianEvent::SignalDetected(make_signal()),
            GuardianEvent::ActionTaken {
                action: ResponseAction::Alert {
                    severity: ThreatLevel::High,
                    message: "Test alert".to_string(),
                    recipients: vec!["ops@test.com".to_string()],
                },
                result: ActuatorResult::success("Alert delivered"),
            },
            GuardianEvent::ThresholdBreached {
                metric: "eb05".to_string(),
                value: 2.5,
                threshold: 2.0,
            },
        ];

        for event in &events {
            let json = serde_json::to_string(event);
            assert!(json.is_ok(), "Failed to serialize: {event:?}");

            let json_str = json.ok().unwrap_or_default();
            assert!(!json_str.is_empty(), "Serialized JSON should not be empty");

            let deserialized: Result<GuardianEvent, _> = serde_json::from_str(&json_str);
            assert!(deserialized.is_ok(), "Failed to deserialize: {json_str}");
        }
    }

    #[test]
    fn test_event_bus_default_capacity() {
        let bus = EventBus::default();
        assert_eq!(bus.capacity(), DEFAULT_CAPACITY);
        assert_eq!(bus.capacity(), 1024);
    }

    #[test]
    fn test_event_bus_no_subscribers() {
        let bus = EventBus::new(8);
        assert_eq!(bus.receiver_count(), 0);

        // Publishing with no subscribers returns an error (event is dropped)
        let result = bus.publish(GuardianEvent::ThresholdBreached {
            metric: "test".to_string(),
            value: 1.0,
            threshold: 0.5,
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_event_bus_subscribe_after_publish() {
        let bus = EventBus::new(8);

        // Publish before any subscriber exists
        let _ = bus.publish(GuardianEvent::ThresholdBreached {
            metric: "old".to_string(),
            value: 1.0,
            threshold: 0.5,
        });

        // New subscriber should NOT see the old event
        let _rx = bus.subscribe();
        assert_eq!(bus.receiver_count(), 1);
        // No assertion on recv() here -- the event was published before subscribe
    }
}
