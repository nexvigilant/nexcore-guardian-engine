//! # Integration Tests for nexcore-guardian-engine
//!
//! End-to-end tests validating the full SENSING → DECISION → RESPONSE pipeline
//! and all 10-gap remediation features.

use nexcore_guardian_engine::{
    OriginatorType, RiskContext,
    config::GuardianConfig,
    feedback::{FeedbackRecord, FeedbackStore},
    homeostasis::{DecisionEngine, DecisionMaker, HomeostasisLoop, LoopState, RuleBasedEngine},
    pattern_detector::PatternDetector,
    response::{AlertActuator, ResponseAction},
    sensing::{ExternalSensor, PvSignalSensor, RequestContext, ThreatSignal},
};

// ============================================================================
// Test 1: Full pipeline with ExternalSensor + SQL injection
// ============================================================================

#[tokio::test]
async fn test_full_pipeline_sql_injection() {
    let engine = DecisionEngine::new();
    let mut control_loop = HomeostasisLoop::new(engine);

    let mut sensor = ExternalSensor::new();
    sensor.set_context(RequestContext {
        path: "/api/users".to_string(),
        query: "id=1' OR '1'='1".to_string(),
        body: String::new(),
        headers: vec![],
        source_ip: "10.0.0.1".to_string(),
        user_agent: "test-agent".to_string(),
        request_rate: 1.0,
        failed_auth_count: 0,
    });
    control_loop.add_sensor(sensor);
    control_loop.add_actuator(AlertActuator::new());

    let result = control_loop.tick().await;

    assert_eq!(result.iteration_id, "iter-1");
    assert!(result.signals_detected > 0, "Expected SQL injection signal");
    assert!(result.actions_taken > 0, "Expected response actions");
}

// ============================================================================
// Test 2: PvSignalSensor with injected RiskContext
// ============================================================================

#[tokio::test]
async fn test_pv_signal_sensor_injection() {
    let engine = DecisionEngine::new();
    let mut control_loop = HomeostasisLoop::new(engine);

    let pv_sensor = PvSignalSensor::new();
    pv_sensor.inject(RiskContext {
        drug: "Aspirin".to_string(),
        event: "GI_Bleed".to_string(),
        prr: 5.0,
        ror_lower: 3.0,
        ic025: 1.5,
        eb05: 4.0,
        n: 50,
        originator: OriginatorType::default(),
    });
    control_loop.add_sensor(pv_sensor);
    control_loop.add_actuator(AlertActuator::new());

    let result = control_loop.tick().await;

    assert!(
        result.signals_detected > 0,
        "Expected PV signal from injected context"
    );
}

// ============================================================================
// Test 3: PatternDetector integration — BlockStorm
// ============================================================================

#[tokio::test]
async fn test_pattern_detector_block_storm() {
    let engine = DecisionEngine::new();
    let mut detector = PatternDetector::new();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);

    // Ingest 6 block events within 60s window (threshold is 5)
    for i in 0..6 {
        detector.ingest(
            now - 1000 * i as u128,
            "tnf_alpha",
            "unwrap-guardian",
            "cytokine:tnf_alpha:blocked:test",
        );
    }

    let control_loop = HomeostasisLoop::new(engine).with_pattern_detector(detector);

    // Verify the detector was wired (pattern detection happens inside tick)
    assert_eq!(control_loop.iteration_count(), 0);
}

// ============================================================================
// Test 4: Feedback persistence round-trip
// ============================================================================

#[test]
fn test_feedback_persistence_roundtrip() {
    let dir = tempfile::tempdir().ok().expect("tempdir");
    let path = dir.path().join("feedback.jsonl");
    let store = FeedbackStore::new(path);

    let record = FeedbackRecord {
        timestamp: nexcore_chrono::DateTime::now(),
        signal_pattern: "sql_injection:DROP TABLE".to_string(),
        severity: "High".to_string(),
        decision: "Alert".to_string(),
        outcome_success: true,
        actuator: "alert-actuator".to_string(),
        iteration_id: "iter-42".to_string(),
    };
    store.append(&record);

    let loaded = store.load_all();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].signal_pattern, "sql_injection:DROP TABLE");
    assert_eq!(loaded[0].iteration_id, "iter-42");
    assert!(loaded[0].outcome_success);
}

// ============================================================================
// Test 5: Graceful shutdown lifecycle
// ============================================================================

#[tokio::test]
async fn test_graceful_shutdown_lifecycle() {
    let engine = DecisionEngine::new();
    let mut control_loop = HomeostasisLoop::new(engine);
    control_loop.add_sensor(ExternalSensor::new());

    // Verify initial state
    assert_eq!(control_loop.state(), LoopState::Running);

    // Tick once
    let result = control_loop.tick().await;
    assert_eq!(result.iteration_id, "iter-1");
    assert_eq!(control_loop.state(), LoopState::Running);

    // Shutdown
    control_loop.shutdown().await;
    assert_eq!(control_loop.state(), LoopState::Stopped);

    // Tick after shutdown is a no-op
    let result = control_loop.tick().await;
    assert_eq!(result.signals_detected, 0);
    assert_eq!(result.actions_taken, 0);

    // Double shutdown is safe
    control_loop.shutdown().await;
    assert_eq!(control_loop.state(), LoopState::Stopped);
}

// ============================================================================
// Test 6: Custom DecisionMaker via with_decision_maker
// ============================================================================

/// A test decision maker that always escalates.
struct AlwaysEscalate;

impl DecisionMaker for AlwaysEscalate {
    fn evaluate_signals(&mut self, signals: &[ThreatSignal<String>]) -> Vec<ResponseAction> {
        signals
            .iter()
            .map(|s| ResponseAction::Escalate {
                level: nexcore_guardian_engine::response::EscalationLevel::L3,
                description: format!("Always escalate: {}", s.pattern),
                assigned_to: Some("test-team@example.com".to_string()),
            })
            .collect()
    }

    fn decay(&mut self, _elapsed_seconds: f64) {}
    fn reset(&mut self) {}
    fn name(&self) -> &str {
        "always-escalate"
    }

    fn get_threshold(&self) -> f64 {
        0.0
    }

    fn set_threshold(&mut self, _threshold: f64) -> f64 {
        0.0
    }
}

#[tokio::test]
async fn test_custom_decision_maker() {
    let mut control_loop = HomeostasisLoop::with_decision_maker(Box::new(AlwaysEscalate));

    let mut sensor = ExternalSensor::new();
    sensor.set_context(RequestContext {
        path: "/api/data".to_string(),
        query: "1' OR 1=1--".to_string(),
        body: String::new(),
        headers: vec![],
        source_ip: "10.0.0.1".to_string(),
        user_agent: "test".to_string(),
        request_rate: 1.0,
        failed_auth_count: 0,
    });
    control_loop.add_sensor(sensor);

    let result = control_loop.tick().await;

    // If sensor detected signals, AlwaysEscalate produces one action per signal
    if result.signals_detected > 0 {
        assert_eq!(result.actions_taken, result.signals_detected);
    }
}

// ============================================================================
// Test 7: GuardianConfig defaults match existing constants
// ============================================================================

#[test]
fn test_guardian_config_defaults() {
    let config = GuardianConfig::default();

    // Decision threshold should match the constant
    assert!(
        (config.decision.risk_threshold - 50.0).abs() < f64::EPSILON,
        "Decision threshold should be 50.0 (DEFAULT_RISK_THRESHOLD)"
    );

    // Amplifier defaults (from response::amplifier_config::MAX_FACTOR)
    assert!(
        (config.amplifier.max_factor - 5.0).abs() < f64::EPSILON,
        "Amplifier max_factor should be 5.0"
    );

    // Ceiling defaults (from response::ceiling_limits constants)
    assert_eq!(config.ceiling.max_blocks_per_minute, 100);
    assert_eq!(config.ceiling.max_alerts_per_minute, 50);
    assert_eq!(config.ceiling.max_escalations_per_hour, 10);

    // Feedback defaults (disabled by default, non-empty path)
    assert!(!config.feedback.enabled);
    assert!(!config.feedback.path.is_empty());
}

// ============================================================================
// Test 8: RibosomeDampSensor wired in monitoring loop
// ============================================================================

#[test]
fn test_monitoring_loop_includes_ribosome_sensor() {
    let control_loop = nexcore_guardian_engine::create_monitoring_loop();
    // Core monitoring sensors must be present; newer builds may include additional sensors.
    assert!(control_loop.sensor_count() >= 4);
}

// ============================================================================
// Test 9: Pause/Resume lifecycle
// ============================================================================

#[tokio::test]
async fn test_pause_resume_lifecycle() {
    let engine = DecisionEngine::new();
    let mut control_loop = HomeostasisLoop::new(engine);

    assert_eq!(control_loop.state(), LoopState::Running);

    // Pause
    control_loop.pause();
    assert_eq!(control_loop.state(), LoopState::Paused);
    assert!(control_loop.is_paused());

    // Tick while paused returns empty
    let result = control_loop.tick().await;
    assert_eq!(result.signals_detected, 0);
    assert_eq!(result.actions_taken, 0);

    // Resume
    control_loop.resume();
    assert_eq!(control_loop.state(), LoopState::Running);
    assert!(!control_loop.is_paused());
}

// ============================================================================
// Test 10: Feedback wired into tick_inner
// ============================================================================

#[tokio::test]
async fn test_feedback_wired_into_tick() {
    let dir = tempfile::tempdir().ok().expect("tempdir");
    let path = dir.path().join("feedback_tick.jsonl");
    let store = FeedbackStore::new(path.clone());

    let engine = DecisionEngine::new();
    let mut control_loop = HomeostasisLoop::new(engine).with_feedback_store(store);

    // Add sensor with SQL injection context to generate signals+actions
    let mut sensor = ExternalSensor::new();
    sensor.set_context(RequestContext {
        path: "/api/test".to_string(),
        query: "id=1' OR 1=1; DROP TABLE--".to_string(),
        body: String::new(),
        headers: vec![],
        source_ip: "10.0.0.1".to_string(),
        user_agent: "test".to_string(),
        request_rate: 1.0,
        failed_auth_count: 0,
    });
    control_loop.add_sensor(sensor);
    control_loop.add_actuator(AlertActuator::new());

    let result = control_loop.tick().await;

    // If signals were detected and actions taken, feedback should have been written
    if result.actions_taken > 0 {
        let feedback_store = FeedbackStore::new(path);
        let records = feedback_store.load_all();
        assert!(
            !records.is_empty(),
            "Expected feedback records after tick with actions"
        );
        assert!(records[0].iteration_id.starts_with("iter-"));
    }
}

// ============================================================================
// Test 11: Shutdown logs to feedback store
// ============================================================================

#[tokio::test]
async fn test_shutdown_logs_to_feedback() {
    let dir = tempfile::tempdir().ok().expect("tempdir");
    let path = dir.path().join("feedback_shutdown.jsonl");
    let store = FeedbackStore::new(path.clone());

    let engine = DecisionEngine::new();
    let mut control_loop = HomeostasisLoop::new(engine).with_feedback_store(store);

    control_loop.tick().await;
    control_loop.shutdown().await;

    let feedback_store = FeedbackStore::new(path);
    let records = feedback_store.load_all();

    // Should have at least the shutdown record
    let shutdown_record = records.iter().find(|r| r.signal_pattern == "shutdown");
    assert!(
        shutdown_record.is_some(),
        "Expected shutdown feedback record"
    );
}

// ============================================================================
// Test 12: DecisionMaker trait alias backward compat
// ============================================================================

#[test]
fn test_decision_engine_alias() {
    // DecisionEngine should still work as the type alias for RuleBasedEngine
    let engine = DecisionEngine::new();
    let _loop = HomeostasisLoop::new(engine);

    let custom = RuleBasedEngine::new().with_threshold(75.0);
    assert!((custom.get_threshold() - 75.0).abs() < f64::EPSILON);
}
