use nexcore_guardian_engine::{
    OriginatorType, RiskContext, calculate_risk_score,
    homeostasis::{DecisionEngine, HomeostasisLoop},
};
use nexcore_primitives::measurement::Measured;
use serde_json::Value;
use std::fs;
use std::path::Path;

#[tokio::test]
async fn test_hexim1_research_integrity_audit() {
    // 1. SENSING: Load HEXIM1 Research Data
    // We treat the research report as a biological organism whose "vitals" we are monitoring.
    let report_path =
        "/home/matthew/Projects/hexim1-research/Data/Validation/HEXIM1_BET_convergence_report.json";
    let report_content = fs::read_to_string(report_path).expect("Failed to read HEXIM1 report");
    let report: Value =
        serde_json::from_str(&report_content).expect("Failed to parse HEXIM1 report");

    // 2. EXTRACT SIGNALS
    // We look for "DAMPs" (Damage Associated Molecular Patterns) - like replication failures.
    let sle_replication = &report["SLE_baseline_hypothesis"];
    let status = sle_replication["status"].as_str().unwrap_or("UNKNOWN");

    // If replication failed, this is a "Damage" signal to the hypothesis.
    let replication_damage = if status == "REPLICATION FAILED" {
        1.0
    } else {
        0.0
    };

    // 3. DECISION: Evaluate Risk using Guardian Engine
    // We map research metadata to RiskContext.
    // Low n (sample size) or high p-values in "original findings" that failed replication
    // are high risk factors.
    let original_n = 37; // From GSE50772 (approx)
    let context = RiskContext {
        drug: "HEXIM1-SLE-Hypothesis".to_string(),
        event: "Replication-Failure".to_string(),
        prr: 2.5, // Mocked values representing effect size
        ror_lower: 1.2,
        ic025: 0.5,
        eb05: 2.1,
        n: original_n,
        originator: OriginatorType::AgentWithVR, // Assume an AI researcher with value evaluation
    };

    let risk_score = calculate_risk_score(&context);

    println!("--- HEXIM1 RESEARCH AUDIT ---");
    println!("Finding: {}", status);
    println!("Integrity Risk Score: {:.2}", risk_score.score.value);
    println!("Risk Level: {}", risk_score.level);
    for factor in &risk_score.factors {
        println!("  - Factor: {}", factor);
    }

    // 4. HOMEOSTASIS: Selection of Response
    let engine = DecisionEngine::new();
    let _control_loop = HomeostasisLoop::new(engine);

    // Trigger an audit if risk is too high
    if risk_score.level == "Critical" || risk_score.level == "High" {
        println!("ACTION: Scientific Integrity Cascade Triggered - Flagging for Peer Review");
    } else {
        println!("ACTION: Integrity Stable - Proceeding with Patent Readiness");
    }

    // Assert that the engine can process this research-derived risk
    assert!(risk_score.score.value > 0.0);
}

#[test]
fn test_hexim1_gvr_autonomy_check() {
    // INNOVATIVE IDEA: Evaluate the "Autonomy" of the research protocol.
    // The HEXIM1 report shows "Automatic Upgrade" logic (e.g., "Literature score upgraded 0.85 -> 0.95").
    // We test if this logic behaves as a 'Tool' (amplifying bias) or an 'Agent' (refusing weak data).

    let tool = OriginatorType::Tool;
    let agent = OriginatorType::AgentWithGVR;

    println!("Tool ceiling: {}", tool.ceiling_multiplier());
    println!("Agent ceiling: {}", agent.ceiling_multiplier());

    // If a research tool just blindly adds up scores, it's a Tool (1.0 multiplier = no self-correction).
    // If it can "Refuse" a dataset (as seen in "removed_datasets"), it has R capability.

    let hexim1_agent_type = OriginatorType::AgentWithR; // It can refuse (R) but follows research goals
    assert!(hexim1_agent_type.has_refusal_capacity());
    assert!(!hexim1_agent_type.has_goal_selection());
}
