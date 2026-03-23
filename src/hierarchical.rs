//! # Hierarchical Homeostasis (§3, §6)
//!
//! Implements Axiom 2 and Axiom 5 via nested control loops.
//! Orchestrates safety monitoring across discrete hierarchical levels.

use crate::hierarchy::{Hierarchy, Level};
use crate::homeostasis::{HomeostasisLoop, LoopIterationResult};
use std::collections::HashMap;

/// Tier: T3 (Domain-Specific)
/// Orchestrator for multiple homeostasis loops at different levels.
pub struct HierarchicalHomeostasis<L: Level> {
    pub hierarchy: Hierarchy<L>,
    pub loops: HashMap<usize, HomeostasisLoop>,
}

impl<L: Level> HierarchicalHomeostasis<L> {
    pub fn new(hierarchy: Hierarchy<L>) -> Self {
        Self {
            hierarchy,
            loops: HashMap::new(),
        }
    }

    pub fn add_loop(&mut self, level_index: usize, homeostasis_loop: HomeostasisLoop) {
        self.loops.insert(level_index, homeostasis_loop);
    }

    /// Ticks all loops in the hierarchy, from finest to coarsest.
    /// Implements Hierarchical Propagation (Axiom 5).
    pub async fn tick_all(&mut self) -> HashMap<usize, LoopIterationResult> {
        let mut results = HashMap::new();
        // Sort level indices to ensure propagation order
        let mut levels: Vec<_> = self.loops.keys().cloned().collect();
        levels.sort();

        for level in levels {
            if let Some(loop_ctrl) = self.loops.get_mut(&level) {
                let result = loop_ctrl.tick().await;
                results.insert(level, result);

                // Logic for cross-level propagation would be injected here
                // e.g. if level N is unstable, inject a DAMP/PAMP into level N+1
            }
        }
        results
    }
}
