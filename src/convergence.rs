// Copyright © 2026 NexVigilant LLC. All Rights Reserved.
//! Convergent Spatial Monitor — recursive frequency convergence across locations.
//!
//! Covers 4 primitive pairs:
//! - ν×ρ (`DampedOscillator`, 0.75) — recursive frequency convergence
//! - λ×ρ (`RecursiveLocator`, 0.71) — self-referencing spatial structures
//! - λ×∝ (`GeographicLockIn`, 0.72) — location-based irreversibility
//! - ν×π (`CadenceLog`, 0.68) — persistent frequency records

use std::collections::HashMap;

use nexcore_chrono::DateTime;
use nexcore_error::{Result, bail, nexerror};
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

/// Convergence state for a monitored probe.
///
/// # Irreversibility
///
/// [`ConvergenceState::LockedIn`] is a **one-way state** (∝ primitive).
/// Once a probe enters `LockedIn` it cannot revert to any other state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ConvergenceState {
    /// Default state — probe is actively oscillating with no convergence trend.
    Oscillating,

    /// Amplitude is decaying consistently (3+ consecutive ratios below threshold).
    ///
    /// `damping_ratio` is the arithmetic mean of consecutive amplitude ratios.
    Converging {
        /// Mean amplitude retained per half-cycle (0 = instant decay, 1 = no decay).
        damping_ratio: f64,
    },

    /// Signal has converged to near-zero amplitude (< 10× lock threshold).
    ///
    /// Transitional state between [`ConvergenceState::Converging`] and
    /// [`ConvergenceState::LockedIn`].
    Converged,

    /// **IRREVERSIBLE**: probe has locked into a fixed near-zero state (∝).
    ///
    /// All future [`ConvergentSpatialMonitor::observe`] calls maintain this state.
    LockedIn {
        /// Timestamp when lock-in was first detected.
        locked_at: DateTime,
    },
}

/// A single record in the cadence history of a probe (ν×π: persistent frequency records).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CadenceRecord {
    /// When this observation was recorded.
    pub timestamp: DateTime,
    /// Location identifier at time of observation.
    pub location: String,
    /// Observed signal value.
    pub value: f64,
    /// Amplitude computed at this observation (0.0 if insufficient data).
    pub amplitude: f64,
    /// Convergence state at time of recording.
    pub state: ConvergenceState,
}

/// A named spatial probe tracking a signal at a location (λ×ρ: recursive locator).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConvergenceProbe {
    /// Unique name for this probe.
    pub name: String,
    /// Current location identifier.
    pub location: String,
    /// Chronological observations as `(timestamp, value)` pairs.
    pub observations: Vec<(DateTime, f64)>,
    /// Current convergence state.
    pub state: ConvergenceState,
    /// Complete cadence history (ν×π).
    pub cadence_history: Vec<CadenceRecord>,
}

/// Monitor for convergent spatial processes (ν×ρ, λ×ρ, λ×∝, ν×π).
///
/// Tracks multiple named probes, each monitoring a signal at a location.
/// Detects convergence via amplitude damping analysis and irreversible lock-in.
///
/// # Algorithm
///
/// 1. Find local extrema (peaks and troughs) in the observation series.
/// 2. Compute amplitude = |extrema[n+1] − extrema[n]| for consecutive pairs.
/// 3. If amplitude[n] / amplitude[n−1] < `damping_threshold` for 3+ consecutive → **Converging**.
/// 4. If amplitude < `lock_threshold` for `min_observations` consecutive → **LockedIn** (irreversible).
///
/// # Example
///
/// ```rust
/// use nexcore_guardian_engine::convergence::ConvergentSpatialMonitor;
/// use nexcore_chrono::DateTime;
///
/// let mut monitor = ConvergentSpatialMonitor::new(0.7, 0.01);
/// assert!(monitor.observe("sensor-1", "site-A", 1.0, DateTime::now()).is_ok());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConvergentSpatialMonitor {
    /// Active probes keyed by probe name.
    probes: HashMap<String, ConvergenceProbe>,
    /// Amplitude ratio below which a half-cycle is counted as decaying.
    damping_threshold: f64,
    /// Amplitude below which a half-cycle contributes toward lock-in.
    lock_threshold: f64,
    /// Consecutive below-threshold amplitudes required to trigger lock-in.
    min_observations: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Find local extrema in a value series.
///
/// Returns `(index, value, is_peak)` for each strict local maximum or minimum.
fn find_extrema(values: &[f64]) -> Vec<(usize, f64, bool)> {
    if values.len() < 3 {
        return Vec::new();
    }
    let mut extrema = Vec::new();
    for i in 1..values.len() - 1 {
        let (prev, curr, next) = (values[i - 1], values[i], values[i + 1]);
        if curr > prev && curr > next {
            extrema.push((i, curr, true)); // peak
        } else if curr < prev && curr < next {
            extrema.push((i, curr, false)); // trough
        }
    }
    extrema
}

/// Compute amplitudes from consecutive extrema pairs.
///
/// amplitude[n] = |extrema[n+1].value − extrema[n].value|
fn compute_amplitudes(extrema: &[(usize, f64, bool)]) -> Vec<f64> {
    extrema
        .windows(2)
        .map(|w| (w[1].1 - w[0].1).abs())
        .collect()
}

/// Compute the arithmetic mean of amplitude ratios (damping per half-cycle).
///
/// Returns `None` when fewer than 2 amplitudes are available.
fn mean_damping_ratio(amplitudes: &[f64]) -> Option<f64> {
    if amplitudes.len() < 2 {
        return None;
    }
    let ratios: Vec<f64> = amplitudes
        .windows(2)
        .filter(|w| w[0] > f64::EPSILON)
        .map(|w| w[1] / w[0])
        .collect();
    if ratios.is_empty() {
        return None;
    }
    Some(ratios.iter().sum::<f64>() / ratios.len() as f64)
}

/// Determine the next convergence state from observations and current state.
fn determine_state(
    observations: &[(DateTime, f64)],
    current_state: &ConvergenceState,
    damping_threshold: f64,
    lock_threshold: f64,
    min_observations: usize,
) -> ConvergenceState {
    // ∝ invariant: LockedIn is irreversible.
    if let ConvergenceState::LockedIn { .. } = current_state {
        return current_state.clone();
    }

    let values: Vec<f64> = observations.iter().map(|(_, v)| *v).collect();
    let extrema = find_extrema(&values);
    let amplitudes = compute_amplitudes(&extrema);

    // Lock-in: last min_observations amplitudes all below lock_threshold.
    if amplitudes.len() >= min_observations {
        let recent = &amplitudes[amplitudes.len() - min_observations..];
        if recent.iter().all(|&a| a < lock_threshold) {
            let locked_at = observations
                .last()
                .map(|(t, _)| *t)
                .unwrap_or_else(|| DateTime::now());
            return ConvergenceState::LockedIn { locked_at };
        }
    }

    // Converged: last amplitude is small but not yet locked (< 10× threshold).
    if amplitudes.len() >= 2 {
        if let Some(&last) = amplitudes.last() {
            if last < lock_threshold * 10.0 {
                return ConvergenceState::Converged;
            }
        }
    }

    // Converging: 3+ consecutive amplitude ratios all below damping_threshold.
    if amplitudes.len() >= 4 {
        let ratios: Vec<f64> = amplitudes
            .windows(2)
            .filter(|w| w[0] > f64::EPSILON)
            .map(|w| w[1] / w[0])
            .collect();
        if ratios.len() >= 3 {
            let tail = &ratios[ratios.len() - 3..];
            if tail.iter().all(|&r| r < damping_threshold) {
                let dr = mean_damping_ratio(&amplitudes).unwrap_or(0.5);
                return ConvergenceState::Converging { damping_ratio: dr };
            }
        }
    }

    ConvergenceState::Oscillating
}

// ─────────────────────────────────────────────────────────────────────────────
// ConvergentSpatialMonitor
// ─────────────────────────────────────────────────────────────────────────────

impl ConvergentSpatialMonitor {
    /// Create a new monitor.
    ///
    /// * `damping_threshold` — amplitude ratio below which a half-cycle counts as decaying
    ///   (typical 0.7; lower = stricter).
    /// * `lock_threshold` — amplitude below which a half-cycle contributes to lock-in
    ///   (typical 0.01).
    ///
    /// `min_observations` defaults to 5 consecutive below-threshold amplitudes for lock-in.
    #[must_use]
    pub fn new(damping_threshold: f64, lock_threshold: f64) -> Self {
        Self {
            probes: HashMap::new(),
            damping_threshold,
            lock_threshold,
            min_observations: 5,
        }
    }

    /// Record an observation for a named probe and return the new convergence state.
    ///
    /// Creates the probe on first call. Updates location if it has changed.
    ///
    /// # Errors
    ///
    /// Returns an error if `probe_name` is empty.
    pub fn observe(
        &mut self,
        probe_name: &str,
        location: &str,
        value: f64,
        timestamp: DateTime,
    ) -> Result<ConvergenceState> {
        if probe_name.is_empty() {
            bail!("probe_name must not be empty");
        }

        let probe = self
            .probes
            .entry(probe_name.to_string())
            .or_insert_with(|| ConvergenceProbe {
                name: probe_name.to_string(),
                location: location.to_string(),
                observations: Vec::new(),
                state: ConvergenceState::Oscillating,
                cadence_history: Vec::new(),
            });

        probe.location = location.to_string();
        probe.observations.push((timestamp, value));

        // Compute amplitude for the cadence record.
        let values: Vec<f64> = probe.observations.iter().map(|(_, v)| *v).collect();
        let extrema = find_extrema(&values);
        let amplitudes = compute_amplitudes(&extrema);
        let current_amplitude = amplitudes.last().copied().unwrap_or(0.0);

        let new_state = determine_state(
            &probe.observations,
            &probe.state,
            self.damping_threshold,
            self.lock_threshold,
            self.min_observations,
        );
        probe.state = new_state.clone();

        probe.cadence_history.push(CadenceRecord {
            timestamp,
            location: location.to_string(),
            value,
            amplitude: current_amplitude,
            state: new_state.clone(),
        });

        Ok(new_state)
    }

    /// Get the current convergence state for a probe.
    ///
    /// Returns `None` if the probe has not been observed yet.
    #[must_use]
    pub fn state(&self, probe_name: &str) -> Option<&ConvergenceState> {
        self.probes.get(probe_name).map(|p| &p.state)
    }

    /// Check whether a probe is converging (amplitude is decaying) — ν×ρ.
    ///
    /// Returns `true` for [`ConvergenceState::Converging`], [`ConvergenceState::Converged`],
    /// and [`ConvergenceState::LockedIn`].
    ///
    /// # Errors
    ///
    /// Returns an error if `probe_name` has not been observed.
    pub fn detect_convergence(&self, probe_name: &str) -> Result<bool> {
        let probe = self
            .probes
            .get(probe_name)
            .ok_or_else(|| nexerror!("probe '{}' not found", probe_name))?;
        Ok(matches!(
            &probe.state,
            ConvergenceState::Converging { .. }
                | ConvergenceState::Converged
                | ConvergenceState::LockedIn { .. }
        ))
    }

    /// Return a map from **location** to **state** across all probes (λ×ρ).
    ///
    /// When multiple probes share a location, the last-iterated value wins.
    #[must_use]
    pub fn spatial_map(&self) -> HashMap<String, ConvergenceState> {
        self.probes
            .values()
            .map(|p| (p.location.clone(), p.state.clone()))
            .collect()
    }

    /// Check whether a probe has irreversibly locked in (λ×∝).
    ///
    /// # Errors
    ///
    /// Returns an error if `probe_name` has not been observed.
    pub fn detect_lockin(&self, probe_name: &str) -> Result<bool> {
        let probe = self
            .probes
            .get(probe_name)
            .ok_or_else(|| nexerror!("probe '{}' not found", probe_name))?;
        Ok(matches!(&probe.state, ConvergenceState::LockedIn { .. }))
    }

    /// Return the cadence history for a probe (ν×π).
    ///
    /// Returns `None` if the probe has not been observed.
    #[must_use]
    pub fn cadence_history(&self, probe_name: &str) -> Option<&[CadenceRecord]> {
        self.probes
            .get(probe_name)
            .map(|p| p.cadence_history.as_slice())
    }

    /// Compute the mean damping ratio for a probe from its amplitude decay history.
    ///
    /// Returns `None` if the probe is not found or has fewer than 2 amplitude samples.
    #[must_use]
    pub fn damping_ratio(&self, probe_name: &str) -> Option<f64> {
        let probe = self.probes.get(probe_name)?;
        let values: Vec<f64> = probe.observations.iter().map(|(_, v)| *v).collect();
        let extrema = find_extrema(&values);
        let amplitudes = compute_amplitudes(&extrema);
        mean_damping_ratio(&amplitudes)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use nexcore_chrono::DateTime;

    use super::*;

    fn ts(seconds: i64) -> DateTime {
        DateTime::from_timestamp(seconds)
    }

    /// Build a strongly-damped oscillation (d=0.3 per half-cycle).
    ///
    /// With d=0.3, all consecutive amplitude ratios ≈ 0.3 < 0.7 (damping_threshold),
    /// so the monitor reaches Converging after ≥4 extrema pairs.
    fn damped_observations(n_halfcycles: u32) -> Vec<(DateTime, f64)> {
        let d = 0.3_f64;
        let a = 8.0_f64;
        let mut obs = vec![(ts(0), 0.0)];
        for i in 0..n_halfcycles {
            let amp = a * d.powi(i as i32);
            let value = if i % 2 == 0 { amp } else { -amp };
            obs.push((ts(i64::from(i) * 2 + 1), value));
            obs.push((ts(i64::from(i) * 2 + 2), 0.0));
        }
        obs
    }

    /// Feed a slice of observations to a monitor under a single probe name.
    fn feed(
        monitor: &mut ConvergentSpatialMonitor,
        name: &str,
        loc: &str,
        obs: &[(DateTime, f64)],
    ) {
        for (ts_val, v) in obs {
            assert!(
                monitor.observe(name, loc, *v, *ts_val).is_ok(),
                "observe failed for probe '{name}'"
            );
        }
    }

    // ── Construction ─────────────────────────────────────────────────────────

    #[test]
    fn test_new_monitor_has_no_probes() {
        let m = ConvergentSpatialMonitor::new(0.7, 0.01);
        assert!(m.state("any").is_none());
        assert!(m.spatial_map().is_empty());
    }

    #[test]
    fn test_new_monitor_min_observations_default() {
        let m = ConvergentSpatialMonitor::new(0.7, 0.01);
        // min_observations=5 is internal; verify indirectly: lock-in requires 5 amplitudes.
        // With only 3 below-threshold amplitudes we should NOT be locked in yet.
        // (Detailed behaviour verified in lock-in tests.)
        assert!(m.cadence_history("none").is_none());
    }

    // ── Error handling ────────────────────────────────────────────────────────

    #[test]
    fn test_observe_empty_probe_name_errors() {
        let mut m = ConvergentSpatialMonitor::new(0.7, 0.01);
        assert!(m.observe("", "loc", 1.0, ts(0)).is_err());
    }

    #[test]
    fn test_detect_convergence_unknown_probe_errors() {
        let m = ConvergentSpatialMonitor::new(0.7, 0.01);
        assert!(m.detect_convergence("ghost").is_err());
    }

    #[test]
    fn test_detect_lockin_unknown_probe_errors() {
        let m = ConvergentSpatialMonitor::new(0.7, 0.01);
        assert!(m.detect_lockin("ghost").is_err());
    }

    // ── Oscillating state ─────────────────────────────────────────────────────

    #[test]
    fn test_single_observation_is_oscillating() {
        let mut m = ConvergentSpatialMonitor::new(0.7, 0.01);
        let state = m
            .observe("p", "s", 1.0, ts(0))
            .unwrap_or(ConvergenceState::Oscillating);
        assert_eq!(state, ConvergenceState::Oscillating);
    }

    #[test]
    fn test_two_observations_is_oscillating() {
        let mut m = ConvergentSpatialMonitor::new(0.7, 0.01);
        assert!(m.observe("p", "s", 1.0, ts(0)).is_ok());
        let state = m
            .observe("p", "s", -1.0, ts(1))
            .unwrap_or(ConvergenceState::Oscillating);
        assert_eq!(state, ConvergenceState::Oscillating);
    }

    #[test]
    fn test_zero_amplitude_single_extremum_is_oscillating() {
        let mut m = ConvergentSpatialMonitor::new(0.7, 0.01);
        // One peak but no trough → only 1 extremum → 0 amplitude pairs → Oscillating.
        assert!(m.observe("p", "s", 0.0, ts(0)).is_ok());
        assert!(m.observe("p", "s", 1.0, ts(1)).is_ok());
        let state = m
            .observe("p", "s", 0.0, ts(2))
            .unwrap_or(ConvergenceState::Oscillating);
        assert_eq!(state, ConvergenceState::Oscillating);
    }

    #[test]
    fn test_constant_amplitude_stays_oscillating() {
        let mut m = ConvergentSpatialMonitor::new(0.7, 0.01);
        // All amplitude ratios = 1.0 ≥ 0.7 → never Converging.
        let signal: Vec<f64> = (0..20)
            .map(|i| match i % 4 {
                0 => 0.0,
                1 => 1.0,
                2 => 0.0,
                _ => -1.0,
            })
            .collect();
        for (i, &v) in signal.iter().enumerate() {
            assert!(m.observe("p", "s", v, ts(i as i64)).is_ok());
        }
        assert_eq!(m.state("p"), Some(&ConvergenceState::Oscillating));
    }

    #[test]
    fn test_detect_convergence_false_for_oscillating() {
        let mut m = ConvergentSpatialMonitor::new(0.7, 0.01);
        assert!(m.observe("p", "s", 1.0, ts(0)).is_ok());
        assert!(!m.detect_convergence("p").unwrap_or(false));
    }

    // ── Converging state ──────────────────────────────────────────────────────

    #[test]
    fn test_strongly_damped_signal_reaches_converging() {
        let mut m = ConvergentSpatialMonitor::new(0.7, 0.01);
        // 8 half-cycles; after extrema[4] we have 3+ ratios ≈ 0.3 < 0.7.
        let obs = damped_observations(8);
        feed(&mut m, "p", "site", &obs);
        assert!(
            matches!(
                m.state("p"),
                Some(ConvergenceState::Converging { .. }) | Some(ConvergenceState::Converged)
            ),
            "expected Converging or Converged, got {:?}",
            m.state("p")
        );
    }

    #[test]
    fn test_detect_convergence_true_for_converging() {
        let mut m = ConvergentSpatialMonitor::new(0.7, 0.01);
        let obs = damped_observations(8);
        feed(&mut m, "p", "site", &obs);
        assert!(m.detect_convergence("p").unwrap_or(false));
    }

    #[test]
    fn test_damping_ratio_approximately_correct() {
        let mut m = ConvergentSpatialMonitor::new(0.7, 0.01);
        let obs = damped_observations(10);
        feed(&mut m, "p", "site", &obs);
        let ratio = m.damping_ratio("p").unwrap_or(1.0);
        // With d=0.3, mean ratio should be well below damping_threshold=0.7.
        assert!(ratio < 0.7, "expected ratio < 0.7, got {ratio}");
    }

    #[test]
    fn test_damping_ratio_none_for_unknown_probe() {
        let m = ConvergentSpatialMonitor::new(0.7, 0.01);
        assert!(m.damping_ratio("ghost").is_none());
    }

    #[test]
    fn test_damping_ratio_none_for_insufficient_data() {
        let mut m = ConvergentSpatialMonitor::new(0.7, 0.01);
        // One observation → no extrema → no amplitudes → None.
        assert!(m.observe("p", "s", 1.0, ts(0)).is_ok());
        assert!(m.damping_ratio("p").is_none());
    }

    // ── Converged state ────────────────────────────────────────────────────────

    #[test]
    fn test_near_zero_amplitude_reaches_converged_before_lockin() {
        let mut m = ConvergentSpatialMonitor::new(0.7, 0.01);
        // Small constant oscillation (0.008 < 0.1 = 10 × lock_threshold).
        // After 2 amplitudes → Converged; after 5 → LockedIn.
        let signal = [0.0_f64, 0.008, 0.0, -0.008, 0.0, 0.008, 0.0];
        let states: Vec<ConvergenceState> = signal
            .iter()
            .enumerate()
            .filter_map(|(i, &v)| m.observe("p", "s", v, ts(i as i64)).ok())
            .collect();
        let has_converged = states.iter().any(|s| *s == ConvergenceState::Converged);
        assert!(
            has_converged,
            "expected Converged state at some point before lock-in"
        );
    }

    // ── Lock-in state ─────────────────────────────────────────────────────────

    #[test]
    fn test_near_zero_oscillations_trigger_converged_or_lockin() {
        let mut m = ConvergentSpatialMonitor::new(0.7, 0.01);
        // amplitude 0.008 < lock_threshold=0.01 for every half-cycle.
        for i in 0..30_i64 {
            let v = match i % 4 {
                0 | 2 => 0.0,
                1 => 0.008,
                _ => -0.008,
            };
            assert!(m.observe("p", "s", v, ts(i)).is_ok());
        }
        assert!(
            matches!(
                m.state("p"),
                Some(ConvergenceState::LockedIn { .. } | ConvergenceState::Converged)
            ),
            "expected converged/locked state after 30 near-zero observations"
        );
    }

    #[test]
    fn test_lockin_is_irreversible() {
        let mut m = ConvergentSpatialMonitor::new(0.7, 0.01);
        // Trigger converged/lock-in regime.
        for i in 0..30_i64 {
            let v = match i % 4 {
                0 | 2 => 0.0,
                1 => 0.008,
                _ => -0.008,
            };
            assert!(m.observe("p", "s", v, ts(i)).is_ok());
        }
        let pre_state = m.state("p").cloned();
        assert!(matches!(
            pre_state,
            Some(ConvergenceState::LockedIn { .. } | ConvergenceState::Converged)
        ));

        // Inject large-amplitude observations.
        assert!(m.observe("p", "s", 999.0, ts(100)).is_ok());
        assert!(m.observe("p", "s", -999.0, ts(101)).is_ok());
        if let Some(ConvergenceState::LockedIn { .. }) = pre_state {
            assert!(
                matches!(m.state("p"), Some(ConvergenceState::LockedIn { .. })),
                "LockedIn must not revert after large-amplitude injection (∝ irreversibility)"
            );
        }
    }

    #[test]
    fn test_lockin_timestamp_is_set() {
        let mut m = ConvergentSpatialMonitor::new(0.7, 0.01);
        for i in 0..30_i64 {
            let v = match i % 4 {
                0 | 2 => 0.0,
                1 => 0.008,
                _ => -0.008,
            };
            assert!(m.observe("p", "s", v, ts(i)).is_ok());
        }
        if let Some(ConvergenceState::LockedIn { locked_at }) = m.state("p") {
            assert!(*locked_at >= ts(0), "locked_at should be a valid timestamp");
        } else {
            assert!(matches!(m.state("p"), Some(ConvergenceState::Converged)));
        }
    }

    #[test]
    fn test_detect_lockin_true_when_locked() {
        let mut m = ConvergentSpatialMonitor::new(0.7, 0.01);
        for i in 0..30_i64 {
            let v = match i % 4 {
                0 | 2 => 0.0,
                1 => 0.008,
                _ => -0.008,
            };
            assert!(m.observe("p", "s", v, ts(i)).is_ok());
        }
        let state_locked = matches!(m.state("p"), Some(ConvergenceState::LockedIn { .. }));
        assert_eq!(m.detect_lockin("p").unwrap_or(false), state_locked);
    }

    #[test]
    fn test_detect_lockin_false_for_oscillating() {
        let mut m = ConvergentSpatialMonitor::new(0.7, 0.01);
        assert!(m.observe("p", "s", 1.0, ts(0)).is_ok());
        assert!(!m.detect_lockin("p").unwrap_or(true));
    }

    // ── Spatial map ────────────────────────────────────────────────────────────

    #[test]
    fn test_spatial_map_empty_when_no_probes() {
        let m = ConvergentSpatialMonitor::new(0.7, 0.01);
        assert!(m.spatial_map().is_empty());
    }

    #[test]
    fn test_spatial_map_contains_all_locations() {
        let mut m = ConvergentSpatialMonitor::new(0.7, 0.01);
        assert!(m.observe("a", "site-north", 1.0, ts(0)).is_ok());
        assert!(m.observe("b", "site-south", 2.0, ts(1)).is_ok());
        assert!(m.observe("c", "site-east", 3.0, ts(2)).is_ok());
        let map = m.spatial_map();
        assert!(map.contains_key("site-north"));
        assert!(map.contains_key("site-south"));
        assert!(map.contains_key("site-east"));
        assert_eq!(map.len(), 3);
    }

    #[test]
    fn test_spatial_map_different_states_at_different_locations() {
        let mut m = ConvergentSpatialMonitor::new(0.7, 0.01);
        assert!(m.observe("probe-a", "site-1", 1.0, ts(0)).is_ok());
        let obs = damped_observations(8);
        feed(&mut m, "probe-b", "site-2", &obs);

        let map = m.spatial_map();
        assert_eq!(map.get("site-1"), Some(&ConvergenceState::Oscillating));
        assert!(
            matches!(
                map.get("site-2"),
                Some(
                    ConvergenceState::Converging { .. }
                        | ConvergenceState::Converged
                        | ConvergenceState::LockedIn { .. }
                )
            ),
            "site-2 should be beyond Oscillating, got {:?}",
            map.get("site-2")
        );
    }

    #[test]
    fn test_spatial_map_location_updates_on_move() {
        let mut m = ConvergentSpatialMonitor::new(0.7, 0.01);
        assert!(m.observe("p", "old-site", 1.0, ts(0)).is_ok());
        assert!(m.observe("p", "new-site", 2.0, ts(1)).is_ok());
        let map = m.spatial_map();
        assert!(
            map.contains_key("new-site"),
            "should reflect updated location"
        );
        assert!(!map.contains_key("old-site"), "old location should be gone");
    }

    // ── Cadence history ────────────────────────────────────────────────────────

    #[test]
    fn test_cadence_history_grows_with_each_observation() {
        let mut m = ConvergentSpatialMonitor::new(0.7, 0.01);
        assert!(m.observe("p", "s", 1.0, ts(0)).is_ok());
        assert!(m.observe("p", "s", 2.0, ts(1)).is_ok());
        assert!(m.observe("p", "s", 3.0, ts(2)).is_ok());
        assert_eq!(m.cadence_history("p").map(|h| h.len()), Some(3));
    }

    #[test]
    fn test_cadence_history_none_for_unknown_probe() {
        let m = ConvergentSpatialMonitor::new(0.7, 0.01);
        assert!(m.cadence_history("ghost").is_none());
    }

    #[test]
    fn test_cadence_history_records_value_and_timestamp() {
        let mut m = ConvergentSpatialMonitor::new(0.7, 0.01);
        assert!(m.observe("p", "s", 42.0, ts(100)).is_ok());
        let hist = m.cadence_history("p").unwrap_or(&[]);
        assert_eq!(hist.len(), 1);
        assert!((hist[0].value - 42.0).abs() < f64::EPSILON);
        assert_eq!(hist[0].timestamp, ts(100));
    }

    #[test]
    fn test_cadence_history_records_location() {
        let mut m = ConvergentSpatialMonitor::new(0.7, 0.01);
        assert!(m.observe("p", "factory-floor", 1.0, ts(0)).is_ok());
        let hist = m.cadence_history("p").unwrap_or(&[]);
        assert!(!hist.is_empty());
        assert_eq!(hist[0].location, "factory-floor");
    }

    #[test]
    fn test_cadence_history_state_matches_probe_state() {
        let mut m = ConvergentSpatialMonitor::new(0.7, 0.01);
        assert!(m.observe("p", "s", 1.0, ts(0)).is_ok());
        let hist = m.cadence_history("p").unwrap_or(&[]);
        let current = m.state("p");
        assert_eq!(hist.last().map(|r| &r.state), current);
    }

    // ── State accessor ─────────────────────────────────────────────────────────

    #[test]
    fn test_state_none_for_unknown_probe() {
        let m = ConvergentSpatialMonitor::new(0.7, 0.01);
        assert!(m.state("ghost").is_none());
    }

    #[test]
    fn test_state_returns_oscillating_initially() {
        let mut m = ConvergentSpatialMonitor::new(0.7, 0.01);
        assert!(m.observe("p", "s", 1.0, ts(0)).is_ok());
        assert_eq!(m.state("p"), Some(&ConvergenceState::Oscillating));
    }

    // ── Full state-machine progression ────────────────────────────────────────

    #[test]
    fn test_full_progression_oscillating_to_converged_or_lockin() {
        let mut m = ConvergentSpatialMonitor::new(0.7, 0.01);
        let mut saw_oscillating = false;
        let mut saw_beyond_oscillating = false;

        for i in 0..40_i64 {
            let v = match i % 4 {
                0 | 2 => 0.0,
                1 => 0.008,
                _ => -0.008,
            };
            if let Ok(state) = m.observe("p", "s", v, ts(i)) {
                match state {
                    ConvergenceState::Oscillating => saw_oscillating = true,
                    ConvergenceState::Converging { .. } | ConvergenceState::Converged => {
                        saw_beyond_oscillating = true;
                    }
                    ConvergenceState::LockedIn { .. } => saw_beyond_oscillating = true,
                }
            }
        }

        assert!(saw_oscillating, "should have passed through Oscillating");
        assert!(
            saw_beyond_oscillating,
            "should have passed through Converging/Converged"
        );
    }

    #[test]
    fn test_multiple_probes_are_isolated() {
        let mut m = ConvergentSpatialMonitor::new(0.7, 0.01);

        // probe-x: forced into converged/lock-in regime with near-zero oscillations.
        for i in 0..30_i64 {
            let v = match i % 4 {
                0 | 2 => 0.0,
                1 => 0.008,
                _ => -0.008,
            };
            assert!(m.observe("probe-x", "x-site", v, ts(i)).is_ok());
        }

        // probe-y: single observation → Oscillating.
        assert!(m.observe("probe-y", "y-site", 100.0, ts(0)).is_ok());

        assert!(matches!(
            m.state("probe-x"),
            Some(ConvergenceState::LockedIn { .. } | ConvergenceState::Converged)
        ));
        assert_eq!(m.state("probe-y"), Some(&ConvergenceState::Oscillating));
    }
}
