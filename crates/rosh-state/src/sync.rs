//! State synchronization protocol implementation
//!
//! Manages sequence numbers, acknowledgments, and state updates between client and server

use crate::{
    compress::{CompressionAlgorithm, Compressor},
    diff::StateDiff,
    StateError,
};
use rkyv::{Archive, Deserialize, Serialize};
use rosh_terminal::TerminalState;
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use tracing::debug;

/// Messages for state synchronization
#[derive(Debug, Clone, Archive, Deserialize, Serialize)]
#[archive(check_bytes)]
pub enum StateMessage {
    /// Full state snapshot
    FullState {
        /// Sequence number
        seq: u64,
        /// Complete terminal state
        state: TerminalState,
    },

    /// Delta update from a previous state
    Delta {
        /// Sequence number
        seq: u64,
        /// State changes
        delta: StateDiff,
    },

    /// Acknowledgment of received state
    Ack(u64),
}

/// Maximum number of unacknowledged states to keep
const MAX_PENDING_STATES: usize = 100;

/// Manages state synchronization
pub struct StateSynchronizer {
    /// Current state sequence number
    current_seq: u64,

    /// Last acknowledged sequence number from peer
    last_ack: u64,

    /// Current terminal state
    current_state: TerminalState,

    /// Pending states waiting for acknowledgment
    pending_states: VecDeque<PendingState>,

    /// Compressor for state diffs
    compressor: Compressor,

    /// Whether this is the server side
    _is_server: bool,
}

#[derive(Debug)]
struct PendingState {
    seq_num: u64,
    _state: TerminalState,
    sent_at: Instant,
}

impl StateSynchronizer {
    /// Create a new state synchronizer
    pub fn new(initial_state: TerminalState, is_server: bool) -> Self {
        Self {
            current_seq: 0,
            last_ack: 0,
            current_state: initial_state,
            pending_states: VecDeque::new(),
            compressor: Compressor::new(CompressionAlgorithm::Zstd),
            _is_server: is_server,
        }
    }

    /// Update local state and generate diff
    pub fn update_state(
        &mut self,
        new_state: TerminalState,
    ) -> Result<Option<StateUpdate>, StateError> {
        if new_state == self.current_state {
            return Ok(None);
        }

        // Generate diff
        let diff = StateDiff::generate(&self.current_state, &new_state)?;

        // Compress diff
        let diff_bytes = diff
            .to_bytes()
            .map_err(|e| StateError::SerializationError(e.to_string()))?;
        let compressed_diff = self.compressor.compress(&diff_bytes)?;

        // Update sequence number
        self.current_seq += 1;

        // Store pending state
        self.pending_states.push_back(PendingState {
            seq_num: self.current_seq,
            _state: new_state.clone(),
            sent_at: Instant::now(),
        });

        // Clean up old pending states
        while self.pending_states.len() > MAX_PENDING_STATES {
            self.pending_states.pop_front();
        }

        // Update current state
        self.current_state = new_state;

        Ok(Some(StateUpdate {
            seq_num: self.current_seq,
            ack_num: self.last_ack,
            compressed_diff,
        }))
    }

    /// Process acknowledgment from peer
    pub fn process_ack(&mut self, ack_num: u64) -> Duration {
        if ack_num > self.last_ack {
            self.last_ack = ack_num;

            // Remove acknowledged states and calculate RTT
            let mut rtt = Duration::from_millis(0);
            while let Some(pending) = self.pending_states.front() {
                if pending.seq_num <= ack_num {
                    // Safe to unwrap as we just checked with front()
                    if let Some(state) = self.pending_states.pop_front() {
                        rtt = state.sent_at.elapsed();
                    }
                } else {
                    break;
                }
            }

            debug!("Processed ACK {}, RTT: {:?}", ack_num, rtt);
            rtt
        } else {
            Duration::from_millis(0)
        }
    }

    /// Apply state update from peer
    pub fn apply_update(&mut self, update: StateUpdate) -> Result<u64, StateError> {
        // Check if we've already processed this update
        if update.seq_num <= self.last_ack {
            debug!("Ignoring duplicate update {}", update.seq_num);
            return Ok(self.last_ack);
        }

        // Decompress diff
        let diff_bytes = self.compressor.decompress(&update.compressed_diff)?;
        let diff = StateDiff::from_bytes(&diff_bytes)
            .map_err(|e| StateError::DeserializationError(e.to_string()))?;

        // Apply diff to current state
        let new_state = diff.apply(&self.current_state)?;

        // Update state
        self.current_state = new_state;
        self.last_ack = update.seq_num;

        Ok(self.last_ack)
    }

    /// Request full state sync
    pub fn request_sync(&self) -> u64 {
        self.last_ack
    }

    /// Generate full state for sync
    pub fn generate_sync(&self) -> Result<Vec<u8>, StateError> {
        let state_bytes = self
            .current_state
            .to_bytes()
            .map_err(|e| StateError::SerializationError(e.to_string()))?;
        self.compressor.compress(&state_bytes)
    }

    /// Apply full state sync
    pub fn apply_sync(&mut self, seq_num: u64, compressed_state: &[u8]) -> Result<(), StateError> {
        let state_bytes = self.compressor.decompress(compressed_state)?;
        let new_state = TerminalState::from_bytes(&state_bytes)
            .map_err(|e| StateError::DeserializationError(e.to_string()))?;

        self.current_state = new_state;
        self.current_seq = seq_num;
        self.last_ack = seq_num;

        // Clear pending states as we're now synced
        self.pending_states.clear();

        Ok(())
    }

    /// Get current state
    pub fn current_state(&self) -> &TerminalState {
        &self.current_state
    }

    /// Get current sequence number
    pub fn current_seq(&self) -> u64 {
        self.current_seq
    }

    /// Check if we need to resync (too many pending states)
    pub fn needs_resync(&self) -> bool {
        self.pending_states.len() >= MAX_PENDING_STATES / 2
    }
}

/// State update message
#[derive(Debug, Clone)]
pub struct StateUpdate {
    pub seq_num: u64,
    pub ack_num: u64,
    pub compressed_diff: Vec<u8>,
}
