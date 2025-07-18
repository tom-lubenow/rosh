//! Client-side prediction for responsive terminal experience
//!
//! Predicts local terminal state changes before server confirmation

use rosh_terminal::TerminalState;
use std::collections::VecDeque;

/// Maximum number of predicted states to keep
const MAX_PREDICTIONS: usize = 50;

/// A predicted user input event
#[derive(Debug, Clone)]
pub struct PredictedInput {
    /// Sequence number of this prediction
    pub seq_num: u64,

    /// The input event
    pub input: UserInput,

    /// Predicted state after applying this input
    pub predicted_state: TerminalState,
}

/// User input types that can be predicted
#[derive(Debug, Clone)]
pub enum UserInput {
    /// Character input
    Character(char),

    /// Special key
    Key(KeyCode),

    /// Paste event
    Paste(String),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeyCode {
    Backspace,
    Delete,
    Left,
    Right,
    Up,
    Down,
    Home,
    End,
    PageUp,
    PageDown,
    Tab,
    Enter,
    Escape,
}

/// Manages client-side prediction
pub struct Predictor {
    /// Last confirmed state from server
    confirmed_state: TerminalState,

    /// Current predicted state
    predicted_state: TerminalState,

    /// Queue of predictions waiting for confirmation
    predictions: VecDeque<PredictedInput>,

    /// Next prediction sequence number
    next_seq: u64,
}

impl Predictor {
    /// Create a new predictor
    pub fn new(initial_state: TerminalState) -> Self {
        Self {
            confirmed_state: initial_state.clone(),
            predicted_state: initial_state,
            predictions: VecDeque::new(),
            next_seq: 1,
        }
    }

    /// Predict the effect of user input
    pub fn predict_input(&mut self, input: UserInput) -> u64 {
        let seq_num = self.next_seq;
        self.next_seq += 1;

        // Apply prediction to current state
        let new_state = self.apply_input_prediction(&self.predicted_state, &input);

        // Store prediction
        self.predictions.push_back(PredictedInput {
            seq_num,
            input,
            predicted_state: new_state.clone(),
        });

        // Limit prediction queue
        while self.predictions.len() > MAX_PREDICTIONS {
            self.predictions.pop_front();
        }

        // Update predicted state
        self.predicted_state = new_state;

        seq_num
    }

    /// Apply input prediction to state
    fn apply_input_prediction(&self, state: &TerminalState, input: &UserInput) -> TerminalState {
        let mut new_state = state.clone();

        match input {
            UserInput::Character(ch) => {
                // Simple character insertion
                let offset = (new_state.cursor_y as usize * new_state.width as usize)
                    + new_state.cursor_x as usize;

                if offset < new_state.screen.len() {
                    new_state.screen[offset] = *ch as u8;

                    // Advance cursor
                    new_state.cursor_x += 1;
                    if new_state.cursor_x >= new_state.width {
                        new_state.cursor_x = 0;
                        new_state.cursor_y += 1;
                        if new_state.cursor_y >= new_state.height {
                            new_state.cursor_y = new_state.height - 1;
                            // Implement scrolling
                            self.scroll_screen(&mut new_state);
                        }
                    }
                }
            }

            UserInput::Key(key) => match key {
                KeyCode::Backspace => {
                    if new_state.cursor_x > 0 {
                        new_state.cursor_x -= 1;
                        let offset = (new_state.cursor_y as usize * new_state.width as usize)
                            + new_state.cursor_x as usize;
                        if offset < new_state.screen.len() {
                            new_state.screen[offset] = b' ';
                        }
                    }
                }

                KeyCode::Left => {
                    if new_state.cursor_x > 0 {
                        new_state.cursor_x -= 1;
                    }
                }

                KeyCode::Right => {
                    if new_state.cursor_x < new_state.width - 1 {
                        new_state.cursor_x += 1;
                    }
                }

                KeyCode::Up => {
                    if new_state.cursor_y > 0 {
                        new_state.cursor_y -= 1;
                    }
                }

                KeyCode::Down => {
                    if new_state.cursor_y < new_state.height - 1 {
                        new_state.cursor_y += 1;
                    }
                }

                KeyCode::Home => {
                    new_state.cursor_x = 0;
                }

                KeyCode::End => {
                    // TODO: Move to end of line content
                    new_state.cursor_x = new_state.width - 1;
                }

                KeyCode::Enter => {
                    new_state.cursor_x = 0;
                    new_state.cursor_y += 1;
                    if new_state.cursor_y >= new_state.height {
                        new_state.cursor_y = new_state.height - 1;
                        // Implement scrolling
                        self.scroll_screen(&mut new_state);
                    }
                }

                _ => {} // Other keys not predicted
            },

            UserInput::Paste(text) => {
                // Simple paste prediction (just characters)
                for ch in text.chars().take(100) {
                    // Limit prediction size
                    let offset = (new_state.cursor_y as usize * new_state.width as usize)
                        + new_state.cursor_x as usize;

                    if offset < new_state.screen.len() && ch.is_ascii() {
                        new_state.screen[offset] = ch as u8;
                        new_state.cursor_x += 1;
                        if new_state.cursor_x >= new_state.width {
                            new_state.cursor_x = 0;
                            new_state.cursor_y += 1;
                            if new_state.cursor_y >= new_state.height {
                                break;
                            }
                        }
                    }
                }
            }
        }

        new_state
    }

    /// Update with confirmed state from server
    pub fn update_confirmed(&mut self, confirmed_state: TerminalState, confirmed_seq: u64) {
        self.confirmed_state = confirmed_state.clone();

        // Remove confirmed predictions
        while let Some(pred) = self.predictions.front() {
            if pred.seq_num <= confirmed_seq {
                self.predictions.pop_front();
            } else {
                break;
            }
        }

        // Reapply remaining predictions
        let mut state = confirmed_state;
        for pred in &self.predictions {
            state = self.apply_input_prediction(&state, &pred.input);
        }

        self.predicted_state = state;
    }

    /// Get current predicted state
    pub fn predicted_state(&self) -> &TerminalState {
        &self.predicted_state
    }

    /// Get confirmed state
    pub fn confirmed_state(&self) -> &TerminalState {
        &self.confirmed_state
    }

    /// Check if we have unconfirmed predictions
    pub fn has_predictions(&self) -> bool {
        !self.predictions.is_empty()
    }

    /// Scroll the screen up by one line
    fn scroll_screen(&self, state: &mut TerminalState) {
        let width = state.width as usize;

        // Save the first line to scrollback
        let first_line = state.screen[..width].to_vec();
        state.scrollback.push(first_line);

        // Shift all lines up by one
        state.screen.rotate_left(width);

        // Clear the last line
        let last_line_start = (state.height as usize - 1) * width;
        for i in last_line_start..state.screen.len() {
            state.screen[i] = b' ';
            if i < state.attributes.len() {
                state.attributes[i] = 0;
            }
        }
    }

    /// Get number of pending predictions
    pub fn pending_predictions(&self) -> usize {
        self.predictions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_character_prediction() {
        let initial_state = TerminalState::new(80, 24);
        let mut predictor = Predictor::new(initial_state);

        // Predict character input
        let seq = predictor.predict_input(UserInput::Character('H'));
        assert_eq!(seq, 1);

        let predicted = predictor.predicted_state();
        assert_eq!(predicted.screen[0], b'H');
        assert_eq!(predicted.cursor_x, 1);
        assert_eq!(predicted.cursor_y, 0);
    }

    #[test]
    fn test_backspace_prediction() {
        let mut initial_state = TerminalState::new(80, 24);
        initial_state.screen[0] = b'A';
        initial_state.cursor_x = 1;

        let mut predictor = Predictor::new(initial_state);

        // Predict backspace
        predictor.predict_input(UserInput::Key(KeyCode::Backspace));

        let predicted = predictor.predicted_state();
        assert_eq!(predicted.screen[0], b' ');
        assert_eq!(predicted.cursor_x, 0);
    }

    #[test]
    fn test_confirmation_update() {
        let initial_state = TerminalState::new(80, 24);
        let mut predictor = Predictor::new(initial_state.clone());

        // Make some predictions
        predictor.predict_input(UserInput::Character('A'));
        predictor.predict_input(UserInput::Character('B'));
        predictor.predict_input(UserInput::Character('C'));

        assert_eq!(predictor.pending_predictions(), 3);

        // Confirm first two predictions
        let mut confirmed_state = initial_state;
        confirmed_state.screen[0] = b'A';
        confirmed_state.screen[1] = b'B';
        confirmed_state.cursor_x = 2;

        predictor.update_confirmed(confirmed_state, 2);

        // Should have one prediction left
        assert_eq!(predictor.pending_predictions(), 1);

        // Predicted state should still show 'C'
        let predicted = predictor.predicted_state();
        assert_eq!(predicted.screen[2], b'C');
        assert_eq!(predicted.cursor_x, 3);
    }

    #[test]
    fn test_scrolling_prediction() {
        // Create a small 3x2 terminal for easy testing
        let initial_state = TerminalState::new(3, 2);
        let mut predictor = Predictor::new(initial_state);

        // Fill the first line
        predictor.predict_input(UserInput::Character('A'));
        predictor.predict_input(UserInput::Character('B'));
        predictor.predict_input(UserInput::Character('C'));

        // Fill the second line
        predictor.predict_input(UserInput::Character('D'));
        predictor.predict_input(UserInput::Character('E'));
        predictor.predict_input(UserInput::Character('F'));

        // This should trigger scrolling
        predictor.predict_input(UserInput::Character('G'));

        let predicted = predictor.predicted_state();

        // First line should now be DEF
        assert_eq!(&predicted.screen[0..3], b"DEF");
        // Second line should start with G
        assert_eq!(predicted.screen[3], b'G');

        // Check that scrollback was updated
        assert_eq!(predicted.scrollback.len(), 1);
        assert_eq!(predicted.scrollback[0], b"ABC");
    }

    #[test]
    fn test_enter_key_scrolling() {
        let initial_state = TerminalState::new(4, 2); // Use wider terminal to avoid wrap
        let mut predictor = Predictor::new(initial_state);

        // Fill first line
        predictor.predict_input(UserInput::Character('X'));
        predictor.predict_input(UserInput::Character('Y'));
        predictor.predict_input(UserInput::Character('Z'));

        // Check that first line is filled
        let state = predictor.predicted_state();
        assert_eq!(&state.screen[0..3], b"XYZ");

        // Press enter (should move to second line)
        predictor.predict_input(UserInput::Key(KeyCode::Enter));
        assert_eq!(predictor.predicted_state().cursor_y, 1);
        assert_eq!(predictor.predicted_state().cursor_x, 0);

        // Fill second line
        predictor.predict_input(UserInput::Character('A'));
        predictor.predict_input(UserInput::Character('B'));
        predictor.predict_input(UserInput::Character('C'));

        // Check current state before scrolling
        let state = predictor.predicted_state();
        assert_eq!(&state.screen[0..3], b"XYZ");
        assert_eq!(&state.screen[4..7], b"ABC"); // Second line starts at index 4 (width=4)

        // Press enter again (should trigger scroll)
        predictor.predict_input(UserInput::Key(KeyCode::Enter));

        let predicted = predictor.predicted_state();
        assert_eq!(predicted.cursor_y, 1); // Still at bottom
        assert_eq!(predicted.cursor_x, 0);

        // After scrolling:
        // - First line should now have what was on second line (ABC)
        // - Second line should be empty (new line created by enter)
        assert_eq!(&predicted.screen[0..3], b"ABC");
        assert_eq!(&predicted.screen[4..8], b"    "); // All spaces

        // Scrollback should have the original first line (padded to width 4)
        assert_eq!(predicted.scrollback.len(), 1);
        assert_eq!(&predicted.scrollback[0][0..3], b"XYZ");
    }
}
