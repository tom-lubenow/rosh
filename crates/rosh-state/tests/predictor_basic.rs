use rosh_state::predictor::{Predictor, UserInput};
use rosh_terminal::TerminalState;

#[test]
fn predictor_character_input_and_confirmation() {
    let initial = TerminalState::new(4, 2);
    let mut pred = Predictor::new(initial.clone());

    // Predict typing 'A'
    let seq = pred.predict_input(UserInput::Character('A'));
    let st = pred.predicted_state().clone();
    assert_eq!(st.screen[0], b'A');
    assert_eq!(st.cursor_x, 1);
    assert!(pred.has_predictions());
    assert!(pred.pending_predictions() >= 1);

    // Server confirms: update confirmed state with the predicted state and sequence number
    pred.update_confirmed(st.clone(), seq);
    assert!(!pred.has_predictions());
    assert_eq!(pred.predicted_state(), &st);
    assert_eq!(pred.confirmed_state(), &st);
}
