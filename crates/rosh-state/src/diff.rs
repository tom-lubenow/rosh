//! State diffing algorithm for efficient synchronization
//!
//! Generates compact diffs between terminal states

use crate::StateError;
use rkyv::{Archive, Deserialize, Serialize};
use rosh_terminal::TerminalState;

/// A diff between two terminal states
#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[archive(check_bytes)]
pub struct StateDiff {
    /// Screen content changes (offset, length, new_data)
    pub screen_changes: Vec<ScreenChange>,

    /// Attribute changes
    pub attribute_changes: Vec<AttributeChange>,

    /// Cursor position change
    pub cursor_change: Option<CursorChange>,

    /// Dimension change
    pub dimension_change: Option<DimensionChange>,

    /// Title change
    pub title_change: Option<String>,

    /// Scrollback changes
    pub scrollback_changes: Vec<ScrollbackChange>,
}

#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[archive(check_bytes)]
pub struct ScreenChange {
    pub offset: u32,
    pub data: Vec<u8>,
}

#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[archive(check_bytes)]
pub struct AttributeChange {
    pub offset: u32,
    pub data: Vec<u8>,
}

#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[archive(check_bytes)]
pub struct CursorChange {
    pub x: u16,
    pub y: u16,
    pub visible: bool,
}

#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[archive(check_bytes)]
pub struct DimensionChange {
    pub width: u16,
    pub height: u16,
}

#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[archive(check_bytes)]
pub struct ScrollbackChange {
    pub index: u32,
    pub line: Vec<u8>,
}

impl StateDiff {
    /// Generate a diff between two states
    pub fn generate(old: &TerminalState, new: &TerminalState) -> Result<Self, StateError> {
        let mut diff = StateDiff {
            screen_changes: Vec::new(),
            attribute_changes: Vec::new(),
            cursor_change: None,
            dimension_change: None,
            title_change: None,
            scrollback_changes: Vec::new(),
        };

        // Check dimension change
        if old.width != new.width || old.height != new.height {
            diff.dimension_change = Some(DimensionChange {
                width: new.width,
                height: new.height,
            });
        }

        // Check cursor change
        if old.cursor_x != new.cursor_x
            || old.cursor_y != new.cursor_y
            || old.cursor_visible != new.cursor_visible
        {
            diff.cursor_change = Some(CursorChange {
                x: new.cursor_x,
                y: new.cursor_y,
                visible: new.cursor_visible,
            });
        }

        // Check title change
        if old.title != new.title {
            diff.title_change = Some(new.title.clone());
        }

        // Generate screen content changes using run-length encoding
        if old.screen.len() == new.screen.len() {
            diff.screen_changes = Self::generate_run_length_changes(&old.screen, &new.screen);
        } else {
            // Full screen update if dimensions changed
            diff.screen_changes = vec![ScreenChange {
                offset: 0,
                data: new.screen.clone(),
            }];
        }

        // Generate attribute changes
        if old.attributes.len() == new.attributes.len() {
            diff.attribute_changes =
                Self::generate_attribute_changes(&old.attributes, &new.attributes);
        } else {
            // Full attribute update if dimensions changed
            diff.attribute_changes = vec![AttributeChange {
                offset: 0,
                data: new.attributes.clone(),
            }];
        }

        // Generate scrollback changes
        diff.scrollback_changes =
            Self::generate_scrollback_changes(&old.scrollback, &new.scrollback);

        Ok(diff)
    }

    /// Generate run-length encoded changes for screen content
    fn generate_run_length_changes(old: &[u8], new: &[u8]) -> Vec<ScreenChange> {
        let mut changes = Vec::new();
        let mut i = 0;

        while i < old.len() {
            if old[i] != new[i] {
                let start = i;
                while i < old.len() && old[i] != new[i] {
                    i += 1;
                }

                changes.push(ScreenChange {
                    offset: start as u32,
                    data: new[start..i].to_vec(),
                });
            } else {
                i += 1;
            }
        }

        changes
    }

    /// Generate attribute changes
    fn generate_attribute_changes(old: &[u8], new: &[u8]) -> Vec<AttributeChange> {
        let mut changes = Vec::new();
        let mut i = 0;

        while i < old.len() {
            if old[i] != new[i] {
                let start = i;
                while i < old.len() && old[i] != new[i] {
                    i += 1;
                }

                changes.push(AttributeChange {
                    offset: start as u32,
                    data: new[start..i].to_vec(),
                });
            } else {
                i += 1;
            }
        }

        changes
    }

    /// Generate scrollback changes
    fn generate_scrollback_changes(old: &[Vec<u8>], new: &[Vec<u8>]) -> Vec<ScrollbackChange> {
        let mut changes = Vec::new();

        // If the new scrollback is longer, those are new lines
        if new.len() > old.len() {
            for (i, line) in new.iter().enumerate().skip(old.len()) {
                changes.push(ScrollbackChange {
                    index: i as u32,
                    line: line.clone(),
                });
            }
        }

        changes
    }

    /// Apply diff to a state to produce a new state
    pub fn apply(&self, state: &TerminalState) -> Result<TerminalState, StateError> {
        let mut new_state = state.clone();

        // Apply dimension change
        if let Some(dim) = &self.dimension_change {
            new_state.width = dim.width;
            new_state.height = dim.height;
            let new_size = (dim.width as usize) * (dim.height as usize);
            new_state.screen.resize(new_size, b' ');
            new_state.attributes.resize(new_size, 0);
        }

        // Apply screen changes
        for change in &self.screen_changes {
            let offset = change.offset as usize;
            if offset + change.data.len() > new_state.screen.len() {
                return Err(StateError::StateDivergence);
            }
            new_state.screen[offset..offset + change.data.len()].copy_from_slice(&change.data);
        }

        // Apply attribute changes
        for change in &self.attribute_changes {
            let offset = change.offset as usize;
            if offset + change.data.len() > new_state.attributes.len() {
                return Err(StateError::StateDivergence);
            }
            new_state.attributes[offset..offset + change.data.len()].copy_from_slice(&change.data);
        }

        // Apply cursor change
        if let Some(cursor) = &self.cursor_change {
            new_state.cursor_x = cursor.x;
            new_state.cursor_y = cursor.y;
            new_state.cursor_visible = cursor.visible;
        }

        // Apply title change
        if let Some(title) = &self.title_change {
            new_state.title = title.clone();
        }

        // Apply scrollback changes
        for change in &self.scrollback_changes {
            let index = change.index as usize;
            // If this is a new line at the end, append it
            if index == new_state.scrollback.len() {
                new_state.scrollback.push(change.line.clone());
            } else if index < new_state.scrollback.len() {
                // Update existing line (shouldn't happen in normal operation)
                new_state.scrollback[index] = change.line.clone();
            }
        }

        Ok(new_state)
    }

    /// Serialize diff to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        rkyv::to_bytes::<_, 256>(self)
            .map(|b| b.to_vec())
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }

    /// Deserialize diff from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let archived = rkyv::check_archived_root::<Self>(bytes)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        archived
            .deserialize(&mut rkyv::Infallible)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diff_generation() {
        let old_state = TerminalState::new(80, 24);
        let mut new_state = old_state.clone();

        // Change some screen content
        new_state.screen[0] = b'H';
        new_state.screen[1] = b'e';
        new_state.screen[2] = b'l';
        new_state.screen[3] = b'l';
        new_state.screen[4] = b'o';

        // Change cursor position
        new_state.cursor_x = 5;
        new_state.cursor_y = 0;

        let diff = StateDiff::generate(&old_state, &new_state).unwrap();

        assert_eq!(diff.screen_changes.len(), 1);
        assert_eq!(diff.screen_changes[0].offset, 0);
        assert_eq!(diff.screen_changes[0].data, b"Hello");

        assert!(diff.cursor_change.is_some());
        let cursor = diff.cursor_change.unwrap();
        assert_eq!(cursor.x, 5);
        assert_eq!(cursor.y, 0);
    }

    #[test]
    fn test_diff_apply() {
        let old_state = TerminalState::new(80, 24);
        let mut expected_state = old_state.clone();

        expected_state.screen[0] = b'T';
        expected_state.screen[1] = b'e';
        expected_state.screen[2] = b's';
        expected_state.screen[3] = b't';
        expected_state.cursor_x = 4;

        let diff = StateDiff::generate(&old_state, &expected_state).unwrap();
        let applied_state = diff.apply(&old_state).unwrap();

        assert_eq!(&applied_state.screen[0..4], b"Test");
        assert_eq!(applied_state.cursor_x, 4);
    }

    #[test]
    fn test_scrollback_diff() {
        let old_state = TerminalState::new(80, 24);
        let mut new_state = old_state.clone();

        // Add some lines to scrollback
        new_state
            .scrollback
            .push(vec![b'L', b'i', b'n', b'e', b' ', b'1']);
        new_state
            .scrollback
            .push(vec![b'L', b'i', b'n', b'e', b' ', b'2']);
        new_state
            .scrollback
            .push(vec![b'L', b'i', b'n', b'e', b' ', b'3']);

        let diff = StateDiff::generate(&old_state, &new_state).unwrap();

        // Should have 3 scrollback changes
        assert_eq!(diff.scrollback_changes.len(), 3);
        assert_eq!(diff.scrollback_changes[0].index, 0);
        assert_eq!(diff.scrollback_changes[0].line, b"Line 1");
        assert_eq!(diff.scrollback_changes[1].index, 1);
        assert_eq!(diff.scrollback_changes[1].line, b"Line 2");
        assert_eq!(diff.scrollback_changes[2].index, 2);
        assert_eq!(diff.scrollback_changes[2].line, b"Line 3");

        // Apply the diff
        let applied_state = diff.apply(&old_state).unwrap();
        assert_eq!(applied_state.scrollback.len(), 3);
        assert_eq!(applied_state.scrollback[0], b"Line 1");
        assert_eq!(applied_state.scrollback[1], b"Line 2");
        assert_eq!(applied_state.scrollback[2], b"Line 3");
    }

    #[test]
    fn test_scrollback_diff_incremental() {
        let mut state1 = TerminalState::new(80, 24);
        state1.scrollback.push(vec![b'O', b'l', b'd']);

        let mut state2 = state1.clone();
        state2.scrollback.push(vec![b'N', b'e', b'w']);

        let diff = StateDiff::generate(&state1, &state2).unwrap();

        // Should only have the new line
        assert_eq!(diff.scrollback_changes.len(), 1);
        assert_eq!(diff.scrollback_changes[0].index, 1);
        assert_eq!(diff.scrollback_changes[0].line, b"New");

        // Apply and verify
        let applied = diff.apply(&state1).unwrap();
        assert_eq!(applied.scrollback.len(), 2);
        assert_eq!(applied.scrollback[0], b"Old");
        assert_eq!(applied.scrollback[1], b"New");
    }
}
