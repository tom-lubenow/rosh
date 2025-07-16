//! Terminal state representation for synchronization

use rkyv::{Archive, Deserialize, Serialize};

/// Terminal state that can be synchronized
#[derive(Archive, Deserialize, Serialize, Debug, Clone, PartialEq)]
#[archive(check_bytes)]
pub struct TerminalState {
    /// Terminal dimensions
    pub width: u16,
    pub height: u16,
    
    /// Screen content (flattened 2D array)
    pub screen: Vec<u8>,
    
    /// Cursor position
    pub cursor_x: u16,
    pub cursor_y: u16,
    
    /// Cursor visibility
    pub cursor_visible: bool,
    
    /// Terminal title
    pub title: String,
    
    /// Scrollback buffer
    pub scrollback: Vec<Vec<u8>>,
    
    /// Terminal attributes (colors, styles, etc.)
    pub attributes: Vec<u8>,
}

impl TerminalState {
    /// Create a new terminal state
    pub fn new(width: u16, height: u16) -> Self {
        let screen_size = (width as usize) * (height as usize);
        Self {
            width,
            height,
            screen: vec![b' '; screen_size],
            cursor_x: 0,
            cursor_y: 0,
            cursor_visible: true,
            title: String::new(),
            scrollback: Vec::new(),
            attributes: vec![0; screen_size],
        }
    }
    
    /// Serialize state to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        rkyv::to_bytes::<_, 1024>(self)
            .map(|b| b.to_vec())
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }
    
    /// Deserialize state from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let archived = rkyv::check_archived_root::<Self>(bytes)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        
        archived.deserialize(&mut rkyv::Infallible)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }
}