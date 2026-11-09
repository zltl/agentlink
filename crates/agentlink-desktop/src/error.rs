//! Errors from capture, input, and accessibility backends.

use std::fmt;

/// Failure while talking to the local desktop.
#[derive(Debug)]
pub struct DesktopError {
    message: String,
}

impl DesktopError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for DesktopError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DesktopError {}

impl From<image::ImageError> for DesktopError {
    fn from(err: image::ImageError) -> Self {
        Self::new(err.to_string())
    }
}

impl From<std::io::Error> for DesktopError {
    fn from(err: std::io::Error) -> Self {
        Self::new(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, DesktopError>;

pub fn msg(text: impl Into<String>) -> DesktopError {
    DesktopError::new(text)
}
