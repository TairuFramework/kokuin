//! The error resolution and the history guard fail with.

use std::fmt;

use kokuin_token::MethodError;

/// A controller resolution failure, typed as the TS error it mirrors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControllerError {
    /// A plain `Error`: the controller as a whole could not be answered for (unknown DID, a log
    /// that does not fold or loses to memory, a saturated epoch).
    Error(String),
    /// A `TypeError` TS raises reading a wrong-typed field (a non-string `kid`).
    TypeError(String),
    /// `IssuerKeyNotFoundError`: the controller resolved, and a claim about it did not hold.
    IssuerKeyNotFound(String),
}

impl ControllerError {
    /// The JavaScript error name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Error(_) => "Error",
            Self::TypeError(_) => "TypeError",
            Self::IssuerKeyNotFound(_) => "IssuerKeyNotFoundError",
        }
    }

    /// The TS message.
    pub fn message(&self) -> &str {
        match self {
            Self::Error(message) | Self::TypeError(message) | Self::IssuerKeyNotFound(message) => {
                message
            }
        }
    }

    pub(crate) fn plain(message: impl Into<String>) -> Self {
        Self::Error(message.into())
    }

    pub(crate) fn key_not_found(message: impl Into<String>) -> Self {
        Self::IssuerKeyNotFound(message.into())
    }
}

impl fmt::Display for ControllerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for ControllerError {}

impl From<ControllerError> for MethodError {
    /// `IssuerKeyNotFoundError` passes through; everything else is unresolvable, message kept.
    fn from(error: ControllerError) -> Self {
        match error {
            ControllerError::IssuerKeyNotFound(message) => Self::IssuerKeyNotFound(message),
            ControllerError::Error(message) | ControllerError::TypeError(message) => {
                Self::Unresolvable(message)
            }
        }
    }
}
