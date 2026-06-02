use thiserror::Error;

use crate::transport::EthTransportError;

#[derive(Debug, Error, uniffi::Error)]
pub enum LedgerEthError {
    #[error("transport error: {reason}")]
    Transport { reason: String },

    #[error("device rejected (status 0x{status_word:04X}): {reason}")]
    DeviceRejected { status_word: u16, reason: String },

    #[error("invalid derivation path: {reason}")]
    InvalidPath { reason: String },

    #[error("invalid envelope: {reason}")]
    InvalidEnvelope { reason: String },

    #[error("protocol error: {reason}")]
    Protocol { reason: String },

    #[error("user canceled on device")]
    UserCanceled,
}

impl From<EthTransportError> for LedgerEthError {
    fn from(err: EthTransportError) -> Self {
        LedgerEthError::Transport {
            reason: err.to_string(),
        }
    }
}

#[allow(dead_code)]
impl LedgerEthError {
    pub(crate) fn protocol(msg: impl Into<String>) -> Self {
        LedgerEthError::Protocol { reason: msg.into() }
    }

    pub(crate) fn invalid_envelope(msg: impl Into<String>) -> Self {
        LedgerEthError::InvalidEnvelope { reason: msg.into() }
    }

    pub(crate) fn from_status(status_word: u16, label: &str) -> Self {
        match status_word {
            0x6985 => LedgerEthError::UserCanceled,
            sw => LedgerEthError::DeviceRejected {
                status_word: sw,
                reason: format!("{label}: device returned 0x{sw:04X}"),
            },
        }
    }
}
