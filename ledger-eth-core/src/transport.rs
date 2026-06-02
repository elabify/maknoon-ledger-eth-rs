use thiserror::Error;

#[derive(Debug, Error, uniffi::Error)]
pub enum EthTransportError {
    #[error("transport disconnected: {reason}")]
    Disconnected { reason: String },
    #[error("transport timed out: {reason}")]
    Timeout { reason: String },
    #[error("transport I/O error: {reason}")]
    Io { reason: String },
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct EthExchangeResponse {
    pub status_word: u16,
    pub data: Vec<u8>,
}

/// Foreign-implemented transport. The host (Swift / Kotlin) owns
/// the BLE / USB stack, framing, MTU chunking, response
/// reassembly, and keep-alive heartbeat; we just hand it a
/// complete APDU and read the reassembled response.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait EthLedgerTransport: Send + Sync {
    async fn exchange(&self, apdu: Vec<u8>) -> Result<EthExchangeResponse, EthTransportError>;
}
