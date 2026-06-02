// ledger-eth-core: cross-platform Ledger Ethereum signing client.
//
// Replaces Maknoon's hand-rolled Swift APDU code with a UniFFI-
// bound Rust client that mirrors `@ledgerhq/hw-app-eth` (TypeScript).
// Surface: GET_PUBLIC_KEY (with on-host address derivation +
// EIP-55 checksum), SIGN_TRANSACTION (EIP-1559 or legacy), and
// SIGN_PERSONAL_MESSAGE (the Identity Sandwich wrap path).

mod client;
mod error;
mod transport;
mod types;

pub use client::{EthereumAddress, LedgerEthClient};
pub use error::LedgerEthError;
pub use transport::{EthExchangeResponse, EthLedgerTransport, EthTransportError};
pub use types::EthereumSignature;

uniffi::setup_scaffolding!();
