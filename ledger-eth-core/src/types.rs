/// Ethereum signature returned by `sign_transaction_*` and
/// `sign_personal_message_*`. Wire layout for the underlying APDU
/// is V(1) || R(32) || S(32). We split into named components for
/// callers; `v` is normalised to 0 or 1 (parity bit). For legacy
/// chain-id encoding, callers add `35 + 2*chain_id` themselves.
#[derive(Debug, Clone, uniffi::Record)]
pub struct EthereumSignature {
    pub v: u8,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
}
