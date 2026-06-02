use std::sync::Arc;

use sha3::{Digest, Keccak256};

use crate::error::LedgerEthError;
use crate::transport::EthLedgerTransport;
use crate::types::EthereumSignature;

// Ethereum app APDU constants. Source of truth:
// https://github.com/LedgerHQ/app-ethereum/blob/develop/doc/ethapp.adoc
// Cross-checked against @ledgerhq/hw-app-eth (TypeScript reference).
const CLA: u8 = 0xE0;
const INS_GET_PUBLIC_KEY: u8 = 0x02;
const INS_SIGN: u8 = 0x04;
const INS_GET_APP_CONFIG: u8 = 0x06;
const INS_SIGN_PERSONAL_MESSAGE: u8 = 0x08;
const INS_PROVIDE_ERC20_TOKEN_INFO: u8 = 0x0A;

const P1_NON_CONFIRM: u8 = 0x00;
const P1_CONFIRM: u8 = 0x01;

const P1_SIGN_FIRST: u8 = 0x00;
const P1_SIGN_MORE: u8 = 0x80;

const MAX_APDU_DATA: usize = 255;
const SW_SUCCESS: u16 = 0x9000;

/// Top-level client for the Ledger Ethereum app. Construct once
/// per device session.
#[derive(uniffi::Object)]
pub struct LedgerEthClient {
    transport: Arc<dyn EthLedgerTransport>,
}

/// Ethereum address record. Pubkey is the 65-byte uncompressed
/// secp256k1 form (0x04 || X || Y); `address` is the EIP-55
/// checksummed `0x...` string the rest of the wallet uses.
#[derive(Debug, Clone, uniffi::Record)]
pub struct EthereumAddress {
    pub pubkey: Vec<u8>,
    pub address: String,
}

#[uniffi::export(async_runtime = "tokio")]
impl LedgerEthClient {
    #[uniffi::constructor]
    pub fn new(transport: Arc<dyn EthLedgerTransport>) -> Arc<Self> {
        Arc::new(Self { transport })
    }

    /// Returns `[major, minor, patch]` for the running Ethereum
    /// app. Useful for diagnostics + future feature gating.
    pub async fn get_app_configuration(&self) -> Result<Vec<u8>, LedgerEthError> {
        let response = self
            .exchange(CLA, INS_GET_APP_CONFIG, 0x00, 0x00, &[])
            .await?;
        if response.len() < 4 {
            return Err(LedgerEthError::protocol(format!(
                "GET_APP_CONFIG: expected ≥4 bytes, got {}",
                response.len()
            )));
        }
        Ok(vec![response[1], response[2], response[3]])
    }

    /// EIP-55 address at the standard Ethereum path
    /// `m/44'/60'/<account>'/0/0`.
    pub async fn get_address_for_account(
        &self,
        account: u32,
        display: bool,
    ) -> Result<EthereumAddress, LedgerEthError> {
        let components = standard_eth_path(account);
        self.get_address_inner(&components, display).await
    }

    /// EIP-55 address at an explicit BIP-32 path. Path syntax
    /// follows BIP-32 with `'` for hardened, e.g.
    /// `"m/44'/60'/0'/0/0"`.
    pub async fn get_address_at_path(
        &self,
        path: String,
        display: bool,
    ) -> Result<EthereumAddress, LedgerEthError> {
        let components = parse_bip32_path(&path)?;
        self.get_address_inner(&components, display).await
    }

    /// Sign an EIP-1559 (or legacy RLP) unsigned envelope at the
    /// standard account path. `envelope` is the wire-format
    /// unsigned bytes the caller built host-side
    /// (`0x02 || rlp(...)` for type-2; bare RLP for legacy).
    pub async fn sign_transaction_for_account(
        &self,
        account: u32,
        envelope: Vec<u8>,
    ) -> Result<EthereumSignature, LedgerEthError> {
        let components = standard_eth_path(account);
        self.sign_inner(INS_SIGN, &components, &envelope).await
    }

    /// Sign at an explicit BIP-32 path. Semantics match
    /// `sign_transaction_for_account`.
    pub async fn sign_transaction_at_path(
        &self,
        path: String,
        envelope: Vec<u8>,
    ) -> Result<EthereumSignature, LedgerEthError> {
        let components = parse_bip32_path(&path)?;
        self.sign_inner(INS_SIGN, &components, &envelope).await
    }

    /// Provide a Ledger-signed ERC-20 token descriptor to the
    /// Ethereum app BEFORE `sign_transaction_*`, so the device can
    /// clear-sign "Send <amount> <TICKER> to 0x…" for a
    /// `transfer(address,uint256)` instead of rejecting with 0x6A80
    /// unless the user has blind signing enabled.
    ///
    /// `token_info` is the opaque descriptor blob from Ledger's
    /// Crypto Asset List, layout per app-ethereum:
    ///   tickerLen(1) || ticker || address(20) || decimals(4 BE) ||
    ///   chainId(4 BE) || Ledger signature
    /// The device verifies Ledger's signature against its embedded
    /// CAL key, so the blob's source is untrusted (we can bundle or
    /// mirror it). The descriptor is well under the 255-byte APDU
    /// ceiling, so this is a single P1=0x00, P2=0x00 exchange. The
    /// provided context applies to the very next SIGN_TRANSACTION on
    /// the same session, so callers must not reset the connection in
    /// between.
    pub async fn provide_erc20_token_information(
        &self,
        token_info: Vec<u8>,
    ) -> Result<(), LedgerEthError> {
        if token_info.is_empty() {
            return Err(LedgerEthError::protocol(
                "ERC-20 token information blob is empty",
            ));
        }
        self.exchange(CLA, INS_PROVIDE_ERC20_TOKEN_INFO, 0x00, 0x00, &token_info)
            .await?;
        Ok(())
    }

    /// EIP-191 `personal_sign` at the standard account path. The
    /// device prefixes `"\x19Ethereum Signed Message:\n<len>"`
    /// and hashes with keccak-256, so the caller passes raw
    /// message bytes (NOT the prefixed form). Used by Maknoon's
    /// Identity Sandwich wrap.
    pub async fn sign_personal_message_for_account(
        &self,
        account: u32,
        message: Vec<u8>,
    ) -> Result<EthereumSignature, LedgerEthError> {
        let components = standard_eth_path(account);
        self.sign_personal_inner(&components, &message).await
    }

    /// `personal_sign` at an explicit BIP-32 path.
    pub async fn sign_personal_message_at_path(
        &self,
        path: String,
        message: Vec<u8>,
    ) -> Result<EthereumSignature, LedgerEthError> {
        let components = parse_bip32_path(&path)?;
        self.sign_personal_inner(&components, &message).await
    }
}

impl LedgerEthClient {
    async fn get_address_inner(
        &self,
        components: &[u32],
        display: bool,
    ) -> Result<EthereumAddress, LedgerEthError> {
        let payload = encode_path(components);
        let p1 = if display { P1_CONFIRM } else { P1_NON_CONFIRM };
        let response = self
            .exchange(CLA, INS_GET_PUBLIC_KEY, p1, 0x00, &payload)
            .await?;
        // Response layout:
        //   1B(pkLen) || pubkey || 1B(addrAsciiLen) || addr ascii ||
        //   optional 32B chain code
        if response.is_empty() {
            return Err(LedgerEthError::protocol("GET_PUBLIC_KEY: empty response"));
        }
        let pk_len = response[0] as usize;
        if response.len() < 1 + pk_len {
            return Err(LedgerEthError::protocol(format!(
                "GET_PUBLIC_KEY: short response (pkLen={} but {} total bytes)",
                pk_len,
                response.len()
            )));
        }
        let pubkey = response[1..1 + pk_len].to_vec();
        if pubkey.len() != 65 || pubkey[0] != 0x04 {
            return Err(LedgerEthError::protocol(format!(
                "expected 65-byte uncompressed pubkey, got {} bytes prefixed 0x{:02X}",
                pubkey.len(),
                pubkey.first().copied().unwrap_or(0),
            )));
        }
        // Derive locally: keccak256(XY)[12..] then EIP-55 mixed-case.
        // We deliberately ignore the device-supplied ASCII because
        // older Ethereum app versions emit lowercase-only addresses;
        // EIP-55 is a host-side concern anyway.
        let xy = &pubkey[1..];
        let hashed = keccak256(xy);
        let last20 = &hashed[12..];
        let address = eip55_checksum(last20);
        Ok(EthereumAddress { pubkey, address })
    }

    async fn sign_inner(
        &self,
        ins: u8,
        components: &[u32],
        envelope: &[u8],
    ) -> Result<EthereumSignature, LedgerEthError> {
        if envelope.is_empty() {
            return Err(LedgerEthError::invalid_envelope("envelope is empty"));
        }
        let path_bytes = encode_path(components);
        let header_len = path_bytes.len();
        if header_len >= MAX_APDU_DATA {
            return Err(LedgerEthError::protocol(format!(
                "derivation-path encoding {} bytes ≥ APDU ceiling {}",
                header_len, MAX_APDU_DATA
            )));
        }

        let mut response = Vec::new();
        let mut offset = 0usize;
        let mut first = true;
        while first || offset < envelope.len() {
            let chunk_capacity = if first {
                MAX_APDU_DATA - header_len
            } else {
                MAX_APDU_DATA
            };
            let end = (offset + chunk_capacity).min(envelope.len());
            let mut chunk = Vec::with_capacity(chunk_capacity + header_len);
            if first {
                chunk.extend_from_slice(&path_bytes);
            }
            chunk.extend_from_slice(&envelope[offset..end]);
            let p1 = if first { P1_SIGN_FIRST } else { P1_SIGN_MORE };
            response = self.exchange(CLA, ins, p1, 0x00, &chunk).await?;
            offset = end;
            first = false;
        }
        decode_vrs(&response)
    }

    async fn sign_personal_inner(
        &self,
        components: &[u32],
        message: &[u8],
    ) -> Result<EthereumSignature, LedgerEthError> {
        let path_bytes = encode_path(components);
        // SIGN_PERSONAL_MESSAGE payload (first chunk):
        //   path_bytes || u32 message-length big-endian || message
        // The length prefix is over the WHOLE message, not just the
        // first chunk; required by the device's own prefix
        // computation. Subsequent chunks carry message bytes only.
        let mut head = Vec::with_capacity(path_bytes.len() + 4 + message.len());
        head.extend_from_slice(&path_bytes);
        head.extend_from_slice(&(message.len() as u32).to_be_bytes());
        head.extend_from_slice(message);

        let header_len = path_bytes.len() + 4;
        if header_len >= MAX_APDU_DATA {
            return Err(LedgerEthError::protocol(format!(
                "SIGN_PERSONAL_MESSAGE header {} bytes ≥ APDU ceiling {}",
                header_len, MAX_APDU_DATA
            )));
        }
        let mut response = Vec::new();
        let mut offset = 0usize;
        let mut first = true;
        while first || offset < head.len() {
            let max_chunk = MAX_APDU_DATA;
            let end = (offset + max_chunk).min(head.len());
            let chunk = &head[offset..end];
            let p1 = if first { P1_SIGN_FIRST } else { P1_SIGN_MORE };
            response = self
                .exchange(CLA, INS_SIGN_PERSONAL_MESSAGE, p1, 0x00, chunk)
                .await?;
            offset = end;
            first = false;
        }
        decode_vrs(&response)
    }

    async fn exchange(
        &self,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
    ) -> Result<Vec<u8>, LedgerEthError> {
        if data.len() > MAX_APDU_DATA {
            return Err(LedgerEthError::protocol(format!(
                "APDU payload {} exceeds {} byte ceiling",
                data.len(),
                MAX_APDU_DATA
            )));
        }
        let mut apdu = Vec::with_capacity(5 + data.len());
        apdu.push(cla);
        apdu.push(ins);
        apdu.push(p1);
        apdu.push(p2);
        apdu.push(data.len() as u8);
        apdu.extend_from_slice(data);

        let response = self.transport.exchange(apdu).await?;
        if response.status_word != SW_SUCCESS {
            return Err(LedgerEthError::from_status(
                response.status_word,
                &format!("INS 0x{ins:02X}"),
            ));
        }
        Ok(response.data)
    }
}

fn decode_vrs(response: &[u8]) -> Result<EthereumSignature, LedgerEthError> {
    if response.len() != 65 {
        return Err(LedgerEthError::protocol(format!(
            "SIGN: expected 65 bytes (V||R||S), got {}",
            response.len()
        )));
    }
    // Some firmware emits V as `parity + 27` (the legacy
    // convention) even for type-2 transactions. Normalize to 0/1
    // so callers don't have to handle two encodings.
    let raw_v = response[0];
    let v: u8 = if raw_v >= 27 {
        (raw_v - 27) & 0x01
    } else {
        raw_v & 0x01
    };
    let r = response[1..33].to_vec();
    let s = response[33..65].to_vec();
    Ok(EthereumSignature { v, r, s })
}

fn standard_eth_path(account: u32) -> Vec<u32> {
    vec![harden(44), harden(60), harden(account), 0, 0]
}

const HARDENED_BIT: u32 = 0x8000_0000;

fn harden(index: u32) -> u32 {
    index | HARDENED_BIT
}

fn parse_bip32_path(path: &str) -> Result<Vec<u32>, LedgerEthError> {
    let trimmed = path.trim();
    let body = trimmed.strip_prefix("m/").unwrap_or(trimmed);
    if body.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for raw in body.split('/') {
        let (digits, hardened) = if let Some(stripped) = raw.strip_suffix('\'') {
            (stripped, true)
        } else if let Some(stripped) = raw.strip_suffix('h') {
            (stripped, true)
        } else {
            (raw, false)
        };
        let n: u32 = digits.parse().map_err(|_| LedgerEthError::InvalidPath {
            reason: format!("'{raw}' is not a valid path component"),
        })?;
        if n >= HARDENED_BIT {
            return Err(LedgerEthError::InvalidPath {
                reason: format!("component {n} exceeds 31-bit range"),
            });
        }
        out.push(if hardened { harden(n) } else { n });
    }
    Ok(out)
}

fn encode_path(components: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + components.len() * 4);
    out.push(components.len() as u8);
    for c in components {
        out.extend_from_slice(&c.to_be_bytes());
    }
    out
}

fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(input);
    h.finalize().into()
}

/// EIP-55 mixed-case checksum for a 20-byte address. Lowercases
/// the hex, keccak-256s the lowercase hex ASCII, then uppercases
/// each hex nibble whose corresponding nibble in the hash byte is
/// ≥ 8.
fn eip55_checksum(addr_bytes: &[u8]) -> String {
    debug_assert_eq!(addr_bytes.len(), 20);
    let lower: String = addr_bytes.iter().map(|b| format!("{b:02x}")).collect();
    let hash = keccak256(lower.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, ch) in lower.chars().enumerate() {
        let byte = hash[i / 2];
        let nibble = if i % 2 == 0 { byte >> 4 } else { byte & 0x0F };
        if nibble >= 8 {
            out.extend(ch.to_uppercase());
        } else {
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{EthExchangeResponse, EthTransportError};
    use std::sync::Mutex;

    /// Records the last APDU it was handed and replies with a fixed
    /// status word + empty data. Enough to assert APDU framing and
    /// status-word handling without a device.
    struct RecordingTransport {
        last_apdu: Mutex<Vec<u8>>,
        status_word: u16,
    }

    #[async_trait::async_trait]
    impl EthLedgerTransport for RecordingTransport {
        async fn exchange(&self, apdu: Vec<u8>) -> Result<EthExchangeResponse, EthTransportError> {
            *self.last_apdu.lock().unwrap() = apdu;
            Ok(EthExchangeResponse {
                status_word: self.status_word,
                data: Vec::new(),
            })
        }
    }

    #[tokio::test]
    async fn provide_erc20_token_information_builds_single_apdu() {
        // A stand-in descriptor blob (real ones are ~70-120 B).
        let blob: Vec<u8> = vec![0x04, b'U', b'S', b'D', b'C', 0xDE, 0xAD, 0xBE, 0xEF];
        let transport = Arc::new(RecordingTransport {
            last_apdu: Mutex::new(Vec::new()),
            status_word: SW_SUCCESS,
        });
        let client = LedgerEthClient::new(transport.clone());
        client
            .provide_erc20_token_information(blob.clone())
            .await
            .unwrap();

        let mut expected = vec![
            CLA,
            INS_PROVIDE_ERC20_TOKEN_INFO,
            0x00,
            0x00,
            blob.len() as u8,
        ];
        expected.extend_from_slice(&blob);
        assert_eq!(*transport.last_apdu.lock().unwrap(), expected);
    }

    #[tokio::test]
    async fn provide_erc20_token_information_maps_device_rejection() {
        let transport = Arc::new(RecordingTransport {
            last_apdu: Mutex::new(Vec::new()),
            status_word: 0x6A80,
        });
        let client = LedgerEthClient::new(transport);
        let err = client
            .provide_erc20_token_information(vec![0x01, 0x02, 0x03])
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            LedgerEthError::DeviceRejected {
                status_word: 0x6A80,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn provide_erc20_token_information_rejects_empty_blob() {
        let transport = Arc::new(RecordingTransport {
            last_apdu: Mutex::new(Vec::new()),
            status_word: SW_SUCCESS,
        });
        let client = LedgerEthClient::new(transport);
        assert!(client
            .provide_erc20_token_information(Vec::new())
            .await
            .is_err());
    }

    #[test]
    fn standard_path_matches_hw_app_eth() {
        // m/44'/60'/0'/0/0 — first three hardened, last two not.
        let path = standard_eth_path(0);
        let encoded = encode_path(&path);
        let expected: Vec<u8> = vec![
            0x05, 0x80, 0x00, 0x00, 0x2C, // 44'
            0x80, 0x00, 0x00, 0x3C, // 60'
            0x80, 0x00, 0x00, 0x00, // 0'
            0x00, 0x00, 0x00, 0x00, // 0
            0x00, 0x00, 0x00, 0x00, // 0
        ];
        assert_eq!(encoded, expected);
    }

    #[test]
    fn eip55_canonical_vectors() {
        // From EIP-55 reference: vitalik.eth and a few canonical
        // addresses. Input bytes are the lowercased 20-byte hex.
        let cases = [
            (
                "fb6916095ca1df60bb79ce92ce3ea74c37c5d359",
                "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            ),
            (
                "52908400098527886e0f7030069857d2e4169ee7",
                "0x52908400098527886E0F7030069857D2E4169EE7",
            ),
            (
                "27b1fdb04752bbc536007a920d24acb045561c26",
                "0x27b1fdb04752bbc536007a920d24acb045561c26",
            ),
        ];
        for (lower, expected) in cases.iter() {
            let bytes = hex::decode(lower).unwrap();
            assert_eq!(&eip55_checksum(&bytes), expected);
        }
    }

    #[test]
    fn parse_path_accepts_apostrophe_and_h() {
        let a = parse_bip32_path("m/44'/60'/0'/0/0").unwrap();
        let b = parse_bip32_path("m/44h/60h/0h/0/0").unwrap();
        assert_eq!(a, b);
    }
}
