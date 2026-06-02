# ledger-eth-rs

A Rust core + [UniFFI](https://github.com/mozilla/uniffi-rs) bindings for talking to the
**Ledger Ethereum app** from iOS (and other UniFFI targets). The Rust crate implements the
Ledger Ethereum app's APDU protocol directly — address derivation, EIP-155 transaction
signing, ERC-20 clear-signing, and `personal_sign` — while the host platform owns its own
BLE / USB transport.

Single source of truth, one artifact:

```
ledger-eth-rs/
   ├── ledger-eth-core   ←  Rust crate (LedgerEthClient)
   └── ios               ←  build-xcframework.sh → LedgerEthCore.xcframework
```

## Design pillars

1. **Audit surface = Ledger device protocol only.** No web3 / RPC dependency; the crate
   speaks the Ledger Ethereum app protocol and nothing else.
2. **Native owns transport.** BLE framing, MTU chunking, and keep-alive live on the
   Swift side; Rust gets complete APDUs in, complete responses out.
3. **Async end-to-end.** The UniFFI callback transport is async; the client is `async`
   throughout (Swift sees `async throws`).
4. **Clear-signing.** `provide_erc20_token_information` feeds the device the token
   descriptor so the user approves a human-readable transfer, not raw calldata.

## Public API

```rust
let client = LedgerEthClient::new(my_transport);
let cfg: Vec<u8>      = client.get_app_configuration().await?;
let addr: String      = client.get_address_at_path("m/44'/60'/0'/0/0".into(), false).await?;
let sig:  Vec<u8>     = client.sign_transaction_at_path(path, rlp_tx).await?;
client.provide_erc20_token_information(token_info).await?;     // clear-signing
let psig: Vec<u8>     = client.sign_personal_message_at_path(path, message).await?;
```

`*_for_account` convenience variants take an account index instead of a full BIP-44 path.

## Building

```sh
make            # fmt-check + clippy + test (CI default)
make ios        # produces ios/LedgerEthCore.xcframework (run setup-ios-targets once)
make clean
```

## License

Apache-2.0.

## Acknowledgements

- [Mozilla UniFFI](https://github.com/mozilla/uniffi-rs) for the cross-language binding generator.
- Ledger's Ethereum app APDU specification.
