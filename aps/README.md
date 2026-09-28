# aps

Apple Push Service activation and courier connections. Activation is an HTTP
request that returns a device certificate. The subsequent APS handshake over
TLS returns a push token. Neither step needs an Apple account or anisette.

```rust,ignore
let identity = aps::activate(&client, &device, &signer).await?;
let mut connection = aps::PushConnection::connect(&client, identity).await?;

// AuthKit's check-in represents the token as lowercase hexadecimal.
let device_data = grandslam::DeviceData {
    push_token: Some(connection.push_token().to_string()),
    ..Default::default()
};

connection.set_topics(&["com.apple.idmsauth"]).await?;
loop {
    let notification = connection.receive().await?;
    // Interpret notification.payload according to its topic.
}
```

`ActivationDevice` contains the actual device fields sent in the activation
plist. `ActivationSigner::sign` receives the exact serialized XML and returns
its FairPlay signature and matching certificate chain. The signer holds the
activation signing identity; the library generates a separate RSA device key
and CSR. A returned `PushIdentity` always contains the matching device key and
certificate, and a returned `PushConnection` always has a token.

Errors follow those boundaries: `IdentityError`, `ActivationError<S::Error>`,
`ConnectError`, and `CourierError`. Signer errors keep their concrete type.
Connecting moves the identity into the connection; reconnecting reuses it
without cloning the private key.

The signer is synchronous, like a local cryptographic provider. Applications
using a slow signer should schedule activation accordingly. The built-in Windows
signer uses embedded constants and Rust cryptography.

## Connection lifetime and persistence

`receive` handles notification acknowledgements and ping/pong traffic. Keep it
running while expecting pushes. There are no hidden background tasks or retry
loops. Call `reconnect` after transport failure; it reuses the identity/token
and restores the enabled topics. Use `close` to shut down deliberately. A
token's existence does not mean a connection is currently reachable.
If cancelling `receive` during an acknowledgement or keepalive write, reconnect
before continuing.

Persist the device certificate, private key, and latest token together.
`PushIdentity::certificate` returns DER bytes; `private_key` exposes the RSA key
for PKCS#8 export or a future adapter. `PushIdentity::new` validates imported
certificate/key pairs. `PushToken` supports serde and exposes `as_bytes`, but
has no public field or arbitrary-byte constructor. Its Debug output is redacted.
`PushConnection::resume` accepts the restored identity and token; read
`push_token` again afterward in case the server replaced it.

The current transport implements the original APS TLV protocol and advertises
`apns-security-v3`. It uses Apple's HTTPS configuration bag and verifies the
courier's TLS certificate and hostname against the bundled
[Apple Root CA](https://www.apple.com/appleca/AppleIncRootCertificate.cer). Notification
payloads stay as bytes, allowing AuthKit and future iMessage consumers to decode
them independently. IDS registration and iMessage-specific operations are not
part of this crate.

## Standalone Windows signing identity

`WindowsActivationSigner::new()` selects one of ten embedded activation signing
identities recovered from iCloud 15.10.39.0 x64. Their RSA primes and matching
certificates live in a private constants module, with the shared CA chain stored
once. No DLL or extraction step is needed. Signing errors use `rsa::Error`.

```sh
cargo run -p aps --example push_token -- /path/to/push-state.plist
```

The example activates on its first run, subscribes to `com.apple.idmsauth`,
saves the identity/token, and closes the connection. Subsequent runs restore
that state. The state file contains a private key; the example requests mode
0600 when creating it on Unix. Applications should use their own credential
storage. Restoring saved state does not perform activation again.

Activation was traced in `APSDaemon_main.dll` at `0x18001e770`; its signing
wrapper is at `0x180005250`. The APS protocol was cross-checked against Apple's
Windows client and rustpush's public protocol implementation. This crate does
not depend on rustpush or its account APIs.

See [the signing format notes](docs/windows-signing.md) for the decoded wrapping
format and its provenance.

All ten embedded identities passed independent RSA signature verification.
The standalone Rust signer also completed live activation and obtained a
32-byte push token; restoring that state reused the same token without a DLL.
