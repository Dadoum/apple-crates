# aps

Apple Push Service activation and courier connections. Activation is an HTTP
request that returns a device certificate. The subsequent APS handshake over
TLS returns a push token. Neither step needs an Apple account or anisette.

```rust,ignore
let client = reqwest::Client::builder()
    .tls_certs_merge([reqwest::Certificate::from_der(aps::APPLE_ROOT_CA)?])
    .build()?;
let identity = aps::activate(&client, &device, &signer).await?;
let mut connection = aps::PushConnection::connect(&client, identity).await?;

// AuthKit's check-in represents the token as lowercase hexadecimal.
let device_data = grandslam::DeviceData {
    push_token: Some(connection.push_token().to_string()),
    ..Default::default()
};

connection.set_topics(&["com.apple.idmsauth"]).await?;
loop {
    match connection.receive().await? {
        aps::Event::Notification(notification) => {
            // Accept or store notification.payload according to its topic.
            connection.acknowledge(&notification).await?;
        }
        aps::Event::Acknowledgement { id, status } => {
            // Match id to an outgoing send; status is Accepted or Rejected(code).
        }
    }
}
```

`ActivationDevice` contains the actual device fields sent in the activation
plist. `ActivationSigner::sign` receives the exact serialized XML and returns
its FairPlay signature and matching certificate chain. The signer holds the
activation signing identity; the library generates a separate RSA device key
and CSR. A returned `PushIdentity` always contains the matching device key and
certificate, and a returned `PushConnection` always has a token.

Errors follow those boundaries: `IdentityError`, `ActivationError<S::Error>`,
`ConnectError`, `SendError`, and `CourierError`. Signer errors keep their concrete type.
Connecting moves the identity into the connection; reconnecting reuses it
without cloning the private key.

The signer is synchronous, like a local cryptographic provider. Applications
using a slow signer should schedule activation accordingly. The built-in Windows
signer uses embedded constants and Rust cryptography.

## Connection lifetime and persistence

`receive` returns notifications or outgoing-send acknowledgements and handles
ping/pong traffic. Call `acknowledge` after accepting or storing each notification;
it borrows the notification, so
an acknowledgement error leaves it available to the caller. Keep calling
`receive` while expecting pushes. There are no hidden background tasks or retry
loops. Call `reconnect` after transport failure; it reuses the identity/token
and restores the enabled topics. Use `close` to shut down deliberately. A
token's existence does not mean a connection is currently reachable.
If cancelling `acknowledge` during its write, or `receive` during a keepalive
write, reconnect before continuing.

`send(id, topic, payload)` writes unchanged payload bytes. Only one send can await
acknowledgement at a time; attempting another returns
`SendError::PendingAcknowledgement`. Use a new ID for each send. Continue calling
`receive`, processing notifications as usual, until `Event::Acknowledgement`
reports that ID. The courier can omit the ID on the wire, in which case it is
associated with the one outstanding send, as in macOS. An explicit nonmatching
ID is ignored. `SendStatus::Accepted` means courier acceptance, not delivery to a
recipient. Nonzero response codes are preserved as `SendStatus::Rejected(code)`.

`max_payload_size()` exposes the courier's advertised limit; larger payloads are
rejected before writing or occupying the pending slot. If the courier omits the
limit, the two-byte TLV length is the local ceiling, not a promise of acceptance.

`receive` reports `CourierError::AcknowledgementTimeout(id)` after 30 seconds
without a matching acknowledgement. This is the crate's existing operation
timeout policy; callers can impose shorter deadlines. The caller owns retry
policy. After a timeout, transport failure, or cancelled send, reconnect before
sending again. Reconnect
clears the outstanding send without replaying it: its outcome is unknown, and
retrying could duplicate delivery. Payload encoding and IDS service registration
remain the caller's responsibility.

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

The HTTPS client also needs this root for `init.push.apple.com`, as shown above.
It is not included in every operating system's default trust store.

## Standalone Windows signing identity

`WindowsActivationSigner::new()` selects one of ten embedded activation signing
identities recovered from iCloud 15.10.39.0 x64. Their RSA primes and matching
certificates live in a private constants module, with the shared CA chain stored
once. No DLL or extraction step is needed. Signing errors use `rsa::Error`.

```sh
cargo run -p aps --example push_token -- /path/to/push-state.plist
```

Add `--check-connection` to drive receive/keepalive for 95 seconds, reconnect,
and report whether the token was preserved. It does not print tokens or payloads.

The example activates on its first run, subscribes to `com.apple.idmsauth`,
saves the identity/token, and closes the connection. Subsequent runs restore
that state. The state file contains a private key; the example requests mode
0600 when creating it on Unix. Applications should use their own credential
storage. Restoring saved state does not perform activation again.

Activation was traced in `APSDaemon_main.dll` at `0x18001e770`; its signing
wrapper is at `0x180005250`. The APS protocol was cross-checked against Apple's
Windows client and rustpush's public protocol implementation. This crate does
not depend on rustpush or its account APIs.

Outgoing messages and acknowledgement handling were also checked against
macOS 27's `apsd`; see [the comparison notes](../research/aps/docs/macos-protocol.md).

See [the signing format notes](../research/aps/docs/windows-signing.md) for the decoded wrapping
format and its provenance.

All ten embedded identities passed independent RSA signature verification.
The standalone Rust signer also completed live activation and obtained a
32-byte push token; restoring that state reused the same token without a DLL.
