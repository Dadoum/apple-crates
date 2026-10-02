# Native iCloud

Experimental native authentication and CloudKit container setup, built on
`grandslam`. This crate does **not yet list or download iCloud Drive files**.
It does not use the iCloud website's session cookies or Drive JSON endpoints.

The implemented authentication steps are:

1. Obtain `PasswordEquivalentToken` from a GrandSlam SRP authentication result.
   Antarctic may return a still-valid cached PET or renew one using CK; it does
   not submit this identifier to the master-token `apptokens` exchange.
2. Build a MobileMe delegate request with `account::login_request_builder` and
   submit it with `account::login`. The result wraps the returned service data.
3. Extract the numeric DSID, `MmeAuthToken`, and `CloudKitToken` as needed.
4. Call `cloudkit::CLOUD_DOCS.initialize` with the DSID and MobileMe token to
   resolve the container-scoped user ID.
5. Construct `CloudKitSession` with that ID and the CloudKit token. Its request
   builder is a low-level header builder; protobuf operations are not implemented.

`ICloudSession::account_settings` implements the native account-settings refresh.
`AccountSettings::service` exposes the server's dataclass configuration, including
`com.apple.Dataclass.CKDatabaseService` and its `url`. Future operations should use
these URLs instead of assuming an account's server shard.

PETs are used for login; MobileMe tokens authenticate setup/account requests;
CloudKit tokens authenticate database requests. None are implicitly forwarded to
asset download servers. Secret-bearing types deliberately omit `Debug`.

## Validation status

Compiled locally; synthetic parser checks covered success, rejected top-level
and delegate statuses, missing fields, malformed plists and both settings layouts.
Native MobileMe login and container initialization have not yet been validated
with an account. PET acquisition has been: password-based SRP returned a fresh
PET, while requesting the PET identifier through the same fresh master-token
exchange returned `-22413`; an Xcode token request before and after it succeeded.

The login builder permits a caller to add `X-Mme-Nas-Qualify` if validation data is
available. Acceptance without that header is **unverified**. The Windows and
macOS login paths must not be assumed interchangeable. No automatic terms
acceptance, IDS enrollment, or account-key recovery is performed.

See [native protocol notes](../research/icloud-windows/docs/native-drive.md) for the verified binary anchors
and the remaining work needed for actual file access.
