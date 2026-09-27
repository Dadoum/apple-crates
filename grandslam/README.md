# apple-account

A library reimplementing `grandslam` and `itunes` endpoints.

`grandslam` is modeled mostly around concepts from AuthKitWin, 
StoreServicesCore and AppleMediaServices.

`itunes` is modeled after some personal reversing of iTunes, and 
the code of [ipatool](https://github.com/majd/ipatool).

## Continuation tokens

Password login requests a continuation token using `ckgen`. When Apple issues
one, extract it from the decrypted server-provided data:

```rust,ignore
let outcome = grandslam::login(&session, apple_id, password).await?;
if let grandslam::AuthOutcome::Success(data) = outcome {
    if let Some(token) = grandslam::ContinuationToken::from_server_provided_data(&data) {
        // Save the token securely with this Apple ID and device identity.
        let resumed = grandslam::login_with_continuation_token(&session, apple_id, &token).await?;
    }
}
```

Continuation login uses the decoded token as the SRP secret and sends
`cpd.ckauth = true` in both exchanges, omitting `bootstrap` and `ckgen`.
It returns the same `AuthOutcome` as password login, including secondary actions.
A successful response preserves the supplied token in `ck` if Apple does not
return a replacement. Extract and save the token again after success to handle
rotation. The library does not persist credentials or automatically fall back to
a password when a token is rejected.

Secondary-action responses can issue a token in `X-Apple-I-CK`. Before consuming
the response body, call
`ContinuationToken::from_response_headers(response.headers())` to base64-decode
that header into a UTF-8 token. An absent header returns `Ok(None)`; malformed
base64, invalid UTF-8, and empty tokens return an error. The `ck` plist value is
already decoded and must not be decoded a second time. Tokens support serde for
secure storage and redact their value in `Debug` output.

These details were traced in AuthKitWin 394.2 in Ghidra:
`_CopyAuthParametersForAccount` (`0x18003ca60`) selects the SRP secret and flags;
`_CreateServerResponseFromAuthContext` (`0x18003d570`) reads `ck` and retains the
input credential when no replacement is issued;
`AKCreateUpdatedServerResponse` (header lookup at `0x1800391a4`) decodes
`X-Apple-I-CK` before passing it to `SaveCKToken` (`0x18003c590`).
