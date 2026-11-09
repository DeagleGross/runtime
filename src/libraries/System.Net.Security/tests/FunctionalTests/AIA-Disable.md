# AIA-Disable experiment (local prototype)

Goal: let a user disable AIA (Authority Information Access) certificate downloads for the certificate a `SslStream` server or client *sends*, on Windows, using the existing public setting `X509ChainPolicy.DisableCertificateDownloads` (via `SslServerAuthenticationOptions.CertificateChainPolicy` / `SslClientAuthenticationOptions.CertificateChainPolicy`) or `SslStreamCertificateContext.Create(..., offline: true)`.

Test: `SslStreamCertificateContextTests.ServerCertificate_AiaDownload_HonorsDisableCertificateDownloads` (Windows only).

## Background

- On Windows, two independent chain builds can download missing intermediates over AIA when a server credential is created:
  1. .NET's own `X509Chain` build in `SslStreamCertificateContext.Create` (`offline` controls `ChainPolicy.DisableCertificateDownloads`). `SslStream` hardcoded `offline: false` for a plain `ServerCertificate` or a selection callback result.
  2. Schannel's native chain build in `AcquireCredentialsHandle`. Controlled by the credential flag `SCH_CRED_CACHE_ONLY_URL_RETRIEVAL_ON_CREATE` (0x20000), which makes Schannel pass `CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL` to `CertGetCertificateChain`.
- Before dotnet/runtime#134585 the Schannel flag was never set. Since then it is set unconditionally on main, so Schannel never downloads, regardless of user settings.
- On Linux and macOS the setting is handled entirely by managed code (`ChainPal.OpenSsl.cs` / `ChainPal.Apple.cs`), the TLS library itself does not download.

## Prototype changes (src/libraries/System.Net.Security/src)

- `SslAuthenticationOptions`: new `DisableCertificateDownloads` (chain policy setting or an offline certificate context). The chain policy is stored before the certificate context is built, and `SetCertificateContextFromCert` passes it as `offline`.
- `SslStreamCertificateContext`: remembers its `offline` value (kept by `Duplicate()`).
- `SslStreamPal.Windows.cs`: sets `SCH_CRED_CACHE_ONLY_URL_RETRIEVAL_ON_CREATE` only when `DisableCertificateDownloads` is set (both `SCHANNEL_CRED` and `SCH_CREDENTIALS` paths). Default behaviour is "downloads allowed", as in shipped runtimes.
- `SslSessionsCache` and its call sites: the setting is part of the credential cache key.

## How the test certificates are created

Everything is generated in code at test time (`CertificateRequest`), nothing is installed or checked in:

1. Root CA: self-signed RSA-2048, `CN=AIA Test Root`, BasicConstraints CA=true, KeyCertSign.
2. Intermediate CA: RSA-2048, `CN=AIA Test Intermediate`, signed by the root, BasicConstraints CA=true. It carries an AIA `caIssuers` URL pointing at the root certificate.
3. Leaf: RSA-2048, `CN=localhost`, SAN `localhost`, EKU serverAuth, signed by the intermediate. It carries an AIA `caIssuers` URL pointing at the **intermediate** certificate (`http://127.0.0.1:<port>/<guid>/intermediate.cer`).
4. The leaf is exported to a PFX that contains only the leaf and re-imported with `DefaultKeySet`. This guarantees no intermediate travels with the certificate and gives a non-ephemeral key (Windows does not accept ephemeral keys for Schannel).
5. The intermediate and root are not installed in any store, so the only way to obtain the intermediate is the AIA URL.

AIA URLs point to a tiny in-test HTTP server (`AiaServer`) that serves the DER certificates and records every request. A random GUID in the path makes URLs unique, so the Windows URL cache cannot hide a download between runs.

## What the test does

A real `SslStream` client/server handshake over loopback. The client uses `CertificateChainPolicy.DisableCertificateDownloads = true` and a permissive validation callback so the client never downloads anything itself. All AIA requests are therefore caused by the server.

| Server configuration | Expected AIA requests |
|---|---|
| `ServerCertificate` only (control) | > 0 |
| `ServerCertificate` + `CertificateChainPolicy.DisableCertificateDownloads` | 0 |
| `ServerCertificateSelectionCallback` + same policy | 0 |
| `ServerCertificateContext = Create(leaf, null, offline: true)` | 0 |

For the "0" rows the test also asserts the intermediate was not written to the CurrentUser `CA` store. .NET adds downloaded intermediates there on Windows, the test removes them in `finally` anyway.

## Results (Windows, 2026-11-09)

- Prototype: 4/4 pass.
- Base (dotnet/runtime main `6cf1b618608`, without the prototype): control passes, `ChainPolicy` and `ChainPolicyWithSelectionCallback` fail with `Unexpected AIA requests: .../intermediate.cer, .../root.cer`. The `OfflineCertificateContext` row passes on main only because #134585 sets the Schannel flag unconditionally.
- Earlier manual runs (`D:\code\.samples\schannel-aia-repro`) agree and additionally showed with direct Schannel calls that flag `0` or `0x8000` still downloads, and `0x20000` does not. `openssl s_client -showcerts` confirmed 2 certificates sent by default and 1 with downloads disabled.
- With the Schannel flag removed but the .NET change kept, the policy scenario still downloaded, so both halves are required.

## Running

```
cd src\libraries\System.Net.Security\src
dotnet build -c Debug
cd ..\tests\FunctionalTests
dotnet build /t:test System.Net.Security.Tests.csproj /p:XunitMethodName=System.Net.Security.Tests.SslStreamCertificateContextTests.ServerCertificate_AiaDownload_HonorsDisableCertificateDownloads
```

Note: build the `src` project first. Building only the test project does not refresh `System.Net.Security.dll` in the testhost.

## Open questions for the proposal

- The default flips back to "Schannel may download", undoing #134585's unconditional behaviour unless the user opts out.
- `CertificateChainPolicy` is documented as the policy for validating the remote certificate. Reusing it for the local chain stretches its meaning. An alternative is a dedicated option.
- A client `ClientCertificateContext` that is offline combined with a client certificate selection callback loses the offline setting when the callback path builds a replacement context.
- Credential cache keying is covered by reasoning only, not by a test.
