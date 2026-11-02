# Signing the release builds

Unsigned builds make macOS and Windows warn testers on first launch. The Release workflow signs
the macOS build with an Apple Developer ID and the Windows build through SignPath Foundation, each
when the repository has its secrets (below); until then that build is unsigned and the run shows
a warning saying so.

## macOS: Developer ID signing and notarization

Signing proves the build comes from you; notarization has Apple scan it. Together they let
Gatekeeper open the programs without the "Apple could not verify…" block. The workflow runs
`packaging/macos-sign.sh`: it signs `nn-server` and `nn-generator` with the hardened runtime and a
secure timestamp, submits them to Apple's notary service, waits for the verdict and fails the
build if Apple rejects them (printing Apple's log).

Bare programs in a `.tar.gz` can't carry a stapled notarization ticket, so a tester's Mac checks
with Apple online the first time each program runs. Offline testers would still see the warning.

### One-time setup (in your Apple account, then GitHub)

1. **Developer ID Application certificate.** In Xcode (Settings → Accounts → Manage
   Certificates → + → Developer ID Application), or at developer.apple.com → Certificates. In
   Keychain Access, find "Developer ID Application: *your name* (*team ID*)", expand it so the
   private key is included, and export both as a `.p12` with a strong password.
2. **App Store Connect API key, for notarization.** appstoreconnect.apple.com → Users and Access
   → Integrations → App Store Connect API → Team Keys → +, with the **Developer** role. Note the
   **Key ID** and the **Issuer ID** shown above the list, and download the `.p8` file (Apple
   offers it once).
3. **Repository secrets.** NetworkNinja → Settings → Secrets and variables → Actions → New
   repository secret, one for each:

   | Secret | Value |
   | --- | --- |
   | `MACOS_CERT_P12` | the `.p12`, base64: `base64 -i cert.p12 \| pbcopy` |
   | `MACOS_CERT_PASSWORD` | the `.p12`'s password |
   | `APPLE_API_KEY` | the `.p8`, base64: `base64 -i AuthKey_XXXX.p8 \| pbcopy` |
   | `APPLE_API_KEY_ID` | the Key ID |
   | `APPLE_API_ISSUER` | the Issuer ID |

   Then delete the local `.p12` and `.p8` copies you don't need.

### Checking it

Re-run the Release workflow on a pull request that touches `packaging/` (or push a tag). The
"Sign and notarize (macOS)" step should print the signing identity, Apple's `Accepted` verdict
and `source=Notarized Developer ID` for both programs. On a Mac, after downloading the archive in
a browser:

```sh
spctl --assess --type execute --verbose=2 nn-server   # accepted, source=Notarized Developer ID
codesign -dv --verbose=2 nn-server                    # Authority=Developer ID Application: …
```

The certificate lasts five years; the API key until you revoke it. Rotate either by replacing
its secret.

## Windows: SignPath Foundation

Windows trusts Authenticode signatures only, so a Google or Apple account doesn't help. As an
open-source project, NetworkNinja can get a free certificate through
[SignPath Foundation](https://signpath.org): the certificate is issued to SignPath Foundation, and
SignPath signs only builds that come from this repository's Release workflow on GitHub-hosted
runners. The README's [code signing policy](../README.md#code-signing-policy) is part of their
terms.

The workflow's Windows build checks that both programs carry the version resource SignPath
checks (`packaging/winres.rs`: ProductName "NetworkNinja", ProductVersion the workspace version).
When SignPath is set up, it then uploads the two programs, has SignPath sign them, and checks the
signatures before archiving. Tags use the **release-signing** policy, which waits up to an hour
for you to approve the request in SignPath; other runs use **test-signing**.

### One-time setup

1. **Apply** at <https://signpath.org/apply> with the repository URL. Their terms ask for:
   an OSI licence (Apache-2.0), an actively maintained and already released project,
   multi-factor authentication on GitHub and SignPath for everyone on the team, and the
   README's code signing policy.
2. **In SignPath**, once accepted (they usually set the project up with you):
   - a project, slug `NetworkNinja` (or another; see the variable below), linked to the
     trusted build system *GitHub.com* and this repository;
   - its default artifact configuration: paste
     [`packaging/signpath/artifact-configuration.xml`](signpath/artifact-configuration.xml);
   - signing policies `test-signing` and `release-signing`, the latter with you as approver and
     restricted to tags or `main`;
   - an API token for a CI user with submitter permission on both policies.
3. **In GitHub**, NetworkNinja → Settings → Secrets and variables → Actions:

   | Kind | Name | Value |
   | --- | --- | --- |
   | Secret | `SIGNPATH_API_TOKEN` | the CI user's API token |
   | Variable | `SIGNPATH_ORGANIZATION_ID` | your SignPath organization ID |
   | Variable (optional) | `SIGNPATH_PROJECT_SLUG` | the project slug, if not `NetworkNinja` |

### Checking it

Re-run the Release workflow on a pull request that touches `packaging/`: "Sign (Windows)" submits
a test-signing request and "Check signature (Windows)" prints each program's signer. After a
tagged release, on Windows:

```powershell
Get-AuthenticodeSignature .\nn-server.exe   # Status Valid, signer SignPath Foundation
```

SmartScreen may still warn about a newly signed program until it builds up reputation; the
publisher shown is then SignPath Foundation rather than "Unknown publisher".
