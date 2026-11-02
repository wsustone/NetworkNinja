# Signing the release builds

Unsigned builds make macOS and Windows warn testers on first launch. The Release workflow signs
the macOS build when the repository has the secrets below; until then it builds unsigned and the
run shows a warning saying so.

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

## Windows

Windows trusts Authenticode signatures only: a Google or Apple account doesn't help. The choices
are Microsoft's **Azure Trusted Signing** (a monthly subscription; signs from CI with an Azure
identity) or a code-signing certificate from a certificate authority (OV, or EV for immediate
SmartScreen reputation; usually on a hardware token or a cloud HSM). Either can be added to the
workflow's Windows build in the same way: a signing step between Stage and Archive that runs
when its secrets are set.
