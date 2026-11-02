#!/usr/bin/env bash
# Sign the macOS binaries in DIR with a Developer ID Application certificate
# and have Apple notarize them, so Gatekeeper opens them without a warning.
#
#   packaging/macos-sign.sh DIR
#
# Reads (the release workflow passes these from repository secrets; see
# packaging/SIGNING.md):
#   MACOS_CERT_P12       the Developer ID Application certificate and its
#                        private key, exported as .p12, base64-encoded
#   MACOS_CERT_PASSWORD  the .p12's password
#   APPLE_API_KEY        an App Store Connect API key (.p8), base64-encoded
#   APPLE_API_KEY_ID     that key's Key ID
#   APPLE_API_ISSUER     the Issuer ID shown with App Store Connect API keys
#
# Fails, and so fails the build, if signing or notarization does. Bare
# binaries can't carry a stapled ticket; Gatekeeper looks the notarization
# up online the first time a binary runs.
set -euo pipefail

dir=${1:?usage: macos-sign.sh DIR}
for v in MACOS_CERT_P12 MACOS_CERT_PASSWORD APPLE_API_KEY APPLE_API_KEY_ID APPLE_API_ISSUER; do
    [[ -n "${!v:-}" ]] || { echo "macos-sign: $v isn't set" >&2; exit 2; }
done

work=$(mktemp -d)
keychain="$work/signing.keychain-db"
keychain_pw=$(uuidgen)
cleanup() {
    security delete-keychain "$keychain" 2> /dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT

# A throwaway keychain holding only the certificate, so codesign can use it
# without a prompt and nothing lingers on the runner.
echo "$MACOS_CERT_P12" | base64 --decode > "$work/cert.p12"
security create-keychain -p "$keychain_pw" "$keychain"
security set-keychain-settings -lut 3600 "$keychain"
security unlock-keychain -p "$keychain_pw" "$keychain"
security import "$work/cert.p12" -k "$keychain" -P "$MACOS_CERT_PASSWORD" -T /usr/bin/codesign
security set-key-partition-list -S apple-tool:,apple: -s -k "$keychain_pw" "$keychain" > /dev/null
security list-keychains -d user -s "$keychain" $(security list-keychains -d user | tr -d '"')
identity=$(security find-identity -v -p codesigning "$keychain" | awk '/Developer ID Application/ {print $2; exit}')
[[ -n "$identity" ]] || { echo "macos-sign: no Developer ID Application identity in the certificate" >&2; exit 1; }
echo "signing with $(security find-identity -v -p codesigning "$keychain" | awk -v id="$identity" '$2 == id {$1=""; $2=""; print}')"

# Hardened runtime and a secure timestamp: both required for notarization.
bins=("$dir/nn-server" "$dir/nn-generator")
for b in "${bins[@]}"; do
    codesign --force --options runtime --timestamp --keychain "$keychain" --sign "$identity" "$b"
    codesign --verify --strict --verbose=2 "$b"
done

# Notarize: Apple scans the binaries; wait for its verdict.
echo "$APPLE_API_KEY" | base64 --decode > "$work/key.p8"
(cd "$dir" && zip -q "$work/notarize.zip" nn-server nn-generator)
result=$(xcrun notarytool submit "$work/notarize.zip" --key "$work/key.p8" --key-id "$APPLE_API_KEY_ID" \
    --issuer "$APPLE_API_ISSUER" --wait --timeout 30m --output-format json)
echo "$result"
id=$(echo "$result" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("id",""))')
status=$(echo "$result" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status",""))')
if [[ "$status" != "Accepted" ]]; then
    echo "::error::Apple didn't notarize the macOS build (status: ${status:-unknown}); its log follows"
    [[ -n "$id" ]] && xcrun notarytool log "$id" --key "$work/key.p8" --key-id "$APPLE_API_KEY_ID" --issuer "$APPLE_API_ISSUER" || true
    exit 1
fi

# What Gatekeeper will say on a tester's Mac. (`--type execute` only judges
# app bundles; the open context assesses a bare program's signature.)
for b in "${bins[@]}"; do
    spctl --assess --verbose=2 --type open --context context:primary-signature "$b" 2>&1 || true
done
echo "signed and notarized: ${bins[*]}"
