#!/bin/bash
# Build RockSign.app and a disk image in dist/.
#
#   scripts/bundle.sh               # for this Mac's processor
#   scripts/bundle.sh --universal   # Apple Silicon + Intel in one app
#
# Environment:
#   BUNDLE_ID       app identifier (default com.prorocketeers.rocksign)
#   SIGN_IDENTITY   codesign identity; "-" (default) signs ad hoc, which needs no Apple account.
#                   With a "Developer ID Application: …" identity the app is signed with the
#                   hardened runtime, ready for notarization.
set -euo pipefail
cd "$(dirname "$0")/.."

BUNDLE_ID="${BUNDLE_ID:-com.prorocketeers.rocksign}"
SIGN_IDENTITY="${SIGN_IDENTITY:--}"
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-12.0}"

version=$(scripts/version.sh)
mkdir -p dist
rm -rf dist/RockSign.app dist/RockSign-*.dmg dist/RockSign-*.dmg.sha256

if [[ "${1:-}" == "--universal" ]]; then
  for target in aarch64-apple-darwin x86_64-apple-darwin; do
    cargo build --release --locked --target "$target"
  done
  binary=target/universal/rocksign
  mkdir -p target/universal
  lipo -create -output "$binary" \
    target/aarch64-apple-darwin/release/rocksign \
    target/x86_64-apple-darwin/release/rocksign
else
  cargo build --release --locked
  binary=target/release/rocksign
fi

app=dist/RockSign.app
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$binary" "$app/Contents/MacOS/rocksign"
cp packaging/macos/AppIcon.icns "$app/Contents/Resources/AppIcon.icns"
sed -e "s/__VERSION__/$version/g" -e "s/__BUNDLE_ID__/$BUNDLE_ID/g" packaging/macos/Info.plist > "$app/Contents/Info.plist"
plutil -lint -s "$app/Contents/Info.plist"

if [[ "$SIGN_IDENTITY" == "-" ]]; then
  codesign --force --sign - "$app"
else
  codesign --force --options runtime --timestamp --sign "$SIGN_IDENTITY" "$app"
fi
codesign --verify --strict "$app"

# Disk image: the app plus a shortcut to Applications to drag it onto.
staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT
ditto "$app" "$staging/RockSign.app"
ln -s /Applications "$staging/Applications"
dmg="RockSign-$version.dmg"
hdiutil create -quiet -volname "RockSign $version" -srcfolder "$staging" -fs HFS+ -format UDZO -ov "dist/$dmg"
(cd dist && shasum -a 256 "$dmg" > "$dmg.sha256")

echo "Built dist/RockSign.app and dist/$dmg ($(lipo -archs "$app/Contents/MacOS/rocksign"))"
