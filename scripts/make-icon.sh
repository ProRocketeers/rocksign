#!/bin/bash
# Rebuild packaging/macos/AppIcon.icns from AppIcon.svg. Only needed when the icon changes.
set -euo pipefail
cd "$(dirname "$0")/.."

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
set_dir="$work/AppIcon.iconset"
mkdir -p "$set_dir"
cargo build -q -p rocksign-core --example render_svg
render=target/debug/examples/render_svg
for size in 16 32 128 256 512; do
  "$render" packaging/macos/AppIcon.svg "$set_dir/icon_${size}x${size}.png" "$size"
  "$render" packaging/macos/AppIcon.svg "$set_dir/icon_${size}x${size}@2x.png" "$((size * 2))"
done
iconutil -c icns "$set_dir" -o packaging/macos/AppIcon.icns
echo "wrote packaging/macos/AppIcon.icns"
